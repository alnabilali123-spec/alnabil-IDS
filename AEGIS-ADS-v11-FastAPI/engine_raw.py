"""AEGIS-ADS ENGINE - Raw Socket Fallback"""
import sys,os,time,joblib,numpy as np,subprocess,socket,struct
from collections import defaultdict
from datetime import datetime

sys.path.insert(0,'.')
from core.feature_extractor import FeatureExtractor
import config

print("="*60)
print("  AEGIS-ADS ENGINE - RAW SOCKET MODE")
print("="*60)

# Load models
rf = joblib.load('models/aegis_ids_rf_model.pkl')
xgb = joblib.load('models/xgb_classifier.pkl')
aegis_scaler = joblib.load('models/aegis_ids_scaler.pkl')
minmax_scaler = joblib.load('models/scaler.pkl')
le = joblib.load('models/label_encoder.pkl')
extractor = FeatureExtractor()
print("[OK] Models loaded")

def block_ip(ip, reason):
    if ip in ('127.0.0.1','192.168.8.5','192.168.8.1','192.168.137.1'): return
    try:
        rule = f"AEGIS_Block_{ip.replace('.','_')}"
        subprocess.run(f'netsh advfirewall firewall delete rule name="{rule}"', shell=True, capture_output=True)
        cmd = f'netsh advfirewall firewall add rule name="{rule}" dir=in action=block remoteip={ip} enable=yes'
        subprocess.run(cmd, shell=True, capture_output=True)
        print(f"  [FIREWALL] BLOCKED {ip} - {reason}")
    except: pass

port_tracker=defaultdict(lambda:{'ports':set(),'start':time.time()})
ping_tracker=defaultdict(lambda:{'count':0,'start':time.time()})
syn_tracker=defaultdict(lambda:{'count':0,'start':time.time()})
packet_count=0; detections=0; blocks=0

print("[OK] Raw socket on 0.0.0.0")
print("="*60)
print("  Press Ctrl+C to stop")
print("="*60)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sock.bind(('0.0.0.0', 0))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.settimeout(0.5)
    
    while True:
        try:
            data = sock.recvfrom(65535)[0]
            if len(data) < 20: continue
            
            s = socket.inet_ntoa(data[12:16])
            d = socket.inet_ntoa(data[16:20])
            proto = data[9]
            
            if s in config.LOCAL_IPS and d in config.LOCAL_IPS: continue
            
            packet_count += 1
            now = time.time()
            transport = {6:"TCP", 17:"UDP", 1:"ICMP"}.get(proto, "IP")
            
            info = {'src_ip':s, 'dst_ip':d, 'length':len(data), 'transport':transport}
            
            if proto in [6,17] and len(data) >= 24:
                info['src_port'] = struct.unpack('!H', data[20:22])[0]
                info['dst_port'] = struct.unpack('!H', data[22:24])[0]
            
            # ICMP Flood
            if transport == 'ICMP':
                t = ping_tracker[s]; t['count'] += 1
                if t['count'] >= 5 and (now - t['start']) < 2:
                    detections += 1; blocks += 1
                    print(f"\n[ICMP FLOOD] {s} → {d} ({t['count']} pings)")
                    block_ip(s, 'ICMP Flood')
                    t['count'] = 0; t['start'] = now
                continue
            
            # Port Scan
            if proto == 6 and info.get('dst_port'):
                pt = port_tracker[s]; pt['ports'].add(info['dst_port'])
                if len(pt['ports']) >= 8 and (now - pt['start']) < 5:
                    detections += 1; blocks += 1
                    print(f"\n[PORT SCAN] {s} ({len(pt['ports'])} ports)")
                    block_ip(s, 'Port Scan')
                    pt['ports'].clear(); pt['start'] = now
                    continue
            
            # AI every 10th
            if packet_count % 10 == 0:
                try:
                    f78 = extractor.extract_from_dict(info)
                    f78s = aegis_scaler.transform(f78)
                    probs = rf.predict_proba(f78s)[0]
                    if probs[1] > 0.2:
                        f10 = f78[:, [0,4,6,8,14,34,44,46,47,52]]
                        f10s = minmax_scaler.transform(f10)
                        pred = int(xgb.predict(f10s)[0])
                        conf = float(max(xgb.predict_proba(f10s)[0])) * 100
                        attack = str(le.inverse_transform([pred])[0])
                        if attack.upper() != 'BENIGN' and conf > 40:
                            detections += 1
                            if conf > 70:
                                blocks += 1
                                block_ip(s, f'AI: {attack} ({conf:.0f}%)')
                            print(f"\n[AI] {attack} from {s} ({conf:.0f}%)")
                except: pass
            
            if packet_count % 50 == 0:
                print(f"\r[Pkts:{packet_count} | Det:{detections} | Blk:{blocks}]", end='', flush=True)
                
        except socket.timeout: continue
        except KeyboardInterrupt: break
        
except KeyboardInterrupt:
    pass
finally:
    sock.close()
    print(f"\n\n{'='*60}")
    print(f"  Packets: {packet_count} | Detections: {detections} | Blocks: {blocks}")
    print(f"{'='*60}")
