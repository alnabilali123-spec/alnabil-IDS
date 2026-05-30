"""
AEGIS-ADS + Kitsune Integration
Combines supervised (RF+XGB) with unsupervised (Autoencoders) detection
"""
import sys, os, time, numpy as np
from collections import defaultdict
from datetime import datetime

sys.path.insert(0, 'C:/Users/ComputerWorld/PycharmProjects/Kitsune-py-master')
sys.path.insert(0, '.')

import joblib
from core.feature_extractor import FeatureExtractor
from core.firewall_manager import block_ip_v2
import config

print("="*60)
print("  AEGIS-ADS + KITSUNE - Dual AI Engine")
print("="*60)

# Load AEGIS models
rf = joblib.load('models/aegis_ids_rf_model.pkl')
xgb = joblib.load('models/xgb_classifier.pkl')
aegis_scaler = joblib.load('models/aegis_ids_scaler.pkl')
minmax_scaler = joblib.load('models/scaler.pkl')
le = joblib.load('models/label_encoder.pkl')
extractor = FeatureExtractor()
print("[OK] AEGIS models loaded")

# Try loading Kitsune
try:
    from Kitsune import Kitsune
    kitsune = Kitsune(None, 10, 1000, 5000)
    print("[OK] Kitsune loaded (unsupervised engine)")
    has_kitsune = True
except Exception as e:
    print(f"[INFO] Kitsune not available: {e}")
    has_kitsune = False

# Detection
ping_tracker = defaultdict(lambda: {'count': 0, 'start': time.time()})
port_tracker = defaultdict(lambda: {'ports': set(), 'start': time.time()})
packet_count = 0; detections = 0; blocks = 0

def process_packet(pkt):
    global packet_count, detections, blocks
    try:
        from scapy.all import IP, TCP, UDP, ICMP
        if IP not in pkt: return
        s = pkt[IP].src; d = pkt[IP].dst
        if s in config.LOCAL_IPS and d in config.LOCAL_IPS: return
        
        packet_count += 1; now = time.time()
        info = {'src_ip': s, 'dst_ip': d, 'length': len(pkt), 'transport': 'IP'}
        flags = ''
        
        if TCP in pkt:
            info.update({'transport': 'TCP', 'src_port': pkt[TCP].sport, 'dst_port': pkt[TCP].dport, 'flags': str(pkt[TCP].flags)})
            flags = str(pkt[TCP].flags)
        elif UDP in pkt:
            info.update({'transport': 'UDP', 'src_port': pkt[UDP].sport, 'dst_port': pkt[UDP].dport})
        elif ICMP in pkt:
            info.update({'transport': 'ICMP'})
        
        # ICMP Flood
        if info['transport'] == 'ICMP' and s.startswith('192.168.137.'):
            t = ping_tracker[s]; t['count'] += 1
            if t['count'] >= 5 and (now - t['start']) < 3:
                detections += 1; blocks += 1
                block_ip_v2(s, 'ICMP Flood')
                print(f"🌊 ICMP FLOOD: {s} → BLOCKED")
                t['count'] = 0; t['start'] = now
            return
        
        # Port Scan
        if 'S' in flags.upper() and 'A' not in flags.upper() and s.startswith('192.168.137.'):
            pt = port_tracker[s]; pt['ports'].add(info.get('dst_port', 0))
            if len(pt['ports']) >= 8 and (now - pt['start']) < 5:
                detections += 1; blocks += 1
                block_ip_v2(s, 'Port Scan')
                print(f"🔍 PORT SCAN: {s} → BLOCKED")
                pt['ports'].clear(); pt['start'] = now
                return
        
        # AEGIS AI
        if packet_count % 10 == 0 and s.startswith('192.168.137.'):
            f78 = extractor.extract_from_dict(info)
            is_attack, l1_conf = rf_predict(f78)
            if is_attack and l1_conf > 20:
                f10 = f78[:, [0,4,6,8,14,34,44,46,47,52]]
                l2 = xgb_predict(f10)
                if l2['confidence'] > 40:
                    detections += 1
                    if l2['confidence'] > 70:
                        blocks += 1
                        block_ip_v2(s, f"AI: {l2['attack_type']}")
                    print(f"🤖 AEGIS: {l2['attack_type']} from {s} ({l2['confidence']:.0f}%)")
        
        # Kitsune anomaly detection
        if has_kitsune and packet_count > 1000 and packet_count % 50 == 0:
            try:
                rmse = kitsune.proc_next_packet()
                if rmse > 0.1:  # Anomaly threshold
                    print(f"🦊 KITSUNE: Anomaly detected! RMSE={rmse:.4f}")
            except:
                pass
        
        if packet_count % 100 == 0:
            print(f"[Pkts:{packet_count} | Det:{detections} | Blk:{blocks}]", end='\r')
            
    except Exception as e:
        pass

def rf_predict(f78):
    try:
        f78s = aegis_scaler.transform(f78)
        probs = rf.predict_proba(f78s)[0]
        return len(probs)>1 and probs[1]>0.3, float(max(probs))*100
    except:
        return False, 0.0

def xgb_predict(f10):
    try:
        f10s = minmax_scaler.transform(f10)
        pred = int(xgb.predict(f10s)[0])
        conf = float(max(xgb.predict_proba(f10s)[0]))*100
        name = str(le.inverse_transform([pred])[0])
        return {"attack_type": name, "confidence": conf}
    except:
        return {"attack_type": "Error", "confidence": 0.0}

# Start capture
from scapy.all import sniff, conf
conf.use_pcap = True
target = None
for name in conf.ifaces:
    if 'Direct' in name or '137' in str(getattr(conf.ifaces[name], 'ip', '')):
        target = name; break
if not target: target = conf.iface.name

print(f"[OK] Sniffing on: {target}")
print("="*60)
print("  Press Ctrl+C to stop")
print("="*60)

try:
    sniff(iface=target, prn=process_packet, store=False)
except KeyboardInterrupt:
    print(f"\n\nPackets: {packet_count} | Detections: {detections} | Blocks: {blocks}")
