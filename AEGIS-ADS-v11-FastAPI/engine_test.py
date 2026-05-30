"""AEGIS-ADS ENGINE TEST - Direct AI Pipeline + Real Blocking"""
import sys,os,time,joblib,numpy as np,subprocess
from collections import defaultdict
from datetime import datetime

sys.path.insert(0,'.')
from core.feature_extractor import FeatureExtractor
import config

print("="*60)
print("  AEGIS-ADS ENGINE - LIVE TEST WITH BLOCKING")
print("="*60)

# Load models
rf = joblib.load('models/aegis_ids_rf_model.pkl')
xgb = joblib.load('models/xgb_classifier.pkl')
aegis_scaler = joblib.load('models/aegis_ids_scaler.pkl')
minmax_scaler = joblib.load('models/scaler.pkl')
le = joblib.load('models/label_encoder.pkl')
extractor = FeatureExtractor()
print("[OK] All models loaded")

# Block function
def block_ip(ip, reason):
    if ip in ('127.0.0.1','192.168.8.5','192.168.8.1','192.168.137.1'): return
    try:
        rule = f"AEGIS_Block_{ip.replace('.','_')}"
        subprocess.run(f'netsh advfirewall firewall delete rule name="{rule}"', shell=True, capture_output=True)
        cmd = f'netsh advfirewall firewall add rule name="{rule}" dir=in action=block remoteip={ip} enable=yes'
        subprocess.run(cmd, shell=True, capture_output=True)
        print(f"  [FIREWALL] BLOCKED {ip} - {reason}")
    except Exception as e: print(f"  [FIREWALL] Error: {e}")

# Trackers
port_tracker=defaultdict(lambda:{'ports':set(),'start':time.time()})
ping_tracker=defaultdict(lambda:{'count':0,'start':time.time()})
syn_tracker=defaultdict(lambda:{'count':0,'start':time.time()})
packet_count=0; detections=0; blocks=0

from scapy.all import sniff,conf,IP,TCP,UDP,ICMP
conf.use_pcap=True

# Find Hotspot interface
target=None
for name in conf.ifaces:
    try:
        ip = conf.ifaces[name].ip
        if ip and '192.168.137' in ip:
            target=name; break
    except: pass
if not target:
    for name in conf.ifaces:
        if 'Direct' in name or 'Wi-Fi Direct' in name: target=name; break
if not target: target=conf.iface.name

print(f"[OK] Interface: {target}")
print(f"[OK] Monitoring Hotspot traffic...")
print("="*60)
print("  Press Ctrl+C to stop")
print("="*60)

def handle(pkt):
    global packet_count,detections,blocks
    try:
        if IP not in pkt: return
        s=pkt[IP].src; d=pkt[IP].dst
        if s in config.LOCAL_IPS and d in config.LOCAL_IPS: return
        
        packet_count+=1; now=time.time()
        info={'src_ip':s,'dst_ip':d,'length':len(pkt),'transport':'IP'}; flags=''; dst_port=0
        
        if TCP in pkt:
            info.update({'transport':'TCP','src_port':pkt[TCP].sport,'dst_port':pkt[TCP].dport,'flags':str(pkt[TCP].flags)})
            flags=str(pkt[TCP].flags); dst_port=pkt[TCP].dport
        elif UDP in pkt:
            info.update({'transport':'UDP','src_port':pkt[UDP].sport,'dst_port':pkt[UDP].dport}); dst_port=pkt[UDP].dport
        elif ICMP in pkt:
            info.update({'transport':'ICMP','src_port':0,'dst_port':0})
        else: return
        
        # ============================================
        # ICMP FLOOD - Block immediately
        # ============================================
        if info['transport']=='ICMP':
            t=ping_tracker[s]; t['count']+=1
            if t['count']>=5 and (now-t['start'])<2:
                detections+=1; blocks+=1
                print(f"\n{'='*60}")
                print(f"  [ICMP FLOOD] {s} → {d}")
                print(f"  Pings: {t['count']} in {(now-t['start']):.1f}s")
                block_ip(s, 'ICMP Flood Attack')
                print(f"{'='*60}")
                t['count']=0; t['start']=now
            return
        
        # ============================================
        # PORT SCAN - Block immediately
        # ============================================
        if 'S' in flags.upper() and 'A' not in flags.upper():
            pt=port_tracker[s]; pt['ports'].add(dst_port)
            if len(pt['ports'])>=8 and (now-pt['start'])<5:
                detections+=1; blocks+=1
                print(f"\n{'='*60}")
                print(f"  [PORT SCAN] {s} scanned {len(pt['ports'])} ports")
                block_ip(s, 'Port Scan Attack')
                print(f"{'='*60}")
                pt['ports'].clear(); pt['start']=now
                return
        
        # ============================================
        # SYN FLOOD - Block immediately
        # ============================================
        if 'S' in flags.upper() and 'A' not in flags.upper():
            st=syn_tracker[s]; st['count']+=1
            if st['count']>=15 and (now-st['start'])<2:
                detections+=1; blocks+=1
                print(f"\n{'='*60}")
                print(f"  [SYN FLOOD] {s} - {st['count']} SYNs")
                block_ip(s, 'SYN Flood Attack')
                print(f"{'='*60}")
                st['count']=0; st['start']=now
                return
        
        # ============================================
        # AI ANALYSIS (every 10th packet)
        # ============================================
        if packet_count%10==0:
            try:
                f78=extractor.extract_from_dict(info)
                f78s=aegis_scaler.transform(f78)
                probs=rf.predict_proba(f78s)[0]
                
                if probs[1]>0.2:  # Low threshold for demo
                    f10=f78[:,[0,4,6,8,14,34,44,46,47,52]]
                    f10s=minmax_scaler.transform(f10)
                    pred=int(xgb.predict(f10s)[0])
                    conf=float(max(xgb.predict_proba(f10s)[0]))*100
                    attack=str(le.inverse_transform([pred])[0])
                    
                    if attack.upper()!='BENIGN' and conf>40:
                        detections+=1
                        sev='CRITICAL' if conf>85 else 'HIGH' if conf>70 else 'MEDIUM'
                        print(f"\n{'='*60}")
                        print(f"  [AI] {attack} from {s}")
                        print(f"  T1: {probs[1]*100:.1f}% | T2: {conf:.1f}% | Severity: {sev}")
                        
                        if sev in ['CRITICAL','HIGH']:
                            blocks+=1
                            block_ip(s, f'AI: {attack} ({conf:.0f}%)')
                        
                        print(f"{'='*60}")
            except Exception as e: pass
        
        # Status
        if packet_count%50==0:
            print(f"\r[Packets: {packet_count} | Detections: {detections} | Blocks: {blocks}]", end='', flush=True)
    except: pass

try:
    sniff(iface=target, prn=handle, store=False)
except KeyboardInterrupt:
    print(f"\n\n{'='*60}")
    print(f"  TEST COMPLETE")
    print(f"  Packets: {packet_count}")
    print(f"  Detections: {detections}")
    print(f"  Blocks: {blocks}")
    print(f"{'='*60}")
