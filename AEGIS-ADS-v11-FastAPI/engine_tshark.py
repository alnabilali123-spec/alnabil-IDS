"""AEGIS-ADS ENGINE - PyShark/Tshark Based (WORKING!)"""
import sys,os,time,joblib,numpy as np,subprocess
from collections import defaultdict
from datetime import datetime

sys.path.insert(0,'.')
from core.feature_extractor import FeatureExtractor
import config

print("="*60)
print("  AEGIS-ADS ENGINE - TSHARK MODE")
print("="*60)

rf = joblib.load('models/aegis_ids_rf_model.pkl')
xgb = joblib.load('models/xgb_classifier.pkl')
aegis_scaler = joblib.load('models/aegis_ids_scaler.pkl')
minmax_scaler = joblib.load('models/scaler.pkl')
le = joblib.load('models/label_encoder.pkl')
extractor = FeatureExtractor()
print("[OK] Models loaded")

def block_ip(ip, reason):
    # Only block local hotspot clients (192.168.137.x)
    if not ip.startswith('192.168.137.'): return
    if ip in ('127.0.0.1','192.168.8.5','192.168.8.1','192.168.137.1','0.0.0.0'): return
    try:
        rule = f"AEGIS_Block_{ip.replace('.','_')}"
        subprocess.run(f'netsh advfirewall firewall delete rule name="{rule}"', shell=True, capture_output=True)
        cmd = f'netsh advfirewall firewall add rule name="{rule}" dir=in action=block remoteip={ip} enable=yes'
        r = subprocess.run(cmd, shell=True, capture_output=True)
        if r.returncode == 0:
            print(f"  [FIREWALL] 🚫 BLOCKED {ip} - {reason}")
            return True
    except Exception as e:
        print(f"  [FIREWALL] Error: {e}")
    return False

port_tracker = defaultdict(lambda: {'ports': set(), 'start': time.time()})
ping_tracker = defaultdict(lambda: {'count': 0, 'start': time.time()})
packet_count = 0; detections = 0; blocks = 0

# Use tshark directly via subprocess - WORKS!
import threading, queue

print("[OK] Starting tshark on interface 4...")
print("="*60)
print("  Press Ctrl+C to stop")
print("  From other device: ping 192.168.137.1 -t")
print("="*60)

def process_line(line):
    global packet_count, detections, blocks
    try:
        parts = line.strip().split('\t')
        if len(parts) < 3: return
        
        src = parts[0].strip()
        dst = parts[1].strip() 
        length = int(parts[2].strip())
        
        if src in config.LOCAL_IPS and dst in config.LOCAL_IPS: return
        
        packet_count += 1
        now = time.time()
        
        # Determine protocol from port/behavior
        transport = "TCP"
        if 'ICMP' in line.upper() or length < 100:
            transport = "ICMP"
        
        info = {'src_ip': src, 'dst_ip': dst, 'length': length, 'transport': transport}
        
        # ICMP Flood Detection
        if transport == 'ICMP' and src.startswith('192.168.137.'):
            t = ping_tracker[src]
            t['count'] += 1
            if t['count'] >= 5 and (now - t['start']) < 3:
                detections += 1
                print(f"\n{'='*60}")
                print(f"  [ICMP FLOOD] {src} → {dst}")
                print(f"  Pings: {t['count']} in {(now-t['start']):.1f}s")
                if block_ip(src, 'ICMP Flood Attack'):
                    blocks += 1
                print(f"{'='*60}")
                t['count'] = 0
                t['start'] = now
            return
        
        # Status
        if packet_count % 50 == 0:
            print(f"\r[Pkts: {packet_count} | Det: {detections} | Blk: {blocks}]", end='', flush=True)
            
    except Exception as e:
        pass

# Start tshark process
tshark_cmd = ['tshark', '-i', '4', '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'frame.len', '-l']
proc = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)

try:
    for line in proc.stdout:
        if line.strip():
            process_line(line)
except KeyboardInterrupt:
    proc.terminate()
    print(f"\n\n{'='*60}")
    print(f"  FINAL RESULTS")
    print(f"  Packets: {packet_count}")
    print(f"  Detections: {detections}")
    print(f"  Blocks: {blocks}")
    print(f"{'='*60}")
