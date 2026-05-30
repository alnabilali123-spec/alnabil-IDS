# core/xgboost_features.py
import logging, os, joblib, numpy as np
from scapy.all import IP, TCP, UDP, ICMP
from datetime import datetime

logger = logging.getLogger(__name__)

# تحميل أسماء الميزات التي تدربت عليها L1 و L2 من features.pkl
_features_path = os.path.join(os.path.dirname(__file__), '..', 'models', 'features.pkl')
if os.path.exists(_features_path):
    with open(_features_path, 'rb') as f:
        FEATURE_NAMES_L1_L2 = joblib.load(f)
    if hasattr(FEATURE_NAMES_L1_L2, 'tolist'):
        FEATURE_NAMES_L1_L2 = FEATURE_NAMES_L1_L2.tolist()
    elif isinstance(FEATURE_NAMES_L1_L2, np.ndarray):
        FEATURE_NAMES_L1_L2 = FEATURE_NAMES_L1_L2.tolist()
else:
    FEATURE_NAMES_L1_L2 = []
    logger.warning("features.pkl not found; L1/L2 will not work correctly.")

# قائمة الـ 60 ميزة التي يستخدمها XGBoost Expert
FEATURE_NAMES_XGB = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets',
    'Total Backward Packets', 'Total Length of Fwd Packets',
    'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
    'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std',
    'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
    'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'SYN Flag Count',
    'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
    'FIN Flag Count', 'Fwd Packets/s', 'Bwd Packets/s', 'Flow Packets/s',
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'Down/Up Ratio', 'Average Packet Size',
    'Subflow Fwd Packets', 'Subflow Bwd Packets',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'act_data_pkt_fwd', 'min_seg_size_forward',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

def _parse_packets(events):
    """تحويل قائمة NetworkEvent إلى قائمة قواميس تحتوي على بيانات الحزم."""
    pkts = []
    for evt in events:
        try:
            raw = evt.raw_bytes if hasattr(evt, 'raw_bytes') else b''
            if not raw: continue
            pkt = IP(raw)
            proto = pkt.proto
            src_ip = pkt.src
            dst_ip = pkt.dst
            length = len(raw)
            ts = evt.timestamp.timestamp() if hasattr(evt.timestamp, 'timestamp') else (datetime.fromisoformat(evt.timestamp).timestamp() if isinstance(evt.timestamp, str) else evt.timestamp)

            sport = dport = 0
            tcp_win = tcp_seq = tcp_ack = 0
            tcp_urg = tcp_psh = tcp_rst = tcp_syn = tcp_fin = 0

            if proto == 6 and pkt.haslayer(TCP):
                tcp = pkt[TCP]
                sport, dport = tcp.sport, tcp.dport
                flags = str(tcp.flags)
                tcp_win, tcp_seq, tcp_ack = tcp.window, tcp.seq, tcp.ack
                tcp_urg = 1 if 'U' in flags else 0
                tcp_psh = 1 if 'P' in flags else 0
                tcp_rst = 1 if 'R' in flags else 0
                tcp_syn = 1 if 'S' in flags else 0
                tcp_fin = 1 if 'F' in flags else 0
            elif proto == 17 and pkt.haslayer(UDP):
                udp = pkt[UDP]
                sport, dport = udp.sport, udp.dport

            pkts.append({
                'src': src_ip, 'dst': dst_ip, 'sport': sport, 'dport': dport,
                'proto': proto, 'len': length, 'time': ts,
                'tcp_win': tcp_win, 'tcp_seq': tcp_seq, 'tcp_ack': tcp_ack,
                'tcp_urg': tcp_urg, 'tcp_psh': tcp_psh, 'tcp_rst': tcp_rst,
                'tcp_syn': tcp_syn, 'tcp_fin': tcp_fin
            })
        except: continue
    return pkts

def _compute_flow_features(pkts):
    """حساب الميزات الأساسية من قائمة الحزم المُعالجة."""
    if not pkts: return {}
    first = pkts[0]
    src_ip, dst_ip = first['src'], first['dst']
    src_port, dst_port = first['sport'], first['dport']
    proto = first['proto']

    if src_port != 0 and dst_port != 0:
        fwd = [p for p in pkts if p['src'] == src_ip and p['sport'] == src_port and p['dport'] == dst_port]
        bwd = [p for p in pkts if p['src'] == dst_ip and p['sport'] == dst_port and p['dport'] == src_port]
    else:
        fwd = [p for p in pkts if p['src'] == src_ip and p['dst'] == dst_ip]
        bwd = [p for p in pkts if p['src'] == dst_ip and p['dst'] == src_ip]

    duration = pkts[-1]['time'] - pkts[0]['time'] if len(pkts) > 1 else 0.001
    total_fwd, total_bwd = len(fwd), len(bwd)
    total_len_fwd = sum(p['len'] for p in fwd)
    total_len_bwd = sum(p['len'] for p in bwd)
    fwd_lens = [p['len'] for p in fwd] if fwd else [0]
    bwd_lens = [p['len'] for p in bwd] if bwd else [0]

    def calc_iat(pkts):
        if len(pkts) < 2: return 0, 0, 0, 0
        iats = np.diff([p['time'] for p in pkts])
        return np.mean(iats), np.std(iats), np.max(iats), np.min(iats)

    fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = calc_iat(fwd)
    bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = calc_iat(bwd)

    flow_rate = len(pkts) / duration
    fwd_rate = total_fwd / duration if duration > 0 else 0
    bwd_rate = total_bwd / duration if duration > 0 else 0

    syn_cnt = sum(p['tcp_syn'] for p in pkts)
    ack_cnt = sum(p['tcp_ack'] for p in pkts)
    fin_cnt = sum(p['tcp_fin'] for p in pkts)
    rst_cnt = sum(p['tcp_rst'] for p in pkts)
    psh_cnt = sum(p['tcp_psh'] for p in pkts)
    urg_cnt = sum(p['tcp_urg'] for p in pkts)

    fwd_psh = sum(p['tcp_psh'] for p in fwd)
    bwd_psh = sum(p['tcp_psh'] for p in bwd)
    fwd_urg = sum(p['tcp_urg'] for p in fwd)
    bwd_urg = sum(p['tcp_urg'] for p in bwd)

    avg_size = np.mean([p['len'] for p in pkts]) if pkts else 0
    fwd_seg_avg = total_len_fwd / total_fwd if total_fwd else 0
    bwd_seg_avg = total_len_bwd / total_bwd if total_bwd else 0
    down_up_ratio = total_len_bwd / total_len_fwd if total_len_fwd else 0

    return {
        'first_dport': first['dport'], 'first_sport': first['sport'], 'proto': proto,
        'duration': duration, 'total_fwd': total_fwd, 'total_bwd': total_bwd,
        'total_len_fwd': total_len_fwd, 'total_len_bwd': total_len_bwd,
        'fwd_lens': fwd_lens, 'bwd_lens': bwd_lens,
        'fwd_iat_mean': fwd_iat_mean, 'fwd_iat_std': fwd_iat_std, 'fwd_iat_max': fwd_iat_max, 'fwd_iat_min': fwd_iat_min,
        'bwd_iat_mean': bwd_iat_mean, 'bwd_iat_std': bwd_iat_std, 'bwd_iat_max': bwd_iat_max, 'bwd_iat_min': bwd_iat_min,
        'flow_rate': flow_rate, 'fwd_rate': fwd_rate, 'bwd_rate': bwd_rate,
        'syn_cnt': syn_cnt, 'ack_cnt': ack_cnt, 'fin_cnt': fin_cnt, 'rst_cnt': rst_cnt, 'psh_cnt': psh_cnt, 'urg_cnt': urg_cnt,
        'fwd_psh': fwd_psh, 'bwd_psh': bwd_psh, 'fwd_urg': fwd_urg, 'bwd_urg': bwd_urg,
        'avg_size': avg_size, 'fwd_seg_avg': fwd_seg_avg, 'bwd_seg_avg': bwd_seg_avg,
        'down_up_ratio': down_up_ratio,
        'fwd_win': fwd[0]['tcp_win'] if fwd and fwd[0]['proto'] == 6 else (fwd[0]['len'] if fwd else 0),
        'bwd_win': bwd[0]['tcp_win'] if bwd and bwd[0]['proto'] == 6 else (bwd[0]['len'] if bwd else 0),
    }

def extract_features_for_l1_l2(events):
    """تستخرج جميع الميزات التي تدربت عليها L1 و L2 (محملة من features.pkl)."""
    pkts = _parse_packets(events)
    if not pkts: return None
    s = _compute_flow_features(pkts)

    features = {}
    for name in FEATURE_NAMES_L1_L2:
        n = name.strip()
        if n in ['Dst Port', 'Destination Port']: features[name] = s['first_dport']
        elif n in ['Src Port', 'Source Port']: features[name] = 0.0  # محذوف من التدريب
        elif n == 'Protocol': features[name] = s['proto']
        elif n == 'Flow Duration': features[name] = s['duration']
        elif n in ['Total Fwd Packets', 'Tot Fwd Pkts']: features[name] = s['total_fwd']
        elif n in ['Total Backward Packets', 'Tot Bwd Pkts']: features[name] = s['total_bwd']
        elif n in ['Total Length of Fwd Packets', 'TotLen Fwd Pkts']: features[name] = s['total_len_fwd']
        elif n in ['Total Length of Bwd Packets', 'TotLen Bwd Pkts']: features[name] = s['total_len_bwd']
        elif n in ['Fwd Packet Length Max', 'Fwd Pkt Len Max']: features[name] = max(s['fwd_lens'])
        elif n in ['Fwd Packet Length Min', 'Fwd Pkt Len Min']: features[name] = min(s['fwd_lens'])
        elif n in ['Fwd Packet Length Mean', 'Fwd Pkt Len Mean']: features[name] = np.mean(s['fwd_lens'])
        elif n in ['Fwd Packet Length Std', 'Fwd Pkt Len Std']: features[name] = np.std(s['fwd_lens'])
        elif n in ['Bwd Packet Length Max', 'Bwd Pkt Len Max']: features[name] = max(s['bwd_lens'])
        elif n in ['Bwd Packet Length Min', 'Bwd Pkt Len Min']: features[name] = min(s['bwd_lens'])
        elif n in ['Bwd Packet Length Mean', 'Bwd Pkt Len Mean']: features[name] = np.mean(s['bwd_lens'])
        elif n in ['Bwd Packet Length Std', 'Bwd Pkt Len Std']: features[name] = np.std(s['bwd_lens'])
        elif n == 'Flow IAT Mean': features[name] = np.mean([s['fwd_iat_mean'], s['bwd_iat_mean']])
        elif n == 'Flow IAT Std': features[name] = np.std([s['fwd_iat_std'], s['bwd_iat_std']])
        elif n == 'Flow IAT Max': features[name] = max(s['fwd_iat_max'], s['bwd_iat_max'])
        elif n == 'Flow IAT Min': features[name] = min(s['fwd_iat_min'], s['bwd_iat_min'])
        elif n in ['Fwd IAT Total', 'Fwd IAT Tot']: features[name] = s['fwd_iat_mean'] * s['total_fwd'] if s['total_fwd'] else 0
        elif n == 'Fwd IAT Mean': features[name] = s['fwd_iat_mean']
        elif n == 'Fwd IAT Std': features[name] = s['fwd_iat_std']
        elif n == 'Fwd IAT Max': features[name] = s['fwd_iat_max']
        elif n == 'Fwd IAT Min': features[name] = s['fwd_iat_min']
        elif n in ['Bwd IAT Total', 'Bwd IAT Tot']: features[name] = s['bwd_iat_mean'] * s['total_bwd'] if s['total_bwd'] else 0
        elif n == 'Bwd IAT Mean': features[name] = s['bwd_iat_mean']
        elif n == 'Bwd IAT Std': features[name] = s['bwd_iat_std']
        elif n == 'Bwd IAT Max': features[name] = s['bwd_iat_max']
        elif n == 'Bwd IAT Min': features[name] = s['bwd_iat_min']
        elif n == 'Fwd PSH Flags': features[name] = s['fwd_psh']
        elif n == 'Bwd PSH Flags': features[name] = s['bwd_psh']
        elif n == 'Fwd URG Flags': features[name] = s['fwd_urg']
        elif n == 'Bwd URG Flags': features[name] = s['bwd_urg']
        elif n in ['SYN Flag Count', 'SYN Flag Cnt']: features[name] = s['syn_cnt']
        elif n in ['RST Flag Count', 'RST Flag Cnt']: features[name] = s['rst_cnt']
        elif n in ['PSH Flag Count', 'PSH Flag Cnt']: features[name] = s['psh_cnt']
        elif n in ['ACK Flag Count', 'ACK Flag Cnt']: features[name] = s['ack_cnt']
        elif n in ['URG Flag Count', 'URG Flag Cnt']: features[name] = s['urg_cnt']
        elif n in ['FIN Flag Count', 'FIN Flag Cnt']: features[name] = s['fin_cnt']
        elif n in ['Fwd Packets/s', 'Fwd Pkts/s']: features[name] = s['fwd_rate']
        elif n in ['Bwd Packets/s', 'Bwd Pkts/s']: features[name] = s['bwd_rate']
        elif n in ['Flow Packets/s', 'Flow Pkts/s', 'Flow Byts/s']: features[name] = s['flow_rate']
        elif n in ['Packet Length Mean', 'Pkt Len Mean']: features[name] = s['avg_size']
        elif n in ['Packet Length Std', 'Pkt Len Std']: features[name] = np.std([p['len'] for p in pkts]) if pkts else 0
        elif n in ['Packet Length Variance', 'Pkt Len Var']: features[name] = np.var([p['len'] for p in pkts]) if pkts else 0
        elif n == 'Down/Up Ratio': features[name] = s['down_up_ratio']
        elif n in ['Average Packet Size', 'Pkt Size Avg']: features[name] = s['avg_size']
        elif n in ['Fwd Segment Size Avg', 'Fwd Seg Size Avg']: features[name] = s['fwd_seg_avg']
        elif n in ['Bwd Segment Size Avg', 'Bwd Seg Size Avg']: features[name] = s['bwd_seg_avg']
        elif n in ['Subflow Fwd Packets', 'Subflow Fwd Pkts']: features[name] = s['total_fwd']
        elif n in ['Subflow Bwd Packets', 'Subflow Bwd Pkts']: features[name] = s['total_bwd']
        elif n in ['Init_Win_bytes_forward', 'Init Fwd Win Byts']: features[name] = s['fwd_win']
        elif n in ['Init_Win_bytes_backward', 'Init Bwd Win Byts']: features[name] = s['bwd_win']
        elif n in ['act_data_pkt_fwd', 'Fwd Act Data Pkts']: features[name] = sum(1 for p in pkts if p['len'] > 0 and p['src'] == pkts[0]['src']) if pkts else 0
        elif n in ['min_seg_size_forward', 'Fwd Seg Size Min']: features[name] = min(s['fwd_lens']) if s['fwd_lens'] else 0
        elif n in ['Fwd Header Len', 'Fwd Header Length']: features[name] = s['total_fwd'] * 20
        elif n in ['Bwd Header Len', 'Bwd Header Length']: features[name] = s['total_bwd'] * 20
        elif n == 'Flow Bytes/s': features[name] = (s['total_len_fwd'] + s['total_len_bwd']) / s['duration'] if s['duration'] > 0 else 0
        elif n in ['Active Mean', 'Active Max', 'Active Min']: features[name] = 1 if s['total_fwd'] > 0 else 0
        elif n in ['Active Std', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']: features[name] = 0.0
        else: features[name] = 0.0
    return features

def extract_xgboost_features(events):
    """تستخرج 60 ميزة المطلوبة لنموذج XGBoost Expert."""
    pkts = _parse_packets(events)
    if not pkts: return None
    s = _compute_flow_features(pkts)
    features = {}
    for name in FEATURE_NAMES_XGB:
        if name == 'Destination Port': features[name] = s['first_dport']
        elif name == 'Flow Duration': features[name] = s['duration']
        elif name == 'Total Fwd Packets': features[name] = s['total_fwd']
        elif name == 'Total Backward Packets': features[name] = s['total_bwd']
        elif name == 'Total Length of Fwd Packets': features[name] = s['total_len_fwd']
        elif name == 'Total Length of Bwd Packets': features[name] = s['total_len_bwd']
        elif name == 'Fwd Packet Length Max': features[name] = max(s['fwd_lens'])
        elif name == 'Fwd Packet Length Min': features[name] = min(s['fwd_lens'])
        elif name == 'Fwd Packet Length Mean': features[name] = np.mean(s['fwd_lens'])
        elif name == 'Fwd Packet Length Std': features[name] = np.std(s['fwd_lens'])
        elif name == 'Bwd Packet Length Max': features[name] = max(s['bwd_lens'])
        elif name == 'Bwd Packet Length Min': features[name] = min(s['bwd_lens'])
        elif name == 'Bwd Packet Length Mean': features[name] = np.mean(s['bwd_lens'])
        elif name == 'Bwd Packet Length Std': features[name] = np.std(s['bwd_lens'])
        elif name == 'Flow IAT Mean': features[name] = np.mean([s['fwd_iat_mean'], s['bwd_iat_mean']])
        elif name == 'Flow IAT Std': features[name] = np.std([s['fwd_iat_std'], s['bwd_iat_std']])
        elif name == 'Flow IAT Max': features[name] = max(s['fwd_iat_max'], s['bwd_iat_max'])
        elif name == 'Flow IAT Min': features[name] = min(s['fwd_iat_min'], s['bwd_iat_min'])
        elif name == 'Fwd IAT Total': features[name] = s['fwd_iat_mean'] * s['total_fwd'] if s['total_fwd'] else 0
        elif name == 'Fwd IAT Mean': features[name] = s['fwd_iat_mean']
        elif name == 'Fwd IAT Std': features[name] = s['fwd_iat_std']
        elif name == 'Fwd IAT Max': features[name] = s['fwd_iat_max']
        elif name == 'Fwd IAT Min': features[name] = s['fwd_iat_min']
        elif name == 'Bwd IAT Total': features[name] = s['bwd_iat_mean'] * s['total_bwd'] if s['total_bwd'] else 0
        elif name == 'Bwd IAT Mean': features[name] = s['bwd_iat_mean']
        elif name == 'Bwd IAT Std': features[name] = s['bwd_iat_std']
        elif name == 'Bwd IAT Max': features[name] = s['bwd_iat_max']
        elif name == 'Bwd IAT Min': features[name] = s['bwd_iat_min']
        elif name == 'Fwd PSH Flags': features[name] = s['fwd_psh']
        elif name == 'Bwd PSH Flags': features[name] = s['bwd_psh']
        elif name == 'Fwd URG Flags': features[name] = s['fwd_urg']
        elif name == 'Bwd URG Flags': features[name] = s['bwd_urg']
        elif name == 'SYN Flag Count': features[name] = s['syn_cnt']
        elif name == 'RST Flag Count': features[name] = s['rst_cnt']
        elif name == 'PSH Flag Count': features[name] = s['psh_cnt']
        elif name == 'ACK Flag Count': features[name] = s['ack_cnt']
        elif name == 'URG Flag Count': features[name] = s['urg_cnt']
        elif name == 'FIN Flag Count': features[name] = s['fin_cnt']
        elif name == 'Fwd Packets/s': features[name] = s['fwd_rate']
        elif name == 'Bwd Packets/s': features[name] = s['bwd_rate']
        elif name == 'Flow Packets/s': features[name] = s['flow_rate']
        elif name == 'Packet Length Mean': features[name] = s['avg_size']
        elif name == 'Packet Length Std': features[name] = np.std([p['len'] for p in pkts]) if pkts else 0
        elif name == 'Packet Length Variance': features[name] = np.var([p['len'] for p in pkts]) if pkts else 0
        elif name == 'Down/Up Ratio': features[name] = s['down_up_ratio']
        elif name == 'Average Packet Size': features[name] = s['avg_size']
        elif name == 'Subflow Fwd Packets': features[name] = s['total_fwd']
        elif name == 'Subflow Bwd Packets': features[name] = s['total_bwd']
        elif name == 'Init_Win_bytes_forward': features[name] = s['fwd_win']
        elif name == 'Init_Win_bytes_backward': features[name] = s['bwd_win']
        elif name == 'act_data_pkt_fwd': features[name] = sum(1 for p in pkts if p['len'] > 0 and p['src'] == pkts[0]['src']) if pkts else 0
        elif name == 'min_seg_size_forward': features[name] = min(s['fwd_lens']) if s['fwd_lens'] else 0
        elif name == 'Active Mean': features[name] = 1 if s['total_fwd'] > 0 else 0
        elif name == 'Active Std': features[name] = 0.0
        elif name == 'Active Max': features[name] = 1 if s['total_fwd'] > 0 else 0
        elif name == 'Active Min': features[name] = 1 if s['total_fwd'] > 0 else 0
        elif name == 'Idle Mean': features[name] = 0.0
        elif name == 'Idle Std': features[name] = 0.0
        elif name == 'Idle Max': features[name] = 0.0
        elif name == 'Idle Min': features[name] = 0.0
        else: features[name] = 0.0
    return features