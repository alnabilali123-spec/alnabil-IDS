# core/feature_extractor.py
import numpy as np
import pickle, os, logging

logger = logging.getLogger(__name__)

# تحميل أسماء الميزات المرجعية (78 ميزة) الخاصة بـ L1 و L2
_features_path = os.path.join(os.path.dirname(__file__), '..', 'models', 'features.pkl')
if os.path.exists(_features_path):
    with open(_features_path, 'rb') as f:
        FEATURE_NAMES_78 = pickle.load(f)
else:
    FEATURE_NAMES_78 = []

# قائمة الميزات المطلوبة خصيصاً لنموذج CatBoost (TCP Specialist)
TCP_FEATURES = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Flow Bytes/s', 'Flow Packets/s', 'Packet Length Mean',
    'Packet Length Std', 'Average Packet Size',
    'SYN Flag Count', 'RST Flag Count', 'ACK Flag Count',
    'PSH Flag Count', 'FIN Flag Count',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward'
]

def extract_features_from_flow(events):
    """
    تستقبل قائمة من كائنات NetworkEvent وتستخرج 78+ ميزة.
    تستخدم raw_bytes و Scapy لاستخراج كل التفاصيل.
    """
    if not events:
        return None

    pkts = []
    for evt in events:
        try:
            raw = evt.raw_bytes if hasattr(evt, 'raw_bytes') else b''
            if not raw:
                # fallback: استخدم الحقول المباشرة
                pkts.append({
                    'src': evt.src_ip,
                    'dst': evt.dst_ip,
                    'sport': evt.src_port or 0,
                    'dport': evt.dst_port or 0,
                    'proto': evt.ip_proto,
                    'len': evt.length,
                    'time': evt.timestamp.timestamp() if hasattr(evt.timestamp, 'timestamp') else 0,
                    'flags': evt.summary if hasattr(evt, 'summary') else '',
                    'tcp_win': 0, 'tcp_seq': 0, 'tcp_ack': 0,
                    'tcp_urg': 0, 'tcp_psh': 0, 'tcp_rst': 0, 'tcp_syn': 0, 'tcp_fin': 0
                })
                continue

            from scapy.all import IP, TCP, UDP, ICMP
            pkt = IP(raw)
            proto = pkt.proto
            src_ip = pkt.src
            dst_ip = pkt.dst
            length = len(raw)
            ts = evt.timestamp.timestamp() if hasattr(evt.timestamp, 'timestamp') else 0

            sport = dport = 0
            tcp_win = tcp_seq = tcp_ack = 0
            tcp_urg = tcp_psh = tcp_rst = tcp_syn = tcp_fin = 0

            if proto == 6 and pkt.haslayer(TCP):
                tcp = pkt[TCP]
                sport = tcp.sport
                dport = tcp.dport
                flags = str(tcp.flags)
                tcp_win = tcp.window
                tcp_seq = tcp.seq
                tcp_ack = tcp.ack
                tcp_urg = 1 if 'U' in flags else 0
                tcp_psh = 1 if 'P' in flags else 0
                tcp_rst = 1 if 'R' in flags else 0
                tcp_syn = 1 if 'S' in flags else 0
                tcp_fin = 1 if 'F' in flags else 0
            elif proto == 17 and pkt.haslayer(UDP):
                udp = pkt[UDP]
                sport = udp.sport
                dport = udp.dport

            pkts.append({
                'src': src_ip,
                'dst': dst_ip,
                'sport': sport,
                'dport': dport,
                'proto': proto,
                'len': length,
                'time': ts,
                'flags': '',
                'tcp_win': tcp_win,
                'tcp_seq': tcp_seq,
                'tcp_ack': tcp_ack,
                'tcp_urg': tcp_urg,
                'tcp_psh': tcp_psh,
                'tcp_rst': tcp_rst,
                'tcp_syn': tcp_syn,
                'tcp_fin': tcp_fin
            })
        except Exception as e:
            logger.debug(f"Feature extraction error: {e}")
            continue

    if not pkts:
        return None

    first = pkts[0]
    src_ip = first['src']
    dst_ip = first['dst']
    proto = first['proto']

    # تقسيم الحزم إلى أمامية وخلفية باستخدام المنافذ
    src_port = first['sport']
    dst_port = first['dport']
    if src_port != 0 and dst_port != 0:
        fwd = [p for p in pkts if p['src'] == src_ip and p['sport'] == src_port and p['dport'] == dst_port]
        bwd = [p for p in pkts if p['src'] == dst_ip and p['sport'] == dst_port and p['dport'] == src_port]
    else:
        fwd = [p for p in pkts if p['src'] == src_ip and p['dst'] == dst_ip]
        bwd = [p for p in pkts if p['src'] == dst_ip and p['dst'] == src_ip]

    duration = pkts[-1]['time'] - pkts[0]['time'] if len(pkts) > 1 else 0.001
    total_fwd = len(fwd)
    total_bwd = len(bwd)
    total_len_fwd = sum(p['len'] for p in fwd)
    total_len_bwd = sum(p['len'] for p in bwd)

    fwd_lens = [p['len'] for p in fwd] if fwd else [0]
    bwd_lens = [p['len'] for p in bwd] if bwd else [0]

    def calc_iat(pkts):
        if len(pkts) < 2:
            return 0, 0, 0, 0
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
    active_mean = 1 if total_fwd > 0 else 0
    idle_mean = 0

    features = {}
    for name in FEATURE_NAMES_78:
        if name == 'Destination Port':
            features[name] = first['dport']
        elif name == 'Flow Duration':
            features[name] = duration
        elif name == 'Total Fwd Packets':
            features[name] = total_fwd
        elif name == 'Total Backward Packets':
            features[name] = total_bwd
        elif name == 'Total Length of Fwd Packets':
            features[name] = total_len_fwd
        elif name == 'Total Length of Bwd Packets':
            features[name] = total_len_bwd
        elif name == 'Fwd Packet Length Max':
            features[name] = max(fwd_lens)
        elif name == 'Fwd Packet Length Min':
            features[name] = min(fwd_lens)
        elif name == 'Fwd Packet Length Mean':
            features[name] = np.mean(fwd_lens)
        elif name == 'Fwd Packet Length Std':
            features[name] = np.std(fwd_lens)
        elif name == 'Bwd Packet Length Max':
            features[name] = max(bwd_lens)
        elif name == 'Bwd Packet Length Min':
            features[name] = min(bwd_lens)
        elif name == 'Bwd Packet Length Mean':
            features[name] = np.mean(bwd_lens)
        elif name == 'Bwd Packet Length Std':
            features[name] = np.std(bwd_lens)
        elif name == 'Flow IAT Mean':
            features[name] = np.mean([fwd_iat_mean, bwd_iat_mean])
        elif name == 'Flow IAT Std':
            features[name] = np.std([fwd_iat_std, bwd_iat_std])
        elif name == 'Flow IAT Max':
            features[name] = max(fwd_iat_max, bwd_iat_max)
        elif name == 'Flow IAT Min':
            features[name] = min(fwd_iat_min, bwd_iat_min)
        elif name == 'Fwd IAT Total':
            features[name] = fwd_iat_mean * total_fwd if total_fwd else 0
        elif name == 'Fwd IAT Mean':
            features[name] = fwd_iat_mean
        elif name == 'Fwd IAT Std':
            features[name] = fwd_iat_std
        elif name == 'Fwd IAT Max':
            features[name] = fwd_iat_max
        elif name == 'Fwd IAT Min':
            features[name] = fwd_iat_min
        elif name == 'Bwd IAT Total':
            features[name] = bwd_iat_mean * total_bwd if total_bwd else 0
        elif name == 'Bwd IAT Mean':
            features[name] = bwd_iat_mean
        elif name == 'Bwd IAT Std':
            features[name] = bwd_iat_std
        elif name == 'Bwd IAT Max':
            features[name] = bwd_iat_max
        elif name == 'Bwd IAT Min':
            features[name] = bwd_iat_min
        elif name == 'Fwd PSH Flags':
            features[name] = fwd_psh
        elif name == 'Bwd PSH Flags':
            features[name] = bwd_psh
        elif name == 'Fwd URG Flags':
            features[name] = fwd_urg
        elif name == 'Bwd URG Flags':
            features[name] = bwd_urg
        elif name == 'SYN Flag Count':
            features[name] = syn_cnt
        elif name == 'RST Flag Count':
            features[name] = rst_cnt
        elif name == 'PSH Flag Count':
            features[name] = psh_cnt
        elif name == 'ACK Flag Count':
            features[name] = ack_cnt
        elif name == 'URG Flag Count':
            features[name] = urg_cnt
        elif name == 'FIN Flag Count':
            features[name] = fin_cnt
        elif name == 'Fwd Packets/s':
            features[name] = fwd_rate
        elif name == 'Bwd Packets/s':
            features[name] = bwd_rate
        elif name == 'Flow Packets/s':
            features[name] = flow_rate
        elif name == 'Fwd Header Length':
            features[name] = total_fwd * 20
        elif name == 'Bwd Header Length':
            features[name] = total_bwd * 20
        elif name == 'Packet Length Mean':
            features[name] = avg_size
        elif name == 'Packet Length Std':
            features[name] = np.std([p['len'] for p in pkts]) if pkts else 0
        elif name == 'Packet Length Variance':
            features[name] = np.var([p['len'] for p in pkts]) if pkts else 0
        elif name == 'Down/Up Ratio':
            features[name] = down_up_ratio
        elif name == 'Average Packet Size':
            features[name] = avg_size
        elif name == 'Fwd Segment Size Avg':
            features[name] = fwd_seg_avg
        elif name == 'Bwd Segment Size Avg':
            features[name] = bwd_seg_avg
        elif name == 'Fwd Bytes/Bulk Avg':
            features[name] = total_len_fwd
        elif name == 'Bwd Bytes/Bulk Avg':
            features[name] = total_len_bwd
        elif name == 'Fwd Packet/Bulk Avg':
            features[name] = total_fwd
        elif name == 'Bwd Packet/Bulk Avg':
            features[name] = total_bwd
        elif name == 'Fwd Bulk Rate Avg':
            features[name] = fwd_rate
        elif name == 'Bwd Bulk Rate Avg':
            features[name] = bwd_rate
        elif name == 'Active Mean':
            features[name] = active_mean
        elif name == 'Active Std':
            features[name] = 0.0
        elif name == 'Active Max':
            features[name] = active_mean
        elif name == 'Active Min':
            features[name] = active_mean
        elif name == 'Idle Mean':
            features[name] = idle_mean
        elif name == 'Idle Std':
            features[name] = 0.0
        elif name == 'Idle Max':
            features[name] = idle_mean
        elif name == 'Idle Min':
            features[name] = idle_mean
        elif name == 'Protocol':
            features[name] = proto
        elif name == 'Subflow Fwd Packets':
            features[name] = total_fwd
        elif name == 'Subflow Bwd Packets':
            features[name] = total_bwd
        elif name == 'Init_Win_bytes_forward':
            features[name] = fwd[0]['tcp_win'] if fwd and fwd[0]['proto'] == 6 else (fwd[0]['len'] if fwd else 0)
        elif name == 'Init_Win_bytes_backward':
            features[name] = bwd[0]['tcp_win'] if bwd and bwd[0]['proto'] == 6 else (bwd[0]['len'] if bwd else 0)
        elif name == 'act_data_pkt_fwd':
            features[name] = sum(1 for p in fwd if p['len'] > 0) if fwd else 0
        elif name == 'min_seg_size_forward':
            features[name] = min(fwd_lens) if fwd else 0
        elif name == 'min_seg_size_backward':
            features[name] = min(bwd_lens) if bwd else 0
        else:
            features[name] = 0.0

    # ضمان وجود جميع ميزات TCP المطلوبة
    for tcp_feat in TCP_FEATURES:
        if tcp_feat not in features:
            if tcp_feat == 'Flow Bytes/s':
                features[tcp_feat] = (total_len_fwd + total_len_bwd) / duration if duration > 0 else 0
            elif tcp_feat == 'Flow Packets/s':
                features[tcp_feat] = flow_rate
            elif tcp_feat == 'Packet Length Mean':
                features[tcp_feat] = avg_size
            elif tcp_feat == 'Packet Length Std':
                features[tcp_feat] = np.std([p['len'] for p in pkts]) if pkts else 0
            elif tcp_feat == 'Average Packet Size':
                features[tcp_feat] = avg_size
            elif tcp_feat == 'Init_Win_bytes_forward':
                features[tcp_feat] = fwd[0]['tcp_win'] if fwd and fwd[0]['proto'] == 6 else (fwd[0]['len'] if fwd else 0)
            elif tcp_feat == 'Init_Win_bytes_backward':
                features[tcp_feat] = bwd[0]['tcp_win'] if bwd and bwd[0]['proto'] == 6 else (bwd[0]['len'] if bwd else 0)
            else:
                features[tcp_feat] = 0.0

    return features

def get_ordered_features(features_dict):
    if not FEATURE_NAMES_78:
        return np.array([])
    return np.array([features_dict.get(name, 0) for name in FEATURE_NAMES_78], dtype=np.float32)