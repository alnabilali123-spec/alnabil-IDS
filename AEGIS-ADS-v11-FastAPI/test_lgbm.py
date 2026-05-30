import joblib, numpy as np

model = joblib.load("models/lgbm/lgbm-binary-model.pkl")

feature_names = [
    'sport', 'dsport', 'dur', 'sbytes', 'dbytes', 'sttl', 'dttl',
    'sload', 'dload', 'spkts', 'swin', 'stcpb', 'dtcpb',
    'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len',
    'sjit', 'djit', 'sintpkt', 'dintpkt', 'tcprtt',
    'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd',
    'is_ftp_login', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm',
    'ct_src__ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm',
    'ct_dst_src_ltm', 'duration', 'src_bps', 'dst_bps',
    'src_pps', 'byte_ratio', 'pkt_ratio', 'jit_ratio',
    'loss_ratio_src', 'loss_ratio_dst', 'window_ratio',
    'total_bytes', 'total_pkts', 'byte_pkt_interaction_src',
    'byte_pkt_interaction_dst', 'load_jit_interaction_src',
    'load_jit_interaction_dst', 'pkt_jit_interaction_src',
    'mean_pkt_size', 'tcp_seq_diff', 'service_src_ratio',
    'service_dst_ratio', 'res_bdy_rate',
    'stime_hour', 'stime_weekday', 'ltime_hour', 'ltime_weekday'
]

fake_flow = {f: 0.0 for f in feature_names}
fake_flow['sport'] = 80
fake_flow['dsport'] = 443
fake_flow['dur'] = 0.5
fake_flow['sbytes'] = 5000
fake_flow['dbytes'] = 1000
fake_flow['spkts'] = 50
fake_flow['sload'] = 100000
fake_flow['dload'] = 20000

X_list = [fake_flow.get(f, 0) for f in feature_names]
X = np.array([X_list])
proba = model.predict_proba(X)[0, 1]
print(f"🔥 احتمالية الهجوم (LGBM): {proba:.4f}")