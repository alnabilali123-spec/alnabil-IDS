"""Mapping - Bridges live packets to 78 model features"""
import numpy as np

# The 78 features in exact order expected by AEGIS IDS RF
FEATURE_78_NAMES = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
    'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
    'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length.1',
    'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
    'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

# Indices for XGBoost 10-feature subset
XGBOOST_10_INDICES = [0, 4, 6, 8, 14, 35, 44, 46, 47, 52]

def live_packet_to_78(packet_info: dict) -> np.ndarray:
    """Convert live packet to 78 feature array"""
    f = np.zeros(78, dtype=np.float32)
    
    transport = str(packet_info.get('transport', '')).upper()
    length = float(packet_info.get('length', 0))
    dst_port = float(packet_info.get('dst_port', 0))
    flags = str(packet_info.get('flags', '')).upper()
    
    # [0] Destination Port
    f[0] = dst_port
    
    # [4] Total Length Fwd
    f[4] = length
    
    # [6-8] Packet Length stats
    f[6] = length; f[7] = length; f[8] = length
    
    # [14] Flow Bytes/s
    f[14] = length
    
    # [34] Fwd Header Length
    f[34] = 40.0 if transport == 'TCP' else 28.0 if transport == 'UDP' else 0.0
    
    # [35] Bwd Header Length
    f[35] = 0.0
    
    # [39] Max Packet Length
    f[39] = length
    
    # [40] Packet Length Mean
    f[40] = length
    
    # [43-48] Flag Counts
    f[43] = 1.0 if 'F' in flags else 0.0  # FIN
    f[44] = 1.0 if 'S' in flags else 0.0  # SYN
    f[45] = 1.0 if 'R' in flags else 0.0  # RST
    f[46] = 1.0 if 'P' in flags else 0.0  # PSH
    f[47] = 1.0 if 'A' in flags else 0.0  # ACK
    f[48] = 1.0 if 'U' in flags else 0.0  # URG
    
    # [52] Average Packet Size
    f[52] = length
    
    # [53] Avg Fwd Segment Size
    f[53] = length if transport == 'TCP' else 0.0
    
    # [63-64] Init_Win_bytes
    f[63] = 64240.0  # Typical TCP window
    f[64] = 64240.0
    
    # [66] act_data_pkt_fwd
    f[66] = 1.0 if length > 0 else 0.0
    
    return f.reshape(1, -1)

def extract_78_to_10(features_78: np.ndarray) -> np.ndarray:
    """Extract 10 features from 78 for XGBoost"""
    return features_78[:, XGBOOST_10_INDICES]
