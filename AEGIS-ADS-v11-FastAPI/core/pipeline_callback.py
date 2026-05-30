from datetime import datetime
import logging, joblib, time
from core.mapping import live_packet_to_78, extract_78_to_10
from database.db_manager import DatabaseManager
import config

logger = logging.getLogger(__name__)
last_alerts = {}

try:
    label_encoder = joblib.load('models/label_encoder.pkl')
    ATTACK_NAMES = list(label_encoder.classes_)
except:
    ATTACK_NAMES = ['BENIGN','Botnet','DDoS','DoS GoldenEye','DoS Hulk','DoS Slowhttptest','DoS Slowloris','FTP-Patator','Heartbleed','Infiltration','PortScan','SSH-Patator','Web Attack Brute Force','Web Attack Sql Injection','Web Attack XSS']

def get_attack_name(class_id):
    try:
        class_id = int(class_id)
        if 0 <= class_id < len(ATTACK_NAMES): return ATTACK_NAMES[class_id]
    except: pass
    return str(class_id)

def process_packet_callback(packet_info: dict, model_loader, feature_extractor, state):
    try:
        src_ip = packet_info.get('src_ip', ''); dst_ip = packet_info.get('dst_ip', '')
        
        # Skip local
        if src_ip in config.LOCAL_IPS: return
        if dst_ip.endswith('.255') or dst_ip.startswith('224.'): return
        
        # Rate limit: 1 alert per source per 5 seconds
        now = time.time()
        if src_ip in last_alerts and now - last_alerts[src_ip] < 5: return
        
        features_78 = live_packet_to_78(packet_info)
        is_suspicious, l1_conf = model_loader.predict_l1(features_78)
        if not is_suspicious and l1_conf < 0.6: return
        
        features_10 = extract_78_to_10(features_78)
        l2_result = model_loader.predict_l2(features_10)
        attack_name = get_attack_name(l2_result.get("attack_type", "Normal"))
        confidence = l2_result.get("confidence", 0)
        
        # Ignore BENIGN
        if attack_name.upper() == "BENIGN" or attack_name == "Normal": return
        if confidence < 40: return
        
        severity = "Low"
        if confidence > 85: severity = "Critical"
        elif confidence > 70: severity = "High"
        elif confidence > 50: severity = "Medium"
        
        action = "Blocked" if severity in ["Critical", "High"] else "Logged"
        
        db = DatabaseManager()
        db.add_threat({"timestamp": datetime.utcnow(), "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": packet_info.get('src_port', 0), "dst_port": packet_info.get('dst_port', 0),
            "protocol": packet_info.get('transport', ''), "attack_type": attack_name,
            "severity": severity, "confidence": confidence, "action_taken": action,
            "l1_score": round(l1_conf * 100, 1), "l2_score": round(confidence, 1)})
        
        last_alerts[src_ip] = now
        logger.info(f"🎯 {attack_name} from {src_ip} ({confidence:.1f}%) - {action}")
    except Exception as e: logger.error(f"Pipeline: {e}")
