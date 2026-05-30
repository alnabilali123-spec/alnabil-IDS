import logging, joblib, numpy as np

logger = logging.getLogger(__name__)

# القائمة الكاملة للميزات التي تدرب عليها النموذج (بنفس ترتيب feature_extractor)
TCP_FEATURES = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Packet Length Mean',
    'Packet Length Std',
    'Average Packet Size',
    'SYN Flag Count',
    'RST Flag Count',
    'ACK Flag Count',
    'PSH Flag Count',
    'FIN Flag Count',
    'Init_Win_bytes_forward',
    'Init_Win_bytes_backward'
]

class TCPSpecialist:
    def __init__(self, model_path, threshold=0.6):
        self.model = joblib.load(model_path)
        self.features = TCP_FEATURES  # نستخدم القائمة الكاملة
        self.threshold = threshold
        logger.info(f"✅ TCP Specialist loaded – {len(self.features)} features, threshold={self.threshold}")

    def predict(self, flow_stats):
        try:
            X = np.array([[flow_stats.get(f, 0) for f in self.features]])
            proba = self.model.predict_proba(X)[0, 1]
            logger.info(f"🔎 TCP Specialist proba={proba:.4f} (threshold={self.threshold})")
            if proba >= self.threshold:
                logger.warning(f"🛡️ TCP Specialist detected attack (prob={proba:.3f})")
                return "Attack", "TCP/RST Flood"
            return "Normal", ""
        except Exception as e:
            logger.error(f"TCP Specialist predict error: {e}", exc_info=True)
            return "Normal", ""