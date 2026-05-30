import logging, numpy as np
import onnxruntime as ort

logger = logging.getLogger(__name__)

class DDoSShield:
    def __init__(self, model_path):
        logger.info(f"🛡️ Loading DDoS Shield from {model_path}...")
        self.session = ort.InferenceSession(model_path)
        self.input_name = self.session.get_inputs()[0].name
        self.label_map = {
            0: "BENIGN",
            1: "DDoS_SYN_Flood",
            2: "DDoS_UDP_Flood",
            3: "DDoS_TCP_Flood",
            4: "Port_Scan",
            # أضف فئات أخرى حسب الحاجة
        }
        logger.info(f"✅ DDoS Shield loaded. Input shape: {self.session.get_inputs()[0].shape}")

    def analyze(self, flow_stats):
        """تحليل إحصائيات التدفق وإصدار قرار"""
        if flow_stats is None:
            return "Normal", ""
        
        feature_vector = self._build_feature_vector(flow_stats)
        outputs = self.session.run(None, {self.input_name: feature_vector})
        pred = int(np.argmax(outputs[0], axis=1)[0])
        confidence = float(np.max(outputs[0], axis=1)[0])
        
        label = self.label_map.get(pred, f"Class_{pred}")
        if label != "BENIGN" and confidence > 0.8:
            logger.warning(f"🛡️ DDoS Shield detected: {label} ({confidence:.2f})")
            return "Attack", label
        return "Normal", ""

    def _build_feature_vector(self, stats):
        """تحويل إحصائيات التدفق إلى متجه الميزات 84 المطلوب (بقية القيم أصفار)"""
        # الميزات الأساسية التي وردت في تدريب النموذج
        features = [
            stats.get('requests_per_sec', 0),
            stats.get('pkt_len_variation', 0),
            stats.get('flow_duration', 0),
            stats.get('fwd_pkt_len_std', 0),
        ]
        # إكمال حتى 84 عنصراً (الصفر مناسب للميزات غير المستخدمة)
        features.extend([0.0] * 80)
        return np.array([features], dtype=np.float32)