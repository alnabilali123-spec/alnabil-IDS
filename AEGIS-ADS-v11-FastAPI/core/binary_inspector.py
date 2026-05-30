# core/binary_inspector.py
import logging
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import numpy as np

logger = logging.getLogger(__name__)

class BinaryInspector:
    def __init__(self, model_path):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        logger.info(f"🔧 Loading Binary BERT from {model_path} on {self.device}")
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path)
        self.model.to(self.device)
        self.model.eval()
        # قائمة التصنيفات التي يستخدمها النموذج (سنحصل عليها من الـ config إن أمكن)
        self.id2label = self.model.config.id2label if hasattr(self.model.config, "id2label") else {}
        logger.info("✅ Binary BERT loaded successfully")

    def packet_to_bytes_input(self, raw_packet: bytes, max_len=128) -> str:
        """
        يحول البايتات الخام إلى صيغة يقبلها النموذج.
        حسب معظم نماذج BERT للشبكات، الصيغة هي سلسلة من البايتات مكتوبة
        كـ hex مفصولة بمسافات، مثال: '48 54 54 50 ...'
        """
        # نأخذ أول max_len بايت فقط لتجنب الإدخالات الطويلة جداً
        packet_bytes = raw_packet[:max_len]
        hex_str = packet_bytes.hex()  # كل بايت يصبح حرفين هيكس
        # إدخال مسافة بين كل بايتين (أي بين كل حرفين)
        spaced_hex = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
        return spaced_hex

    def analyze(self, raw_packet: bytes) -> tuple:
        """
        يُصنف الحزمة ويعيد (decision, attack_type) حيث decision = 'Attack' أو 'Normal'.
        نستخدم متوسط الثقة عبر عدة حزم للتدفق لاحقاً، لكن هنا نُحلل الحزمة الواحدة.
        """
        if not raw_packet or len(raw_packet) < 20:  # أقل طول لرأس IP
            return "Normal", ""

        hex_input = self.packet_to_bytes_input(raw_packet)
        inputs = self.tokenizer(hex_input, return_tensors="pt", truncation=True, max_length=256)
        inputs = {k: v.to(self.device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = self.model(**inputs)
            logits = outputs.logits
            probs = torch.softmax(logits, dim=1).cpu().numpy()[0]
            pred_idx = int(np.argmax(probs))
            confidence = float(probs[pred_idx])

        # إذا كان التصنيف هو "Benign" أو "Normal" نعتبرها طبيعية
        label = self.id2label.get(pred_idx, f"Class-{pred_idx}")
        # النموذج قد يكون درب على تسميات محددة، سنفترض أن أي شيء غير "Benign" و "Normal" هو هجوم
        if label.lower() in ["benign", "normal"]:
            return "Normal", ""
        else:
            # إذا كانت الثقة مرتفعة، نبلغ عن هجوم
            if confidence > 0.7:   # عتبة لتقليل الإيجابيات الكاذبة
                logger.info(f"🔎 Binary BERT → {label} (confidence: {confidence:.2f})")
                return "Attack", label
            else:
                return "Normal", ""