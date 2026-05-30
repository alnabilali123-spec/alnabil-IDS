import torch
from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline
import logging

logger = logging.getLogger(__name__)

class SecureBERTForensic:
    """Forensic Analyzer – يستخرج كيانات التهديد من Payload."""
    def __init__(self, model_path="models/securebert-ner"):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        logger.info(f"[SecureBERT-Forensic] Loading from {model_path} on {self.device}...")
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForTokenClassification.from_pretrained(model_path)
        self.model.to(self.device)
        self.model.eval()
        self.ner_pipeline = pipeline(
            "ner",
            model=self.model,
            tokenizer=self.tokenizer,
            aggregation_strategy="first",
            device=0 if self.device.type == "cuda" else -1
        )
        # الكيانات التي تهمنا
        self.target_entities = [
            "MALWARE", "INDICATOR", "VULNERABILITY", "SYSTEM", "ORGANIZATION", "ATTACK-TYPE"
        ]
        logger.info("[SecureBERT-Forensic] Ready.")

    def analyze(self, payload_text: str) -> list:
        """يرجع قائمة بالكيانات المستخرجة."""
        if not payload_text or len(payload_text.strip()) < 3:
            return []
        try:
            entities = self.ner_pipeline(payload_text)
        except Exception as e:
            logger.error(f"[SecureBERT-Forensic] NER failed: {e}")
            return []
        threats = []
        for ent in entities:
            ent_type = ent['entity_group'].upper().replace(" ", "-")
            if ent_type in self.target_entities:
                threats.append({
                    "entity": ent['word'],
                    "type": ent_type,
                    "confidence": float(ent['score'])
                })
        return threats