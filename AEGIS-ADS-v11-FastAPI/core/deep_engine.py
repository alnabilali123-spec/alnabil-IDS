import os, logging, torch, numpy as np
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
import onnxruntime as ort

logger = logging.getLogger(__name__)

class InsytLayer3:
    def __init__(self, model_path, use_onnx=True):
        self.device = "cpu"
        onnx_path = model_path + "_onnx"

        # تحميل tokenizer مرة واحدة
        if use_onnx and os.path.exists(onnx_path):
            logger.info(f"[Insyt] Loading ONNX model from {onnx_path}")
            self.tokenizer = DistilBertTokenizerFast.from_pretrained(onnx_path)
            self.session = ort.InferenceSession(os.path.join(onnx_path, "model.onnx"))
            self.use_onnx = True
        else:
            logger.info(f"[Insyt] Loading PyTorch model from {model_path}")
            self.tokenizer = DistilBertTokenizerFast.from_pretrained(model_path)
            self.model = DistilBertForSequenceClassification.from_pretrained(model_path)
            self.model.eval()
            self.use_onnx = False

        self.attack_labels = {
            0: "BENIGN",
            1: "SQL Injection",
            2: "XSS",
            3: "Command Injection",
            4: "Path Traversal",
            5: "SSRF",
            6: "XXE",
            7: "LDAP Injection",
            8: "Buffer Overflow",
            9: "Format String",
            10: "File Inclusion"
        }
        logger.info("[Insyt] Ready.")

    def _tokenize(self, texts):
        return self.tokenizer(
            texts,
            return_tensors="np" if self.use_onnx else "pt",
            truncation=True,
            max_length=512,
            padding=True
        )

    def _process_model_output(self, logits, num_samples):
        """تحويل logits إلى قائمة نتائج (decision, threats)"""
        if self.use_onnx:
            # ONNX يعيد numpy array
            probs = np.exp(logits) / np.exp(logits).sum(axis=1, keepdims=True)
            max_probs = np.max(probs, axis=1)
            preds = np.argmax(probs, axis=1)
        else:
            probs = torch.softmax(torch.tensor(logits), dim=1) if isinstance(logits, np.ndarray) else torch.softmax(logits, dim=1)
            max_probs, preds = torch.max(probs, dim=1)
            max_probs = max_probs.cpu().numpy()
            preds = preds.cpu().numpy()

        results = []
        for i in range(num_samples):
            max_prob = max_probs[i]
            pred = preds[i]
            if pred != 0 and max_prob >= 0.7:
                attack_type = self.attack_labels.get(pred, f"Attack_Class_{pred}")
                threats = [{"type": attack_type, "confidence": round(float(max_prob) * 100, 1)}]
                results.append(("Attack", threats))
            else:
                results.append(("Normal", []))
        return results

    def analyze_payload(self, payload: str):
        """تحليل حمولة واحدة (تحويل داخلي إلى batch)"""
        if not payload or len(payload.strip()) < 3:
            return "Normal", []
        results = self.analyze_batch([payload])
        return results[0]

    def analyze_batch(self, payloads: list):
        """تحليل دفعة من الحمولات معاً"""
        if not payloads:
            return []

        # تصفية الحمولات القصيرة جداً
        valid_payloads = []
        short_results = []
        for p in payloads:
            if p and len(p.strip()) >= 3:
                valid_payloads.append(p)
                short_results.append(None)  # عنصر نائب
            else:
                short_results.append(("Normal", []))
        
        if not valid_payloads:
            return [("Normal", []) for _ in payloads]

        inputs = self._tokenize(valid_payloads)

        if self.use_onnx:
            ort_inputs = {
                "input_ids": inputs["input_ids"].astype(np.int64),
                "attention_mask": inputs["attention_mask"].astype(np.int64),
            }
            logits = self.session.run(None, ort_inputs)[0]
        else:
            with torch.no_grad():
                outputs = self.model(**{k: v for k, v in inputs.items()})
                logits = outputs.logits.cpu().numpy()

        # معالجة النتائج للحمولات الصالحة
        processed = self._process_model_output(logits, len(valid_payloads))

        # دمج النتائج مع الحمولات القصيرة
        final_results = []
        proc_idx = 0
        for sr in short_results:
            if sr is None:
                final_results.append(processed[proc_idx])
                proc_idx += 1
            else:
                final_results.append(sr)
        return final_results