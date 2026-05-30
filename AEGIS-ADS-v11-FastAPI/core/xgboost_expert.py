# core/xgboost_expert.py
import logging, joblib, numpy as np, os

logger = logging.getLogger(__name__)

class XGBoostExpert:
    def __init__(self, model_path, scaler_path=None, threshold=0.7):
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path) if scaler_path and os.path.exists(scaler_path) else None
        self.threshold = threshold

        # أفضل مكان لاستخلاص أسماء الميزات هو الـ scaler لأنه تدرب على DataFrame
        if self.scaler and hasattr(self.scaler, 'feature_names_in_') and self.scaler.feature_names_in_ is not None:
            self.expected_features = list(self.scaler.feature_names_in_)
            logger.info(f"✅ XGBoost Expert loaded from scaler ({len(self.expected_features)} features, threshold={threshold})")
        else:
            try:
                booster = self.model.get_booster()
                self.expected_features = booster.feature_names
                if self.expected_features is None:
                    raise ValueError("None")
                logger.info(f"✅ XGBoost Expert loaded from model ({len(self.expected_features)} features, threshold={threshold})")
            except:
                # قائمة احتياطية (60 ميزة)
                self.expected_features = [
                    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
                    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
                    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
                    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
                    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
                    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
                    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
                    'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
                    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
                    'URG Flag Count', 'FIN Flag Count', 'Fwd Packets/s', 'Bwd Packets/s', 'Flow Packets/s',
                    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
                    'Down/Up Ratio', 'Average Packet Size', 'Subflow Fwd Packets', 'Subflow Bwd Packets',
                    'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
                    'act_data_pkt_fwd', 'min_seg_size_forward',
                    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
                    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
                ]
                logger.warning(f"⚠️ Using default feature order ({len(self.expected_features)} features)")

    def predict(self, feat_dict):
        try:
            X_list = [feat_dict.get(f, 0) for f in self.expected_features]
            X = np.array([X_list])
            if self.scaler:
                X = self.scaler.transform(X)
            proba = self.model.predict_proba(X)[0, 1]
            logger.debug(f"🔎 XGBoost Expert proba={proba:.4f}")
            if proba >= self.threshold:
                return "Attack", "XGBoost Expert: Network Attack"
            return "Normal", ""
        except Exception as e:
            logger.error(f"XGBoost error: {e}")
            return "Normal", ""

    def predict_batch(self, feat_dicts):
        """
        تنبؤ على مجموعة من قواميس الميزات في دفعة واحدة.
        feat_dicts: list of dict, كل dict يمثل تدفقاً.
        تُرجع: list of tuples (decision, attack_type) بنفس ترتيب الميزات.
        """
        if not feat_dicts:
            return []
        try:
            X_list = [[fd.get(f, 0) for f in self.expected_features] for fd in feat_dicts]
            X = np.array(X_list)
            if self.scaler:
                X = self.scaler.transform(X)
            probas = self.model.predict_proba(X)[:, 1]
            results = []
            for proba in probas:
                if proba >= self.threshold:
                    results.append(("Attack", "XGBoost Expert: Network Attack"))
                else:
                    results.append(("Normal", ""))
                logger.debug(f"🔎 XGBoost Expert batch proba={proba:.4f}")
            return results
        except Exception as e:
            logger.error(f"XGBoost batch error: {e}")
            return [("Normal", "")] * len(feat_dicts)