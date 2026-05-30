import logging
import joblib
import numpy as np

logger = logging.getLogger(__name__)

class LGBMBinaryDetector:
    def __init__(self, model_path, threshold=0.5):
        self.model = joblib.load(model_path)
        self.threshold = threshold
        self.last_proba = 0.0
        self._debug_logged = False

        # استخراج أسماء الميزات التي تدرب عليها النموذج
        try:
            self.expected_features = self.model.booster_.feature_name()
            logger.info(f"✅ Loaded {len(self.expected_features)} feature names from model")
        except Exception as e:
            logger.error(f"❌ Could not read feature names from model: {e}")
            # قائمة احتياطية
            self.expected_features = [
                'Destination Port', 'Flow Duration', 'Total Fwd Packets',
                'Total Backward Packets', 'Total Length of Fwd Packets',
                'Total Length of Bwd Packets', 'Fwd Packet Length Max',
                'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
                'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
                'Bwd Packet Length Std', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
                'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std',
                'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
                'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
                'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'SYN Flag Count',
                'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
                'FIN Flag Count', 'Fwd Packets/s', 'Bwd Packets/s', 'Flow Packets/s',
                'Packet Length Mean', 'Packet Length Std', 'Down/Up Ratio',
                'Average Packet Size', 'Fwd Segment Size Avg', 'Bwd Segment Size Avg',
                'Subflow Fwd Packets', 'Subflow Bwd Packets',
                'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
                'act_data_pkt_fwd', 'min_seg_size_forward',
                'Active Mean', 'Active Max', 'Active Min',
                'Idle Mean', 'Idle Max', 'Idle Min'
            ]

        # طباعة جميع أسماء الميزات المتوقعة للتشخيص
        logger.info(f"🔍 All expected features: {self.expected_features}")
        logger.info(f"✅ LGBM Binary Detector loaded (threshold={self.threshold})")

    def predict(self, feat_dict):
        """للتوافق مع الاستدعاءات القديمة (ميزات تمر مباشرة)"""
        try:
            X_list = [feat_dict.get(f, 0) for f in self.expected_features]

            if not self._debug_logged:
                logger.info(f"🔍 عدد الميزات المستخرجة: {len(X_list)}")
                logger.info(f"🔍 أول 5 ميزات: {list(zip(self.expected_features[:5], X_list[:5]))}")
                logger.info(f"🔍 عدد الأصفار في X_list: {X_list.count(0)} / {len(X_list)}")
                logger.info(f"🔍 آخر 5 ميزات: {list(zip(self.expected_features[-5:], X_list[-5:]))}")
                self._debug_logged = True

            X = np.array([X_list])
            proba = self.model.predict_proba(X)[0, 1]
            self.last_proba = proba
            logger.debug(f"🔎 LGBM Binary proba={proba:.4f}")
            if proba >= self.threshold:
                return "Attack", "Network Attack"
            return "Normal", ""
        except Exception as e:
            logger.error(f"LGBM error: {e}")
            return "Normal", ""

    def predict_batch(self, flow_list):
        """
        تنبؤ على مجموعة تدفقات (دفعة واحدة).
        flow_list: قائمة من tuples (events, metadata)
        تعيد: list of dicts بنفس الترتيب تحتوي على 'index', 'proba', 'decision'
        """
        from core.unsw_feature_extractor import extract_unsw_features_batch
        try:
            batch_feats = extract_unsw_features_batch(flow_list)
            X_batch = []
            for feat_dict in batch_feats:
                X_list = [feat_dict.get(f, 0) for f in self.expected_features]
                X_batch.append(X_list)

            if not X_batch:
                return []

            X = np.array(X_batch)
            probas = self.model.predict_proba(X)[:, 1]

            results = []
            for i, proba in enumerate(probas):
                decision = "Attack" if proba >= self.threshold else "Normal"
                results.append({
                    'index': i,
                    'proba': proba,
                    'decision': decision
                })
                logger.debug(f"🔎 LGBM Batch[{i}] proba={proba:.4f} -> {decision}")

            # تسجيل تشخيصي لأول دفعة
            if not self._debug_logged:
                logger.info(f"🔍 أول دفعة: عدد التدفقات = {len(flow_list)}")
                logger.info(f"🔍 عينة أول تدفق (أول 5 ميزات): {list(zip(self.expected_features[:5], X_batch[0][:5]))}")
                logger.info(f"🔍 عدد الأصفار في أول تدفق: {X_batch[0].count(0)} / {len(X_batch[0])}")
                self._debug_logged = True

            return results
        except Exception as e:
            logger.error(f"LGBM batch error: {e}")
            return []