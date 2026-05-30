# core/models_loader.py
import os, logging, time, joblib, threading, random
from collections import defaultdict, deque
from queue import Queue
import numpy as np
from cachetools import TTLCache
from core.xgboost_features import (
    extract_features_for_l1_l2,
    extract_xgboost_features,
    FEATURE_NAMES_L1_L2
)
from core.ja3_detector import JA3Detector

ENABLE_RST_ANOMALY = True
ENABLE_UDP_ANOMALY = False
ENABLE_ICMP_ANOMALY = False

if ENABLE_RST_ANOMALY:
    from core.rst_anomaly import RSTAnomalyDetector
if ENABLE_UDP_ANOMALY:
    from core.udp_anomaly import UDPAnomalyDetector
if ENABLE_ICMP_ANOMALY:
    from core.icmp_anomaly import ICMPAnomalyDetector

from core.xgboost_expert import XGBoostExpert

logger = logging.getLogger(__name__)

BATCH_INTERVAL = 15
MIN_FLOW_PACKETS = 2
MIN_BATCH_PACKETS = 50
MAX_EVENTS_PER_FLOW = 64
MAX_BATCH_BUFFER = 20000
RECOVERY_COOLDOWN = 300

class ModelsLoader:
    def __init__(self, models_dir='models', enable_deep=False, whitelist=None):
        self.models_dir = models_dir
        self.iso_forest = None
        self.l2_model = None
        self.scaler = None
        self.label_encoder = None
        self.skeptical_thresholds = {}
        self.deep_inspector = None
        self.rst_anomaly = None
        self.udp_anomaly = None
        self.icmp_anomaly = None
        self.xgb_expert = None
        self.batch_processor = None
        self.ja3_detector = JA3Detector()

        # قائمة التنبيهات الموحدة (للواجهة)
        self.alert_queue = Queue()

        # أقفال محسّنة
        self.flow_lock = threading.RLock()
        self.alert_lock = threading.Lock()
        self.state_lock = threading.Lock()
        self.cache_lock = threading.Lock()

        # L3 (LightGBM Calibrated)
        self.l3_model = None
        self.l3_scaler = None
        self.l3_selector = None
        self.l3_label_encoder = None
        self.l3_features_71 = None
        self.l3_features_24 = None
        self.l3_benign_label = None

        l3_dir = os.path.join(models_dir, 'L3')
        l3_model_path = os.path.join(l3_dir, 'tier1_lgbm_calibrated.pkl')
        l3_scaler_path = os.path.join(l3_dir, 'scaler.pkl')
        l3_selector_path = os.path.join(l3_dir, 'feature_selector.pkl')
        l3_encoder_path = os.path.join(l3_dir, 'label_encoder.pkl')
        l3_features_71_path = os.path.join(l3_dir, 'feature_cols.pkl')
        l3_features_24_path = os.path.join(l3_dir, 'selected_features.pkl')

        if os.path.exists(l3_model_path):
            try:
                self.l3_model = joblib.load(l3_model_path)
                self.l3_scaler = joblib.load(l3_scaler_path)
                self.l3_selector = joblib.load(l3_selector_path)
                self.l3_label_encoder = joblib.load(l3_encoder_path)
                self.l3_features_71 = joblib.load(l3_features_71_path)
                self.l3_features_24 = joblib.load(l3_features_24_path)
                benign_candidates = ['BENIGN', 'Normal', 'benign', 'normal']
                for cls in self.l3_label_encoder.classes_:
                    if cls in benign_candidates:
                        self.l3_benign_label = cls
                        break
                if self.l3_benign_label is None:
                    self.l3_benign_label = self.l3_label_encoder.classes_[0]
                logger.info(f"✅ L3: LightGBM Calibrated loaded ({len(self.l3_features_24)} features)")
            except Exception as e:
                logger.error(f"❌ L3 model load failed: {e}")

        # L1
        iso_path = os.path.join(models_dir, 'layer1_sentry_model.pkl')
        if os.path.exists(iso_path):
            try:
                self.iso_forest = joblib.load(iso_path)
                logger.info("✅ L1: Isolation Forest loaded")
            except Exception as e:
                logger.error(f"❌ Failed to load L1: {e}")

        # L2
        l2_path = os.path.join(models_dir, 'aegis_ids_rf_model.pkl')
        if os.path.exists(l2_path):
            try:
                self.l2_model = joblib.load(l2_path)
                logger.info("✅ L2: Random Forest loaded")
            except Exception as e:
                logger.error(f"❌ Failed to load L2: {e}")

        # Scalers & Encoders
        scaler_path = os.path.join(models_dir, 'aegis_ids_scaler.pkl')
        if os.path.exists(scaler_path):
            try: self.scaler = joblib.load(scaler_path)
            except: pass
        encoder_path = os.path.join(models_dir, 'label_encoder.pkl')
        if os.path.exists(encoder_path):
            try: self.label_encoder = joblib.load(encoder_path)
            except: pass

        if enable_deep:
            try:
                from core.deep_engine import InsytLayer3
                self.deep_inspector = InsytLayer3(os.path.join(models_dir, 'deep'), use_onnx=True)
                logger.info("✅ Deep inspector loaded")
            except Exception as e:
                logger.error(f"Deep inspector load failed: {e}")

        if ENABLE_RST_ANOMALY:
            self.rst_anomaly = RSTAnomalyDetector(10, 300, 30, 10, 3600, whitelist or set())
        if ENABLE_UDP_ANOMALY:
            self.udp_anomaly = UDPAnomalyDetector(10, 300, 30, 10, 3600, whitelist or set())
        if ENABLE_ICMP_ANOMALY:
            self.icmp_anomaly = ICMPAnomalyDetector(10, 300, 30, 10, 3600, whitelist or set())

        xgb_path = os.path.join(models_dir, 'xgboost_78_model.pkl')
        if os.path.exists(xgb_path):
            self.xgb_expert = XGBoostExpert(xgb_path, os.path.join(models_dir, 'xgboost_78_scaler.pkl'), 0.5)

        # Batch infrastructure
        self.batch_buffer = []
        self.batch_lock = threading.Lock()
        self.xgb_detections = TTLCache(maxsize=5000, ttl=3600)

        # SYN scan tracker
        self._syn_scan_tracker = TTLCache(maxsize=5000, ttl=120)
        self._syn_scan_last_clean = time.time()

        # Dynamic threshold & reputation
        self.recent_l1_scores = deque(maxlen=100)
        self.ip_reputation = defaultdict(float)
        self.ip_attack_history = TTLCache(maxsize=10000, ttl=600)

        # Alert suppression
        self.alert_suppression = TTLCache(maxsize=10000, ttl=30)

        # Circuit breaker
        self.model_failures = 0
        self.models_disabled = False
        self.last_failure_reset = time.time()

        if self.xgb_expert:
            t = threading.Thread(target=self._batch_worker, daemon=True)
            t.start()

        self.flows = TTLCache(maxsize=5000, ttl=300)
        self.flows_last_time = TTLCache(maxsize=5000, ttl=300)

    def _validate_event(self, event):
        required = ['src_ip', 'dst_ip', 'ip_proto']
        for attr in required:
            if not hasattr(event, attr):
                return False
        return True

    def _is_tcp_termination(self, event):
        if event.ip_proto != 6:
            return False
        summary = getattr(event, 'summary', '')
        return 'FIN' in summary or 'RST' in summary

    def _check_syn_scan(self, event):
        if event.ip_proto == 6 and 'S' in getattr(event, 'summary', '') and 'A' not in getattr(event, 'summary', ''):
            src = event.src_ip
            dst_port = event.dst_port
            if dst_port:
                with self.cache_lock:
                    if src not in self._syn_scan_tracker:
                        self._syn_scan_tracker[src] = set()
                    self._syn_scan_tracker[src].add(dst_port)
                    if len(self._syn_scan_tracker[src]) >= 10:
                        ports = sorted(list(self._syn_scan_tracker[src]))
                        del self._syn_scan_tracker[src]
                        logger.warning(f"SYN Scan from {src}: {ports[:20]}...")
                        return True
        return False

    def _adaptive_l1_threshold(self):
        if len(self.recent_l1_scores) < 50:
            return -0.12
        with self.state_lock:
            scores = list(self.recent_l1_scores)
        mean_score = np.mean(scores)
        std_score = np.std(scores)
        threshold = mean_score - (2 * std_score)
        return min(threshold, -0.05)

    def _update_ip_reputation(self, ip, score):
        with self.state_lock:
            self.ip_reputation[ip] += score
            if len(self.ip_reputation) % 100 == 0:
                for k in list(self.ip_reputation.keys()):
                    if self.ip_reputation[k] < 0.1:
                        del self.ip_reputation[k]

    def _check_correlation(self, src_ip, attack_type):
        now = time.time()
        with self.cache_lock:
            if src_ip not in self.ip_attack_history:
                self.ip_attack_history[src_ip] = []
            self.ip_attack_history[src_ip].append({'time': now, 'type': attack_type})
            self.ip_attack_history[src_ip] = [
                a for a in self.ip_attack_history[src_ip] if now - a['time'] < 60
            ]
            unique = set(a['type'] for a in self.ip_attack_history[src_ip])
        if len(unique) >= 3:
            logger.warning(f"Campaign from {src_ip}: {unique}")
            return True, list(unique)
        return False, list(unique)

    def _generate_explanation(self, src_ip, l1_score, l2_label, l3_label, ja3_threat, is_campaign):
        reasons = []
        if l1_score < -0.2: reasons.append("Strong L1 anomaly")
        if l2_label != 'benign': reasons.append(f"L2: {l2_label}")
        if l3_label.lower() != str(self.l3_benign_label).lower(): reasons.append(f"L3: {l3_label}")
        if ja3_threat: reasons.append(f"JA3: {ja3_threat}")
        if is_campaign: reasons.append("Campaign correlated")
        with self.state_lock:
            rep = self.ip_reputation.get(src_ip, 0)
        if rep > 1.0: reasons.append(f"Reputation {rep:.1f}")
        return "; ".join(reasons) if reasons else "Anomaly unconfirmed"

    def _dynamic_confidence_fusion(self, l1_score, l2_prob, l2_label, l3_prob, l3_label, src_ip, ja3_bonus=0.0):
        cfg = {"l1_weight": 0.15, "l2_weight": 0.35, "l3_weight": 0.35, "ja3_weight": 0.15}
        l1_n = min(abs(l1_score)/0.5, 1.0)
        l2_c = l2_prob if l2_label != 'benign' else (1-l2_prob)
        l3_c = l3_prob if l3_label.lower() != str(self.l3_benign_label).lower() else (1-l3_prob)
        with self.state_lock:
            rep_bonus = min(self.ip_reputation.get(src_ip, 0)/10.0, 0.2)
        effective_ja3 = ja3_bonus if (l1_score < -0.05 or l2_label != 'benign' or l3_label.lower() != str(self.l3_benign_label).lower()) else 0.0
        score = (l1_n*cfg["l1_weight"] + l2_c*cfg["l2_weight"] + l3_c*cfg["l3_weight"] + effective_ja3*cfg["ja3_weight"] + rep_bonus)*100
        return min(score, 100.0)

    def _batch_worker(self):
        while True:
            time.sleep(BATCH_INTERVAL)
            try:
                self._process_batch()
                if time.time() - self._syn_scan_last_clean > 60:
                    with self.cache_lock:
                        self._syn_scan_tracker.clear()
                    self._syn_scan_last_clean = time.time()
            except Exception as e:
                logger.error(f"Batch worker error: {e}")

    def _process_batch(self):
        with self.batch_lock:
            if len(self.batch_buffer) < MIN_BATCH_PACKETS: return
            batch, self.batch_buffer = self.batch_buffer, []

        flows_dict = defaultdict(list)
        for evt in batch:
            flows_dict[(evt.src_ip, evt.dst_ip, evt.src_port, evt.dst_port, evt.ip_proto)].append(evt)

        feat_dicts, flow_keys = [], []
        for key, events in flows_dict.items():
            if len(events) >= MIN_FLOW_PACKETS:
                fd = extract_xgboost_features(events)
                if fd:
                    feat_dicts.append(fd)
                    flow_keys.append(key)

        if not feat_dicts: return

        results = self.xgb_expert.predict_batch(feat_dicts)
        for i, (decision, attack_type) in enumerate(results):
            if decision == "Attack":
                src_ip, dst_ip, sport, dport, _ = flow_keys[i]
                self._update_ip_reputation(src_ip, 1.0)
                is_campaign, ctypes = self._check_correlation(src_ip, attack_type)
                alert_key = f"{src_ip}:{attack_type}"
                with self.alert_lock:
                    if alert_key in self.alert_suppression: continue
                    self.alert_suppression[alert_key] = True
                campaign_msg = f" (Campaign: {ctypes})" if is_campaign else ""
                logger.warning(f"XGBoost Expert: {attack_type} from {src_ip}:{sport} -> {dst_ip}:{dport}{campaign_msg}")

                with self.cache_lock:
                    self.xgb_detections[time.time()] = {
                        "timestamp": time.time(),
                        "src_ip": src_ip, "dst_ip": dst_ip,
                        "sport": sport, "dsport": dport,
                        "attack_type": f"{attack_type}{campaign_msg}",
                        "risk_score": 90.0
                    }

                # إضافة إلى القناة الموحدة (دون تغيير سلوك process_packet)
                self.alert_queue.put({
                    "timestamp": time.time(),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "sport": sport,
                    "dport": dport,
                    "attack_type": f"{attack_type}{campaign_msg}",
                    "risk_score": 90.0,
                    "engine": "XGBoost_Expert"
                })

    def _check_circuit_breaker(self):
        if self.models_disabled:
            if time.time() - self.last_failure_reset > RECOVERY_COOLDOWN:
                logger.warning("Re-enabling models after cooldown")
                self.models_disabled = False
                self.model_failures = 0
            else:
                return True
        return False

    def process_packet(self, event):
        if not self._validate_event(event):
            return None

        if self._check_circuit_breaker():
            return {"decision": "Suspicious", "risk_score": 50, "explanation": "Models temporarily disabled"}

        # --- JA3 (للاستعلام فقط) ---
        ja3_threat = None
        ja3_bonus = 0.0
        if self.ja3_detector:
            res = self.ja3_detector.analyze(event)
            if res:
                ja3_threat = res['threat']
                ja3_bonus = res['risk_score_bonus']

        # --- SYN scan (النمط القديم للإرجاع) ---
        if self._check_syn_scan(event):
            result = {
                "decision": "Attack",
                "risk_score": 95.0,
                "attack_type": "SYN Scan (nmap)",
                "explanation": "Multiple SYN to different ports"
            }
            self.alert_queue.put({
                "timestamp": time.time(),
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "sport": getattr(event, 'src_port', 0),
                "dport": getattr(event, 'dst_port', 0),
                "attack_type": "SYN Scan (nmap)",
                "risk_score": 95.0,
                "engine": "SYN_Scanner"
            })
            return result

        # --- RST Anomaly ---
        if self.rst_anomaly and 'RST' in getattr(event, 'summary', ''):
            dst_port = getattr(event, 'dst_port', 0) or 0
            decision, attack_type = self.rst_anomaly.update_and_predict(event.src_ip, dst_port, event.length)
            if decision == "Attack":
                result = {
                    "decision": "Attack",
                    "risk_score": 95.0,
                    "attack_type": f"RST Anomaly: {attack_type}"
                }
                self.alert_queue.put({
                    "timestamp": time.time(),
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                    "sport": getattr(event, 'src_port', 0),
                    "dport": dst_port,
                    "attack_type": f"RST Anomaly: {attack_type}",
                    "risk_score": 95.0,
                    "engine": "RST_Anomaly"
                })
                return result

        # --- Batch buffer ---
        if self.xgb_expert:
            with self.batch_lock:
                if len(self.batch_buffer) < MAX_BATCH_BUFFER:
                    self.batch_buffer.append(event)

        # --- معالجة التدفقات (L1/L2/L3) ---
        flow_key = (event.src_ip, event.dst_ip, event.src_port, event.dst_port, event.ip_proto)
        with self.flow_lock:
            self.flows.setdefault(flow_key, [])
            if len(self.flows[flow_key]) >= MAX_EVENTS_PER_FLOW:
                return self._finish_flow(flow_key)
            self.flows[flow_key].append(event)
            self.flows_last_time[flow_key] = time.time()

            if self._is_tcp_termination(event):
                return self._finish_flow(flow_key)
            if len(self.flows[flow_key]) >= 10:
                return self._finish_flow(flow_key)

        return self._check_stale_flows()

    def _finish_flow(self, flow_key):
        with self.flow_lock:
            events = self.flows.pop(flow_key, None)
            self.flows_last_time.pop(flow_key, None)
        if events:
            return self._process_completed_flow(events)
        return None

    def _check_stale_flows(self):
        now = time.time()
        stale = []
        with self.flow_lock:
            for key in list(self.flows.keys()):
                if now - self.flows_last_time.get(key, 0) > 5.0:
                    stale.append(key)
        results = []
        for key in stale:
            res = self._finish_flow(key)
            if res: results.append(res)
        return results[-1] if results else None

    def _process_completed_flow(self, events):
        result = self.analyze_flow(events)
        if result and result.get("decision") in ("Attack", "Suspicious"):
            # إضافة إلى queue للواجهة مع الحفاظ على النتيجة القديمة
            alert_data = {
                "timestamp": time.time(),
                "src_ip": events[0].src_ip if events else "0.0.0.0",
                "dst_ip": events[0].dst_ip if events else "0.0.0.0",
                "sport": events[0].src_port if events else 0,
                "dport": events[0].dst_port if events else 0,
                "attack_type": result.get("attack_type", "Unknown"),
                "risk_score": result.get("risk_score", 0),
                "explanation": result.get("explanation", ""),
                "engine": "L1-L2-L3"
            }
            self.alert_queue.put(alert_data)
        return result

    def analyze_flow(self, events):
        if self.models_disabled:
            return {"decision": "Suspicious", "risk_score": 50, "explanation": "Models temporarily disabled"}

        try:
            feat_dict = extract_features_for_l1_l2(events)
            if not feat_dict:
                return {"decision": "Normal", "risk_score": 0}

            X = np.array([[feat_dict.get(n, 0) for n in FEATURE_NAMES_L1_L2]], dtype=np.float32)
            if self.scaler:
                X_scaled = self.scaler.transform(X)
            else:
                X_scaled = X

            l1_score = self.iso_forest.decision_function(X_scaled)[0]
            with self.state_lock:
                self.recent_l1_scores.append(l1_score)
            dynamic_th = self._adaptive_l1_threshold()
            is_anomaly = l1_score < dynamic_th
            logger.debug(f"L1 score={l1_score:.4f} ANOMALY={is_anomaly} th={dynamic_th:.4f}")
            if not is_anomaly:
                return {"decision": "Normal", "risk_score": 0, "explanation": "L1 benign"}

            ja3_threat = None
            ja3_bonus = 0.0
            if self.ja3_detector and events:
                res = self.ja3_detector.analyze(events[0])
                if res:
                    ja3_threat = res['threat']
                    ja3_bonus = res['risk_score_bonus']

            l2_label, l2_prob = 'benign', 0.0
            if self.l2_model and self.label_encoder:
                probs = self.l2_model.predict_proba(X_scaled)[0]
                idx = np.argmax(probs)
                l2_prob = probs[idx]
                l2_label = self.label_encoder.inverse_transform([idx])[0]
                logger.debug(f"L2: {l2_label} prob={l2_prob:.4f}")
                BENIGN_OVERRIDE = 0.85
                if l2_label.lower() == 'benign' and l2_prob >= BENIGN_OVERRIDE and not ja3_threat:
                    return {"decision": "Normal", "risk_score": 5.0, "explanation": f"L2 benign {l2_prob:.0%}"}

            l3_label, l3_prob = str(self.l3_benign_label or 'benign'), 0.0
            if self.l3_model and self.l3_scaler and self.l3_selector:
                X_l3_71 = np.array([[feat_dict.get(f,0) for f in self.l3_features_71]], dtype=np.float32)
                X_l3_s = self.l3_scaler.transform(X_l3_71)
                X_l3_sel = self.l3_selector.transform(X_l3_s)
                l3_probs = self.l3_model.predict_proba(X_l3_sel)[0]
                idx3 = np.argmax(l3_probs)
                l3_prob = l3_probs[idx3]
                l3_label = self.l3_label_encoder.inverse_transform([idx3])[0]
                logger.debug(f"L3: {l3_label} prob={l3_prob:.4f}")

            src_ip = events[0].src_ip if events else "0.0.0.0"
            risk = self._dynamic_confidence_fusion(l1_score, l2_prob, l2_label, l3_prob, l3_label, src_ip, ja3_bonus)

            is_campaign, ctypes = False, []
            if risk >= 70:
                atype = l3_label if l3_label.lower() != str(self.l3_benign_label).lower() else l2_label
                is_campaign, ctypes = self._check_correlation(src_ip, atype)
                if is_campaign:
                    self._update_ip_reputation(src_ip, 5.0)

            explanation = self._generate_explanation(src_ip, l1_score, l2_label, l3_label, ja3_threat, is_campaign)

            # قرار نهائي (بالحفاظ على نمط المخرجات القديم)
            if risk >= 70:
                alert_key = f"{src_ip}:{l3_label}"
                with self.alert_lock:
                    if alert_key not in self.alert_suppression:
                        self.alert_suppression[alert_key] = True
                        logger.warning(f"Attack: {l3_label} risk={risk:.1f}")
                return {
                    "decision": "Attack",
                    "risk_score": risk,
                    "attack_type": f"{l3_label}{' (Campaign)' if is_campaign else ''}",
                    "explanation": explanation,
                    "ja3_threat": ja3_threat
                }
            if risk < 40:
                return {"decision": "Normal", "risk_score": risk, "explanation": explanation}

            return {"decision": "Suspicious", "risk_score": risk, "explanation": explanation}

        except Exception as e:
            self.model_failures += 1
            if self.model_failures > 20 and not self.models_disabled:
                self.models_disabled = True
                self.last_failure_reset = time.time()
                logger.critical("Models disabled due to repeated failures")
            logger.error(f"analyze_flow error: {e}", exc_info=False)
            return {"decision": "Suspicious", "risk_score": 50, "explanation": "Internal error fallback"}

    def _get_payload(self, events):
        for evt in reversed(events):
            if hasattr(evt, 'payload') and evt.payload:
                return evt.payload
        return ""

    def get_status(self):
        return {
            "l1": self.iso_forest is not None,
            "l2": self.l2_model is not None,
            "l3": self.l3_model is not None or self.deep_inspector is not None,
            "xgb_expert": self.xgb_expert is not None,
            "ja3": self.ja3_detector is not None,
            "models_disabled": self.models_disabled,
            "ready": self.iso_forest is not None
        }