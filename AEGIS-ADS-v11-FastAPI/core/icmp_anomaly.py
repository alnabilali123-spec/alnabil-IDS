import time, logging, numpy as np
from collections import deque, defaultdict

logger = logging.getLogger(__name__)

class ICMPAnomalyDetector:
    """
    كاشف فيضان ICMP (Ping Flood) متقدم مع:
    - تدريب تلقائي + إعادة تدريب كل ساعة.
    - قائمة بيضاء.
    - ميزات إضافية (حجم الحزم، أنواع ICMP).
    - عتبة مزدوجة (عالمية + محلية لكل مصدر).
    """
    def __init__(self, window_seconds=10, train_seconds=120, suppression_seconds=30,
                 min_packets=5, retrain_interval=3600, whitelist=None):
        self.window = window_seconds
        self.train_time = train_seconds
        self.suppression = suppression_seconds
        self.min_packets = min_packets
        self.retrain_interval = retrain_interval
        self.whitelist = whitelist or set()

        self.start_time = time.time()
        self.last_retrain_time = time.time()
        self.is_trained = False

        self.global_rate = 0.0
        self.ip_stats = defaultdict(lambda: {
            'timestamps': deque(),
            'packet_sizes': [],
            'icmp_types': set(),
        })
        self.ip_normal_rate = {}
        self.last_alert_time = {}
        self._all_rates = []
        self._all_rates_timestamps = []

    def add_icmp_packet(self, src_ip, packet_size=0, icmp_type=0):
        now = time.time()
        stats = self.ip_stats[src_ip]
        q = stats['timestamps']
        while q and now - q[0] > self.window:
            q.popleft()
        q.append(now)
        if packet_size > 0:
            stats['packet_sizes'].append(packet_size)
        stats['icmp_types'].add(icmp_type)

        return len(q) / self.window

    def update_and_predict(self, src_ip, packet_size=0, icmp_type=0):
        if src_ip in self.whitelist:
            return "Normal", ""

        rate = self.add_icmp_packet(src_ip, packet_size, icmp_type)
        now = time.time()

        if not self.is_trained:
            if now - self.start_time < self.train_time:
                self._all_rates.append(rate)
                self._all_rates_timestamps.append(now)
                return "Normal", ""
            else:
                self._recalculate_thresholds(now)
                self.is_trained = True
                logger.info(f"✅ ICMP Anomaly trained: global threshold = {self.global_rate:.2f} ICMP/s")

        if self.is_trained and (now - self.last_retrain_time >= self.retrain_interval):
            cutoff = now - self.retrain_interval
            self._all_rates = [r for r, t in zip(self._all_rates, self._all_rates_timestamps) if t >= cutoff]
            self._all_rates_timestamps = [t for t in self._all_rates_timestamps if t >= cutoff]
            for ip, stats in self.ip_stats.items():
                q = stats['timestamps']
                if q:
                    current_rate = len(q) / self.window
                    self._all_rates.append(current_rate)
            self._recalculate_thresholds(now)
            self.last_retrain_time = now
            logger.info(f"🔄 ICMP Anomaly retrained: global threshold = {self.global_rate:.2f} ICMP/s")

        self._all_rates.append(rate)
        self._all_rates_timestamps.append(now)

        if self.is_trained and rate >= self.global_rate:
            stats = self.ip_stats[src_ip]
            q = stats['timestamps']
            if len(q) >= self.min_packets:
                local_threshold = self.ip_normal_rate.get(src_ip, 0) * 5
                if local_threshold > 0 and rate < local_threshold:
                    return "Normal", ""

                unique_types = len(stats['icmp_types'])
                if unique_types > 1:
                    logger.info(f"🔍 ICMP from {src_ip} with {unique_types} different types (potential scan)")

                last = self.last_alert_time.get(src_ip, 0)
                if now - last >= self.suppression:
                    self.last_alert_time[src_ip] = now
                    avg_size = np.mean(stats['packet_sizes']) if stats['packet_sizes'] else 0
                    logger.warning(f"🚨 ICMP Flood from {src_ip}: {rate:.1f} ICMP/s, types={unique_types}, avg size {avg_size:.0f}B (global thr={self.global_rate:.1f})")
                    return "Attack", "ICMP Flood"
        else:
            if rate < self.global_rate:
                if src_ip in self.ip_normal_rate:
                    self.ip_normal_rate[src_ip] = 0.9 * self.ip_normal_rate[src_ip] + 0.1 * rate
                else:
                    self.ip_normal_rate[src_ip] = rate

        return "Normal", ""

    def _recalculate_thresholds(self, now):
        if len(self._all_rates) > 10:
            mean_rate = np.mean(self._all_rates)
            std_rate = np.std(self._all_rates)
            self.global_rate = mean_rate + 2 * std_rate
            if self.global_rate < 1.0:
                self.global_rate = 1.0
            self.ip_normal_rate.clear()
            logger.debug(f"ICMP thresholds recalculated: global={self.global_rate:.2f}")
        else:
            self.global_rate = 1.0