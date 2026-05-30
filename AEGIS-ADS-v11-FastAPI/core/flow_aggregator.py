import time, logging
from collections import defaultdict

logger = logging.getLogger(__name__)

class FlowAggregator:
    """
    يجمع الحزم إلى تدفقات وينشئ إحصائيات متوافقة مع نموذج Darkknight DDoS XGBoost.
    """
    def __init__(self, timeout=2.0):
        self.timeout = timeout
        self.flows = defaultdict(list)
        self.last_activity = {}

    def add_packet(self, event):
        """يضيف حزمة للتجميع ويعيد إحصائيات التدفق عند اكتماله، وإلا None"""
        flow_key = (event.src_ip, event.dst_ip, event.src_port, event.dst_port, event.ip_proto)
        now = time.time()
        
        self.flows[flow_key].append(event)
        self.last_activity[flow_key] = now
        
        # إغلاق التدفقات منتهية الصلاحية
        self._check_stale_flows(now)
        
        # إغلاق التدفق إذا انتهى بـ FIN أو RST
        if hasattr(event, 'summary') and event.summary:
            if 'FIN' in event.summary or 'RST' in event.summary:
                return self._close_flow(flow_key)
        
        return None

    def _check_stale_flows(self, now):
        stale = [k for k, t in self.last_activity.items() if now - t > self.timeout]
        for k in stale:
            self._close_flow(k)

    def _close_flow(self, flow_key):
        events = self.flows.pop(flow_key, None)
        if events:
            self.last_activity.pop(flow_key, None)
            return self._extract_stats(events)
        return None

    def _extract_stats(self, events):
        """استخراج الميزات الإحصائية للتدفق"""
        if not events:
            return None
        
        # استخراج الأطوال والطوابع الزمنية
        lengths = []
        timestamps = []
        for e in events:
            if hasattr(e, 'raw_bytes') and e.raw_bytes:
                lengths.append(len(e.raw_bytes))
            else:
                lengths.append(0)
            if hasattr(e, 'timestamp'):
                try:
                    timestamps.append(time.mktime(e.timestamp.timetuple()))
                except:
                    timestamps.append(time.time())
            else:
                timestamps.append(time.time())
        
        pkt_count = len(events)
        byte_count = sum(lengths)
        duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.001
        
        stats = {
            'flow_duration': duration,
            'pkt_count': pkt_count,
            'byte_count': byte_count,
            'requests_per_sec': pkt_count / duration if duration > 0 else 0,
            'max_pkt_len': max(lengths) if lengths else 0,
            'min_pkt_len': min(lengths) if lengths else 0,
            'pkt_len_variation': (max(lengths) - min(lengths)) if lengths else 0,
            'fwd_pkt_len_std': (sum((l - (byte_count/pkt_count))**2 for l in lengths) / pkt_count)**0.5 if pkt_count else 0,
            'src_ip': events[0].src_ip,
            'dst_ip': events[0].dst_ip,
        }
        return stats