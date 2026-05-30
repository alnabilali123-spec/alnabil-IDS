"""Global State - Thread-safe Singleton"""
import threading
from collections import deque
from datetime import datetime

class GlobalState:
    _instance = None
    _lock = threading.RLock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._init = False
        return cls._instance
    
    def __init__(self):
        if self._init: return
        self._init = True
        self._lock = threading.RLock()
        self.capture_running = False
        self.capture_mode = "hotspot"
        self.current_interface = None
        self.packets_processed = 0
        self.alerts_count = 0
        self.attacks_detected = 0
        self.blocked_ips_count = 0
        self.recent_alerts = deque(maxlen=500)
        self.traffic_history = deque(maxlen=60)
        self.l1_status = "STANDBY"
        self.l2_status = "STANDBY"
        self.l3_status = "STANDBY"
        self.night_mode = False
        self.current_user = None
    
    def add_alert(self, alert: dict):
        with self._lock:
            self.alerts_count += 1
            alert['id'] = self.alerts_count
            alert['timestamp'] = datetime.now().isoformat()
            self.recent_alerts.appendleft(alert)
    
    def get_stats(self) -> dict:
        with self._lock:
            return {
                "packets": self.packets_processed,
                "alerts": self.alerts_count,
                "attacks": self.attacks_detected,
                "blocked": self.blocked_ips_count,
                "l1": self.l1_status,
                "l2": self.l2_status,
                "l3": self.l3_status,
                "capture": self.capture_running
            }
