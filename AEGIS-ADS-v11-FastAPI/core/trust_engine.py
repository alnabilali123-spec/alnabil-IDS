# core/trust_engine.py
import time
from typing import Dict

class TrustEngine:
    PROTECTED_IPS = {"127.0.0.1", "192.168.8.1", "192.168.8.5", "192.168.137.1"}
    
    def __init__(self):
        self._last_email_time: Dict[str, float] = {}
    
    def is_protected(self, ip: str) -> bool:
        return ip in self.PROTECTED_IPS
    
    def can_send_email(self, ip: str) -> bool:
        now = time.time()
        last = self._last_email_time.get(ip, 0)
        if now - last < 300:
            return False
        self._last_email_time[ip] = now
        return True

trust_engine = TrustEngine()
