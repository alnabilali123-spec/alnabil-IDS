# core/analytics.py
from collections import defaultdict
from datetime import datetime
import threading

attack_stats = defaultdict(lambda: {"count": 0, "timeline": defaultdict(int)})
_stats_lock = threading.Lock()

def record_attack(attack_type, severity, src_ip):
    with _stats_lock:
        hour = datetime.now().strftime("%H:00")
        attack_stats[attack_type]["count"] += 1
        attack_stats[attack_type]["timeline"][hour] += 1

def get_chart_data():
    with _stats_lock:
        attack_types = {}
        for atype, data in attack_stats.items():
            if data["count"] > 0:
                attack_types[atype] = data["count"]
        timeline = []
        for i in range(24):
            hour = f"{i:02d}:00"
            total = sum(data["timeline"][hour] for data in attack_stats.values())
            timeline.append({"hour": hour, "attacks": total})
        return {"attack_types": attack_types, "timeline": timeline, "total_attacks": sum(d["count"] for d in attack_stats.values())}

def get_attack_stats():
    with _stats_lock:
        return {"DDoS": attack_stats["DDoS"]["count"], "PortScan": attack_stats["PortScan"]["count"], "Bruteforce": attack_stats["Bruteforce"]["count"]}
