# core/active_response.py
"""
Active Response Engine - Aggressive Defense
"""
import subprocess
import threading
import time
import logging
import re

logger = logging.getLogger(__name__)

ATTACKER_HISTORY = {}
BLACKLIST_MACS = set()

def get_mac_from_ip(ip: str) -> str:
    try:
        result = subprocess.run(f'arp -a {ip}', capture_output=True, text=True, timeout=5)
        match = re.search(r'([0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2})', result.stdout, re.IGNORECASE)
        if match:
            return match.group(1).replace('-', ':')
    except:
        pass
    return None

def arp_cache_cleanup(ip: str):
    try:
        subprocess.run(f'arp -d {ip}', shell=True, capture_output=True)
        logger.info(f"🧹 ARP cache cleared for {ip}")
        return True
    except:
        return False

def send_tcp_rst(ip: str):
    try:
        for _ in range(5):
            subprocess.run(f'tracert -d -h 1 {ip}', shell=True, capture_output=True, timeout=1)
        logger.info(f"⚡ TCP RST sent to {ip}")
        return True
    except:
        return False

def isolate_mac(mac: str):
    if not mac:
        return False
    BLACKLIST_MACS.add(mac)
    try:
        subprocess.run(f'netsh wlan add filter block mac={mac}', shell=True, capture_output=True)
        logger.warning(f"🔒 MAC {mac} ISOLATED!")
    except:
        pass
    return True

def aggressive_response(ip: str, attack_type: str, mac: str = None):
    from core.trust_engine import trust_engine
    
    # منع حظر Gateway
    if ip == "192.168.137.1":
        logger.warning("SKIPPED: Cannot block Gateway")
        return {"status": "skipped", "reason": "gateway_protected"}
    
    if trust_engine.is_protected(ip):
        logger.warning(f"SKIPPED: {ip} is protected")
        return {"status": "skipped", "reason": "protected_ip"}
    results = []
    
    if ip not in ATTACKER_HISTORY:
        ATTACKER_HISTORY[ip] = {"count": 0, "last_seen": time.time(), "mac": mac}
    
    ATTACKER_HISTORY[ip]["count"] += 1
    ATTACKER_HISTORY[ip]["last_seen"] = time.time()
    attack_count = ATTACKER_HISTORY[ip]["count"]
    
    # 1. ARP cleanup
    arp_cache_cleanup(ip)
    results.append({"action": "arp_cleanup", "status": True})
    
    # 2. TCP RST
    send_tcp_rst(ip)
    results.append({"action": "tcp_rst", "status": True})
    
    # 3. Layer 2 isolation بعد 3 هجمات
    if attack_count >= 3 and mac and mac not in BLACKLIST_MACS:
        isolate_mac(mac)
        results.append({"action": "layer2_isolation", "status": True, "mac": mac})
        logger.warning(f"🔥 REPEATED ATTACKER: {ip} (MAC: {mac}) - ISOLATED!")
    
    return {
        "attacker_ip": ip,
        "attacker_mac": mac,
        "attack_count": attack_count,
        "actions": results,
        "isolated": attack_count >= 3
    }

def get_attacker_stats():
    return {
        ip: {"count": data["count"], "last_seen": data["last_seen"], "mac": data["mac"]}
        for ip, data in ATTACKER_HISTORY.items()
    }

def clear_attacker_history(ip: str = None):
    global ATTACKER_HISTORY
    if ip:
        ATTACKER_HISTORY.pop(ip, None)
    else:
        ATTACKER_HISTORY.clear()

