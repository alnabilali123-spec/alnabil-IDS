# core/improved_firewall.py
import subprocess
import threading
import time
import logging

logger = logging.getLogger(__name__)

BLOCKED_IPS = {}
_rules_lock = threading.Lock()

def _add_firewall_rule(ip):
    rule_name = "AEGIS_BLOCK_" + ip.replace(".", "_")
    try:
        subprocess.run(
            f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip} enable=yes',
            shell=True, capture_output=True, timeout=5
        )
        return True
    except Exception as e:
        logger.error(f"Firewall error for {ip}: {e}")
        return False

def _remove_firewall_rule(ip):
    rule_name = "AEGIS_BLOCK_" + ip.replace(".", "_")
    subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name}"', shell=True, capture_output=True)

def block_ip(ip, reason="Manual"):
    with _rules_lock:
        if ip in BLOCKED_IPS:
            return {"status": "already_blocked", "kernel": True, "ip": ip}
        result = _add_firewall_rule(ip)
        BLOCKED_IPS[ip] = {"reason": reason, "time": time.time()}
        logger.info(f"🚫 BLOCKED: {ip} - {reason}")
        return {"status": "blocked", "kernel": result, "ip": ip}

def unblock_ip(ip):
    with _rules_lock:
        if ip in BLOCKED_IPS:
            del BLOCKED_IPS[ip]
        _remove_firewall_rule(ip)
        return {"status": "unblocked"}

def block_ip_kernel(ip, reason="Manual"):
    return block_ip(ip, reason)

def unblock_ip_kernel(ip):
    return unblock_ip(ip)

def panic_mode():
    subprocess.run('netsh advfirewall firewall add rule name="AEGIS_PANIC_IN" dir=in action=block enable=yes', shell=True, capture_output=True)
    subprocess.run('netsh wlan stop hostednetwork', shell=True, capture_output=True)
    logger.warning("🚨 PANIC MODE ACTIVATED")
    return {"status": "panic_activated"}

def unpanic_mode():
    subprocess.run('netsh advfirewall firewall delete rule name="AEGIS_PANIC_IN"', shell=True, capture_output=True)
    return {"status": "panic_deactivated"}

def get_blocked_ips():
    with _rules_lock:
        return list(BLOCKED_IPS.keys())
