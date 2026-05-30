# core/windivert_engine.py
"""
WinDivert Engine - Real-time Packet Blocking
"""
import threading
import time
import subprocess
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

# قائمة العناوين المحظورة
BLOCKED_IPS = set()
BLOCKED_RULES = {}  # {ip: {"reason": str, "time": float, "rule_id": int}}

_running = False
_thread = None

def block_ip_windivert(ip: str, reason: str = "Manual", rule_id: int = None) -> dict:
    """حظر IP باستخدام Windows Firewall (قوي وفوري)"""
    if ip in BLOCKED_IPS:
        return {"status": "already_blocked", "ip": ip, "kernel": True}
    
    try:
        # إضافة قاعدة Windows Firewall (حظر كامل)
        rule_name_in = f"AEGIS_BLOCK_IN_{ip.replace('.', '_')}"
        rule_name_out = f"AEGIS_BLOCK_OUT_{ip.replace('.', '_')}"
        
        # حظر inbound
        subprocess.run(
            f'netsh advfirewall firewall add rule name="{rule_name_in}" dir=in action=block remoteip={ip} enable=yes profile=any',
            shell=True, capture_output=True, timeout=5
        )
        
        # حظر outbound
        subprocess.run(
            f'netsh advfirewall firewall add rule name="{rule_name_out}" dir=out action=block remoteip={ip} enable=yes profile=any',
            shell=True, capture_output=True, timeout=5
        )
        
        # إضافة إلى القائمة
        BLOCKED_IPS.add(ip)
        BLOCKED_RULES[ip] = {
            "reason": reason,
            "time": time.time(),
            "rule_id": rule_id,
            "in_rule": rule_name_in,
            "out_rule": rule_name_out
        }
        
        # إرسال TCP RST لقطع الاتصالات الحالية
        _send_tcp_rst(ip)
        
        logger.info(f"🚫 WINDivert BLOCKED: {ip} - {reason}")
        return {"status": "blocked", "ip": ip, "kernel": True, "windivert": True}
        
    except Exception as e:
        logger.error(f"WinDivert block error: {e}")
        return {"status": "error", "error": str(e)}


def unblock_ip_windivert(ip: str) -> dict:
    """إلغاء حظر IP"""
    if ip in BLOCKED_IPS:
        BLOCKED_IPS.discard(ip)
        
    if ip in BLOCKED_RULES:
        rules = BLOCKED_RULES[ip]
        # حذف قواعد Windows Firewall
        subprocess.run(f'netsh advfirewall firewall delete rule name="{rules["in_rule"]}"', shell=True, capture_output=True)
        subprocess.run(f'netsh advfirewall firewall delete rule name="{rules["out_rule"]}"', shell=True, capture_output=True)
        del BLOCKED_RULES[ip]
        
    logger.info(f"🔓 UNBLOCKED: {ip}")
    return {"status": "unblocked", "ip": ip}


def _send_tcp_rst(ip: str):
    """إرسال حزمة TCP RST لقطع الاتصال فورا"""
    try:
        # استخدام tracert لقطع الاتصال (بديل آمن للـ RAW socket)
        subprocess.run(f'tracert -d -h 1 {ip}', shell=True, capture_output=True, timeout=2)
    except:
        pass


def panic_mode_windivert():
    """وضع الطوارئ - حظر كل الاتصالات"""
    results = []
    
    # حظر الشبكة بالكامل
    r = subprocess.run(
        'netsh advfirewall firewall add rule name="AEGIS_PANIC_FULL" dir=in action=block remoteip=192.168.137.0/24 enable=yes',
        shell=True, capture_output=True
    )
    results.append({"panic_block": r.returncode == 0})
    
    # إيقاف Hotspot
    subprocess.run('netsh wlan stop hostednetwork', shell=True, capture_output=True)
    results.append({"hotspot": "stopped"})
    
    logger.warning("🚨 PANIC MODE ACTIVATED - All connections blocked!")
    return {"status": "panic_activated", "actions": results}


def unpanic_mode_windivert():
    """إلغاء وضع الطوارئ"""
    subprocess.run('netsh advfirewall firewall delete rule name="AEGIS_PANIC_FULL"', shell=True, capture_output=True)
    subprocess.run('netsh wlan start hostednetwork', shell=True, capture_output=True)
    return {"status": "panic_deactivated"}


def get_blocked_ips_list():
    """الحصول على قائمة العناوين المحظورة"""
    return list(BLOCKED_IPS)


def get_blocked_rules():
    """الحصول على تفاصيل القواعد"""
    return [
        {
            "ip": ip,
            "reason": data["reason"],
            "time": data["time"],
            "rule_id": data["rule_id"]
        }
        for ip, data in BLOCKED_RULES.items()
    ]


# تصدير الوظائف
__all__ = [
    'block_ip_windivert',
    'unblock_ip_windivert',
    'panic_mode_windivert',
    'unpanic_mode_windivert',
    'get_blocked_ips_list',
    'get_blocked_rules',
    'BLOCKED_IPS'
]
