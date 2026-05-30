# core/firewall_manager.py - Fixed
import subprocess
import re
import logging
import socket

logger = logging.getLogger(__name__)

PROTECTED_IPS = {'127.0.0.1', '192.168.8.1', '192.168.8.5'}

# قاعدة بيانات البائعين
VENDOR_DB = {
    "7C:B3:7B": "Apple Inc.",
    "B8:8A:60": "Apple Inc.",
    "98:E7:F4": "Apple Inc.",
    "08:31:8B": "Samsung Electronics",
    "F4:8C:50": "Samsung Electronics",
    "68:5D:43": "Huawei Technologies",
    "62:4A:58": "Huawei Technologies",
    "28:6C:07": "Xiaomi Communications",
    "9C:9E:6E": "Xiaomi Communications",
}

def get_vendor(mac: str) -> str:
    if not mac:
        return "Unknown"
    mac_clean = mac.upper().replace('-', ':')
    for prefix, vendor in VENDOR_DB.items():
        if mac_clean.startswith(prefix):
            return vendor
    return "Unknown"

def get_hostname(ip: str) -> str:
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname.split('.')[0]
    except:
        return "Unknown"

def block_ip_v2(ip: str, reason: str = "AEGIS-ADS") -> dict:
    if ip in PROTECTED_IPS:
        return {"status": "skipped", "reason": "protected"}
    
    try:
        rule_in = f"AEGIS_IN_{ip.replace('.', '_')}"
        rule_out = f"AEGIS_OUT_{ip.replace('.', '_')}"
        
        subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_in}"', shell=True, capture_output=True)
        subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_out}"', shell=True, capture_output=True)
        
        cmd_in = f'netsh advfirewall firewall add rule name="{rule_in}" dir=in action=block remoteip={ip} enable=yes'
        cmd_out = f'netsh advfirewall firewall add rule name="{rule_out}" dir=out action=block remoteip={ip} enable=yes'
        
        ri_ok = subprocess.run(cmd_in, shell=True, capture_output=True).returncode == 0
        ro_ok = subprocess.run(cmd_out, shell=True, capture_output=True).returncode == 0
        
        if ri_ok and ro_ok:
            logger.info(f"BLOCKED: {ip} - {reason}")
            return {"status": "blocked", "ip": ip}
        return {"status": "partial", "in": ri_ok, "out": ro_ok}
    except Exception as e:
        logger.error(f"Block error: {e}")
        return {"status": "error", "error": str(e)}

def unblock_ip(ip: str) -> dict:
    for d in ['IN', 'OUT']:
        subprocess.run(f'netsh advfirewall firewall delete rule name="AEGIS_{d}_{ip.replace(".", "_")}"', shell=True, capture_output=True)
    return {"status": "unblocked", "ip": ip}

def panic_button() -> dict:
    subprocess.run('netsh advfirewall firewall add rule name="AEGIS_PANIC_ALL" dir=out action=block remoteip=192.168.137.0/24 enable=yes', shell=True, capture_output=True)
    subprocess.run('netsh wlan stop hostednetwork', shell=True, capture_output=True)
    logger.warning("PANIC MODE!")
    return {"panic": True}

def unpanic() -> dict:
    subprocess.run('netsh advfirewall firewall delete rule name="AEGIS_PANIC_ALL"', shell=True, capture_output=True)
    subprocess.run('netsh wlan start hostednetwork', shell=True, capture_output=True)
    return {"status": "restored"}

def get_connected_devices() -> list:
    """جلب الأجهزة المتصلة بالشبكة"""
    devices = []
    try:
        result = subprocess.run('arp -a', capture_output=True, text=True, timeout=10)
        lines = result.stdout.split('\n')
        
        for line in lines:
            # تطابق IP, MAC, Type
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f-]{17})\s+(\w+)', line, re.IGNORECASE)
            if match:
                ip = match.group(1)
                mac = match.group(2).replace('-', ':').upper()
                typ = match.group(3)
                
                # فقط أجهزة شبكة Hotspot (192.168.137.x)
                if ip.startswith('192.168.137.') and not ip.endswith('.255'):
                    vendor = get_vendor(mac)
                    hostname = get_hostname(ip)
                    devices.append({
                        "ip_address": ip,
                        "mac_address": mac,
                        "vendor": vendor,
                        "hostname": hostname if hostname != "Unknown" else "Client",
                        "status": "Active",
                        "type": typ
                    })
    except Exception as e:
        logger.error(f"ARP error: {e}")
    
    return devices
