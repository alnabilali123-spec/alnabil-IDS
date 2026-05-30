# core/vendor_db.py
import socket
import subprocess
import re

# قاعدة بيانات محلية للـ MAC prefixes
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
    "00:0C:29": "VMware Inc.",
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
