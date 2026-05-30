"""Device Scanner - Accurate vendor detection using manuf library"""
import subprocess, socket, re
from manuf import manuf

# Initialize manuf parser (loads OUI database once)
parser = manuf.MacParser(update=False)

def get_vendor(mac):
    """Get vendor using manuf library - accurate and independent"""
    if not mac or mac == "Unknown" or mac == "00:00:00:00:00:00":
        return "Unknown"
    try:
        vendor = parser.get_manuf(mac)
        if vendor:
            return vendor
    except:
        pass
    return "Unknown"

def get_hostname(ip):
    """Try multiple methods to get hostname"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname != ip:
            return hostname
    except:
        pass
    try:
        result = subprocess.run(['nbtstat', '-A', ip], capture_output=True, text=True, timeout=3)
        for line in result.stdout.split('\n'):
            if '<00>' in line and 'UNIQUE' in line:
                name = line.strip().split()[0]
                if name and name != ip: return name
    except: pass
    return "Unknown"

_device_cache = {}
_cache_time = 0
CACHE_TTL = 30

def scan_network(subnet="192.168.137.0/24"):
    """Scan network with accurate manuf-based vendor detection"""
    devices = []
    seen = set()
    
    # Method 1: netsh neighbors
    try:
        r = subprocess.run('netsh interface ip show neighbors', capture_output=True, text=True, timeout=10, shell=True)
        for line in r.stdout.split('\n'):
            match = re.search(r'(192\.168\.137\.\d+)', line)
            if match:
                ip = match.group(1)
                if ip.endswith('.1') or ip.endswith('.255'): continue
                if ip not in seen:
                    seen.add(ip)
                    mac_match = re.search(r'([0-9A-Fa-f]{2}[-]){5}[0-9A-Fa-f]{2}', line)
                    mac = mac_match.group(0).replace('-',':').upper() if mac_match else 'Unknown'
                    vendor = get_vendor(mac)
                    hostname = get_hostname(ip)
                    devices.append({"ip":ip,"mac":mac,"vendor":vendor,"hostname":hostname})
    except: pass
    
    # Method 2: arp -a fallback
    if not devices:
        try:
            r = subprocess.run('arp -a', capture_output=True, text=True, timeout=10)
            for line in r.stdout.split('\n'):
                match = re.match(r'\s*(192\.168\.137\.\d+)\s+([0-9A-Fa-f-]{17})\s+(\w+)', line)
                if match:
                    ip = match.group(1)
                    if ip.endswith('.1') or ip.endswith('.255'): continue
                    if ip not in seen:
                        seen.add(ip)
                        mac = match.group(2).replace('-',':').upper()
                        vendor = get_vendor(mac)
                        hostname = get_hostname(ip)
                        devices.append({"ip":ip,"mac":mac,"vendor":vendor,"hostname":hostname})
        except: pass
    
    return devices


