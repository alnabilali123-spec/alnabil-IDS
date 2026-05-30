"""
AEGIS-ADS v11.0 – THREE‑LAYER ARCHITECTURE (Live Capture with Scapy)
+ RST Anomaly Detector (Adaptive, Whitelist-Aware)
+ UDP Anomaly Detector (Adaptive, Whitelist-Aware)
+ ICMP Anomaly Detector (Adaptive, Whitelist-Aware)
+ ONNX Runtime + Batch Inference
+ XGBoost Expert (cicflowmeter mode)
+ Bridge for XGBoost Expert alerts (timestamp-safe)
"""
import sys, os, time, threading, smtplib, asyncio, psutil, subprocess, json, re, shutil
import numpy as np
from datetime import datetime
from collections import defaultdict
from contextlib import asynccontextmanager
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from fastapi import FastAPI, Request, WebSocket, HTTPException, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import uvicorn, logging

from core.models_loader import ModelsLoader
from core.global_state import GlobalState
from core.packet_capture import PacketCaptureEngine
import config

# ============================================================
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("AEGIS")
state = GlobalState()

PROTECTED_IPS = {'127.0.0.1', '192.168.8.1', '192.168.8.5'}
BLOCKED_IPS_STORAGE = []
BLOCKED_RULES = []
WHITELIST_IPS = set()
WHITELIST_IPS_FILE = 'whitelist.json'

def load_whitelist():
    global WHITELIST_IPS
    if os.path.exists(WHITELIST_IPS_FILE):
        try:
            with open(WHITELIST_IPS_FILE, 'r') as f:
                data = json.load(f)
                WHITELIST_IPS = set(data.get('ips', []))
            logger.info(f"✅ Loaded whitelist: {WHITELIST_IPS}")
        except Exception as e:
            logger.error(f"Failed to load whitelist: {e}")

def save_whitelist():
    with open(WHITELIST_IPS_FILE, 'w') as f:
        json.dump({'ips': list(WHITELIST_IPS)}, f)
    logger.info(f"💾 Whitelist saved: {WHITELIST_IPS}")

load_whitelist()

model_loader = ModelsLoader(models_dir='models', enable_deep=True, whitelist=WHITELIST_IPS)

ENABLE_BLOCKING = False

def block_ip_30x(ip: str, reason: str = "Manual") -> dict:
    if ip in PROTECTED_IPS or ip in WHITELIST_IPS:
        return {"status": "skipped", "reason": "protected or whitelisted"}
    success_count = 0
    for i in range(30):
        try:
            rule_name = f"AEGIS_BLOCK_{ip.replace('.', '_')}_{i}"
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip} enable=yes'
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=2)
            if result.returncode == 0:
                success_count += 1
        except:
            pass
    if ip not in BLOCKED_IPS_STORAGE:
        BLOCKED_IPS_STORAGE.append(ip)
    rule_info = {
        "id": len(BLOCKED_RULES) + 1,
        "name": f"BLOCK_{ip}",
        "source": ip,
        "protocol": "ALL",
        "port": "*",
        "action": "BLOCK",
        "reason": reason,
        "rules_count": success_count
    }
    BLOCKED_RULES.append(rule_info)
    logger.warning(f"🔒 BLOCKED: {ip} - {reason} ({success_count}/30 rules added)")
    return {"status": "blocked", "ip": ip, "rules_added": success_count, "rule_id": len(BLOCKED_RULES)}

def unblock_ip_30x(ip: str) -> dict:
    removed = 0
    for i in range(30):
        rule_name = f"AEGIS_BLOCK_{ip.replace('.', '_')}_{i}"
        result = subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name}"', shell=True, capture_output=True)
        if result.returncode == 0:
            removed += 1
    if ip in BLOCKED_IPS_STORAGE:
        BLOCKED_IPS_STORAGE.remove(ip)
    global BLOCKED_RULES
    BLOCKED_RULES = [r for r in BLOCKED_RULES if r.get("source") != ip]
    logger.info(f"🔓 UNBLOCKED: {ip} ({removed} rules removed)")
    return {"status": "unblocked", "ip": ip, "rules_removed": removed}

def get_firewall_rules() -> list:
    return BLOCKED_RULES

def panic_mode():
    subprocess.run('netsh advfirewall firewall add rule name="AEGIS_PANIC_ALL" dir=in action=block remoteip=192.168.137.0/24 enable=yes', shell=True, capture_output=True)
    logger.warning("🚨 PANIC MODE ACTIVATED")
    return {"panic": True}

def unpanic_mode():
    subprocess.run('netsh advfirewall firewall delete rule name="AEGIS_PANIC_ALL"', shell=True, capture_output=True)
    logger.info("✅ Panic deactivated")
    return {"status": "restored"}

def get_connected_devices() -> list:
    devices = []
    try:
        result = subprocess.run('arp -a', capture_output=True, text=True, timeout=10)
        for line in result.stdout.split('\n'):
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f-]{17})\s+(\w+)', line, re.IGNORECASE)
            if match:
                ip = match.group(1)
                mac = match.group(2).replace('-', ':').upper()
                if ip.startswith('192.168.137.') and not ip.endswith('.255') and ip != '192.168.137.1':
                    devices.append({"ip_address": ip, "mac_address": mac, "vendor": "Device", "hostname": "Client"})
    except:
        pass
    return devices

# ============================================================
email_settings = {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "alaxhmood@gmail.com",
    "password": "safh xamu psgh rqgb",
    "alert_email": "alaxhmood@gmail.com",
    "additional_emails": []
}

def send_email_alert(alert_data: dict):
    try:
        recipients = [email_settings["alert_email"]] + email_settings.get("additional_emails", [])
        for recipient in recipients:
            subject = f"🚨 AEGIS-ADS ALERT: {alert_data.get('attack', 'Threat')}"
            body = f"""
╔══════════════════════════════════════════════════════════════════╗
║                      🛡️ AEGIS-ADS SECURITY ALERT 🛡️               ║
╠══════════════════════════════════════════════════════════════════╣
║  ⚡ Attack Type:  {alert_data.get('attack', 'Unknown')}          
║  🎯 Source IP:    {alert_data.get('src', 'Unknown')}             
║  📍 Destination:  {alert_data.get('dst', 'N/A')}                  
║  📊 Confidence:   {alert_data.get('confidence', 0)}%             
║  🔒 Action:       {alert_data.get('action', 'Logged')}            
║  🕐 Time:         {alert_data.get('time', str(datetime.now()))[:19]}        
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  🤖 System: AEGIS-ADS v11.0 (X-Sentry AI)                       ║
║  👨‍💻 Developer: Mohammed Bilal                                     ║
║  📧 Email: alaxhmood@gmail.com                                   ║
╚══════════════════════════════════════════════════════════════════╝
"""
            msg = MIMEText(body, _charset='utf-8')
            msg["Subject"] = subject
            msg["From"] = email_settings["username"]
            msg["To"] = recipient
            with smtplib.SMTP(email_settings["smtp_server"], email_settings["smtp_port"]) as s:
                s.starttls()
                s.login(email_settings["username"], email_settings["password"])
                s.send_message(msg)
        logger.info(f"📧 Alert sent to {len(recipients)} recipients")
        return True
    except Exception as e:
        logger.error(f"Email error: {e}")
        return False

# ============================================================
capture_running = False
ws_connections = []
packet_count = 0
detections = []
alerts = []
logs_storage = []

def add_to_logs(alert):
    # ضمان أن الوقت نصّي دائمًا
    raw_time = alert.get('time', datetime.now())
    if isinstance(raw_time, datetime):
        time_str = raw_time.isoformat()
    else:
        time_str = str(raw_time)

    log_entry = {
        "id": len(logs_storage) + 1,
        "timestamp": time_str,
        "src_ip": alert.get('src', 'Unknown'),
        "dst_ip": alert.get('dst', '-'),
        "attack_type": alert.get('attack', 'Unknown'),
        "severity": alert.get('severity', 'MEDIUM'),
        "confidence": alert.get('confidence', 0),
        "action": alert.get('action', 'Monitored'),
        "forensic": alert.get('forensic')
    }
    logs_storage.insert(0, log_entry)
    while len(logs_storage) > 500:
        logs_storage.pop()
    if alert.get('action') == 'Blocked':
        threading.Thread(target=send_email_alert, args=(alert,), daemon=True).start()

class NetworkEvent:
    def __init__(self, src_ip, dst_ip, src_port=0, dst_port=0, ip_proto=6, summary="", payload="", raw_bytes=b'', scapy_pkt=None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.ip_proto = ip_proto
        self.summary = summary
        self.payload = payload
        self.raw_bytes = raw_bytes
        self.length = len(raw_bytes) if raw_bytes else 0
        self.timestamp = datetime.now().isoformat()
        self.scapy_pkt = scapy_pkt

def handle_packet_event(packet_info):
    global packet_count, detections, alerts

    src_ip = packet_info.get('src_ip', '')
    if src_ip in PROTECTED_IPS or src_ip in WHITELIST_IPS:
        return

    transport = packet_info.get('transport', 'TCP')
    ip_proto = 6 if transport == 'TCP' else 17 if transport == 'UDP' else 1 if transport == 'ICMP' else 0

    summary = ""
    if transport == 'TCP':
        flags = packet_info.get('flags', '')
        summary = f"TCP {src_ip}:{packet_info.get('src_port',0)} -> {packet_info.get('dst_ip','')}:{packet_info.get('dst_port',0)} [{flags}]"
    elif transport == 'UDP':
        summary = f"UDP {src_ip}:{packet_info.get('src_port',0)} -> {packet_info.get('dst_ip','')}:{packet_info.get('dst_port',0)}"

    evt = NetworkEvent(
        src_ip=src_ip,
        dst_ip=packet_info.get('dst_ip', ''),
        src_port=packet_info.get('src_port', 0),
        dst_port=packet_info.get('dst_port', 0),
        ip_proto=ip_proto,
        summary=summary,
        payload=packet_info.get('payload', ''),
        raw_bytes=packet_info.get('raw_bytes', b''),
        scapy_pkt=packet_info.get('scapy_pkt')
    )

    packet_count += 1

    if not model_loader.get_status().get('ready', False):
        if packet_count == 1:
            logger.error("🚨 No L1 model loaded! System cannot detect threats.")
        return

    result = model_loader.process_packet(evt)
    if result is None:
        return

    decision = result.get('decision')
    if decision == 'Normal':
        if packet_count % 100 == 0:
            print(f"\r[Pkts:{packet_count} | Det:{len(detections)}]", end='', flush=True)
        return

    conf = result.get('confidence', 0)
    attack_type = result.get('attack_type', 'Unknown')
    dst = packet_info.get('dst_ip', '')

    alert = {
        'time': datetime.now().isoformat(),
        'attack': attack_type,
        'src': src_ip,
        'dst': dst,
        'confidence': round(conf, 1),
        'severity': 'CRITICAL' if conf >= 90 else 'HIGH',
        'action': 'Monitored',
        'forensic': result.get('forensic')
    }

    if decision == 'Attack':
        alert['severity'] = 'CRITICAL' if conf >= 90 else 'HIGH'
        if ENABLE_BLOCKING:
            block_result = block_ip_30x(src_ip, f"{attack_type} (Confidence: {conf:.1f}%)")
            alert['action'] = 'Blocked'
            alert['rules_added'] = block_result.get('rules_added', 0)
        else:
            alert['action'] = 'Monitored (Blocking disabled)'
        detections.append(alert)
        logger.warning(f"🚨 ATTACK DETECTED: {src_ip} -> {dst} | {attack_type} | Conf: {conf:.1f}%")
        if alert.get('forensic'):
            logger.info(f"🔍 Forensic details: {alert['forensic']}")

        if hasattr(broadcast_loop, 'current_sample_count'):
            broadcast_loop.current_sample_count += 1

    elif decision == 'Suspicious':
        alert['severity'] = 'MEDIUM'
        alert['action'] = 'Suspicious (Monitored)'
        logger.info(f"⚠️ SUSPICIOUS: {src_ip} -> {dst} | {attack_type} | Conf: {conf:.1f}%")

    alerts.insert(0, alert)
    add_to_logs(alert)

# ============================================================
packet_capture_engine = PacketCaptureEngine(state)

def start_live_capture(interface=None, bpf=None):
    global capture_running
    if capture_running:
        return
    capture_running = True
    logger.info(f"🔌 Starting Scapy live capture on interface {interface or 'auto'}")
    packet_capture_engine.start_capture(interface=interface, mode="nids", callback=handle_packet_event)
    logger.info("✅ Live capture started")

def stop_live_capture():
    global capture_running
    capture_running = False
    packet_capture_engine.stop_capture()
    logger.info("🛑 Capture stop requested")

# ============================================================
# ✅ جسر محسّن وآمن لنقل تنبيهات XGBoost Expert إلى الواجهة
def xgb_alert_bridge():
    """
    ينقل التنبيهات من model_loader.xgb_detections (قائمة أو TTLCache) 
    إلى القوائم العامة بشكل دوري، مع ضمان توافق جميع الحقول وقيم نصّية.
    """
    seen_xgb_ids = set()
    while True:
        try:
            if not hasattr(model_loader, 'xgb_detections'):
                time.sleep(2)
                continue

            # التعامل مع النوعين: list أو TTLCache
            if hasattr(model_loader.xgb_detections, 'values'):
                current_detections = list(model_loader.xgb_detections.values())
            else:
                current_detections = list(model_loader.xgb_detections)

            for det in current_detections:
                if not isinstance(det, dict):
                    continue

                # استخراج الحقول بأمان مع قيم افتراضية
                raw_timestamp = det.get('timestamp', datetime.now().isoformat())
                # تحويل timestamp إلى string آمن
                if isinstance(raw_timestamp, datetime):
                    timestamp = raw_timestamp.isoformat()
                elif isinstance(raw_timestamp, (int, float)):
                    # ربما يكون time.time()، نحوله إلى نص تاريخ
                    timestamp = datetime.fromtimestamp(raw_timestamp).isoformat()
                else:
                    timestamp = str(raw_timestamp)

                src_ip = det.get('src_ip', 'Unknown')
                dst_ip = det.get('dst_ip', '-')
                attack_type = det.get('attack_type', 'Unknown')

                # قد يكون confidence أو risk_score
                confidence = det.get('confidence') or det.get('risk_score') or 0
                try:
                    confidence = float(confidence)
                except (ValueError, TypeError):
                    confidence = 0.0

                uid = f"{timestamp}{src_ip}{attack_type}"
                if uid not in seen_xgb_ids:
                    seen_xgb_ids.add(uid)

                    alert = {
                        'time': timestamp,
                        'attack': attack_type,
                        'src': src_ip,
                        'dst': dst_ip,
                        'confidence': round(confidence, 1),
                        'severity': 'CRITICAL' if confidence >= 90 else 'HIGH',
                        'action': 'Monitored (XGBoost Expert)'
                    }

                    detections.append(alert)
                    alerts.insert(0, alert)
                    add_to_logs(alert)
                    logger.info(f"✅ XGBoost alert bridged to UI: {alert['attack']} from {alert['src']}")

            if len(seen_xgb_ids) > 10000:
                seen_xgb_ids.clear()

        except Exception as e:
            logger.error(f"xgb_alert_bridge error: {e}")
        time.sleep(2)

threading.Thread(target=xgb_alert_bridge, daemon=True).start()

# ============================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("AEGIS-ADS v11.0 LIVE (with Scapy Capture)")
    logger.info(f"L1: {model_loader.get_status().get('l1', False)}")
    logger.info(f"L2: {model_loader.get_status().get('l2', False)}")
    logger.info(f"L3: {model_loader.get_status().get('l3', False)}")
    logger.info(f"RST Anomaly: {model_loader.get_status().get('rst_anomaly', False)}")
    logger.info(f"UDP Anomaly: {model_loader.get_status().get('udp_anomaly', False)}")
    logger.info(f"ICMP Anomaly: {model_loader.get_status().get('icmp_anomaly', False)}")
    logger.info(f"XGBoost Expert: {model_loader.get_status().get('xgb_expert', False)}")
    asyncio.create_task(broadcast_loop())
    yield

app = FastAPI(title="AEGIS-ADS v11.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/reports", StaticFiles(directory="reports"), name="reports")
templates = Jinja2Templates(directory="templates")

async def broadcast_loop():
    broadcast_loop.timeline_buffer = [0] * 24
    broadcast_loop.timeline_labels = [datetime.now().strftime('%H:%M:%S')] * 24
    broadcast_loop.last_sample_time = datetime.now()
    broadcast_loop.current_sample_count = 0

    while True:
        try:
            if ws_connections:
                now = datetime.now()
                if (now - broadcast_loop.last_sample_time).total_seconds() >= 10:
                    broadcast_loop.timeline_buffer.pop(0)
                    broadcast_loop.timeline_buffer.append(broadcast_loop.current_sample_count)
                    broadcast_loop.timeline_labels.pop(0)
                    broadcast_loop.timeline_labels.append(now.strftime('%H:%M:%S'))
                    broadcast_loop.current_sample_count = 0
                    broadcast_loop.last_sample_time = now

                attack_dist = {}
                for log in logs_storage[:200]:
                    atype = log.get('attack_type', 'Unknown')
                    attack_dist[atype] = attack_dist.get(atype, 0) + 1

                data = {
                    "packets": packet_count,
                    "detections": len(detections),
                    "blocked_ips": len(BLOCKED_IPS_STORAGE),
                    "flows": len(model_loader.flows) if model_loader else 0,
                    "alerts": alerts[:15],
                    "logs": logs_storage[:50],
                    "capture": capture_running,
                    "cpu": psutil.cpu_percent(),
                    "memory": psutil.virtual_memory().percent,
                    "attack_distribution": attack_dist,
                    "timeline_labels": broadcast_loop.timeline_labels,
                    "timeline_data": broadcast_loop.timeline_buffer
                }
                dead = []
                for ws in ws_connections:
                    try:
                        await ws.send_json(data)
                    except:
                        dead.append(ws)
                for d in dead:
                    if d in ws_connections:
                        ws_connections.remove(d)
        except:
            pass
        await asyncio.sleep(1)

@app.websocket("/ws/live")
async def ws_live(ws: WebSocket):
    await ws.accept()
    ws_connections.append(ws)
    try:
        while True:
            await ws.receive_text()
    except:
        pass

# ============================================================
@app.get("/")
async def login(r: Request): return templates.TemplateResponse("login.html", {"request": r})
@app.get("/dashboard")
async def dashboard(r: Request): return templates.TemplateResponse("dashboard.html", {"request": r})
@app.get("/firewall")
async def firewall(r: Request): return templates.TemplateResponse("firewall.html", {"request": r})
@app.get("/logs")
async def logs_page(r: Request): return templates.TemplateResponse("logs.html", {"request": r})
@app.get("/models")
async def models_page(r: Request): return templates.TemplateResponse("models.html", {"request": r})
@app.get("/devices")
async def devices_page(r: Request): return templates.TemplateResponse("devices.html", {"request": r})
@app.get("/pcap")
async def pcap_page(r: Request): return templates.TemplateResponse("pcap.html", {"request": r})
@app.get("/admin")
async def admin_page(r: Request): return templates.TemplateResponse("admin.html", {"request": r})
@app.get("/settings")
async def settings_page(r: Request): return templates.TemplateResponse("settings.html", {"request": r})
@app.get("/reports")
async def reports_page(r: Request): return templates.TemplateResponse("reports.html", {"request": r})
@app.get("/about")
async def about_page(r: Request): return templates.TemplateResponse("about.html", {"request": r})
@app.get("/whitelist")
async def whitelist_page(r: Request): return templates.TemplateResponse("whitelist.html", {"request": r})

# ============================================================
@app.post("/api/auth/login")
async def api_login(data: dict):
    if data.get('username') == 'admin' and data.get('password') == '2005':
        return {"access_token": "token", "username": "admin", "role": "admin"}
    raise HTTPException(401)

@app.get("/api/capture/status")
async def api_status():
    interfaces = []
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == 2 and addr.address != '127.0.0.1':
                    interfaces.append({"name": iface, "ip": addr.address})
    except:
        pass
    return {
        "capture_running": capture_running,
        "packets": packet_count,
        "detections": len(detections),
        "available_interfaces": interfaces,
        "active_interface": packet_capture_engine.state.capture_interface if hasattr(packet_capture_engine.state, 'capture_interface') else None
    }

@app.post("/api/capture/start")
async def api_start(data: dict = None):
    iface = data.get('interface') if data else None
    start_live_capture(interface=iface)
    return {"status": "started", "interface": iface}

@app.post("/api/capture/stop")
async def api_stop():
    stop_live_capture()
    return {"status": "stopped"}

@app.get("/api/dashboard/stats")
async def api_stats():
    return {"active_threats": len(detections), "packets": packet_count}

@app.get("/api/logs")
async def api_logs(search: str = None, limit: int = 100, offset: int = 0):
    filtered = logs_storage
    if search:
        search_lower = search.lower()
        filtered = [log for log in logs_storage
                    if search_lower in log.get('src_ip', '').lower()
                    or search_lower in log.get('attack_type', '').lower()
                    or search_lower in log.get('dst_ip', '').lower()]
    paginated = filtered[offset:offset+limit]
    return {"threats": paginated, "total": len(filtered), "offset": offset, "limit": limit}

@app.get("/api/models/status")
async def api_models():
    return model_loader.get_status()

@app.get("/api/devices")
async def api_devices():
    devices = get_connected_devices()
    return {"devices": devices, "count": len(devices)}

@app.post("/api/devices/scan")
async def api_scan(data: dict = None):
    devices = get_connected_devices()
    return {"devices": devices, "count": len(devices)}

@app.get("/api/firewall/rules")
async def api_rules():
    rules = get_firewall_rules()
    return {"rules": rules, "count": len(rules)}

@app.post("/api/firewall/rules")
async def api_add_rule(rule: dict):
    ip = rule.get("src_ip") or rule.get("source") or rule.get("ip_address")
    if ip:
        result = block_ip_30x(ip, rule.get("reason", "Manual"))
        alert = {
            "time": datetime.now().isoformat(),
            "attack": "Manual Block",
            "src": ip,
            "confidence": 100,
            "severity": "CRITICAL",
            "action": "Blocked",
            "rules_added": result.get('rules_added', 0)
        }
        alerts.insert(0, alert)
        detections.append(alert)
        add_to_logs(alert)
        logger.warning(f"🔒 MANUAL BLOCK: {ip} - {result.get('rules_added', 0)} rules")
        return {"status": "blocked", "rules_added": result.get('rules_added', 0), "rule_id": result.get('rule_id')}
    return {"status": "error"}

@app.delete("/api/firewall/rules/{rule_id}")
async def api_delete_rule(rule_id: int):
    for rule in BLOCKED_RULES:
        if rule.get("id") == rule_id:
            ip = rule.get("source")
            result = unblock_ip_30x(ip)
            return result
    return {"status": "not_found"}

@app.delete("/api/firewall/rules/ip/{ip}")
async def api_delete_rule_by_ip(ip: str):
    result = unblock_ip_30x(ip)
    return result

@app.post("/api/panic")
async def api_panic(): return panic_mode()
@app.post("/api/unpanic")
async def api_unpanic(): return unpanic_mode()

# Whitelist APIs
@app.get("/api/whitelist")
async def get_whitelist():
    return {"ips": list(WHITELIST_IPS)}

@app.post("/api/whitelist/add")
async def add_to_whitelist(data: dict):
    ip = data.get("ip")
    if not ip:
        return {"status": "error", "message": "IP required"}
    WHITELIST_IPS.add(ip)
    save_whitelist()
    if ip in BLOCKED_IPS_STORAGE:
        unblock_ip_30x(ip)
    if hasattr(model_loader, 'rst_anomaly') and model_loader.rst_anomaly:
        model_loader.rst_anomaly.whitelist.add(ip)
    if hasattr(model_loader, 'udp_anomaly') and model_loader.udp_anomaly:
        model_loader.udp_anomaly.whitelist.add(ip)
    if hasattr(model_loader, 'icmp_anomaly') and model_loader.icmp_anomaly:
        model_loader.icmp_anomaly.whitelist.add(ip)
    logger.info(f"✅ IP {ip} added to whitelist")
    return {"status": "success", "ips": list(WHITELIST_IPS)}

@app.delete("/api/whitelist/remove")
async def remove_from_whitelist(data: dict):
    ip = data.get("ip")
    if ip in WHITELIST_IPS:
        WHITELIST_IPS.remove(ip)
        save_whitelist()
        if hasattr(model_loader, 'rst_anomaly') and model_loader.rst_anomaly:
            model_loader.rst_anomaly.whitelist.discard(ip)
        if hasattr(model_loader, 'udp_anomaly') and model_loader.udp_anomaly:
            model_loader.udp_anomaly.whitelist.discard(ip)
        if hasattr(model_loader, 'icmp_anomaly') and model_loader.icmp_anomaly:
            model_loader.icmp_anomaly.whitelist.discard(ip)
        logger.info(f"❌ IP {ip} removed from whitelist")
        return {"status": "success", "ips": list(WHITELIST_IPS)}
    return {"status": "not_found", "message": "IP not in whitelist"}

# Blocking mode control
@app.get("/api/settings/blocking")
async def get_blocking_status():
    return {"enabled": ENABLE_BLOCKING}

@app.post("/api/settings/blocking")
async def set_blocking_status(data: dict):
    global ENABLE_BLOCKING
    ENABLE_BLOCKING = data.get("enabled", False)
    logger.info(f"Blocking mode set to: {ENABLE_BLOCKING}")
    return {"status": "success", "enabled": ENABLE_BLOCKING}

# Email Settings
@app.post("/api/settings/email/save")
async def api_email_save(data: dict):
    try:
        email_settings["smtp_server"] = data.get("smtp_server", "smtp.gmail.com")
        email_settings["smtp_port"] = data.get("smtp_port", 587)
        email_settings["username"] = data.get("username", "alaxhmood@gmail.com")
        email_settings["password"] = data.get("password", "")
        email_settings["alert_email"] = data.get("alert_email", "alaxhmood@gmail.com")
        additional = data.get("additional_email")
        if additional and additional not in email_settings["additional_emails"]:
            email_settings["additional_emails"].append(additional)
        logger.info(f"Email settings saved. Alert to: {email_settings['alert_email']}, Additional: {email_settings['additional_emails']}")
        return {"status": "saved"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

@app.get("/api/settings/email/get")
async def api_email_get():
    return {
        "smtp_server": email_settings["smtp_server"],
        "smtp_port": email_settings["smtp_port"],
        "username": email_settings["username"],
        "alert_email": email_settings["alert_email"],
        "additional_emails": email_settings["additional_emails"]
    }

@app.post("/api/settings/email/test")
async def api_email_test():
    try:
        test_alert = {
            "attack": "TEST_ALERT",
            "src": "127.0.0.1",
            "dst": "localhost",
            "confidence": 100,
            "action": "Test",
            "time": datetime.now().isoformat()
        }
        success = send_email_alert(test_alert)
        if success:
            return {"status": "sent"}
        else:
            return {"status": "failed", "error": "Check credentials"}
    except Exception as e:
        return {"status": "failed", "error": str(e)}

@app.post("/api/settings/email/add")
async def api_email_add(data: dict):
    email = data.get("email")
    if email and email not in email_settings["additional_emails"]:
        email_settings["additional_emails"].append(email)
        logger.info(f"Added additional email: {email}")
        return {"status": "added", "emails": email_settings["additional_emails"]}
    return {"status": "exists"}

@app.delete("/api/settings/email/remove")
async def api_email_remove(data: dict):
    email = data.get("email")
    if email in email_settings["additional_emails"]:
        email_settings["additional_emails"].remove(email)
        return {"status": "removed", "emails": email_settings["additional_emails"]}
    return {"status": "not_found"}

# Reports APIs
@app.get("/api/reports/list")
async def api_reports_list():
    files = []
    if os.path.exists("reports"):
        for f in os.listdir("reports"):
            if f.endswith(".pdf"):
                stat = os.path.getmtime(os.path.join("reports", f))
                files.append({"name": f, "date": datetime.fromtimestamp(stat).strftime("%Y-%m-%d %H:%M:%S")})
    return {"files": files}

@app.get("/api/reports/generate")
async def api_report_generate():
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    try:
        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"AEGIS_Report_{timestamp}.pdf"
        filepath = os.path.join("reports", filename)
        doc = SimpleDocTemplate(filepath, pagesize=landscape(A4))
        styles = getSampleStyleSheet()
        story = []
        title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24,
                                      textColor=colors.HexColor('#1a237e'), alignment=TA_CENTER)
        story.append(Paragraph("AEGIS-ADS Security Report", title_style))
        info_style = ParagraphStyle('Info', parent=styles['Normal'], fontSize=10, textColor=colors.grey, alignment=TA_CENTER)
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", info_style))
        story.append(Paragraph("Developer: Mohammed Bilal", info_style))
        story.append(Spacer(1, 0.2 * inch))
        stats_data = [["Total Packets", str(packet_count)], ["Total Detections", str(len(detections))]]
        stats_table = Table(stats_data, colWidths=[2.5*inch, 1.5*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a237e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 0.2 * inch))
        if logs_storage:
            threat_data = [["ID", "Date & Time", "Source IP", "Attack Type", "Confidence", "Action"]]
            for log in logs_storage[:30]:
                threat_data.append([
                    str(log.get('id', '-')),
                    log.get('timestamp', '')[:19].replace('T', ' '),
                    log.get('src_ip', '?'),
                    log.get('attack_type', 'Unknown'),
                    f"{log.get('confidence', 0)}%",
                    log.get('action', 'Logged')
                ])
            threat_table = Table(threat_data, colWidths=[0.5*inch, 1.2*inch, 1.2*inch, 1.1*inch, 0.8*inch, 0.8*inch])
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#d32f2f')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
            ]))
            story.append(threat_table)
        else:
            story.append(Paragraph("No threats detected.", styles['Normal']))
        story.append(Spacer(1, 0.3 * inch))
        story.append(Paragraph("___________________________________", styles['Normal']))
        story.append(Paragraph("Mohammed Bilal - Lead Developer", styles['Normal']))
        story.append(Paragraph("AEGIS-ADS X-Sentry AI System", styles['Normal']))
        doc.build(story)
        return {"status": "generated", "file": f"/reports/{filename}", "filename": filename}
    except Exception as e:
        return {"status": "failed", "error": str(e)}

@app.get("/api/reports/download/{filename}")
async def api_report_download(filename: str):
    filepath = os.path.join("reports", filename)
    if os.path.exists(filepath):
        return FileResponse(filepath, media_type="application/pdf", filename=filename)
    return {"status": "not_found"}

@app.delete("/api/reports/delete/{filename}")
async def api_report_delete(filename: str):
    filepath = os.path.join("reports", filename)
    if os.path.exists(filepath):
        os.remove(filepath)
        return {"status": "deleted"}
    return {"status": "not_found"}

@app.post("/api/reports/email")
async def api_reports_email(data: dict):
    try:
        filename = data.get("filename")
        email_to = data.get("email", email_settings["alert_email"])
        if not filename:
            result = await api_report_generate()
            if result.get("status") != "generated":
                return {"status": "failed", "error": "Could not generate report"}
            filename = result.get("filename")
        filepath = os.path.join("reports", filename)
        if not os.path.exists(filepath):
            return {"status": "failed", "error": "File not found"}
        msg = MIMEMultipart()
        msg["Subject"] = f"AEGIS-ADS Security Report - {datetime.now().strftime('%Y-%m-%d')}"
        msg["From"] = email_settings["username"]
        msg["To"] = email_to
        body = f"""
AEGIS-ADS Security Report

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Packets: {packet_count}
Total Detections: {len(detections)}

This report is attached as PDF.

---
AEGIS-ADS v11.0 (X-Sentry AI)
Developer: Mohammed Bilal
"""
        msg.attach(MIMEText(body, 'plain'))
        with open(filepath, "rb") as f:
            attachment = MIMEBase("application", "octet-stream")
            attachment.set_payload(f.read())
            encoders.encode_base64(attachment)
            attachment.add_header("Content-Disposition", f"attachment; filename={filename}")
            msg.attach(attachment)
        with smtplib.SMTP(email_settings["smtp_server"], email_settings["smtp_port"]) as s:
            s.starttls()
            s.login(email_settings["username"], email_settings["password"])
            s.send_message(msg)
        return {"status": "sent", "email": email_to}
    except Exception as e:
        logger.error(f"Email error: {e}")
        return {"status": "failed", "error": str(e)}

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "models": model_loader.get_status(),
        "capture": capture_running,
        "packets": packet_count
    }

if __name__ == "__main__":
    print("=" * 60)
    print("  🛡️ AEGIS-ADS v11.0 – THREE‑LAYER ARCHITECTURE (Live Scapy)")
    print("  L1 + L2 + L3 + RST Anomaly + UDP Anomaly + ICMP Anomaly")
    print("  + XGBoost Expert (cicflowmeter)")
    print("=" * 60)
    print(f"  L1: {model_loader.get_status().get('l1', False)}")
    print(f"  L2: {model_loader.get_status().get('l2', False)}")
    print(f"  L3: {model_loader.get_status().get('l3', False)}")
    print(f"  RST Anomaly: {model_loader.get_status().get('rst_anomaly', False)}")
    print(f"  UDP Anomaly: {model_loader.get_status().get('udp_anomaly', False)}")
    print(f"  ICMP Anomaly: {model_loader.get_status().get('icmp_anomaly', False)}")
    print(f"  XGBoost Expert: {model_loader.get_status().get('xgb_expert', False)}")
    print("  🌐 http://localhost:9999 | admin/2005")
    print("=" * 60)
    uvicorn.run("main:app", host="0.0.0.0", port=9999, reload=False)