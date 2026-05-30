"""
AEGIS-ADS v11.0 - FINAL FIXED VERSION
"""
import sys, os, time, threading, smtplib, asyncio, psutil, subprocess, json, re
from datetime import datetime
from collections import defaultdict
from contextlib import asynccontextmanager
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fastapi import FastAPI, Request, WebSocket, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import uvicorn, logging

from core.models_loader import UnifiedModelLoader
from core.feature_extractor import FeatureExtractor
from core.global_state import GlobalState
from core.firewall_manager import block_ip_v2, unblock_ip, panic_button, unpanic, get_connected_devices
from core.active_response import aggressive_response, get_mac_from_ip
from core.trust_engine import trust_engine
import config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("AEGIS")
state = GlobalState()
model_loader = UnifiedModelLoader()
feature_extractor = FeatureExtractor()

capture_running = False
ws_connections = []
packet_count = 0
detections = []
alerts = []
logs_storage = []
LOCAL_IPS = {'127.0.0.1', '192.168.8.5', '192.168.8.1', '192.168.8.15', '192.168.137.1'}
ping_tracker = defaultdict(lambda: {'count': 0, 'start': time.time()})
port_tracker = defaultdict(lambda: {'ports': set(), 'start': time.time()})


def send_automated_alert(alert_data):
    try:
        em = config.EMAIL_CONFIG
        body = f"""
AEGIS-ADS SECURITY ALERT
------------------------
Attack: {alert_data.get('attack', 'Unknown')}
Source IP: {alert_data.get('src', 'Unknown')}
Confidence: {alert_data.get('confidence', 0)}%
Action: {alert_data.get('action', 'Logged')}
Time: {alert_data.get('time', str(datetime.now()))}
------------------------
System: AEGIS-ADS v11.0 | Developer: Mohammed Bilal
"""
        msg = MIMEText(body, _charset='utf-8')
        msg["Subject"] = f"ALERT: {alert_data.get('attack', 'Threat')}"
        msg["From"] = em["username"]
        msg["To"] = em["alert_email"]
        with smtplib.SMTP(em["smtp_server"], em["smtp_port"]) as s:
            s.starttls()
            s.login(em["username"], em["password"])
            s.send_message(msg)
        logger.info("Email sent")
    except Exception as e:
        logger.error(f"Email error: {e}")


def add_to_logs(alert):
    log_entry = {
        "id": len(logs_storage) + 1,
        "timestamp": alert.get('time', datetime.now().isoformat()),
        "src_ip": alert.get('src', 'Unknown'),
        "dst_ip": alert.get('dst', '-'),
        "protocol": alert.get('protocol', 'TCP'),
        "port": alert.get('port', '-'),
        "attack_type": alert.get('attack', 'Unknown'),
        "severity": alert.get('severity', 'MEDIUM'),
        "confidence": alert.get('confidence', 0),
        "action": alert.get('action', 'Logged')
    }
    logs_storage.insert(0, log_entry)
    while len(logs_storage) > 500:
        logs_storage.pop()


def process_tshark_line(line):
    global packet_count, detections, alerts
    try:
        parts = line.strip().split('\t')
        if len(parts) < 3:
            return
        
        src = parts[0].strip()
        dst = parts[1].strip()
        length = int(parts[2].strip())
        
        # Fix double IP issue
        if ',' in src:
            src = src.split(',')[0]
        if ',' in dst:
            dst = dst.split(',')[0]
        
        # تحديث عداد الحزم
        packet_count += 1
        now = time.time()  # تعريف المتغير now هنا
        
        # ICMP Flood Detection - 10 pings
        if length < 200 and src.startswith('192.168.137.'):
            t = ping_tracker[src]
            t['count'] += 1
            
            if t['count'] >= 10 and (now - t['start']) < 3:
                mac = get_mac_from_ip(src)
                result = block_ip_v2(src, f'ICMP Flood ({t["count"]} pings)')
                
                alert = {
                    'time': datetime.now().isoformat(),
                    'attack': 'ICMP-Flood',
                    'src': src,
                    'dst': dst,
                    'mac': mac,
                    'confidence': 95.0,
                    'severity': 'CRITICAL',
                    'action': 'Blocked',
                    'protocol': 'ICMP'
                }
                alerts.insert(0, alert)
                detections.append(alert)
                add_to_logs(alert)
                logger.warning(f"ICMP FLOOD: {src} -> BLOCKED")
                
                if trust_engine.can_send_email(src):
                    threading.Thread(target=send_automated_alert, args=(alert,), daemon=True).start()
                
                t['count'] = 0
                t['start'] = now
        
        # عرض التقدم كل 50 حزمة
        if packet_count % 50 == 0:
            print(f"\r[Pkts:{packet_count} | Det:{len(detections)}]", end='', flush=True)
            
    except Exception as e:
        logger.error(f"Process error: {e}")


def start_tshark_capture():
    global capture_running
    capture_running = True
    def loop():
        proc = subprocess.Popen(
            ['tshark', '-i', '4', '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'frame.len', '-l'],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1
        )
        for line in proc.stdout:
            if not capture_running:
                break
            if line.strip():
                process_tshark_line(line)
        proc.terminate()
    threading.Thread(target=loop, daemon=True).start()
    logger.info("Tshark capture started on interface 4")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("AEGIS-ADS v11.0 LIVE")
    asyncio.create_task(broadcast_loop())
    yield


app = FastAPI(title="AEGIS-ADS v11.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/reports", StaticFiles(directory="reports"), name="reports")
templates = Jinja2Templates(directory="templates")


async def broadcast_loop():
    while True:
        try:
            if ws_connections:
                data = {
                    "packets": packet_count,
                    "detections": len(detections),
                    "alerts": alerts[:15],
                    "logs": logs_storage[:50],
                    "capture": capture_running,
                    "cpu": psutil.cpu_percent(),
                    "memory": psutil.virtual_memory().percent,
                    "timestamp": datetime.now().isoformat()
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
        except Exception as e:
            logger.error(f"Broadcast error: {e}")
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


# Pages
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


# APIs
@app.post("/api/auth/login")
async def api_login(data: dict):
    if data.get('username') == 'admin' and data.get('password') == '2005':
        return {"access_token": "token", "username": "admin", "role": "admin"}
    raise HTTPException(401)

@app.get("/api/capture/status")
async def api_status():
    return {"capture_running": capture_running, "packets": packet_count, "detections": len(detections)}

@app.post("/api/capture/start")
async def api_start(data: dict = None):
    if not capture_running:
        start_tshark_capture()
    return {"status": "started"}

@app.post("/api/capture/stop")
async def api_stop():
    global capture_running
    capture_running = False
    return {"status": "stopped"}

@app.get("/api/dashboard/stats")
async def api_stats():
    blocked = len([a for a in alerts if a.get('action') == 'Blocked'])
    return {"active_threats": len(detections), "blocked_ips": blocked, "packets": packet_count}

@app.get("/api/logs")
async def api_logs():
    return {"threats": logs_storage[:100], "total": len(logs_storage)}

@app.get("/api/models/status")
async def api_models():
    return model_loader.get_status()

@app.get("/api/devices")
async def api_devices():
    real = get_connected_devices()
    # إضافة hostname من ARP
    for d in real:
        if d.get('hostname') == 'Unknown':
            d['hostname'] = 'Client'
    return {"devices": real, "count": len(real)}

@app.post("/api/devices/scan")
async def api_scan(data: dict = None):
    devices = get_connected_devices()
    return {"devices": devices, "count": len(devices)}

@app.get("/api/firewall/rules")
async def api_rules():
    return {"rules": [], "count": 0}

@app.post("/api/firewall/rules")
async def api_add_rule(rule: dict):
    ip = rule.get("src_ip") or rule.get("source")
    if ip:
        result = block_ip_v2(ip, rule.get("reason", "Manual"))
        alert = {
            "time": datetime.now().isoformat(),
            "attack": "Manual Block",
            "src": ip,
            "confidence": 100,
            "severity": "CRITICAL",
            "action": "Blocked"
        }
        alerts.insert(0, alert)
        detections.append(alert)
        add_to_logs(alert)
        return {"status": "blocked", "result": result}
    return {"status": "error"}

@app.post("/api/panic")
async def api_panic(): return panic_button()
@app.post("/api/unpanic")
async def api_unpanic(): return unpanic()

@app.get("/health")
async def health():
    return {"status": "ok", "models": model_loader.is_ready, "capture": capture_running, "packets": packet_count}

if __name__ == "__main__":
    print("=" * 60)
    print("  AEGIS-ADS v11.0 - FINAL VERSION")
    print("=" * 60)
    print(f"  RF={'YES' if model_loader.rf_model else 'NO'} | XGB={'YES' if model_loader.xgb_model else 'NO'}")
    print(f"  http://localhost:9999 | admin/2005")
    print("=" * 60)
    uvicorn.run("main:app", host="0.0.0.0", port=9999, reload=False)
