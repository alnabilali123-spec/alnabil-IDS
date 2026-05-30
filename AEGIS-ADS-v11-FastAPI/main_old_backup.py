"""
AEGIS-ADS v11.0 - FULL WORKING VERSION
"""
import sys, os, time, threading, smtplib, asyncio, psutil, subprocess, json, re
from datetime import datetime
from collections import defaultdict
from contextlib import asynccontextmanager
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email import encoders

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fastapi import FastAPI, Request, WebSocket, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
import uvicorn, logging

from core.models_loader import UnifiedModelLoader
from core.feature_extractor import FeatureExtractor
from core.global_state import GlobalState
from core.firewall_manager import block_ip_v2, unblock_ip, panic_button, unpanic, get_connected_devices
from core.active_response import aggressive_response, get_mac_from_ip, get_attacker_stats, clear_attacker_history
from core.trust_engine import trust_engine
from database.db_manager import DatabaseManager
import config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("AEGIS")
state = GlobalState()
model_loader = UnifiedModelLoader()
db = DatabaseManager()
feature_extractor = FeatureExtractor()

capture_running = False
ws_connections = []
packet_count = 0
detections = []
alerts = []
LOCAL_IPS = {'127.0.0.1', '192.168.8.5', '192.168.8.1', '192.168.8.15'}
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
        logger.info(f"Email sent")
    except Exception as e:
        logger.error(f"Email error: {e}")

def process_tshark_line(line):
    global packet_count, detections, alerts
    try:
        parts = line.strip().split('\t')
        if len(parts) < 3:
            return
        src = parts[0].strip()
            if ',' in src:
                src = src.split(',')[0]
            if ',' in dst:
                dst = dst.split(',')[0]
        dst = parts[1].strip()
        length = int(parts[2].strip())
        if src in LOCAL_IPS:
            return
        if not src.startswith('192.168.137.'):
            return
        packet_count += 1
        now = time.time()
        if length < 200:
            t = ping_tracker[src]
            t['count'] += 1
            if t['count'] >= 10 and (now - t['start']) < 2:
                mac = get_mac_from_ip(src)
                result = block_ip_v2(src, f'ICMP Flood ({t["count"]} pings)')
                active_result = aggressive_response(src, "ICMP-Flood", mac)
                alert = {
                    'time': datetime.now().isoformat(),
                    'attack': 'ICMP-Flood',
                    'src': src,
                    'dst': dst,
                    'mac': mac,
                    'confidence': 98.0,
                    'severity': 'CRITICAL',
                    'action': 'Blocked + Active Response',
                    'block_result': result,
                    'active_response': active_result
                }
                alerts.insert(0, alert)
                detections.append(alert)
                logger.warning(f"🌊 ICMP FLOOD + ACTIVE: {src}")
                threading.Thread(target=send_automated_alert, args=(alert,), daemon=True).start()
                t['count'] = 0
                t['start'] = now
        if packet_count % 100 == 0:
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
    logger.info("Tshark capture started")

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
        await asyncio.sleep(1)
        dead = []
        for ws in ws_connections:
            try:
                await ws.send_json({
                    "packets": packet_count,
                    "detections": len(detections),
                    "alerts": alerts[:10],
                    "capture": capture_running,
                    "cpu": psutil.cpu_percent(),
                    "memory": psutil.virtual_memory().percent
                })
            except:
                dead.append(ws)
        for d in dead:
            if d in ws_connections:
                ws_connections.remove(d)

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

# Auth API
@app.post("/api/auth/login")
async def api_login(data: dict):
    if data.get('username') == 'admin' and data.get('password') == '2005':
        return {"access_token": "token", "username": "admin", "role": "admin"}
    raise HTTPException(401)

# Capture APIs
@app.get("/api/capture/status")
async def api_status():
    interfaces = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2 and addr.address != '127.0.0.1':
                interfaces.append({"name": iface, "ip": addr.address})
    return {"capture_running": capture_running, "packets": packet_count, "detections": len(detections), "available_interfaces": interfaces}

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

# Dashboard API
@app.get("/api/dashboard/stats")
async def api_stats():
    return {"active_threats": len(detections), "blocked_ips": len([a for a in alerts if a.get('action') == 'Blocked']), "cpu": psutil.cpu_percent(), "memory": psutil.virtual_memory().percent, "packets": packet_count}

@app.get("/api/logs")
async def api_logs():
    return {"threats": detections[-100:], "total": len(detections)}

@app.get("/api/models/status")
async def api_models():
    return model_loader.get_status()

@app.get("/api/devices")
async def api_devices():
    real = get_connected_devices()
    return {"devices": [{"ip_address": d['ip'], "mac_address": d['mac'], "vendor": d['vendor']} for d in real], "count": len(real)}

@app.post("/api/devices/scan")
async def api_scan(data: dict = None):
    devices = get_connected_devices()
    return {"devices": devices, "count": len(devices)}

# Firewall APIs
@app.get("/api/firewall/rules")
async def api_rules():
    return {"rules": [], "count": 0}

@app.post("/api/firewall/rules")
async def api_add_rule(rule: dict):
    if rule.get("action") == "Block" and rule.get("src_ip"):
        result = block_ip_v2(rule["src_ip"], rule.get("reason", "Manual"))
        return {"status": "blocked", "result": result}
    return {"status": "created"}

@app.post("/api/panic")
async def api_panic():
    return panic_button()

@app.post("/api/unpanic")
async def api_unpanic():
    return unpanic()

# Attackers APIs
@app.get("/api/attackers/stats")
async def api_attackers():
    return {"attackers": get_attacker_stats(), "total": len(get_attacker_stats())}

@app.post("/api/attackers/clear")
async def api_clear_attackers(data: dict = None):
    ip = data.get("ip") if data else None
    clear_attacker_history(ip)
    return {"status": "cleared"}

# Email Settings APIs
@app.post("/api/settings/email/save")
async def api_email_save(data: dict):
    try:
        config.EMAIL_CONFIG["smtp_server"] = data.get("smtp_server", "smtp.gmail.com")
        config.EMAIL_CONFIG["smtp_port"] = data.get("smtp_port", 587)
        config.EMAIL_CONFIG["username"] = data.get("username", "alaxhmood@gmail.com")
        config.EMAIL_CONFIG["password"] = data.get("password", "")
        config.EMAIL_CONFIG["alert_email"] = data.get("alert_email", "alaxhmood@gmail.com")
        return {"status": "saved"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

@app.post("/api/settings/email/test")
async def api_email_test():
    try:
        em = config.EMAIL_CONFIG
        msg = MIMEText(f"AEGIS-ADS Test Email - {datetime.now()}", _charset='utf-8')
        msg["Subject"] = f"AEGIS-ADS Test - {datetime.now().strftime('%H:%M:%S')}"
        msg["From"] = em["username"]
        msg["To"] = em["alert_email"]
        with smtplib.SMTP(em["smtp_server"], em["smtp_port"]) as s:
            s.starttls()
            s.login(em["username"], em["password"])
            s.send_message(msg)
        return {"status": "sent"}
    except Exception as e:
        return {"status": "failed", "error": str(e)}

# Reports APIs
@app.get("/api/reports/generate")
async def api_report_generate():
    from reportlab.lib.pagesizes import A4
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
        
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24,
                                      textColor=colors.HexColor('#1a237e'), alignment=TA_CENTER, spaceAfter=30)
        story.append(Paragraph("AEGIS-ADS Security Report", title_style))
        
        info_style = ParagraphStyle('Info', parent=styles['Normal'], fontSize=10, textColor=colors.grey, alignment=TA_CENTER)
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", info_style))
        story.append(Paragraph("System: AEGIS-ADS v11.0 | Developer: Mohammed Bilal", info_style))
        story.append(Spacer(1, 0.2 * inch))
        
        story.append(Paragraph("<b>Executive Summary</b>", styles['Heading2']))
        story.append(Spacer(1, 0.1 * inch))
        
        stats_data = [
            ["Total Packets", str(packet_count)],
            ["Total Detections", str(len(detections))],
            ["Blocked IPs", str(len([a for a in alerts if a.get('action') == 'Blocked']))],
        ]
        stats_table = Table(stats_data, colWidths=[200, 100])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a237e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 0.3 * inch))
        
        story.append(Paragraph("<b>Threats Detected</b>", styles['Heading2']))
        story.append(Spacer(1, 0.1 * inch))
        
        if alerts:
            threat_data = [["Time", "Attack", "Source IP", "Confidence", "Action"]]
            for a in alerts[:30]:
                threat_data.append([
                    a.get('time', '')[:19] if a.get('time') else 'N/A',
                    a.get('attack', 'Unknown'),
                    a.get('src', '?'),
                    f"{a.get('confidence', 0)}%",
                    a.get('action', 'Logged')
                ])
            threat_table = Table(threat_data, colWidths=[80, 100, 100, 60, 60])
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#d32f2f')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
            ]))
            story.append(threat_table)
        else:
            story.append(Paragraph("No threats detected.", styles['Normal']))
        
        story.append(Spacer(1, 0.5 * inch))
        story.append(Paragraph("___________________________________", styles['Normal']))
        story.append(Paragraph("Mohammed Bilal - Lead Developer", styles['Normal']))
        story.append(Paragraph("AEGIS-ADS X-Sentry AI System", styles['Normal']))
        
        doc.build(story)
        
        if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
            return {"status": "generated", "file": f"/reports/{filename}", "filename": filename}
        return {"status": "failed", "error": "PDF not created"}
    except Exception as e:
        return {"status": "failed", "error": str(e)}

@app.get("/api/reports/list")
async def api_reports_list():
    files = []
    if os.path.exists("reports"):
        for f in os.listdir("reports"):
            if f.endswith(".pdf"):
                stat = os.path.getmtime(os.path.join("reports", f))
                files.append({"name": f, "date": datetime.fromtimestamp(stat).strftime("%Y-%m-%d %H:%M:%S"), "url": f"/reports/{f}"})
    files.sort(key=lambda x: x["date"], reverse=True)
    return {"files": files}

@app.get("/api/reports/download/{filename}")
async def api_report_download(filename: str):
    if ".." in filename or "/" in filename or "\\" in filename:
        return {"status": "error"}
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

@app.get("/health")
async def health():
    return {"status": "ok", "models": model_loader.is_ready, "capture": capture_running, "packets": packet_count}

if __name__ == "__main__":
    print("=" * 60)
    print("  AEGIS-ADS v11.0 - FULL VERSION")
    print("=" * 60)
    print(f"  RF={'YES' if model_loader.rf_model else 'NO'} | XGB={'YES' if model_loader.xgb_model else 'NO'}")
    print(f"  http://localhost:9999 | admin/2005")
    print("=" * 60)
    uvicorn.run("main:app", host="0.0.0.0", port=9999, reload=False)



