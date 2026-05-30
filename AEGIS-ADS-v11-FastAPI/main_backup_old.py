"""
AEGIS-ADS v11.0 - FINAL WORKING VERSION
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
ping_tracker = defaultdict(lambda: {'count': 0, 'start': time.time()})


def add_to_logs(alert):
    log_entry = {
        "id": len(logs_storage) + 1,
        "timestamp": alert.get('time', datetime.now().isoformat()),
        "src_ip": alert.get('src', 'Unknown'),
        "dst_ip": alert.get('dst', '-'),
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
        
        packet_count += 1
        now = time.time()
        
        # ICMP Flood Detection
        if length < 200 and src.startswith('192.168.137.') and src not in ['192.168.137.1']:
            t = ping_tracker[src]
            t['count'] += 1
            
            if t['count'] >= 10 and (now - t['start']) < 3:
                result = block_ip_v2(src, f'ICMP Flood')
                alert = {
                    'time': datetime.now().isoformat(),
                    'attack': 'ICMP-Flood',
                    'src': src,
                    'dst': dst,
                    'confidence': 95.0,
                    'severity': 'CRITICAL',
                    'action': 'Blocked'
                }
                alerts.insert(0, alert)
                detections.append(alert)
                add_to_logs(alert)
                logger.warning(f"ICMP FLOOD: {src}")
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
        try:
            if ws_connections:
                data = {
                    "packets": packet_count,
                    "detections": len(detections),
                    "alerts": alerts[:15],
                    "logs": logs_storage[:50],
                    "capture": capture_running,
                    "cpu": psutil.cpu_percent(),
                    "memory": psutil.virtual_memory().percent
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
        "available_interfaces": interfaces if interfaces else [{"name": "4", "ip": "192.168.137.1"}]
    }

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
    devices = get_connected_devices()
    return {"devices": devices, "count": len(devices)}

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
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    
    try:
        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"AEGIS_Report_{timestamp}.pdf"
        filepath = os.path.join("reports", filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=landscape(A4),
                                leftMargin=0.5*inch, rightMargin=0.5*inch,
                                topMargin=0.5*inch, bottomMargin=0.5*inch)
        styles = getSampleStyleSheet()
        story = []
        
        # عنوان
        title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=22,
                                      textColor=colors.HexColor('#1a237e'), alignment=TA_CENTER, spaceAfter=20)
        story.append(Paragraph("AEGIS-ADS Security Report", title_style))
        
        # معلومات
        info_style = ParagraphStyle('Info', parent=styles['Normal'], fontSize=10, textColor=colors.grey, alignment=TA_CENTER)
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", info_style))
        story.append(Paragraph("Developer: Mohammed Bilal | System: AEGIS-ADS v11.0", info_style))
        story.append(Spacer(1, 0.3 * inch))
        
        # إحصائيات
        story.append(Paragraph("<b>Executive Summary</b>", styles['Heading2']))
        story.append(Spacer(1, 0.1 * inch))
        
        stats_data = [
            ["Total Packets", str(packet_count)],
            ["Total Detections", str(len(detections))],
            ["Blocked IPs", str(len([a for a in alerts if a.get('action') == 'Blocked']))],
        ]
        
        stats_table = Table(stats_data, colWidths=[2.5*inch, 1.5*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a237e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f5f5')),
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 0.3 * inch))
        
        # جدول التهديدات
        story.append(Paragraph("<b>Threats Detected</b>", styles['Heading2']))
        story.append(Spacer(1, 0.1 * inch))
        
        if logs_storage:
            threat_data = [["#", "Time", "Source IP", "Attack", "Severity", "Confidence", "Action"]]
            for i, log in enumerate(logs_storage[:30], 1):
                threat_data.append([
                    str(i),
                    log.get('timestamp', '')[:19] if log.get('timestamp') else 'N/A',
                    log.get('src_ip', '?'),
                    log.get('attack_type', 'Unknown'),
                    log.get('severity', 'MEDIUM'),
                    f"{log.get('confidence', 0)}%",
                    log.get('action', 'Logged')
                ])
            
            threat_table = Table(threat_data, colWidths=[0.4*inch, 1.2*inch, 1.2*inch, 1.0*inch, 0.7*inch, 0.7*inch, 0.8*inch])
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#d32f2f')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#fafafa')),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(threat_table)
        else:
            story.append(Paragraph("No threats detected during this period.", styles['Normal']))
        
        # توقيع
        story.append(Spacer(1, 0.5 * inch))
        story.append(Paragraph("___________________________________", styles['Normal']))
        story.append(Paragraph("<b>Mohammed Bilal</b> - Lead Developer", styles['Normal']))
        story.append(Paragraph("AEGIS-ADS X-Sentry AI System", styles['Normal']))
        
        doc.build(story)
        return {"status": "generated", "file": f"/reports/{filename}"}
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
