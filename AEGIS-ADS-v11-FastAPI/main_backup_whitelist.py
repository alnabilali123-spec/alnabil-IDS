"""
AEGIS-ADS v11.0 - FINAL WORKING VERSION (FIXED TSHARK PATH)
"""
import sys, os, time, threading, smtplib, asyncio, psutil, subprocess, json, re, shutil
from datetime import datetime
from collections import defaultdict
from contextlib import asynccontextmanager
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from fastapi import FastAPI, Request, WebSocket, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import uvicorn, logging

from core.models_loader import UnifiedModelLoader
from core.feature_extractor import FeatureExtractor
from core.global_state import GlobalState
import config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("AEGIS")
state = GlobalState()
model_loader = UnifiedModelLoader()
feature_extractor = FeatureExtractor()

# ============================================================
# Helper to find tshark executable
# ============================================================
def get_tshark_path():
    """Find tshark.exe in common locations"""
    # Try from PATH first
    tshark = shutil.which("tshark")
    if tshark:
        return tshark
    # Common installation paths
    common_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe"
    ]
    for path in common_paths:
        if os.path.exists(path):
            return path
    raise FileNotFoundError("tshark.exe not found. Please install Wireshark with Tshark.")

TSHARK_PATH = get_tshark_path()
logger.info(f"✅ Using tshark at: {TSHARK_PATH}")

# ============================================================
# Firewall Functions
# ============================================================
PROTECTED_IPS = {'127.0.0.1', '192.168.8.1', '192.168.8.5'}
BLOCKED_IPS_STORAGE = []
BLOCKED_RULES = []

def block_ip_30x(ip: str, reason: str = "Manual") -> dict:
    """حظر IP مع 30 قاعدة Windows Firewall"""
    if ip in PROTECTED_IPS:
        return {"status": "skipped", "reason": "protected"}
    
    success_count = 0
    rules_added = []
    
    for i in range(30):
        try:
            rule_name = f"AEGIS_BLOCK_{ip.replace('.', '_')}_{i}"
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip} enable=yes'
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=2)
            if result.returncode == 0:
                success_count += 1
                rules_added.append(rule_name)
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
# Email Functions
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
# Main App
# ============================================================
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
    if alert.get('action') == 'Blocked':
        threading.Thread(target=send_email_alert, args=(alert,), daemon=True).start()

def process_tshark_line(line):
    global packet_count, detections, alerts
    # *** مهم: زيادة العداد فوراً لأي حزمة تصل ***
    packet_count += 1
    print(f"DEBUG: Packet received - count={packet_count}, line={line.strip()[:100]}...")  # طباعة للتصحيح

    try:
        parts = line.strip().split('\t')
        if len(parts) < 3:
            return
        src = parts[0].strip()
        dst = parts[1].strip()
        length = int(parts[2].strip())
        now = time.time()
        
        if length < 200 and src.startswith('192.168.137.') and src != '192.168.137.1':
            t = ping_tracker[src]
            t['count'] += 1
            if t['count'] >= 3 and (now - t['start']) < 2:
                result = block_ip_30x(src, 'ICMP Flood')
                alert = {
                    'time': datetime.now().isoformat(),
                    'attack': 'ICMP-Flood',
                    'src': src,
                    'dst': dst,
                    'confidence': 95.0,
                    'severity': 'CRITICAL',
                    'action': 'Blocked',
                    'rules_added': result.get('rules_added', 0)
                }
                alerts.insert(0, alert)
                detections.append(alert)
                add_to_logs(alert)
                logger.warning(f"🌊 ICMP FLOOD: {src} -> {result.get('rules_added', 0)} rules")
                t['count'] = 0
                t['start'] = now
        
        if packet_count % 100 == 0:
            print(f"\r[Pkts:{packet_count} | Det:{len(detections)}]", end='', flush=True)
    except Exception as e:
        logger.error(f"Process error: {e}")

def start_tshark_capture():
    global capture_running
    if capture_running:
        return
    capture_running = True
    def loop():
        # استخدام المسار الصحيح لـ tshark
        cmd = [TSHARK_PATH, '-i', '4', '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'frame.len', '-l']
        logger.info(f"Starting Tshark with command: {' '.join(cmd)}")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1
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
    if not interfaces:
        interfaces = [{"name": "4", "ip": "192.168.137.1"}]
    return {"capture_running": capture_running, "packets": packet_count, "detections": len(detections), "available_interfaces": interfaces}

@app.post("/api/capture/start")
async def api_start(data: dict = None):
    start_tshark_capture()
    return {"status": "started"}

@app.post("/api/capture/stop")
async def api_stop():
    global capture_running
    capture_running = False
    return {"status": "stopped"}

@app.get("/api/dashboard/stats")
async def api_stats():
    return {"active_threats": len(detections), "packets": packet_count}

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

# Email Settings APIs
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
    return {"status": "ok", "models": model_loader.is_ready, "capture": capture_running, "packets": packet_count}

if __name__ == "__main__":
    print("=" * 60)
    print("  🛡️ AEGIS-ADS v11.0 - FINAL VERSION")
    print("=" * 60)
    print("  🌐 http://localhost:9999 | admin/2005")
    print("=" * 60)
    uvicorn.run("main:app", host="0.0.0.0", port=9999, reload=False)
