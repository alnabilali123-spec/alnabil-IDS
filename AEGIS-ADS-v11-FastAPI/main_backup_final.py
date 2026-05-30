"""AEGIS-ADS v11.0 FINAL - Kernel IPS + FastAPI"""
import sys,os,time,threading,smtplib,asyncio,psutil,subprocess,json
from datetime import datetime
from collections import defaultdict
from contextlib import asynccontextmanager
from email.mime.text import MIMEText
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fastapi import FastAPI,Request,WebSocket,HTTPException
from fastapi.responses import FileResponse,StreamingResponse
import io, os as os_module
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
import uvicorn
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from core.models_loader import UnifiedModelLoader
from core.feature_extractor import FeatureExtractor
from core.global_state import GlobalState
from core.firewall_manager import block_ip_v2,unblock_ip,get_connected_devices,panic_button
from core.kernel_shield import get_blacklist,clear_blacklist
from database.db_manager import DatabaseManager
import config
logging.basicConfig(level=logging.INFO,format='%(asctime)s - %(levelname)s - %(message)s')
logger=logging.getLogger("AEGIS")\n
# ============================================================
# EMAIL ALERT SYSTEM - Automated Threat Notifications
# ============================================================

def send_automated_alert(alert_data):
    """إرسال تنبيه آلي عند اكتشاف هجوم"""
    try:
        import smtplib
        from email.mime.text import MIMEText
        
        em = config.EMAIL_CONFIG
        
        body = f"""
╔══════════════════════════════════════════════════════════╗
║              🚨 AEGIS-ADS SECURITY ALERT 🚨              ║
╠══════════════════════════════════════════════════════════╣
║  نوع الهجوم: {alert_data.get('attack', 'Unknown'):<45} ║
║  المصدر (IP): {alert_data.get('src', 'Unknown'):<45} ║
║  الهدف: {alert_data.get('dst', 'N/A'):<45} ║
║  مستوى الخطورة: {alert_data.get('severity', 'MEDIUM'):<45} ║
║  نسبة الثقة: {alert_data.get('l2', alert_data.get('confidence', 0)):.1f}%{' ' * 42}║
║  الإجراء: {alert_data.get('action', 'Logged'):<45} ║
║  التوقيت: {alert_data.get('time', str(datetime.now())):<45} ║
╠══════════════════════════════════════════════════════════╣
║  توقيع النظام: AEGIS-ADS v11.0 (X-Sentry AI)            ║
║  مطور النظام: {em.get('developer', 'AEGIS Team'):<45} ║
║  الحالة: نظام الحماية الذاتية يعمل                      ║
╚══════════════════════════════════════════════════════════╝
"""
        
        msg = MIMEText(body, _charset='utf-8')
        msg["Subject"] = f"🚨 ALERT: {alert_data.get('attack', 'Threat')} from {alert_data.get('src', 'Unknown')}"
        msg["From"] = f"{em['from_name']} <{em['username']}>"
        msg["To"] = ", ".join(em.get("alert_emails", [em["username"]]))
        
        with smtplib.SMTP(em["smtp_server"], em["smtp_port"]) as s:
            s.starttls()
            s.login(em["username"], em["password"])
            s.send_message(msg)
        
        logger.info(f"📧 Alert email sent to {len(em.get('alert_emails', []))} recipients")
    except Exception as e:
        logger.error(f"❌ Email failed: {e}")

# دالة الاختبار اليدوي
def send_test_alert():
    send_automated_alert({
        "attack": "TEST_ALERT",
        "src": "127.0.0.1",
        "dst": "localhost",
        "severity": "INFO",
        "l2": 100,
        "action": "Test",
        "time": str(datetime.now())
    })
state=GlobalState()
model_loader=UnifiedModelLoader()
db=DatabaseManager()
feature_extractor=FeatureExtractor()
capture_running=False; ws_connections=[]; packet_count=0; detections=[]; alerts=[]
LOCAL_IPS={'127.0.0.1','192.168.8.5','192.168.8.15','192.168.8.1','192.168.137.1'}
ping_tracker=defaultdict(lambda:{'count':0,'start':time.time()})
port_tracker=defaultdict(lambda:{'ports':set(),'start':time.time()})
flows={}
FLOW_TIMEOUT=60

def flow_key(s,d,sp,dp,pr):
    a=(s,sp);b=(d,dp)
    if a>b: a,b=b,a
    return f"{a[0]}:{a[1]}-{b[0]}:{b[1]}-{pr}"

def cleanup_flows():
    now=time.time()
    expired=[k for k,v in flows.items() if now-v['last']>FLOW_TIMEOUT]
    for k in expired: del flows[k]

def extract_features(f):
    f78=np.zeros(78,dtype=np.float32)
    dur=max(f['last']-f['start'],0.001)
    pkts=f['packets'];b=f['bytes'];avg=b//max(pkts,1)
    f78[0]=0;f78[1]=float(dur);f78[2]=float(pkts);f78[4]=float(b)
    f78[6]=float(avg);f78[7]=float(avg);f78[8]=float(avg)
    f78[14]=float(b/dur);f78[15]=float(pkts/dur)
    f78[34]=40.0 if f['proto']==6 else 28.0
    f78[38]=float(avg);f78[39]=float(avg);f78[40]=float(avg)
    f78[43]=float(f['fin']);f78[44]=float(f['syn'])
    f78[45]=float(f['rst']);f78[47]=float(f['ack'])
    f78[52]=float(avg);f78[53]=float(avg) if f['proto']==6 else 0
    f78[62]=float(pkts);f78[63]=float(b)
    f78[66]=64240.0;f78[67]=64240.0;f78[68]=1.0 if b>0 else 0.0
    return f78.reshape(1,-1)

def process_tshark_line(line):
    global packet_count
    try:
        parts=line.strip().split('\t')
        if len(parts)<3:return
        src=parts[0].strip();dst=parts[1].strip()
        if ',' in src:src=src.split(',')[0]
        length=int(parts[2].strip())
        if src in LOCAL_IPS and dst in LOCAL_IPS:return
        if not src.startswith('192.168.137.') and not dst.startswith('192.168.137.'):return
        packet_count+=1;now=time.time()
        is_icmp=length<200
        
        if is_icmp and src.startswith('192.168.137.'):
            t=ping_tracker[src];t['count']+=1
            if t['count']>=5 and (now-t['start'])<3:
                result=block_ip_v2(src,f'ICMP Flood')
                alert={'time':datetime.now().isoformat(),'attack':'ICMP-Flood','src':src,'dst':dst,'confidence':95,'action':'Blocked','kernel':result.get('kernel',False)}
                alerts.append(alert);detections.append(alert)
                logger.info(f"🌊 ICMP FLOOD: {src} → BLOCKED [Kernel:{result.get('kernel')}]")
                t['count']=0;t['start']=now
            return
        
        if not is_icmp and src.startswith('192.168.137.'):
            pt=port_tracker[src];pt['ports'].add(dst)
            if len(pt['ports'])>=10 and (now-pt['start'])<5:
                result=block_ip_v2(src,f'Port Scan ({len(pt["ports"])} ports)')
                alert={'time':datetime.now().isoformat(),'attack':'PortScan','src':src,'ports':len(pt['ports']),'action':'Blocked','kernel':result.get('kernel',False)}
                alerts.append(alert);detections.append(alert)
                logger.info(f"🔍 PORT SCAN: {src} → BLOCKED [Kernel:{result.get('kernel')}]")
                pt['ports'].clear();pt['start']=now
                return
        
        if src.startswith('192.168.137.'):
            key=flow_key(src,dst,0,int(dst.split('.')[-1]) if '.' in dst else 0,6 if not is_icmp else 1)
            if key not in flows:
                flows[key]={'start':now,'last':now,'packets':0,'bytes':0,'syn':0,'ack':0,'fin':0,'rst':0,'proto':6 if not is_icmp else 1}
            f=flows[key];f['last']=now;f['packets']+=1;f['bytes']+=length
            
            if packet_count%10==0 and f['packets']>=5 and model_loader.is_ready:
                try:
                    features=extract_features(f)
                    is_attack,l1_conf=model_loader.predict_l1(features)
                    if is_attack and l1_conf>25:
                        f10=features[:,[0,4,6,8,14,34,44,46,47,52]]
                        l2=model_loader.predict_l2(f10)
                        if l2['attack_type'].upper() not in ('NORMAL','BENIGN') and l2['confidence']>50:
                            sev='CRITICAL' if l2['confidence']>85 else 'HIGH' if l2['confidence']>70 else 'MEDIUM'
                            result=block_ip_v2(src,f'AI: {l2["attack_type"]}') if sev in ('CRITICAL','HIGH') else {}
                            alert={'time':datetime.now().isoformat(),'attack':l2['attack_type'],'src':src,'dst':dst,'l1':round(l1_conf,1),'l2':round(l2['confidence'],1),'severity':sev,'action':'Blocked' if sev in('CRITICAL','HIGH') else 'Logged','kernel':result.get('kernel',False)}
                            alerts.append(alert);detections.append(alert)
                            logger.info(f"🤖 AI: {l2['attack_type']} from {src} (L2:{l2['confidence']:.0f}%) [Kernel:{result.get('kernel')}]")
                except:pass
        
        if packet_count%200==0:
            cleanup_flows()
            if len(alerts) > 500:
                alerts[:] = alerts[-200:]
            if len(detections) > 500:
                detections[:] = detections[-200:]
            logger.info(f"📊 Pkts:{packet_count} | Det:{len(detections)} | Flows:{len(flows)}")
    except:pass

def start_tshark():
    global capture_running
    capture_running=True;state.l1_status=state.l2_status="ONLINE";state.l3_status="ONLINE"
    def loop():
        from scapy.all import sniff as scapy_sniff, conf as scapy_conf, IP as scapy_IP, TCP as scapy_TCP, UDP as scapy_UDP, ICMP as scapy_ICMP
        scapy_conf.use_pcap = True
        target = None
        for name in scapy_conf.ifaces:
            try:
                if "137" in str(scapy_conf.ifaces[name].ip):
                    target = name; break
            except: pass
        if not target:
            for name in scapy_conf.ifaces:
                if "Intel" in name and "Wireless" in name: target = name; break
        if not target: target = scapy_conf.iface.name
        logger.info(f"👁️ Scapy capture on: {target}")

        proc=subprocess.Popen(['tshark','-i','4','-T','fields','-e','ip.src','-e','ip.dst','-e','frame.len','-l'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
        for line in proc.stdout:
            if not capture_running:break
            if line.strip():process_tshark_line(line)
        pass
    threading.Thread(target=loop,daemon=True).start()
    logger.info("👁️ TSHARK capture started on interface 4")

@asynccontextmanager
async def lifespan(app:FastAPI):
    logger.info("🚀 AEGIS-ADS v11.0 FINAL + KERNEL IPS");asyncio.create_task(broadcast_loop());yield

app=FastAPI(title="AEGIS-ADS v11.0 Final",lifespan=lifespan)
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_credentials=True,allow_methods=["*"],allow_headers=["*"])
app.mount("/static",StaticFiles(directory="static"),name="static")
templates=Jinja2Templates(directory="templates")

async def broadcast_loop():
    while True:
        await asyncio.sleep(1);dead=[]
        for ws in ws_connections:
            try:await ws.send_json({"packets":packet_count,"detections":len(detections),"alerts":alerts[-5:],"capture":capture_running,"flows":len(flows),"cpu":psutil.cpu_percent(),"blocked_ips":sum(1 for a in alerts if a.get("action")=="Blocked"),"kernel_blacklist":len(get_blacklist()),"auto_block":True})
            except:dead.append(ws)
        for d in dead:
            if d in ws_connections:ws_connections.remove(d)

@app.websocket("/ws/live")
async def ws_live(ws:WebSocket):
    await ws.accept()
    ws_connections.append(ws)
    if len(ws_connections) > 10:
        oldest = ws_connections.pop(0)
        try: oldest.close()
        except: pass
    try:
        while True:
            await ws.receive_text()
    except:
        pass

@app.get("/")
async def login(r:Request):return templates.TemplateResponse("login.html",{"request":r})
@app.get("/dashboard")
async def dashboard(r:Request):return templates.TemplateResponse("dashboard.html",{"request":r})
@app.get("/firewall")
async def firewall(r:Request):return templates.TemplateResponse("firewall.html",{"request":r})
@app.get("/logs")
async def logs_page(r:Request):return templates.TemplateResponse("logs.html",{"request":r})
@app.get("/models")
async def models_page(r:Request):return templates.TemplateResponse("models.html",{"request":r})
@app.get("/devices")
async def devices_page(r:Request):return templates.TemplateResponse("devices.html",{"request":r})
@app.get("/admin")
async def admin_page(r:Request):return templates.TemplateResponse("admin.html",{"request":r})
@app.get("/settings")
async def settings_page(r:Request):return templates.TemplateResponse("settings.html",{"request":r})
@app.get("/reports")
async def reports_page(r:Request):return templates.TemplateResponse("reports.html",{"request":r})
@app.get("/about")
async def about_page(r:Request):return templates.TemplateResponse("about.html",{"request":r})

@app.post("/api/auth/login")
async def api_login(data:dict):
    if data.get('username')=='admin' and data.get('password')=='2005':
        from jose import jwt
        return {"access_token":jwt.encode({"sub":"admin","role":"admin"},config.SECRET_KEY,algorithm=config.ALGORITHM),"username":"admin","role":"admin"}
    raise HTTPException(401)

@app.get("/api/capture/status")
async def api_status():
    interfaces=[]
    for iface,addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family==2 and addr.address!='127.0.0.1':interfaces.append({"name":iface,"ip":addr.address})
    return {"capture_running":capture_running,"packets":packet_count,"detections":len(detections),"flows":len(flows),"available_interfaces":interfaces,"engine":"TSHARK+Kernel"}

@app.post("/api/capture/start")
async def api_start(data:dict=None):start_tshark();return {"status":"started","engine":"TSHARK+Kernel IPS"}
@app.post("/api/capture/stop")
async def api_stop():
    global capture_running;capture_running=False;return {"status":"stopped"}

@app.get("/api/dashboard/stats")
async def api_stats():return {"active_threats":len(detections),"blocked_ips":sum(1 for a in alerts if a.get('action')=='Blocked'),"flows":len(flows),"cpu":psutil.cpu_percent(),"packets":packet_count}

@app.get("/api/logs")
async def api_logs():
    result = []
    for i, d in enumerate(detections[-100:]):
        result.append({
            "id": d.get("id", len(detections)-i),
            "timestamp": str(d.get("time", ""))[:19],
            "src_ip": str(d.get("src", "")),
            "dst_ip": str(d.get("dst", "")),
            "protocol": str(d.get("protocol", "ICMP")),
            "port": d.get("port", 0),
            "attack_type": str(d.get("attack", "")),
            "severity": str(d.get("severity", "Medium")),
            "confidence": d.get("confidence", 95.0),
            "action": str(d.get("action", "Blocked"))
        })
    return {"threats": result, "total": len(detections)}

@app.get("/api/models/status")
async def api_models():return model_loader.get_status()

@app.get("/api/devices")
async def api_devices():
    from core.device_scanner import scan_network
    real = scan_network()
    return {"devices":[{"ip_address":d['ip'],"mac_address":d.get('mac','Unknown'),"vendor":d.get('vendor','Unknown')} for d in real],"count":len(real)}

@app.post("/api/devices/scan")
async def api_scan(data:dict=None):
    devices=get_connected_devices()
    for d in devices:db.add_device({"ip_address":d['ip'],"mac_address":d['mac'],"vendor":d['vendor']})
    return {"devices":[{"ip_address":d['ip'],"mac_address":d['mac']} for d in devices],"count":len(devices)}

@app.get("/api/firewall/rules")
async def api_rules():return {"rules":db.get_firewall_rules(),"count":len(db.get_firewall_rules())}

@app.post("/api/firewall/rules")
async def api_add_rule(rule:dict):
    rid = db.add_firewall_rule(rule)
    if rule.get("action")=="Block" and rule.get("src_ip"):
        ip = rule["src_ip"]
        result = block_ip_v2(ip, rule.get("reason","Manual"))
        logger.info(f"🚫 Firewall Rule: {ip} -> BLOCKED [Kernel:{result.get('kernel',False)}]")
        return {"status":"blocked","id":rid,"result":result}
    return {"status":"created","id":rid}

@app.post("/api/panic")
async def api_panic():return panic_button()

@app.post("/api/settings/email/test")
async def api_test_email():
    try:
        em=config.EMAIL_CONFIG
        msg=MIMEText(f"AEGIS-ADS Alert\nThreats:{len(detections)}\nTime:{datetime.now()}")
        msg["Subject"]=f"AEGIS-ADS Test - {datetime.now().strftime('%H:%M:%S')}"
        msg["From"]=em["username"];msg["To"]=em["alert_email"]
        with smtplib.SMTP(em["smtp_server"],em["smtp_port"]) as s:s.starttls();s.login(em["username"],em["password"]);s.send_message(msg)
        return {"status":"sent"}
    except Exception as e:return {"status":"failed","error":str(e)}

@app.get("/api/reports/generate")
async def api_report():
    try:
        # reportlab imported at top
        from reportlab.pdfgen import canvas
        fn=f"reports/AEGIS_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        os.makedirs("reports",exist_ok=True)
        c=canvas.Canvas(fn,pagesize=A4)
        c.setFont("Helvetica-Bold",20);c.drawString(50,800,"AEGIS-ADS Security Report")
        c.setFont("Helvetica",12);c.drawString(50,770,f"Generated: {datetime.now()}")
        c.drawString(50,750,f"Packets: {packet_count}");c.drawString(50,730,f"Detections: {len(detections)}")
        y=700
        for a in alerts[-15:]:c.drawString(50,y,f"[{a.get('time','')[:19]}] {a.get('attack','')} from {a.get('src','')}");y-=15
        c.save()
        return {"status":"generated","file":fn}
    except Exception as e:return {"status":"failed","error":str(e)}

@app.get("/pcap")
async def pcap_page(r:Request):return templates.TemplateResponse("pcap.html",{"request":r})

@app.get("/api/reports/download/{filename}")
async def download_report(filename: str):
    file_path = os_module.path.join("reports", filename)
    if os_module.path.exists(file_path):
        return FileResponse(path=file_path, filename=filename, media_type="application/pdf")
    raise HTTPException(status_code=404, detail="Report not found")

@app.delete("/api/firewall/rules/{rule_id}")
async def api_delete_rule(rule_id: int):
    from core.firewall_manager import unblock_ip
    rules = db.get_firewall_rules()
    for r in rules:
        if r.get("id") == rule_id:
            ip = r.get("src_ip", "")
            if ip and ip != "0.0.0.0/0":
                # 1. Remove from Windows Firewall
                unblock_ip(ip)
                # 2. Remove from kernel shield
                from core.kernel_shield import remove_from_blacklist
                remove_from_blacklist(ip)
                logger.info(f"🔓 Unblocked: {ip} (Firewall + Kernel)")
            break
    # Also try to delete from database
    try:
        db.delete_firewall_rule(rule_id)
    except:
        pass
    return {"status": "deleted"}

@app.get("/health")
async def health():return {"status":"ok","models":model_loader.is_ready,"capture":capture_running,"kernel":True,"shield_active":True,"blacklist":len(get_blacklist()),"packets":packet_count}


# ============================================================
# NEW APIS - Improved Firewall, Analytics, User Management
# ============================================================

from core.improved_firewall import block_ip_kernel, unblock_ip_kernel, panic_mode, unpanic_mode, BLOCKED_IPS
from core.analytics import record_attack, get_chart_data, get_attack_stats, reset_stats
from core.user_manager import get_users, add_user, delete_user, update_user, verify_user

@app.get("/api/users")
async def api_get_users():
    return {"users": get_users()}

@app.post("/api/users")
async def api_add_user(data: dict):
    result = add_user(data["username"], data["password"], data["role"], data["email"])
    return {"status": "created" if result else "exists"}

@app.delete("/api/users/{username}")
async def api_delete_user(username: str):
    result = delete_user(username)
    return {"status": "deleted" if result else "failed"}

@app.put("/api/users/{username}")
async def api_update_user(username: str, data: dict):
    result = update_user(username, data["role"], data["email"])
    return {"status": "updated" if result else "failed"}

@app.get("/api/charts/timeline")
async def api_chart_timeline():
    return get_chart_data()

@app.get("/api/charts/stats")
async def api_chart_stats():
    return get_attack_stats()

@app.post("/api/panic")
async def api_panic():
    result = panic_mode()
    return result

@app.post("/api/unpanic")
async def api_unpanic():
    result = unpanic_mode()
    return result

# تحسين دالة Block لتسجيل التحليلات
@app.post("/api/firewall/rules")
async def api_add_rule_enhanced(rule: dict):
    if rule.get("action") == "Block" and rule.get("src_ip"):
        ip = rule["src_ip"]
        # منع الإضافة المكررة
        if ip in BLOCKED_IPS:
            return {"status": "already_blocked", "kernel": True, "ip": ip}
        
        result = block_ip_kernel(ip, rule.get("reason", "Manual"))
        # تسجيل في التحليلات
        record_attack("Manual", "HIGH", ip)
        return result
    return {"status": "created"}

@app.delete("/api/firewall/rules/{ip}")
async def api_delete_rule_enhanced(ip: str):
    result = unblock_ip_kernel(ip)
    return result

# تحسين WebSocket broadcast
async def broadcast_loop():
    while True:
        if ws_connections:
            data = {
                "packets": packet_count,
                "detections": len(detections),
                "cpu": psutil.cpu_percent(),
                "memory": psutil.virtual_memory().percent,
                "alerts": alerts[-15:],
                "blocked_ips": list(BLOCKED_IPS)[:20]
            }
            # إرسال إلى جميع المتصلين
            for ws in ws_connections[:]:
                try:
                    await ws.send_json(data)
                except:
                    if ws in ws_connections:
                        ws_connections.remove(ws)
        await asyncio.sleep(1)

if __name__=="__main__":
    print("="*60);print("  🛡️ AEGIS-ADS v11.0 FINAL + KERNEL IPS");print("="*60)
    print(f"  RF={'✅' if model_loader.rf_model else '❌'} | XGB={'✅' if model_loader.xgb_model else '❌'} | PyDivert=✅")
    print(f"  http://localhost:9999 | admin/2005");print("="*60)
    uvicorn.run("main:app",host="0.0.0.0",port=9999,reload=False)
















