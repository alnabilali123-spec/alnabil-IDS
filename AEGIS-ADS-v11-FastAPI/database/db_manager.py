import os, hashlib
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import config

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    email = Column(String(100)); role = Column(String(20), default='viewer')
    status = Column(String(20), default='active')
    created_at = Column(DateTime, default=datetime.utcnow); last_login = Column(DateTime)

class ThreatLog(Base):
    __tablename__ = 'threat_logs'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    src_ip = Column(String(45)); dst_ip = Column(String(45))
    src_port = Column(Integer); dst_port = Column(Integer)
    protocol = Column(String(10)); attack_type = Column(String(50))
    severity = Column(String(20)); confidence = Column(Float)
    action_taken = Column(String(50)); l1_score = Column(Float); l2_score = Column(Float)

class FirewallRule(Base):
    __tablename__ = 'firewall_rules'
    id = Column(Integer, primary_key=True)
    rule_name = Column(String(100), unique=True); src_ip = Column(String(45))
    protocol = Column(String(10)); port = Column(String(20))
    action = Column(String(20)); reason = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow); is_active = Column(Boolean, default=True)

class Device(Base):
    __tablename__ = 'devices'
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45)); mac_address = Column(String(17))
    vendor = Column(String(100)); hostname = Column(String(100))
    first_seen = Column(DateTime, default=datetime.utcnow); last_seen = Column(DateTime, default=datetime.utcnow)

class DatabaseManager:
    _instance = None
    def __new__(cls):
        if cls._instance is None: cls._instance = super().__new__(cls); cls._instance._init = False
        return cls._instance
    
    def __init__(self):
        if self._init: return
        self._init = True
        self.engine = create_engine(f'sqlite:///{config.DATABASE_PATH}', echo=False, pool_size=5, max_overflow=10)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self._create_admin()
    
    def _create_admin(self):
        s = self.Session()
        try:
            if not s.query(User).filter_by(username='admin').first():
                h = hashlib.sha256('2005'.encode()).hexdigest()
                s.add(User(username='admin', password_hash=h, role='admin', email=config.EMAIL_CONFIG['alert_email']))
                s.commit()
        finally: s.close()
    
    def authenticate_user(self, username, password):
        s = self.Session()
        try:
            u = s.query(User).filter_by(username=username).first()
            if u and u.password_hash == hashlib.sha256(password.encode()).hexdigest():
                u.last_login = datetime.utcnow(); s.commit()
                return {"username": u.username, "role": u.role, "email": u.email or ""}
            return None
        finally: s.close()
    
    def add_threat(self, data):
        data.pop('attack_category', None); data.pop('features_summary', None)
        valid = {k: v for k, v in data.items() if hasattr(ThreatLog, k)}
        s = self.Session()
        try:
            t = ThreatLog(**valid); s.add(t); s.commit(); return t.id
        finally: s.close()
    
    def get_threats(self, limit=100, offset=0, filters=None):
        s = self.Session()
        try:
            q = s.query(ThreatLog)
            if filters:
                if filters.get('severity') and filters['severity'] != 'all': q = q.filter(ThreatLog.severity == filters['severity'])
                if filters.get('search'): q = q.filter(ThreatLog.src_ip.contains(filters['search']))
            total = q.count()
            threats = q.order_by(ThreatLog.timestamp.desc()).offset(offset).limit(limit).all()
            return {"threats": [{"id": t.id, "timestamp": str(t.timestamp), "src_ip": t.src_ip, "dst_ip": t.dst_ip,
                    "src_port": t.src_port, "dst_port": t.dst_port, "protocol": t.protocol,
                    "attack_type": t.attack_type, "severity": t.severity, "confidence": t.confidence,
                    "action_taken": t.action_taken} for t in threats], "total": total}
        finally: s.close()
    
    def add_device(self, d):
        s = self.Session()
        try:
            ex = s.query(Device).filter_by(ip_address=d.get('ip_address')).first()
            if ex: ex.last_seen = datetime.utcnow()
            else: s.add(Device(**d))
            s.commit()
        finally: s.close()
    
    def get_devices(self):
        s = self.Session()
        try: return [{"ip_address": d.ip_address, "mac_address": d.mac_address or "Unknown", "vendor": d.vendor or "Unknown", "hostname": d.hostname or "Unknown"} for d in s.query(Device).all()]
        finally: s.close()
    
    def add_firewall_rule(self, rule):
        valid = {k: v for k, v in rule.items() if hasattr(FirewallRule, k)}
        s = self.Session()
        try:
            f = FirewallRule(**valid); s.add(f); s.commit(); return f.id
        finally: s.close()
    
    def get_firewall_rules(self):
        s = self.Session()
        try: return [{"id": r.id, "rule_name": r.rule_name, "src_ip": r.src_ip, "protocol": r.protocol, "port": r.port, "action": r.action, "reason": r.reason} for r in s.query(FirewallRule).filter_by(is_active=True).all()]
        finally: s.close()
    
    def get_all_users(self):
        s = self.Session()
        try: return [{"id": u.id, "username": u.username, "role": u.role, "email": u.email or ""} for u in s.query(User).all()]
        finally: s.close()
    
    def add_user(self, username, password, role="viewer"):
        s = self.Session()
        try:
            if s.query(User).filter_by(username=username).first(): return False
            s.add(User(username=username, password_hash=hashlib.sha256(password.encode()).hexdigest(), role=role))
            s.commit(); return True
        finally: s.close()
    
    def delete_firewall_rule(self, rule_id):
        s = self.Session()
        try:
            s.query(FirewallRule).filter_by(id=rule_id).delete()
            s.commit()
            return True
        except:
            return False
        finally:
            s.close()
    
    def get_statistics(self):
        s = self.Session()
        try: return {"total_threats": s.query(ThreatLog).count() or 0, "blocked": s.query(ThreatLog).filter_by(action_taken='Blocked').count() or 0, "devices": s.query(Device).count() or 0}
        except: return {"total_threats": 0, "blocked": 0, "devices": 0}
        finally: s.close()

