# core/firewall_engine.py - Fixed Version
import threading
import subprocess
import json
import time
import uuid
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Set, Dict, Optional
import logging

logger = logging.getLogger(__name__)

@dataclass
class FirewallRule:
    id: str
    source_ip: str
    protocol: str
    port: Optional[int]
    action: str
    reason: str
    created_at: float
    windows_firewall_added: bool

class UnifiedFirewallEngine:
    def __init__(self):
        self.rules: Dict[str, FirewallRule] = {}
        self.blocked_ips: Set[str] = set()
        self._lock = threading.Lock()
        self.rules_file = Path("firewall_rules.json")
        self._load_rules()
    
    def _load_rules(self):
        if self.rules_file.exists():
            try:
                with open(self.rules_file, 'r') as f:
                    data = json.load(f)
                    for rule_data in data:
                        rule = FirewallRule(**rule_data)
                        self.rules[rule.id] = rule
                        if rule.action == "BLOCK":
                            self.blocked_ips.add(rule.source_ip)
                            # إعادة تطبيق القواعد على Windows Firewall
                            self._add_windows_firewall_rule(rule.source_ip, rule.protocol, rule.port)
                logger.info(f"Loaded {len(self.rules)} rules")
            except Exception as e:
                logger.error(f"Load error: {e}")
    
    def _save_rules(self):
        with open(self.rules_file, 'w') as f:
            json.dump([asdict(r) for r in self.rules.values()], f, indent=2)
    
    def _add_windows_firewall_rule(self, ip: str, protocol: str, port: Optional[int]) -> bool:
        """إضافة قاعدة حظر حقيقية إلى Windows Firewall"""
        if ip in ["192.168.137.1", "127.0.0.1", "0.0.0.0"]:
            logger.warning(f"Cannot block protected IP: {ip}")
            return False
        
        rule_name_in = f"AEGIS_BLOCK_IN_{ip.replace('.', '_')}"
        rule_name_out = f"AEGIS_BLOCK_OUT_{ip.replace('.', '_')}"
        
        try:
            # حذف القواعد القديمة
            subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name_in}"', shell=True, capture_output=True, timeout=2)
            subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name_out}"', shell=True, capture_output=True, timeout=2)
            
            # إضافة قاعدة Inbound
            cmd_in = f'netsh advfirewall firewall add rule name="{rule_name_in}" dir=in action=block remoteip={ip} enable=yes profile=any'
            result_in = subprocess.run(cmd_in, shell=True, capture_output=True, text=True, timeout=5)
            
            # إضافة قاعدة Outbound
            cmd_out = f'netsh advfirewall firewall add rule name="{rule_name_out}" dir=out action=block remoteip={ip} enable=yes profile=any'
            result_out = subprocess.run(cmd_out, shell=True, capture_output=True, text=True, timeout=5)
            
            success = result_in.returncode == 0 and result_out.returncode == 0
            
            if success:
                logger.info(f"✅ Windows Firewall: Blocked {ip} (Inbound + Outbound)")
            else:
                logger.error(f"❌ Firewall error for {ip}: In={result_in.returncode}, Out={result_out.returncode}")
            
            return success
            
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout adding firewall rule for {ip}")
            return False
        except Exception as e:
            logger.error(f"Firewall exception: {e}")
            return False
    
    def _remove_windows_firewall_rule(self, ip: str):
        """إزالة قاعدة من Windows Firewall"""
        rule_name_in = f"AEGIS_BLOCK_IN_{ip.replace('.', '_')}"
        rule_name_out = f"AEGIS_BLOCK_OUT_{ip.replace('.', '_')}"
        subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name_in}"', shell=True, capture_output=True)
        subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name_out}"', shell=True, capture_output=True)
        logger.info(f"✅ Removed firewall rules for {ip}")
    
    def add_rule(self, source_ip: str, protocol: str = "ANY", port: Optional[int] = None,
                 action: str = "BLOCK", reason: str = "Manual") -> dict:
        """إضافة قاعدة حظر جديدة"""
        
        # منع حظر العناوين المحمية
        if source_ip in ["192.168.137.1", "127.0.0.1", "0.0.0.0"]:
            return {"status": "skipped", "reason": "Cannot block protected IP"}
        
        with self._lock:
            # التحقق من وجود القاعدة مسبقاً
            for rule in self.rules.values():
                if rule.source_ip == source_ip and rule.action == "BLOCK":
                    return {"status": "already_blocked", "rule_id": rule.id, "ip": source_ip}
            
            rule_id = str(uuid.uuid4())[:8]
            
            # إضافة إلى Windows Firewall
            fw_success = self._add_windows_firewall_rule(source_ip, protocol, port)
            
            rule = FirewallRule(
                id=rule_id,
                source_ip=source_ip,
                protocol=protocol,
                port=port,
                action=action,
                reason=reason,
                created_at=time.time(),
                windows_firewall_added=fw_success
            )
            
            self.rules[rule_id] = rule
            
            if action == "BLOCK":
                self.blocked_ips.add(source_ip)
            
            self._save_rules()
            
            logger.warning(f"🚫 RULE DEPLOYED: {source_ip} - Windows Firewall: {fw_success}")
            
            return {
                "status": "blocked",
                "rule_id": rule_id,
                "ip": source_ip,
                "windows_firewall": fw_success,
                "message": f"IP {source_ip} blocked successfully" if fw_success else "Firewall rule may not be active"
            }
    
    def remove_rule(self, rule_id: str) -> dict:
        """إزالة قاعدة حظر"""
        with self._lock:
            if rule_id in self.rules:
                rule = self.rules.pop(rule_id)
                if rule.action == "BLOCK":
                    self.blocked_ips.discard(rule.source_ip)
                    self._remove_windows_firewall_rule(rule.source_ip)
                self._save_rules()
                logger.info(f"🔓 RULE REMOVED: {rule.source_ip}")
                return {"status": "removed", "ip": rule.source_ip}
            return {"status": "not_found"}
    
    def get_all_rules(self) -> list:
        return [asdict(r) for r in self.rules.values()]
    
    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

firewall_engine = UnifiedFirewallEngine()
