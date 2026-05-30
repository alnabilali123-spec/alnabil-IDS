"""
Flow Builder - Reconstructs network flows from packets
"""
import time, hashlib
from collections import defaultdict
from datetime import datetime
from typing import Dict, List

class NetworkFlow:
    """Represents a single network flow"""
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.flow_id = hashlib.md5(f"{src_ip}{dst_ip}{src_port}{dst_port}{protocol}".encode()).hexdigest()[:16]
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.start_time = time.time()
        self.last_seen = time.time()
        self.packet_count = 0
        self.byte_count = 0
        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.unique_ports = set()
        self.packets = []
    
    def add_packet(self, packet_info: dict):
        """Add packet to flow"""
        self.last_seen = time.time()
        self.packet_count += 1
        self.byte_count += packet_info.get('length', 0)
        
        flags = packet_info.get('flags', '')
        if 'S' in flags.upper() and 'A' not in flags.upper():
            self.syn_count += 1
        if 'A' in flags.upper():
            self.ack_count += 1
        if 'F' in flags.upper():
            self.fin_count += 1
        if 'R' in flags.upper():
            self.rst_count += 1
        
        self.unique_ports.add(packet_info.get('dst_port', 0))
        self.packets.append(packet_info)
    
    @property
    def duration(self):
        return self.last_seen - self.start_time
    
    @property
    def packets_per_second(self):
        dur = self.duration
        return self.packet_count / dur if dur > 0 else 0
    
    @property
    def bytes_per_second(self):
        dur = self.duration
        return self.byte_count / dur if dur > 0 else 0
    
    @property
    def is_active(self):
        return (time.time() - self.last_seen) < 30
    
    def get_features(self) -> dict:
        """Get flow features for AI analysis"""
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "duration": self.duration,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "packets_per_second": self.packets_per_second,
            "bytes_per_second": self.bytes_per_second,
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "unique_ports": len(self.unique_ports),
            "is_active": self.is_active
        }

class FlowBuilder:
    """Builds and manages network flows"""
    def __init__(self, timeout=30):
        self.flows: Dict[str, NetworkFlow] = {}
        self.timeout = timeout
        self.completed_flows: List[NetworkFlow] = []
    
    def process_packet(self, packet_info: dict) -> NetworkFlow:
        """Process a packet and return its flow"""
        src_ip = packet_info.get('src_ip', '0.0.0.0')
        dst_ip = packet_info.get('dst_ip', '0.0.0.0')
        src_port = packet_info.get('src_port', 0)
        dst_port = packet_info.get('dst_port', 0)
        protocol = packet_info.get('transport', 'TCP')
        
        key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        
        if key not in self.flows:
            self.flows[key] = NetworkFlow(src_ip, dst_ip, src_port, dst_port, protocol)
        
        flow = self.flows[key]
        flow.add_packet(packet_info)
        
        return flow
    
    def cleanup(self):
        """Remove expired flows"""
        now = time.time()
        expired = [k for k, v in self.flows.items() if now - v.last_seen > self.timeout]
        for k in expired:
            self.completed_flows.append(self.flows[k])
            del self.flows[k]
        return len(expired)
    
    def get_active_flows(self) -> List[NetworkFlow]:
        """Get currently active flows"""
        return [f for f in self.flows.values() if f.is_active]
    
    def get_stats(self) -> dict:
        """Get flow statistics"""
        active = self.get_active_flows()
        return {
            "total_flows": len(self.flows),
            "active_flows": len(active),
            "completed_flows": len(self.completed_flows),
            "total_packets": sum(f.packet_count for f in self.flows.values()),
            "total_bytes": sum(f.byte_count for f in self.flows.values())
        }
