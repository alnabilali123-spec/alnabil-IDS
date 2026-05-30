"""
AEGIS-ADS - Telemetry & Metrics System
"""

import time
import threading
from collections import deque
from datetime import datetime

class Telemetry:
    def __init__(self):
        self.metrics = {
            'packets_per_second': deque(maxlen=60),
            'detections_per_minute': deque(maxlen=60),
            'inference_latency': deque(maxlen=100),
            'rf_predictions': 0,
            'xgb_predictions': 0,
            'dl_predictions': 0,
            'active_blocks': 0,
            'total_packets': 0,
            'total_detections': 0
        }
        self.running = False
        self.last_packet_count = 0
        self.last_time = time.time()
    
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._collect_loop, daemon=True)
        self.thread.start()
    
    def _collect_loop(self):
        while self.running:
            time.sleep(1)
            self._update_metrics()
    
    def _update_metrics(self):
        now = time.time()
        dt = now - self.last_time
        if dt > 0:
            packets = self.metrics['total_packets'] - self.last_packet_count
            self.metrics['packets_per_second'].append(packets / dt)
            self.last_packet_count = self.metrics['total_packets']
            self.last_time = now
    
    def record_packet(self):
        self.metrics['total_packets'] += 1
    
    def record_detection(self):
        self.metrics['total_detections'] += 1
    
    def record_rf(self):
        self.metrics['rf_predictions'] += 1
    
    def record_xgb(self):
        self.metrics['xgb_predictions'] += 1
    
    def record_dl(self):
        self.metrics['dl_predictions'] += 1
    
    def record_latency(self, ms):
        self.metrics['inference_latency'].append(ms)
    
    def get_status(self):
        return {
            'total_packets': self.metrics['total_packets'],
            'total_detections': self.metrics['total_detections'],
            'packets_per_second': round(sum(self.metrics['packets_per_second'])/max(1,len(self.metrics['packets_per_second'])), 2),
            'avg_latency_ms': round(sum(self.metrics['inference_latency'])/max(1,len(self.metrics['inference_latency'])), 2),
            'rf_predictions': self.metrics['rf_predictions'],
            'xgb_predictions': self.metrics['xgb_predictions'],
            'dl_predictions': self.metrics['dl_predictions'],
            'active_blocks': self.metrics['active_blocks'],
            'pipeline_mode': 'tiered',
            'rf_threshold': 0.65,
            'xgb_threshold': 0.85
        }

telemetry = Telemetry()
