"""
AEGIS-ADS - Queue Based Packet Worker
This file is separate and safe - won't break main.py
"""

import threading
import queue
import time
from collections import defaultdict
from datetime import datetime

packet_queue = queue.Queue(maxsize=5000)
ai_queue = queue.Queue(maxsize=1000)

class PacketWorker:
    def __init__(self, model_loader, feature_extractor, config):
        self.model_loader = model_loader
        self.feature_extractor = feature_extractor
        self.config = config
        self.running = False
        self.stats = {
            'packets_processed': 0,
            'rf_predictions': 0,
            'xgb_predictions': 0,
            'dl_predictions': 0,
            'avg_latency': 0
        }
    
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.thread.start()
        print("✅ PacketWorker started")
    
    def stop(self):
        self.running = False
    
    def _worker_loop(self):
        while self.running:
            try:
                packet = packet_queue.get(timeout=1)
                start_time = time.time()
                self._process_packet(packet)
                latency = (time.time() - start_time) * 1000
                self.stats['avg_latency'] = self.stats['avg_latency'] * 0.95 + latency * 0.05
                self.stats['packets_processed'] += 1
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Worker error: {e}")
    
    def _process_packet(self, packet):
        # Tiered Inference
        self.stats['rf_predictions'] += 1
        # RF prediction logic here
        pass
    
    def get_stats(self):
        return self.stats

# Global worker instance
worker = None

def init_worker(model_loader, feature_extractor, config):
    global worker
    worker = PacketWorker(model_loader, feature_extractor, config)
    worker.start()
    return worker
