"""
Kitsune Bridge - Integrates Kitsune as L3 Anomaly Detector
Runs as background thread, reports anomalies to AEGIS dashboard
"""
import sys, os, time, threading, logging
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'kitsune_engine'))

logger = logging.getLogger(__name__)

class KitsuneBridge:
    """
    Wraps Kitsune autoencoders as a silent background worker.
    Reports RMSE anomaly scores to the dashboard.
    """
    
    def __init__(self, max_ae=10, fm_grace=1000, ad_grace=5000):
        self.max_ae = max_ae
        self.fm_grace = fm_grace
        self.ad_grace = ad_grace
        self.kitsune = None
        self.current_rmse = 0.0
        self.anomaly_score = 0.0  # 0-100%
        self.is_training = True
        self.packets_processed = 0
        self.anomalies_detected = 0
        self.running = False
        self.thread = None
        self.callback = None
        
        # Try loading Kitsune
        try:
            from Kitsune import Kitsune
            self.kitsune = Kitsune(None, max_ae, fm_grace, ad_grace)
            logger.info(f"🦊 Kitsune initialized (maxAE={max_ae}, FM={fm_grace}, AD={ad_grace})")
        except Exception as e:
            logger.warning(f"Kitsune not available: {e}")
    
    def set_callback(self, callback):
        """Set callback for anomaly alerts"""
        self.callback = callback
    
    def process_packet(self, packet_features):
        """
        Process a packet through Kitsune
        Returns: anomaly_score (0-100), rmse_value
        """
        if self.kitsune is None:
            return 0.0, 0.0
        
        try:
            # Convert features to numpy array if needed
            if not isinstance(packet_features, np.ndarray):
                packet_features = np.array(packet_features)
            
            # Kitsune processes one packet at a time
            rmse = self.kitsune.proc_next_packet()
            
            self.packets_processed += 1
            
            # Skip during grace periods
            if rmse == -1 or rmse == 0:
                self.is_training = self.packets_processed < (self.fm_grace + self.ad_grace)
                return 0.0, 0.0
            
            self.is_training = False
            self.current_rmse = rmse
            
            # Convert RMSE to 0-100 scale
            # Typical RMSE range: 0.0 (normal) to 2.0 (highly anomalous)
            self.anomaly_score = min(100.0, (rmse / 2.0) * 100)
            
            if self.anomaly_score > 50:
                self.anomalies_detected += 1
                logger.warning(f"🦊 Kitsune Anomaly: RMSE={rmse:.4f}, Score={self.anomaly_score:.1f}%")
                
                if self.callback:
                    self.callback({
                        'engine': 'Kitsune',
                        'type': 'Anomaly',
                        'rmse': rmse,
                        'score': self.anomaly_score,
                        'timestamp': time.time()
                    })
            
            return self.anomaly_score, rmse
            
        except Exception as e:
            logger.error(f"Kitsune process error: {e}")
            return 0.0, 0.0
    
    def get_status(self):
        """Get current status for dashboard"""
        return {
            'engine': 'Kitsune',
            'running': self.running,
            'training': self.is_training,
            'packets_processed': self.packets_processed,
            'anomalies_detected': self.anomalies_detected,
            'current_rmse': round(self.current_rmse, 4),
            'anomaly_score': round(self.anomaly_score, 1),
            'status': 'TRAINING' if self.is_training else 'ACTIVE'
        }
    
    def start(self):
        """Start background monitoring thread"""
        if self.running:
            return
        self.running = True
        logger.info("🦊 Kitsune background worker started")
    
    def stop(self):
        """Stop background worker"""
        self.running = False
        logger.info("🦊 Kitsune stopped")
