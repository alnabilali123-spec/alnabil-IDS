"""
AfterImage Feature Extractor - Advanced temporal features
Uses damped incremental statistics for better detection
"""
import numpy as np
from collections import defaultdict
import time

class AfterImageExtractor:
    """
    Extracts temporal features using damped incremental statistics.
    Tracks patterns per network channel.
    """
    
    def __init__(self, decay_factor=0.9):
        self.decay = decay_factor
        self.channels = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'last_seen': time.time(),
            'iat_values': [],  # Inter-arrival times
            'size_values': [],
            'syn_count': 0,
            'ack_count': 0,
            'fin_count': 0,
            'rst_count': 0
        })
    
    def get_channel_key(self, src_ip, dst_ip, src_port, dst_port, protocol):
        return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{protocol}"
    
    def process_packet(self, packet_info):
        """
        Extract features for a single packet within its channel context
        Returns: feature vector with temporal statistics
        """
        src_ip = packet_info.get('src_ip', '0.0.0.0')
        dst_ip = packet_info.get('dst_ip', '0.0.0.0')
        src_port = packet_info.get('src_port', 0)
        dst_port = packet_info.get('dst_port', 0)
        protocol = packet_info.get('transport', 'TCP')
        length = packet_info.get('length', 0)
        flags = packet_info.get('flags', '')
        
        key = self.get_channel_key(src_ip, dst_ip, src_port, dst_port, protocol)
        channel = self.channels[key]
        
        now = time.time()
        iat = now - channel['last_seen'] if channel['packet_count'] > 0 else 0
        
        # Update channel statistics with decay
        channel['packet_count'] = channel['packet_count'] * self.decay + 1
        channel['byte_count'] = channel['byte_count'] * self.decay + length
        channel['last_seen'] = now
        channel['iat_values'].append(iat)
        channel['size_values'].append(length)
        
        # Track TCP flags
        flags_upper = flags.upper()
        if 'S' in flags_upper: channel['syn_count'] += 1
        if 'A' in flags_upper: channel['ack_count'] += 1
        if 'F' in flags_upper: channel['fin_count'] += 1
        if 'R' in flags_upper: channel['rst_count'] += 1
        
        # Keep only recent values
        if len(channel['iat_values']) > 50: channel['iat_values'] = channel['iat_values'][-50:]
        if len(channel['size_values']) > 50: channel['size_values'] = channel['size_values'][-50:]
        
        # Build feature vector
        features = {
            'iat_mean': np.mean(channel['iat_values']) if channel['iat_values'] else 0,
            'iat_std': np.std(channel['iat_values']) if len(channel['iat_values']) > 1 else 0,
            'size_mean': np.mean(channel['size_values']) if channel['size_values'] else length,
            'size_std': np.std(channel['size_values']) if len(channel['size_values']) > 1 else 0,
            'packet_count_decayed': channel['packet_count'],
            'byte_count_decayed': channel['byte_count'],
            'syn_ratio': channel['syn_count'] / max(channel['packet_count'], 1),
            'ack_ratio': channel['ack_count'] / max(channel['packet_count'], 1),
            'channel_duration': now - channel['last_seen'] if channel['packet_count'] > 1 else 0,
        }
        
        return features
