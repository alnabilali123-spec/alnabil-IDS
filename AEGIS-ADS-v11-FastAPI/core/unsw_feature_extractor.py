# core/unsw_feature_extractor.py
import logging
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)

FEATURE_ORDER = [
    'sport', 'dsport', 'dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sload', 'dload', 'spkts',
    'swin', 'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 'sjit', 'djit',
    'sintpkt', 'dintpkt', 'tcprtt', 'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd',
    'is_ftp_login', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src__ltm', 'ct_src_dport_ltm',
    'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'duration', 'src_bps', 'dst_bps', 'src_pps',
    'byte_ratio', 'pkt_ratio', 'jit_ratio', 'loss_ratio_src', 'loss_ratio_dst', 'window_ratio',
    'total_bytes', 'total_pkts', 'byte_pkt_interaction_src', 'byte_pkt_interaction_dst',
    'load_jit_interaction_src', 'load_jit_interaction_dst', 'pkt_jit_interaction_src',
    'mean_pkt_size', 'tcp_seq_diff', 'service_src_ratio', 'service_dst_ratio', 'res_bdy_rate',
    'stime_hour', 'stime_weekday', 'ltime_hour', 'ltime_weekday'
]

def extract_unsw_features_batch(flow_list):
    """
    استخراج ميزات UNSW-NB15 لمجموعة تدفقات دفعة واحدة.
    flow_list: قائمة من tuples (events, metadata)
      events: قائمة كائنات NetworkEvent (لها: src_ip, dst_ip, src_port, dst_port, ip_proto, length, time, summary)
      metadata: dict يحتوي على src_ip, dst_ip, sport, dsport, start_time, protocol, last_time
    تعيد: list of dicts بنفس ترتيب flow_list
    """
    batch_features = []

    # عدادات عبر التدفقات (ct_*)
    count_srv_src = defaultdict(int)
    count_srv_dst = defaultdict(int)
    count_dst_ltm = defaultdict(int)
    count_src_ltm = defaultdict(int)
    count_src_dport_ltm = defaultdict(int)
    count_dst_sport_ltm = defaultdict(int)
    count_dst_src_ltm = defaultdict(int)

    for events, meta in flow_list:
        src = meta.get('src_ip', '0.0.0.0')
        dst = meta.get('dst_ip', '0.0.0.0')
        sp = meta.get('sport', 0)
        dp = meta.get('dsport', 0)
        count_srv_src[(src, dp)] += 1
        count_srv_dst[(dst, dp)] += 1
        count_dst_ltm[(dst, dp)] += 1
        count_src_ltm[src] += 1
        count_src_dport_ltm[(src, dp)] += 1
        count_dst_sport_ltm[(dst, sp)] += 1
        count_dst_src_ltm[(dst, src)] += 1

    for events, meta in flow_list:
        feat = {}
        try:
            src = meta.get('src_ip', '0.0.0.0')
            dst = meta.get('dst_ip', '0.0.0.0')
            sp = meta.get('sport', 0)
            dp = meta.get('dsport', 0)
            proto = meta.get('protocol', 6)
            start_time = meta.get('start_time', 0)
            last_time = meta.get('last_time', start_time)

            dur = last_time - start_time if last_time > start_time else 0.001

            # عد الحزم والبايتات لكل اتجاه
            src_pkts = 0
            dst_pkts = 0
            sbytes = 0
            dbytes = 0
            # قيم TCP من أول وآخر حزمة
            tcp_seq_first = 0
            tcp_ack_last = 0
            tcp_window = 0
            tcp_rtt = 0
            first_ttl = 0
            last_ttl = 0

            # استخراج من كل كائن NetworkEvent
            for pkt in events:
                try:
                    # الاتجاه: نقارن src_ip مع src_ip المعلن (أو نفحص منافذ؟ سنعتمد IP)
                    pkt_src = getattr(pkt, 'src_ip', '')
                    pkt_len = getattr(pkt, 'length', 0) or 0
                    if pkt_src == src:
                        src_pkts += 1
                        sbytes += pkt_len
                    else:
                        dst_pkts += 1
                        dbytes += pkt_len

                    # TTL
                    pkt_ttl = getattr(pkt, 'ip_ttl', 0) or 0
                    if first_ttl == 0:
                        first_ttl = pkt_ttl
                    last_ttl = pkt_ttl

                    # TCP SEQ/ACK (إذا كان البروتوكول TCP)
                    if proto == 6 and hasattr(pkt, 'tcp_seq'):
                        if pkt_src == src and tcp_seq_first == 0:
                            tcp_seq_first = pkt.tcp_seq or 0
                            tcp_window = getattr(pkt, 'tcp_window', 0) or 0
                            tcp_rtt = getattr(pkt, 'tcp_rtt', 0) or 0
                        if pkt_src != src:
                            tcp_ack_last = getattr(pkt, 'tcp_ack', 0) or 0
                except Exception:
                    continue

            total_pkts = src_pkts + dst_pkts
            total_bytes = sbytes + dbytes

            feat['sport'] = sp
            feat['dsport'] = dp
            feat['dur'] = dur
            feat['sbytes'] = sbytes
            feat['dbytes'] = dbytes
            feat['sttl'] = first_ttl
            feat['dttl'] = last_ttl
            feat['sload'] = sbytes / dur
            feat['dload'] = dbytes / dur
            feat['spkts'] = src_pkts
            feat['swin'] = tcp_window
            feat['stcpb'] = tcp_seq_first
            feat['dtcpb'] = tcp_ack_last
            feat['smeansz'] = sbytes / src_pkts if src_pkts else 0
            feat['dmeansz'] = dbytes / dst_pkts if dst_pkts else 0
            feat['trans_depth'] = 0
            feat['res_bdy_len'] = 0
            feat['sjit'] = 0
            feat['djit'] = 0
            feat['sintpkt'] = 0
            feat['dintpkt'] = 0
            feat['tcprtt'] = tcp_rtt
            feat['is_sm_ips_ports'] = 1 if src == dst and sp == dp else 0
            feat['ct_state_ttl'] = 0
            feat['ct_flw_http_mthd'] = 0
            feat['is_ftp_login'] = 0
            feat['ct_srv_src'] = count_srv_src[(src, dp)]
            feat['ct_srv_dst'] = count_srv_dst[(dst, dp)]
            feat['ct_dst_ltm'] = count_dst_ltm[(dst, dp)]
            feat['ct_src__ltm'] = count_src_ltm[src]
            feat['ct_src_dport_ltm'] = count_src_dport_ltm[(src, dp)]
            feat['ct_dst_sport_ltm'] = count_dst_sport_ltm[(dst, sp)]
            feat['ct_dst_src_ltm'] = count_dst_src_ltm[(dst, src)]
            feat['duration'] = dur
            feat['src_bps'] = sbytes * 8 / dur
            feat['dst_bps'] = dbytes * 8 / dur
            feat['src_pps'] = src_pkts / dur
            feat['byte_ratio'] = sbytes / dbytes if dbytes else 0
            feat['pkt_ratio'] = src_pkts / dst_pkts if dst_pkts else 0
            feat['jit_ratio'] = 0
            feat['loss_ratio_src'] = 0
            feat['loss_ratio_dst'] = 0
            feat['window_ratio'] = 0
            feat['total_bytes'] = total_bytes
            feat['total_pkts'] = total_pkts
            feat['byte_pkt_interaction_src'] = sbytes * src_pkts
            feat['byte_pkt_interaction_dst'] = dbytes * dst_pkts
            feat['load_jit_interaction_src'] = 0
            feat['load_jit_interaction_dst'] = 0
            feat['pkt_jit_interaction_src'] = 0
            feat['mean_pkt_size'] = total_bytes / total_pkts if total_pkts else 0
            feat['tcp_seq_diff'] = abs(tcp_seq_first - tcp_ack_last)
            feat['service_src_ratio'] = 0
            feat['service_dst_ratio'] = 0
            feat['res_bdy_rate'] = 0
            feat['stime_hour'] = datetime.fromtimestamp(start_time).hour if start_time else 0
            feat['stime_weekday'] = datetime.fromtimestamp(start_time).weekday() if start_time else 0
            feat['ltime_hour'] = datetime.fromtimestamp(last_time).hour if last_time else 0
            feat['ltime_weekday'] = datetime.fromtimestamp(last_time).weekday() if last_time else 0

        except Exception as e:
            logger.error(f"Feature extraction error: {e}")
            feat = {f: 0 for f in FEATURE_ORDER}

        batch_features.append(feat)

    return batch_features