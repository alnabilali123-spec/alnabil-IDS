# core/packet_capture.py
import threading, socket, struct, time
from datetime import datetime
import logging, config, psutil

logger = logging.getLogger(__name__)

last_alerts = {}

class PacketCaptureEngine:
    def __init__(self, state):
        self.state = state
        self.capture_thread = None
        self.stop_flag = False
        self.callback = None
        self.sock = None

    def start_capture(self, interface=None, mode="nids", callback=None):
        if self.state.capture_running:
            return False
        self.state.capture_running = True
        self.stop_flag = False
        self.callback = callback
        self.state.capture_start_time = datetime.now()
        if interface is None:
            interface = self._find_best_interface()
        logger.info(f"Starting NIDS capture on interface: {interface}")
        self.state.capture_interface = interface
        self._start_scapy(interface)
        return True

    def _find_best_interface(self):
        preferred_patterns = [
            'Local Area Connection', 'Wireless', 'Ethernet', 'Wi‑Fi', 'WLAN', 'vEthernet'
        ]
        for iface, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and a.address.startswith('192.168.137.'):
                    logger.info(f"✅ Found Hotspot interface: {iface} with IP {a.address}")
                    return iface
        for pattern in preferred_patterns:
            for iface, addrs in psutil.net_if_addrs().items():
                if pattern.lower() in iface.lower():
                    for a in addrs:
                        if a.family == socket.AF_INET and not a.address.startswith('127.'):
                            logger.info(f"✅ Selected interface: {iface} (IP: {a.address})")
                            return iface
        for iface, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and not a.address.startswith('127.'):
                    logger.info(f"⚠️ Fallback interface: {iface} (IP: {a.address})")
                    return iface
        return None

    def stop_capture(self):
        self.state.capture_running = False
        self.stop_flag = True
        if self.sock:
            try:
                self.sock.close()
            except:
                pass

    def _start_scapy(self, iface):
        def loop():
            try:
                from scapy.all import sniff, conf
                conf.use_pcap = True
                logger.info(f"Sniffing on: {iface}")
                self.state.l1_status = self.state.l2_status = self.state.l3_status = "ONLINE"
                sniff(iface=iface, prn=self._handle, store=False, promisc=True,
                      stop_filter=lambda x: self.stop_flag)
            except Exception as e:
                logger.error(f"Scapy: {e}")
                self._raw_fallback()

        self.capture_thread = threading.Thread(target=loop, daemon=True)
        self.capture_thread.start()

    def _handle(self, pkt):
        try:
            from scapy.all import IP, TCP, UDP, ICMP, ARP
            now = time.time()

            if IP in pkt:
                s = pkt[IP].src
                d = pkt[IP].dst

                if s in last_alerts and (now - last_alerts[s]) < 0.01:
                    return

                info = {
                    "src_ip": s,
                    "dst_ip": d,
                    "length": len(pkt),
                    "timestamp": datetime.now().isoformat(),
                    "raw_bytes": bytes(pkt),
                    "scapy_pkt": pkt,          # ✅ أضفنا الكائن الأصلي
                    "ip_proto": pkt[IP].proto
                }

                if TCP in pkt:
                    info.update({
                        "transport": "TCP",
                        "src_port": pkt[TCP].sport,
                        "dst_port": pkt[TCP].dport,
                        "flags": str(pkt[TCP].flags)
                    })
                elif UDP in pkt:
                    info.update({
                        "transport": "UDP",
                        "src_port": pkt[UDP].sport,
                        "dst_port": pkt[UDP].dport
                    })
                elif ICMP in pkt:
                    info["transport"] = "ICMP"

                self.state.packets_processed += 1
                if self.callback:
                    self.callback(info)

                last_alerts[s] = now

            elif ARP in pkt:
                info = {
                    "src_ip": pkt[ARP].psrc,
                    "dst_ip": pkt[ARP].pdst,
                    "transport": "ARP",
                    "length": len(pkt),
                    "raw_bytes": bytes(pkt),
                    "scapy_pkt": pkt,          # ✅ أضفنا الكائن الأصلي
                    "ip_proto": 0x0806
                }
                self.state.packets_processed += 1
                if self.callback:
                    self.callback(info)

        except:
            pass

    def _raw_fallback(self):
        def loop():
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.sock.bind(('0.0.0.0', 0))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.sock.settimeout(0.5)
                self.state.l1_status = "ONLINE"
                while not self.stop_flag:
                    try:
                        data = self.sock.recvfrom(65535)[0]
                        if len(data) >= 20:
                            s = socket.inet_ntoa(data[12:16])
                            d = socket.inet_ntoa(data[16:20])
                            # --- تغيير 1: إزالة فلتر LOCAL_IPS للسماح برؤية الحركة بين الأجهزة المحلية ---
                            # if s in config.LOCAL_IPS and d in config.LOCAL_IPS:
                            #     continue
                            p = data[9]
                            t = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(p, "IP")
                            info = {
                                "src_ip": s,
                                "dst_ip": d,
                                "length": len(data),
                                "protocol": p,
                                "transport": t,
                                "raw_bytes": data           # ✅ البيانات الخام كما هي (bytes)
                            }
                            self.state.packets_processed += 1
                            if self.callback:
                                self.callback(info)
                    except socket.timeout:
                        continue
            except:
                pass

        self.capture_thread = threading.Thread(target=loop, daemon=True)
        self.capture_thread.start()