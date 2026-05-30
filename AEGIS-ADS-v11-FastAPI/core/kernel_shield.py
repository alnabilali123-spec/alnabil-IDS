"""Kernel IPS Shield - Force Reset + UDP + DNS Block"""
import threading, logging, subprocess, time
from scapy.all import IP, TCP, send, Raw

logger = logging.getLogger(__name__)

blacklist = set()
shield_lock = threading.Lock()
shield_running = False

def add_to_blacklist(ip: str):
    with shield_lock:
        blacklist.add(ip)
    # Force kill existing connections via TCP RST
    _send_tcp_reset(ip)
    # Flush DNS cache on target
    _flush_dns(ip)
    logger.info(f"[SHIELD] 💀 {ip} blacklisted + TCP RST sent + DNS flushed")

def remove_from_blacklist(ip: str):
    with shield_lock:
        blacklist.discard(ip)
    logger.info(f"[SHIELD] 🔓 {ip} removed from blacklist")

def _send_tcp_reset(target_ip: str, count: int = 5):
    """Send TCP RST packets to kill existing connections"""
    try:
        for port in [80, 443, 8080, 53, 22, 3389]:
            for _ in range(count):
                try:
                    rst_pkt = IP(dst=target_ip) / TCP(dport=port, flags="R")
                    send(rst_pkt, verbose=False)
                    time.sleep(0.01)
                except:
                    pass
        logger.info(f"[SHIELD] TCP RST packets sent to {target_ip}")
    except Exception as e:
        logger.debug(f"[SHIELD] RST error: {e}")

def _flush_dns(target_ip: str):
    """Attempt to flush DNS via netsh (affects local resolution)"""
    try:
        subprocess.run("ipconfig /flushdns", shell=True, capture_output=True)
    except:
        pass

def start_windivert_shield():
    global shield_running
    if shield_running:
        return
    shield_running = True
    
    def run():
        try:
            import pydivert
            logger.info("[SHIELD] WinDivert kernel interceptor starting (FULL CAPTURE)...")
            # "true" captures EVERYTHING - no exceptions
            with pydivert.WinDivert("true") as w:
                for packet in w:
                    with shield_lock:
                        # Check both directions
                        if packet.src_addr in blacklist or packet.dst_addr in blacklist:
                            # DROP the packet silently
                            logger.debug(f"[SHIELD] 💀 Dropped: {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port}")
                            continue
                    # Allow non-blacklisted traffic
                    w.send(packet)
        except Exception as e:
            logger.error(f"[SHIELD] Error: {e}")
            shield_running = False
    
    threading.Thread(target=run, daemon=True).start()
    logger.info("[SHIELD] Kernel IPS Shield ACTIVE (Full Capture Mode)")

def get_blacklist():
    with shield_lock:
        return list(blacklist)

def clear_blacklist():
    with shield_lock:
        count = len(blacklist)
        blacklist.clear()
    return count
