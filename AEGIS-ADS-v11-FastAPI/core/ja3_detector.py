# core/ja3_detector.py

import hashlib
import logging
from cachetools import TTLCache

logger = logging.getLogger(__name__)

# RFC 8701 GREASE values
GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
    0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa
}


class JA3Detector:
    """
    Lightweight JA3-like TLS fingerprint detector.

    Features:
    - GREASE removal (RFC 8701)
    - Safe TLS parsing
    - Memory-safe caching
    - Stable fingerprint generation
    - Defensive malformed packet handling
    """

    def __init__(self):
        # Local experimental threat intelligence
        self.malicious_fingerprints = {
            "a0e9f5d6431e8b2c7f6a5d4e3c2b1a09": "Cobalt Strike Beacon",
            "c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7": "Metasploit Meterpreter",
            "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9": "Empire C2",
        }

        # Prevent memory leak
        self.seen_hashes = TTLCache(maxsize=50000, ttl=3600)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _safe_read(self, data, offset, size):
        """Safe boundary-checked read."""
        if offset < 0 or size < 0:
            return None

        if offset + size > len(data):
            return None

        return data[offset:offset + size]

    def _remove_grease(self, values):
        """
        Remove GREASE values and return JA3-compatible string.
        """

        if not values:
            return ""

        # JA3 numeric fields are 2-byte aligned
        if len(values) % 2 != 0:
            return ""

        cleaned = []

        for i in range(0, len(values), 2):
            val = int.from_bytes(values[i:i + 2], "big")

            if val not in GREASE_VALUES:
                cleaned.append(str(val))

        return "-".join(cleaned)

    # ------------------------------------------------------------------
    # TLS Parsing
    # ------------------------------------------------------------------

    def extract_ja3(self, raw_bytes):
        """
        Extract lightweight JA3-like fingerprint from TLS ClientHello.
        """

        try:
            from scapy.all import IP, TCP, Raw

            pkt = IP(raw_bytes)

            # TCP only
            if not pkt.haslayer(TCP):
                return None

            if not pkt.haslayer(Raw):
                return None

            payload = bytes(pkt[Raw])

            # Minimal TLS ClientHello validation
            if len(payload) < 11:
                return None

            # TLS Handshake
            if payload[0] != 0x16:
                return None

            # ClientHello
            if payload[5] != 0x01:
                return None

            # ----------------------------------------------------------
            # TLS Version
            # ----------------------------------------------------------

            tls_version_raw = self._safe_read(payload, 1, 2)

            if not tls_version_raw:
                return None

            tls_version = tls_version_raw.hex()

            # ----------------------------------------------------------
            # Session ID
            # ----------------------------------------------------------

            session_id_len_offset = 43

            if session_id_len_offset >= len(payload):
                return None

            session_id_len = payload[session_id_len_offset]

            # ----------------------------------------------------------
            # Cipher Suites
            # ----------------------------------------------------------

            cipher_offset = 44 + session_id_len

            cipher_len_raw = self._safe_read(payload, cipher_offset, 2)

            if not cipher_len_raw:
                return None

            cipher_len = int.from_bytes(cipher_len_raw, "big")

            # Cipher suites must be even length
            if cipher_len % 2 != 0:
                return None

            cipher_start = cipher_offset + 2
            cipher_end = cipher_start + cipher_len

            if cipher_end > len(payload):
                return None

            cipher_blob = payload[cipher_start:cipher_end]

            cipher_suites = self._remove_grease(cipher_blob)

            # ----------------------------------------------------------
            # Compression Methods
            # ----------------------------------------------------------

            compression_offset = cipher_end

            compression_len_raw = self._safe_read(
                payload,
                compression_offset,
                1
            )

            if not compression_len_raw:
                return None

            compression_len = compression_len_raw[0]

            # ----------------------------------------------------------
            # Extensions
            # ----------------------------------------------------------

            ext_offset = compression_offset + 1 + compression_len

            ext_len_raw = self._safe_read(payload, ext_offset, 2)

            if not ext_len_raw:
                return None

            ext_len = int.from_bytes(ext_len_raw, "big")

            ext_start = ext_offset + 2
            ext_end = ext_start + ext_len

            if ext_end > len(payload):
                return None

            extensions_blob = payload[ext_start:ext_end]

            extensions = []
            ec_curves = ""
            ec_formats = ""

            pos = 0

            while pos + 4 <= len(extensions_blob):

                ext_type = int.from_bytes(
                    extensions_blob[pos:pos + 2],
                    "big"
                )

                ext_size = int.from_bytes(
                    extensions_blob[pos + 2:pos + 4],
                    "big"
                )

                pos += 4

                if pos + ext_size > len(extensions_blob):
                    break

                ext_data = extensions_blob[pos:pos + ext_size]

                # Remove GREASE extensions
                if ext_type not in GREASE_VALUES:
                    extensions.append(str(ext_type))

                # supported_groups (JA3 real EC Curves)
                if ext_type == 10 and ext_size >= 2:

                    group_len = int.from_bytes(
                        ext_data[:2],
                        "big"
                    )

                    groups_blob = ext_data[2:2 + group_len]

                    ec_curves = self._remove_grease(groups_blob)

                # ec_point_formats
                elif ext_type == 11 and ext_size >= 1:

                    fmt_len = ext_data[0]

                    formats = []

                    for b in ext_data[1:1 + fmt_len]:
                        formats.append(str(b))

                    ec_formats = "-".join(formats)

                pos += ext_size

            extensions_str = "-".join(extensions)

            # ----------------------------------------------------------
            # Final JA3 string
            # ----------------------------------------------------------

            ja3_string = (
                f"{tls_version},"
                f"{cipher_suites},"
                f"{extensions_str},"
                f"{ec_curves},"
                f"{ec_formats}"
            )

            ja3_hash = hashlib.md5(
                ja3_string.encode()
            ).hexdigest()

            return {
                "hash": ja3_hash
            }

        except Exception as e:
            logger.debug(f"JA3 extraction error: {e}")
            return None

    # ------------------------------------------------------------------
    # Threat Analysis
    # ------------------------------------------------------------------

    def analyze(self, event):
        """
        Analyze packet and enrich with JA3 threat intelligence.
        """

        try:

            if not hasattr(event, "raw_bytes"):
                return None

            if not event.raw_bytes:
                return None

            ja3_info = self.extract_ja3(event.raw_bytes)

            if not ja3_info:
                return None

            ja3_hash = ja3_info["hash"]

            # Memory-safe tracking
            self.seen_hashes[ja3_hash] = (
                self.seen_hashes.get(ja3_hash, 0) + 1
            )

            # Threat match
            if ja3_hash in self.malicious_fingerprints:

                threat = self.malicious_fingerprints[ja3_hash]

                logger.warning(
                    f"JA3-like threat detected: "
                    f"{threat} from "
                    f"{getattr(event, 'src_ip', 'unknown')}"
                )

                return {
                    "type": "JA3 Threat",
                    "threat": threat,
                    "hash": ja3_hash,
                    "risk_score_bonus": 0.15
                }

            return None

        except Exception as e:
            logger.error(f"JA3 analyze error: {e}")
            return None