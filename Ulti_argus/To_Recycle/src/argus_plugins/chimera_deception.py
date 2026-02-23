import logging
import random
import time

from src.argus_plugins.manager import ArgusPlugin


class ChimeraDeception(ArgusPlugin):
    """
    Chimera: Active Deception & Fingerprint Obfuscation.
    Injects noise into traffic to confuse automated scanner fingerprinting
    and detects high-entropy data blobs (potential C2 beacons).
    """
    def name(self):
        return "ChimeraDeception"

    def description(self):
        return "Injects deception headers and detects encrypted C2 heartbeats."

    def on_load(self):
        self.logger = logging.getLogger("CHIMERA")
        self.deception_headers = [
            ("X-Backend-Server", "Apache/2.2.3 (CentOS)"),
            ("X-Managed-By", "Argus-Global-Deception-Grid"),
            ("Set-Cookie", "argus_session_id=" + str(random.randint(100000, 999999)) + "; HttpOnly")
        ]
        self.threat_db = {} # Tracking suspicious IPs

    def on_payload(self, content: bytes):
        # 1. Detect high entropy (Simple heuristic for encrypted data)
        # If the content is large and doesn't contain common English chars/HTML
        if len(content) > 128:
            non_printable = sum(1 for b in content if b < 32 or b > 126)
            if non_printable / len(content) > 0.4:
                self.logger.warning("[!] CHIMERA: High-entropy data detected (Potential encrypted C2/Exfiltration)")
                return {"alert": "HIGH_ENTROPY_TRAFFIC", "details": "Potential encrypted exfiltration detected"}

        return None

    def on_packet(self, flow_data):
        # Fingerprint Obfuscation Logic
        # In a real XDP/Proxy, we would modify the response here.
        # For the plugin, we track the 'active recon' behavior.
        src = flow_data.get("src_ip")
        if not src: return

        # Simple port scan detection (simulated)
        if src not in self.threat_db:
            self.threat_db[src] = {"ports": set(), "first_seen": time.time()}
        
        self.threat_db[src]["ports"].add(flow_data.get("dst_port"))
        
        if len(self.threat_db[src]["ports"]) > 5:
            self.logger.warning(f"[!] CHIMERA: Port scan detected from {src}!")
            return {"alert": "PORT_SCAN_DETECTION", "details": f"IP probed {len(self.threat_db[src]['ports'])} unique ports"}
        
        return None
