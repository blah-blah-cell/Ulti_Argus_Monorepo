import logging

from src.argus_plugins.manager import ArgusPlugin


class GhostService(ArgusPlugin):
    def name(self):
        return "GhostService"

    def description(self):
        return "Honeypot triggers. Detects traffic aimed at closed 'Ghost' ports."

    def on_load(self):
        self.logger = logging.getLogger("GhostService")

    def on_payload(self, content: bytes):
        # In a real honeypot, this would run as a separate thread listening on port 23 (Telnet).
        # Here, as a plugin to the proxy, we look for attempts to tunnel to internal IPs on weird ports.
        
        # Naive check: Does payload contain "telnet" or "sh" command sequences commonly sent to honeypots?
        suspect_commands = [b"sh", b"wget", b"curl", b"/bin/bash", b"cat /etc/passwd"]
        
        hits = [cmd for cmd in suspect_commands if cmd in content]
        if hits:
            self.logger.critical(f"[!!!] GHOST TRAP TRIGGERED: Attacker trying to execute {hits}")
            return {"alert": "HONEYPOT_TRIGGER", "commands": [h.decode('utf-8', errors='ignore') for h in hits]}
        return None
