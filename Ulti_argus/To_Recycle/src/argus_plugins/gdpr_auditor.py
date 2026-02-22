from src.argus_plugins.manager import ArgusPlugin
import re
import logging

class GDPRLogAuditor(ArgusPlugin):
    def name(self):
        return "GDPRLogAuditor"

    def description(self):
        return "Scans for PII (emails, phone numbers) to ensure GDPR compliance."

    def on_load(self):
        self.logger = logging.getLogger("GDPR")
        # Regex for common PII
        self.email_pattern = re.compile(rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        self.phone_pattern = re.compile(rb'\b\d{10}\b') # Simple 10-digit number
        self.pan_pattern = re.compile(rb'[A-Z]{5}[0-9]{4}[A-Z]{1}') # Indian PAN Card format simulation

    def on_payload(self, content: bytes):
        try:
            # Quick scan
            emails = self.email_pattern.findall(content)
            phones = self.phone_pattern.findall(content)
            
            alerts = []
            if emails:
                alerts.append(f"Emails found: {len(emails)}")
            if phones:
                alerts.append(f"Phones found: {len(phones)}")
                
            if alerts:
                self.logger.warning(f"[!] GDPR VIOLATION: PII detected in stream! {alerts}")
                return {"alert": "GDPR_PII_LEAK", "details": ", ".join(alerts)}
                
        except Exception:
            pass # Don't crash on bad encoding
        return None
