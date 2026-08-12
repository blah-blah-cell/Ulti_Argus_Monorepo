"""Module-level constants for the live-capture pipeline.

These are immutable lookup tables used across the package.
"""
from __future__ import annotations

PROTOCOL_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

# Known malicious patterns (signature-based DPI)
MALICIOUS_PATTERNS = [
    (rb"select.*from.*where", "SQL Injection"),
    (rb"union.*select", "SQL Injection (Union)"),
    (rb"<script.*>", "XSS Script Tag"),
    (rb"javascript:", "XSS JavaScript URI"),
    (rb"\.\.\/", "Path Traversal"),
    (rb"\/etc\/passwd", "File Inclusion (/etc/passwd)"),
    (rb"cmd\.exe", "Command Injection (Windows)"),
    (rb"\/bin\/sh", "Command Injection (Unix)"),
    (rb"powershell", "PowerShell Injection"),
    (rb"eval\(", "Code Execution (eval)"),
    (rb"base64_decode", "Base64 Decode (obfuscation)"),
    (rb"wget\s+http", "Download Command"),
    (rb"curl\s+http", "Download Command"),
]

# Suspicious ports (common C2, exploits)
SUSPICIOUS_PORTS = {
    4444: "Metasploit Handler",
    5555: "ADB Debug",
    6666: "IRC (C2)",
    31337: "Back Orifice",
    12345: "NetBus",
    54321: "Backdoor",
    8888: "Suspicious HTTP",
    9999: "Suspicious",
}

# TLS fingerprints (JA3)
KNOWN_MALICIOUS_JA3 = set()

# Maximum recent flow results kept in memory for the dashboard.
MAX_RESULTS = 500
