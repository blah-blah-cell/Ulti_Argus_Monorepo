"""Layer 0: Deep Packet Inspection (DPI).

Pure functions — no module-level state, no side effects on import.

- ``dpi_identify_protocol``: signature-based application protocol detection.
- ``dpi_scan_patterns``: scan a payload for known malicious byte patterns.
- ``dpi_extract_features``: byte-level statistical features for ML.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from argus_v.dpi import calculate_entropy

from web.api.capture.constants import MALICIOUS_PATTERNS, SUSPICIOUS_PORTS


def dpi_identify_protocol(
    payload: bytes, dst_port: int, src_port: int
) -> dict[str, Any]:
    """Layer 0 DPI: Identify application protocol from payload."""
    result = {
        "app_id": "Unknown",
        "tls_version": None,
        "http_method": None,
        "http_host": None,
        "dns_query": None,
        "ssh_banner": None,
        "entropy": 0.0,
        "payload_hash": None,
        "suspicious_patterns": [],
        "suspicious_port": None,
    }

    if not payload or len(payload) < 2:
        return result

    # Payload hash
    result["payload_hash"] = hashlib.sha256(payload).hexdigest()[:16]

    # Shannon entropy
    result["entropy"] = calculate_entropy(payload)

    # Suspicious port check
    for port in [dst_port, src_port]:
        if port in SUSPICIOUS_PORTS:
            result["suspicious_port"] = f"{port} ({SUSPICIOUS_PORTS[port]})"

    # TLS detection
    if len(payload) >= 3 and payload[0] == 0x16 and payload[1] == 0x03:
        result["app_id"] = "TLS"
        tls_versions = {
            0x01: "TLS 1.0",
            0x02: "TLS 1.1",
            0x03: "TLS 1.2",
            0x04: "TLS 1.3",
        }
        if len(payload) > 5:
            result["tls_version"] = tls_versions.get(
                payload[5], f"Unknown (0x{payload[5]:02x})"
            )
        return result

    # HTTP detection
    http_methods = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
    ]
    for method in http_methods:
        if payload.startswith(method):
            result["app_id"] = "HTTP"
            result["http_method"] = method.decode().strip()
            # Extract Host header
            host_match = re.search(rb"Host:\s*([^\r\n]+)", payload)
            if host_match:
                result["http_host"] = host_match.group(1).decode()
            return result

    # HTTP response
    if payload.startswith(b"HTTP/"):
        result["app_id"] = "HTTP"
        return result

    # SSH detection
    if payload.startswith(b"SSH-"):
        result["app_id"] = "SSH"
        result["ssh_banner"] = payload[:50].decode(errors="ignore")
        return result

    # DNS detection (port 53)
    if dst_port == 53 or src_port == 53:
        result["app_id"] = "DNS"
        if len(payload) > 12:
            try:
                # Parse DNS query name
                qname = b""
                idx = 12
                while idx < len(payload) and payload[idx] != 0:
                    length = payload[idx]
                    qname += payload[idx + 1 : idx + 1 + length] + b"."
                    idx += 1 + length
                if qname:
                    result["dns_query"] = qname.decode().rstrip(".")
            except (IndexError, UnicodeDecodeError):
                pass
        return result

    # BitTorrent detection
    if len(payload) >= 20 and payload[0:20] == b"\x13BitTorrent protocol":
        result["app_id"] = "BitTorrent"
        return result

    # SMB detection
    if payload[:4] == b"\xffSMB" or payload[:4] == b"\xfeSMB":
        result["app_id"] = "SMB"
        return result

    # RDP detection
    if len(payload) >= 3 and payload[0] == 0x03 and payload[1] == 0x00:
        result["app_id"] = "RDP"
        return result

    # Port-based fallback
    port_map = {
        22: "SSH",
        443: "TLS",
        80: "HTTP",
        53: "DNS",
        3389: "RDP",
        445: "SMB",
        21: "FTP",
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
    }
    for port in [dst_port, src_port]:
        if port in port_map:
            result["app_id"] = port_map[port]

    return result


def dpi_scan_patterns(payload: bytes) -> list[dict[str, str]]:
    """Layer 0 DPI: Scan payload for malicious patterns."""
    if not payload:
        return []

    matches = []
    payload_lower = payload.lower()
    for pattern, name in MALICIOUS_PATTERNS:
        if re.search(pattern, payload_lower):
            matches.append(
                {
                    "pattern": name,
                    "severity": "high"
                    if "Injection" in name or "Execution" in name
                    else "medium",
                }
            )
    return matches


def dpi_extract_features(payload: bytes) -> dict[str, Any]:
    """Layer 0 DPI: Extract deep features from payload."""
    if not payload:
        return {}

    features = {
        "length": len(payload),
        "entropy": calculate_entropy(payload),
        "printable_ratio": sum(1 for b in payload if 32 <= b <= 126)
        / max(len(payload), 1),
        "null_bytes": payload.count(0),
        "high_bytes": sum(1 for b in payload if b > 127),
    }

    # Byte distribution
    freq = [0] * 256
    for b in payload:
        freq[b] += 1
    features["unique_bytes"] = sum(1 for f in freq if f > 0)
    features["max_freq"] = max(freq) / max(len(payload), 1)

    return features
