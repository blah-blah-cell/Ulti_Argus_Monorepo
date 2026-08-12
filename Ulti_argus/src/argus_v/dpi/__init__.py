# ruff: noqa: E402
"""Expanded DPI Feature Extraction Module.

Extracts comprehensive features from network packets and flows:
- Network layer (IP flags, TTL, packet sizes)
- Transport layer (TCP flags, window sizes, scan detection)
- Application layer (HTTP, TLS, DNS, FTP, SMTP)
- Payload features (entropy, n-grams, byte distribution)
- Behavioral features (throughput, ratios, timing patterns)
"""

from __future__ import annotations

import hashlib
import math
import re
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# ═══════════════════════════════════════════════════════════════════════════════
#  Constants
# ═══════════════════════════════════════════════════════════════════════════════

PROTOCOL_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

TCP_FLAGS = {
    "FIN": 0x01,
    "SYN": 0x02,
    "RST": 0x04,
    "PSH": 0x08,
    "ACK": 0x10,
    "URG": 0x20,
    "ECE": 0x40,
    "CWR": 0x80,
}

DNS_RECORD_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
    256: "URI",
    257: "CAA",
}

TLS_CIPHER_WEAK = [
    "RC4",
    "DES",
    "NULL",
    "EXPORT",
    "anon",
]

KNOWN_MALICIOUS_JA3 = {
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike",
    "e9d4a14f059b5a40e43e57e92b1847a7": "Metasploit Meterpreter",
    "a0e9f5d64349fb13191bc781f81f42e1": "Emotet",
    "cd08e31494f9531f560d64c695473da9": "TrickBot",
    "bc6c386f1f78c8f41258c03e0044c474": "QakBot",
}

HTTP_SUSPICIOUS_USERAGENTS = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "nuclei",
    "gobuster",
    "dirbuster",
    "wpscan",
    "burp",
    "havij",
    "acunetix",
    "nessus",
    "openvas",
    "metasploit",
]

SQL_INJECTION_PATTERNS = [
    rb"(?i)(?:union\s+(?:all\s+)?select)",
    rb"(?i)(?:select\s+.*\s+from\s+)",
    rb"(?i)(?:insert\s+into\s+)",
    rb"(?i)(?:delete\s+from\s+)",
    rb"(?i)(?:drop\s+(?:table|database))",
    rb"(?i)(?:update\s+.*\s+set\s+)",
    rb"(?i)(?:or\s+1\s*=\s*1)",
    rb"(?i)(?:and\s+1\s*=\s*1)",
    rb"(?i)(?:'\s*or\s+')",
    rb"(?i)(?:--\s*$)",
    rb"(?i)(?:;.*(?:drop|delete|insert|update))",
]

XSS_PATTERNS = [
    rb"(?i)(?:<script[^>]*>)",
    rb"(?i)(?:javascript\s*:)",
    rb"(?i)(?:on(?:load|error|click|mouseover)\s*=)",
    rb"(?i)(?:<iframe[^>]*>)",
    rb"(?i)(?:<object[^>]*>)",
    rb"(?i)(?:<embed[^>]*>)",
    rb"(?i)(?:eval\s*\()",
    rb"(?i)(?:document\.cookie)",
    rb"(?i)(?:document\.location)",
]

PATH_TRAVERSAL_PATTERNS = [
    rb"(?:\.\./){2,}",
    rb"(?:\.\.\\){2,}",
    rb"(?:/etc/passwd)",
    rb"(?:/etc/shadow)",
    rb"(?:/proc/self)",
    rb"(?:\\windows\\system32)",
]

COMMAND_INJECTION_PATTERNS = [
    rb"(?i)(?:;\s*(?:ls|cat|id|whoami|pwd|uname))",
    rb"(?i)(?:\|\s*(?:nc|netcat|bash|sh|cmd))",
    rb"(?i)(?:`[^`]+`)",
    rb"(?i)(?:\$\([^)]+\))",
    rb"(?i)(?:wget\s+http)",
    rb"(?i)(?:curl\s+http)",
    rb"(?i)(?:powershell)",
    rb"(?i)(?:cmd\.exe)",
]


# ═══════════════════════════════════════════════════════════════════════════════
#  Feature Extraction Classes
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class NetworkFeatures:
    """Network layer features extracted from IP headers."""

    ip_flags_df: bool = False  # Don't Fragment
    ip_flags_mf: bool = False  # More Fragments
    ip_fragment_offset: int = 0
    ttl: int = 0
    ip_id: int = 0
    ip_total_length: int = 0
    ip_version: int = 4
    ip_ihl: int = 5  # Header length in 32-bit words


@dataclass
class TransportFeatures:
    """Transport layer features extracted from TCP/UDP headers."""

    src_port: int = 0
    dst_port: int = 0
    protocol: str = "OTHER"

    # TCP specific
    tcp_flags: int = 0
    tcp_window: int = 0
    tcp_seq: int = 0
    tcp_ack: int = 0
    tcp_urgent_ptr: int = 0
    tcp_options_len: int = 0

    # Computed
    is_syn: bool = False
    is_syn_ack: bool = False
    is_fin: bool = False
    is_rst: bool = False
    is_psh: bool = False
    is_ack: bool = False
    is_urg: bool = False
    is_xmas: bool = False  # FIN+PSH+URG
    is_null: bool = False  # No flags

    # UDP specific
    udp_length: int = 0

    # ICMP specific
    icmp_type: int = 0
    icmp_code: int = 0


@dataclass
class PayloadFeatures:
    """Features extracted from packet payload."""

    payload_size: int = 0
    entropy: float = 0.0
    printable_ratio: float = 0.0
    unique_bytes: int = 0
    null_bytes: int = 0
    high_bytes: int = 0  # Bytes > 127
    max_freq: float = 0.0

    # Byte distribution (256-bin histogram, normalized)
    byte_histogram: List[float] = field(default_factory=lambda: [0.0] * 256)

    # N-gram frequencies
    bigram_entropy: float = 0.0
    trigram_entropy: float = 0.0

    # Content detection
    has_base64: bool = False
    has_hex_encoded: bool = False
    has_pe_magic: bool = False  # MZ header
    has_elf_magic: bool = False  # ELF header

    # Payload hash
    md5: str = ""
    sha256: str = ""


@dataclass
class HTTPFeatures:
    """HTTP protocol features."""

    method: str = ""
    uri: str = ""
    host: str = ""
    user_agent: str = ""
    referer: str = ""
    content_type: str = ""
    accept_language: str = ""
    response_code: int = 0
    response_reason: str = ""
    request_size: int = 0
    response_size: int = 0
    uri_length: int = 0
    header_count: int = 0
    has_suspicious_useragent: bool = False


@dataclass
class TLSFeatures:
    """TLS/SSL protocol features."""

    tls_version: str = ""
    tls_version_int: int = 0
    cipher_suite: str = ""
    cipher_suite_id: int = 0
    is_weak_cipher: bool = False
    server_name: str = ""  # SNI

    # Certificate
    cert_issuer: str = ""
    cert_subject: str = ""
    cert_serial: str = ""
    cert_not_before: str = ""
    cert_not_after: str = ""
    cert_is_expired: bool = False
    cert_is_self_signed: bool = False
    cert_key_size: int = 0
    cert_san: List[str] = field(default_factory=list)

    # JA3
    ja3_hash: str = ""
    ja3_string: str = ""
    ja3s_hash: str = ""
    ja3s_string: str = ""
    ja3_malware_family: str = ""


@dataclass
class DNSFeatures:
    """DNS protocol features."""

    query_name: str = ""
    query_type: int = 0
    query_type_name: str = ""
    query_class: int = 0
    is_response: bool = False
    response_code: int = 0  # 0=NOERROR, 3=NXDOMAIN
    answer_count: int = 0
    authority_count: int = 0
    additional_count: int = 0

    # Derived
    query_name_length: int = 0
    subdomain_count: int = 0
    is_txt_query: bool = False
    is_null_query: bool = False
    is_nxdomain: bool = False
    query_entropy: float = 0.0

    # Tunneling indicators
    has_long_subdomain: bool = False  # >50 chars
    has_high_entropy_subdomain: bool = False  # >4.0
    has_base64_subdomain: bool = False


@dataclass
class FlowFeatures:
    """Flow-level behavioral features."""

    flow_id: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    duration: float = 0.0

    # Packet counts
    total_packets: int = 0
    fwd_packets: int = 0
    bwd_packets: int = 0

    # Byte counts
    total_bytes: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    # Packet sizes
    pkt_size_min: int = 0
    pkt_size_max: int = 0
    pkt_size_mean: float = 0.0
    pkt_size_std: float = 0.0

    # Timing
    inter_arrival_mean: float = 0.0
    inter_arrival_std: float = 0.0
    active_time: float = 0.0
    idle_time: float = 0.0

    # Ratios
    bytes_per_second: float = 0.0
    packets_per_second: float = 0.0
    fwd_bwd_byte_ratio: float = 0.0
    fwd_bwd_packet_ratio: float = 0.0

    # TCP specific
    syn_count: int = 0
    syn_ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    avg_window: float = 0.0
    min_window: int = 0
    max_window: int = 0


@dataclass
class DPIResult:
    """Complete DPI extraction result."""

    # Protocol identification
    app_protocol: str = "Unknown"

    # All feature groups
    network: NetworkFeatures = field(default_factory=NetworkFeatures)
    transport: TransportFeatures = field(default_factory=TransportFeatures)
    payload: PayloadFeatures = field(default_factory=PayloadFeatures)
    http: HTTPFeatures = field(default_factory=HTTPFeatures)
    tls: TLSFeatures = field(default_factory=TLSFeatures)
    dns: DNSFeatures = field(default_factory=DNSFeatures)
    flow: FlowFeatures = field(default_factory=FlowFeatures)

    # Pattern matches
    pattern_matches: List[Dict[str, str]] = field(default_factory=list)

    # Timestamp
    timestamp: float = field(default_factory=time.time)


# ═══════════════════════════════════════════════════════════════════════════════
#  Feature Extraction Functions
# ═══════════════════════════════════════════════════════════════════════════════


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte sequence."""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def calculate_byte_histogram(data: bytes) -> List[float]:
    """Calculate normalized 256-bin byte frequency histogram."""
    if not data:
        return [0.0] * 256
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    total = len(data)
    return [f / total for f in freq]


def calculate_ngram_entropy(data: bytes, n: int = 2) -> float:
    """Calculate entropy of n-gram frequency distribution."""
    if len(data) < n:
        return 0.0
    ngrams = defaultdict(int)
    for i in range(len(data) - n + 1):
        ngrams[data[i : i + n]] += 1
    total = len(data) - n + 1
    entropy = 0.0
    for count in ngrams.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_network_features(ip_packet: bytes) -> NetworkFeatures:
    """Extract network layer features from IP packet."""
    features = NetworkFeatures()

    if len(ip_packet) < 20:
        return features

    try:
        # IP header
        version_ihl = ip_packet[0]
        features.ip_version = (version_ihl >> 4) & 0xF
        features.ip_ihl = version_ihl & 0xF

        # Flags and fragment offset
        flags_frag = struct.unpack("!H", ip_packet[6:8])[0]
        features.ip_flags_df = bool((flags_frag >> 14) & 1)
        features.ip_flags_mf = bool((flags_frag >> 13) & 1)
        features.ip_fragment_offset = flags_frag & 0x1FFF

        # TTL
        features.ttl = ip_packet[8]

        # Total length
        features.ip_total_length = struct.unpack("!H", ip_packet[2:4])[0]

        # IP ID
        features.ip_id = struct.unpack("!H", ip_packet[4:6])[0]

    except Exception:
        pass

    return features


def extract_transport_features(
    packet: bytes,
    ip_header_len: int = 20,
    protocol: int = 6,
) -> TransportFeatures:
    """Extract transport layer features from TCP/UDP packet."""
    features = TransportFeatures()
    features.protocol = PROTOCOL_MAP.get(protocol, "OTHER")

    if len(packet) < ip_header_len + 8:
        return features

    try:
        transport_header = packet[ip_header_len:]

        if protocol == 6:  # TCP
            if len(transport_header) < 20:
                return features

            features.src_port = struct.unpack("!H", transport_header[0:2])[0]
            features.dst_port = struct.unpack("!H", transport_header[2:4])[0]
            features.tcp_seq = struct.unpack("!I", transport_header[4:8])[0]
            features.tcp_ack = struct.unpack("!I", transport_header[8:12])[0]

            data_offset = (transport_header[12] >> 4) & 0xF
            features.tcp_options_len = max(0, (data_offset - 5) * 4)

            features.tcp_flags = transport_header[13]
            features.is_syn = bool(features.tcp_flags & TCP_FLAGS["SYN"])
            features.is_syn_ack = features.is_syn and bool(features.tcp_flags & TCP_FLAGS["ACK"])
            features.is_fin = bool(features.tcp_flags & TCP_FLAGS["FIN"])
            features.is_rst = bool(features.tcp_flags & TCP_FLAGS["RST"])
            features.is_psh = bool(features.tcp_flags & TCP_FLAGS["PSH"])
            features.is_ack = bool(features.tcp_flags & TCP_FLAGS["ACK"])
            features.is_urg = bool(features.tcp_flags & TCP_FLAGS["URG"])

            # XMAS scan: FIN+PSH+URG
            features.is_xmas = features.is_fin and features.is_psh and features.is_urg

            # NULL scan: no flags
            features.is_null = features.tcp_flags == 0

            features.tcp_window = struct.unpack("!H", transport_header[14:16])[0]
            features.tcp_urgent_ptr = struct.unpack("!H", transport_header[18:20])[0]

        elif protocol == 17:  # UDP
            features.src_port = struct.unpack("!H", transport_header[0:2])[0]
            features.dst_port = struct.unpack("!H", transport_header[2:4])[0]
            features.udp_length = struct.unpack("!H", transport_header[4:6])[0]

        elif protocol == 1:  # ICMP
            features.icmp_type = transport_header[0]
            features.icmp_code = transport_header[1]

    except Exception:
        pass

    return features


def extract_payload_features(payload: bytes) -> PayloadFeatures:
    """Extract payload-level features."""
    features = PayloadFeatures()

    if not payload:
        return features

    features.payload_size = len(payload)
    features.entropy = calculate_entropy(payload)
    features.byte_histogram = calculate_byte_histogram(payload)

    # Printable ratio
    features.printable_ratio = round(
        sum(1 for b in payload if 32 <= b <= 126) / max(len(payload), 1), 4
    )

    # Byte stats
    features.null_bytes = payload.count(0)
    features.high_bytes = sum(1 for b in payload if b > 127)

    # Unique bytes
    freq = [0] * 256
    for b in payload:
        freq[b] += 1
    features.unique_bytes = sum(1 for f in freq if f > 0)
    features.max_freq = round(max(freq) / max(len(payload), 1), 4)

    # N-gram entropy
    features.bigram_entropy = calculate_ngram_entropy(payload, 2)
    features.trigram_entropy = calculate_ngram_entropy(payload, 3)

    # Content detection
    features.has_pe_magic = payload[:2] == b"MZ"
    features.has_elf_magic = payload[:4] == b"\x7fELF"

    # Base64 detection
    features.has_base64 = _detect_base64(payload)

    # Hex encoding detection
    features.has_hex_encoded = _detect_hex_encoding(payload)

    # Hashes
    features.md5 = hashlib.md5(payload).hexdigest()
    features.sha256 = hashlib.sha256(payload).hexdigest()

    return features


def _detect_base64(data: bytes) -> bool:
    """Detect base64 encoded content."""
    if len(data) < 16:
        return False
    # High printable ratio + base64 charset
    printable = sum(1 for b in data if 32 <= b <= 126)
    if printable / len(data) < 0.9:
        return False
    # Check for base64 pattern
    b64_chars = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    b64_count = sum(1 for b in data[:256] if b in b64_chars)
    return b64_count / min(len(data), 256) > 0.95


def _detect_hex_encoding(data: bytes) -> bool:
    """Detect hex-encoded content."""
    if len(data) < 8:
        return False
    hex_chars = set(b"0123456789abcdefABCDEF")
    hex_count = sum(1 for b in data[:128] if b in hex_chars)
    return hex_count / min(len(data), 128) > 0.95


def extract_http_features(payload: bytes) -> HTTPFeatures:
    """Extract HTTP protocol features."""
    features = HTTPFeatures()

    if not payload or len(payload) < 10:
        return features

    try:
        text = payload[:4096].decode("utf-8", errors="ignore")
        lines = text.split("\r\n")

        if not lines:
            return features

        # Request line
        first_line = lines[0]
        if first_line.startswith(
            ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")
        ):
            parts = first_line.split(" ", 2)
            features.method = parts[0]
            if len(parts) > 1:
                features.uri = parts[1]
                features.uri_length = len(parts[1])
        elif first_line.startswith("HTTP/"):
            parts = first_line.split(" ", 2)
            if len(parts) > 1:
                try:
                    features.response_code = int(parts[1])
                except ValueError:
                    pass
                if len(parts) > 2:
                    features.response_reason = parts[2]

        # Headers
        for line in lines[1:]:
            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()

                if key == "host":
                    features.host = value
                elif key == "user-agent":
                    features.user_agent = value
                    features.has_suspicious_useragent = any(
                        ua.lower() in value.lower() for ua in HTTP_SUSPICIOUS_USERAGENTS
                    )
                elif key == "referer":
                    features.referer = value
                elif key == "content-type":
                    features.content_type = value
                elif key == "accept-language":
                    features.accept_language = value

                features.header_count += 1

        features.request_size = len(payload)

    except Exception:
        pass

    return features


def extract_tls_features(payload: bytes) -> TLSFeatures:
    """Extract TLS/SSL features."""
    features = TLSFeatures()

    if not payload or len(payload) < 5:
        return features

    try:
        # TLS record header
        content_type = payload[0]
        if content_type != 0x16:  # Not a handshake
            return features

        tls_major = payload[1]
        tls_minor = payload[2]

        features.tls_version_int = (tls_major << 8) | tls_minor

        version_map = {
            0x0300: "SSL 3.0",
            0x0301: "TLS 1.0",
            0x0302: "TLS 1.1",
            0x0303: "TLS 1.2",
            0x0304: "TLS 1.3",
        }
        features.tls_version = version_map.get(
            features.tls_version_int, f"Unknown (0x{features.tls_version_int:04x})"
        )

        # Check for weak versions
        if features.tls_version_int <= 0x0301:
            features.is_weak_cipher = True

    except Exception:
        pass

    return features


def extract_dns_features(payload: bytes, dst_port: int, src_port: int) -> DNSFeatures:
    """Extract DNS protocol features."""
    features = DNSFeatures()

    if not payload or len(payload) < 12:
        return features

    if dst_port != 53 and src_port != 53:
        return features

    try:
        # DNS header
        struct.unpack("!H", payload[0:2])[0]
        flags = struct.unpack("!H", payload[2:4])[0]

        features.is_response = bool((flags >> 15) & 1)
        features.response_code = flags & 0xF

        qdcount = struct.unpack("!H", payload[4:6])[0]
        ancount = struct.unpack("!H", payload[6:8])[0]
        nscount = struct.unpack("!H", payload[8:10])[0]
        arcount = struct.unpack("!H", payload[10:12])[0]

        features.answer_count = ancount
        features.authority_count = nscount
        features.additional_count = arcount
        features.is_nxdomain = features.response_code == 3

        # Parse query name
        if qdcount > 0 and len(payload) > 12:
            qname_parts = []
            idx = 12
            while idx < len(payload) and payload[idx] != 0:
                length = payload[idx]
                if idx + 1 + length > len(payload):
                    break
                qname_parts.append(
                    payload[idx + 1 : idx + 1 + length].decode("ascii", errors="ignore")
                )
                idx += 1 + length

            features.query_name = ".".join(qname_parts)
            features.query_name_length = len(features.query_name)
            features.subdomain_count = len(qname_parts)

            # Query type and class
            if idx + 5 <= len(payload):
                features.query_type = struct.unpack("!H", payload[idx + 1 : idx + 3])[0]
                features.query_class = struct.unpack("!H", payload[idx + 3 : idx + 5])[0]
                features.query_type_name = DNS_RECORD_TYPES.get(
                    features.query_type, f"TYPE{features.query_type}"
                )

                features.is_txt_query = features.query_type == 16
                features.is_null_query = features.query_type == 10

            # Tunneling indicators
            if features.query_name:
                features.query_entropy = calculate_entropy(features.query_name.encode())

                # Long subdomain
                for part in qname_parts:
                    if len(part) > 50:
                        features.has_long_subdomain = True
                        break

                # High entropy
                features.has_high_entropy_subdomain = features.query_entropy > 4.0

                # Base64-like subdomain
                features.has_base64_subdomain = bool(
                    re.match(
                        r"^[A-Za-z0-9+/]{20,}={0,2}$",
                        qname_parts[-1] if qname_parts else "",
                    )
                )

    except Exception:
        pass

    return features


def extract_pattern_matches(
    payload: bytes, http: HTTPFeatures, dns: DNSFeatures
) -> List[Dict[str, str]]:
    """Scan for malicious patterns in payload and protocol data."""
    matches = []

    if not payload:
        return matches

    payload_lower = payload.lower()

    # SQL Injection
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, payload_lower):
            matches.append(
                {
                    "type": "SQL Injection",
                    "severity": "critical",
                    "pattern": pattern.decode(errors="ignore"),
                }
            )
            break

    # XSS
    for pattern in XSS_PATTERNS:
        if re.search(pattern, payload_lower):
            matches.append(
                {
                    "type": "XSS",
                    "severity": "high",
                    "pattern": pattern.decode(errors="ignore"),
                }
            )
            break

    # Path Traversal
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, payload_lower):
            matches.append(
                {
                    "type": "Path Traversal",
                    "severity": "high",
                    "pattern": pattern.decode(errors="ignore"),
                }
            )
            break

    # Command Injection
    for pattern in COMMAND_INJECTION_PATTERNS:
        if re.search(pattern, payload_lower):
            matches.append(
                {
                    "type": "Command Injection",
                    "severity": "critical",
                    "pattern": pattern.decode(errors="ignore"),
                }
            )
            break

    # Suspicious User-Agent
    if http.has_suspicious_useragent:
        matches.append(
            {
                "type": "Suspicious User-Agent",
                "severity": "high",
                "pattern": http.user_agent,
            }
        )

    # DNS tunneling
    if dns.has_long_subdomain or dns.has_high_entropy_subdomain:
        matches.append(
            {
                "type": "DNS Tunneling",
                "severity": "medium",
                "pattern": f"query={dns.query_name}",
            }
        )

    return matches


def perform_full_dpi(
    packet_bytes: bytes,
    payload: bytes = b"",
    src_ip: str = "",
    dst_ip: str = "",
    direction: str = "in",
    flow_state: Optional[Dict] = None,
) -> DPIResult:
    """Perform full DPI extraction on a packet.

    Args:
        packet_bytes: Raw IP packet bytes
        payload: Application payload (TCP/UDP data)
        src_ip: Source IP address
        dst_ip: Destination IP address
        direction: 'in' or 'out'
        flow_state: Existing flow state for behavioral features

    Returns:
        DPIResult with all extracted features
    """
    result = DPIResult()

    # Network features
    result.network = extract_network_features(packet_bytes)

    # Transport features
    ip_header_len = result.network.ip_ihl * 4
    protocol = packet_bytes[9] if len(packet_bytes) > 9 else 0
    result.transport = extract_transport_features(packet_bytes, ip_header_len, protocol)

    # Payload features
    if payload:
        result.payload = extract_payload_features(payload)

    # Protocol identification and application features
    dst_port = result.transport.dst_port
    src_port = result.transport.src_port

    # HTTP
    if dst_port in [80, 8080, 8443] or src_port in [80, 8080, 8443]:
        result.http = extract_http_features(payload)
        if result.http.method or result.http.response_code:
            result.app_protocol = "HTTP"

    # TLS
    elif dst_port in [443, 8443] or (payload and len(payload) >= 3 and payload[0] == 0x16):
        result.tls = extract_tls_features(payload)
        result.app_protocol = "TLS"

    # DNS
    elif dst_port == 53 or src_port == 53:
        result.dns = extract_dns_features(payload, dst_port, src_port)
        result.app_protocol = "DNS"

    # SSH
    elif dst_port == 22 or src_port == 22:
        result.app_protocol = "SSH"

    # Port-based fallback
    else:
        port_map = {
            21: "FTP",
            25: "SMTP",
            110: "POP3",
            143: "IMAP",
            445: "SMB",
            3389: "RDP",
            5432: "PostgreSQL",
            3306: "MySQL",
            6379: "Redis",
            27017: "MongoDB",
        }
        result.app_protocol = port_map.get(dst_port, port_map.get(src_port, "Unknown"))

    # Pattern matching
    result.pattern_matches = extract_pattern_matches(payload, result.http, result.dns)

    return result


def dpi_result_to_dict(result: DPIResult) -> Dict[str, Any]:
    """Convert DPIResult to a flat dictionary for JSON serialization."""
    return {
        "app_protocol": result.app_protocol,
        # Network
        "ip_flags_df": result.network.ip_flags_df,
        "ip_flags_mf": result.network.ip_flags_mf,
        "ttl": result.network.ttl,
        "ip_total_length": result.network.ip_total_length,
        # Transport
        "src_port": result.transport.src_port,
        "dst_port": result.transport.dst_port,
        "protocol": result.transport.protocol,
        "tcp_flags": result.transport.tcp_flags,
        "tcp_window": result.transport.tcp_window,
        "is_syn": result.transport.is_syn,
        "is_syn_ack": result.transport.is_syn_ack,
        "is_fin": result.transport.is_fin,
        "is_rst": result.transport.is_rst,
        "is_xmas": result.transport.is_xmas,
        "is_null": result.transport.is_null,
        # Payload
        "payload_size": result.payload.payload_size,
        "entropy": result.payload.entropy,
        "printable_ratio": result.payload.printable_ratio,
        "unique_bytes": result.payload.unique_bytes,
        "bigram_entropy": result.payload.bigram_entropy,
        "has_pe_magic": result.payload.has_pe_magic,
        "has_elf_magic": result.payload.has_elf_magic,
        "has_base64": result.payload.has_base64,
        "payload_md5": result.payload.md5,
        "payload_sha256": result.payload.sha256,
        # HTTP
        "http_method": result.http.method,
        "http_host": result.http.host,
        "http_uri_length": result.http.uri_length,
        "http_user_agent": result.http.user_agent,
        "http_response_code": result.http.response_code,
        "http_suspicious_ua": result.http.has_suspicious_useragent,
        # TLS
        "tls_version": result.tls.tls_version,
        "tls_weak_cipher": result.tls.is_weak_cipher,
        "ja3_hash": result.tls.ja3_hash,
        "ja3_malware": result.tls.ja3_malware_family,
        # DNS
        "dns_query": result.dns.query_name,
        "dns_type": result.dns.query_type_name,
        "dns_nxdomain": result.dns.is_nxdomain,
        "dns_tunneling": result.dns.has_long_subdomain or result.dns.has_high_entropy_subdomain,
        # Patterns
        "pattern_matches": result.pattern_matches,
    }


def perform_dpi_with_suricata(
    packet_bytes: bytes,
    payload: bytes = b"",
    src_ip: str = "",
    dst_ip: str = "",
    direction: str = "in",
    flow_state: Optional[Dict] = None,
) -> Tuple[DPIResult, List[Dict[str, Any]]]:
    """Perform full DPI extraction with Suricata rule matching (L0 Layer Integration).

    This function integrates signature-based detection with DPI for the L0 layer.

    Args:
        packet_bytes: Raw IP packet bytes
        payload: Application payload (TCP/UDP data)
        src_ip: Source IP address
        dst_ip: Destination IP address
        direction: 'in' or 'out'
        flow_state: Existing flow state for behavioral features

    Returns:
        Tuple of (DPIResult, suricata_matches)
    """
    result = perform_full_dpi(
        packet_bytes=packet_bytes,
        payload=payload,
        src_ip=src_ip,
        dst_ip=dst_ip,
        direction=direction,
        flow_state=flow_state,
    )

    suricata_matches = []

    try:
        from ..suricata_integration import get_suricata_engine

        engine = get_suricata_engine()

        if engine and payload:
            detections = engine.detect(
                payload=payload,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=result.transport.src_port,
                dst_port=result.transport.dst_port,
                protocol=result.transport.protocol,
                flow_state=flow_state,
            )

            suricata_matches = [
                {
                    "rule_id": d.rule_id,
                    "rule_msg": d.rule_msg,
                    "severity": d.severity,
                    "classtype": d.classtype,
                    "confidence": d.confidence,
                    "action": d.action,
                    "metadata": d.metadata,
                }
                for d in detections
            ]

            for match in suricata_matches:
                result.pattern_matches.append(
                    {
                        "type": f"Suricata: {match['classtype']}",
                        "severity": match["severity"],
                        "pattern": match["rule_msg"],
                        "rule_id": match["rule_id"],
                        "source": "suricata",
                    }
                )
    except Exception:
        pass

    return result, suricata_matches


class L0DetectionPipeline:
    """L0 Layer Detection Pipeline integrating DPI and Suricata IDS.

    This class provides a unified interface for the L0 layer that combines:
    - Deep Packet Inspection (DPI)
    - Signature-based detection (Suricata rules)
    - Pattern matching (built-in)
    """

    def __init__(self, enable_suricata: bool = True):
        self.enable_suricata = enable_suricata
        self._suricata_engine = None

        if enable_suricata:
            try:
                from ..suricata_integration import get_suricata_engine

                self._suricata_engine = get_suricata_engine()
            except Exception:
                pass

    def process_packet(
        self,
        packet_bytes: bytes,
        payload: bytes = b"",
        src_ip: str = "",
        dst_ip: str = "",
        direction: str = "in",
        flow_state: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Process a packet through the L0 pipeline.

        Args:
            packet_bytes: Raw IP packet bytes
            payload: Application payload
            src_ip: Source IP address
            dst_ip: Destination IP address
            direction: 'in' or 'out'
            flow_state: Flow state dict

        Returns:
            Dict with DPI results and Suricata matches
        """
        dpi_result, suricata_matches = perform_dpi_with_suricata(
            packet_bytes=packet_bytes,
            payload=payload,
            src_ip=src_ip,
            dst_ip=dst_ip,
            direction=direction,
            flow_state=flow_state,
        )

        dpi_dict = dpi_result_to_dict(dpi_result)

        threat_score = 0.0
        threat_level = "normal"

        if dpi_result.pattern_matches:
            severity_weights = {
                "critical": 1.0,
                "high": 0.75,
                "medium": 0.5,
                "low": 0.25,
            }
            for match in dpi_result.pattern_matches:
                severity = match.get("severity", "low")
                threat_score += severity_weights.get(severity, 0.25)

        if suricata_matches:
            for match in suricata_matches:
                severity = match.get("severity", "low")
                severity_weights = {
                    "critical": 1.0,
                    "high": 0.75,
                    "medium": 0.5,
                    "low": 0.25,
                }
                threat_score += severity_weights.get(severity, 0.25) * match.get("confidence", 1.0)

        threat_score = min(threat_score, 1.0)

        if threat_score >= 0.8:
            threat_level = "critical"
        elif threat_score >= 0.6:
            threat_level = "high"
        elif threat_score >= 0.4:
            threat_level = "medium"
        elif threat_score >= 0.2:
            threat_level = "low"

        return {
            "dpi": dpi_dict,
            "suricata_matches": suricata_matches,
            "threat_score": round(threat_score, 3),
            "threat_level": threat_level,
            "signature_detected": len(suricata_matches) > 0,
            "pattern_detected": len(dpi_result.pattern_matches) > 0,
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get pipeline statistics."""
        stats = {
            "suricata_enabled": self._suricata_engine is not None,
        }

        if self._suricata_engine:
            stats["suricata_stats"] = self._suricata_engine.get_stats()

        return stats
