"""Feature Vector Constructor.

Combines all extracted features into normalized vectors for ML models.
Maintains a feature registry that maps feature names to vector indices.
"""

from __future__ import annotations

import json
from typing import Dict, List, Optional, Tuple

import numpy as np

from . import DPIResult, dpi_result_to_dict

# ═══════════════════════════════════════════════════════════════════════════════
#  Feature Registry
# ═══════════════════════════════════════════════════════════════════════════════


# Numeric features (normalized 0-1)
NUMERIC_FEATURES = [
    ("ttl", 0, 255),
    ("ip_total_length", 0, 65535),
    ("src_port", 0, 65535),
    ("dst_port", 0, 65535),
    ("tcp_window", 0, 65535),
    ("payload_size", 0, 65535),
    ("entropy", 0, 8),
    ("printable_ratio", 0, 1),
    ("unique_bytes", 0, 256),
    ("bigram_entropy", 0, 16),
    ("http_uri_length", 0, 10000),
    ("http_response_code", 100, 599),
    ("dns_query_length", 0, 255),
]

# Boolean features (0 or 1)
BOOLEAN_FEATURES = [
    "ip_flags_df",
    "ip_flags_mf",
    "is_syn",
    "is_syn_ack",
    "is_fin",
    "is_rst",
    "is_psh",
    "is_ack",
    "is_urg",
    "is_xmas",
    "is_null",
    "has_pe_magic",
    "has_elf_magic",
    "has_base64",
    "http_suspicious_ua",
    "tls_weak_cipher",
    "dns_nxdomain",
    "dns_tunneling",
    "dns_is_txt",
]

# Categorical features (one-hot encoded)
CATEGORICAL_FEATURES = {
    "protocol": ["TCP", "UDP", "ICMP", "OTHER"],
    "app_protocol": ["HTTP", "TLS", "DNS", "SSH", "FTP", "SMTP", "Unknown"],
    "tls_version": ["SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"],
    "dns_type": ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR"],
}

# Flow-level features (from flow state)
FLOW_FEATURES = [
    ("duration", 0, 3600),
    ("total_packets", 0, 100000),
    ("total_bytes", 0, 10000000),
    ("bytes_per_second", 0, 10000000),
    ("packets_per_second", 0, 10000),
    ("fwd_bwd_byte_ratio", 0, 100),
    ("pkt_size_mean", 0, 65535),
    ("pkt_size_std", 0, 65535),
    ("inter_arrival_mean", 0, 60),
    ("syn_count", 0, 10000),
    ("rst_count", 0, 10000),
]


class FeatureVector:
    """Constructs normalized feature vectors from DPI results.

    Maintains a registry of feature names and their vector indices.
    """

    def __init__(self):
        self._build_registry()
        self.vector_size = self._next_index

    def _build_registry(self) -> None:
        """Build feature name to index mapping."""
        self.registry: Dict[str, int] = {}
        self._next_index = 0

        # Numeric features
        for name, _, _ in NUMERIC_FEATURES:
            self.registry[name] = self._next_index
            self._next_index += 1

        # Boolean features
        for name in BOOLEAN_FEATURES:
            self.registry[name] = self._next_index
            self._next_index += 1

        # Categorical features (one-hot)
        for name, values in CATEGORICAL_FEATURES.items():
            for val in values:
                self.registry[f"{name}_{val}"] = self._next_index
                self._next_index += 1

        # Flow features
        for name, _, _ in FLOW_FEATURES:
            self.registry[name] = self._next_index
            self._next_index += 1

    def build_vector(self, dpi_result: DPIResult, flow_state: Optional[Dict] = None) -> np.ndarray:
        """Build a normalized feature vector from DPI result.

        Args:
            dpi_result: DPI extraction result
            flow_state: Optional flow-level state dict

        Returns:
            numpy array of shape (vector_size,)
        """
        vector = np.zeros(self.vector_size, dtype=np.float32)
        features = dpi_result_to_dict(dpi_result)

        # Numeric features (normalize to 0-1)
        for name, min_val, max_val in NUMERIC_FEATURES:
            if name in self.registry:
                val = features.get(name, 0)
                if val is not None:
                    normalized = (float(val) - min_val) / (max_val - min_val)
                    vector[self.registry[name]] = max(0, min(1, normalized))

        # Boolean features
        for name in BOOLEAN_FEATURES:
            if name in self.registry:
                val = features.get(name, False)
                vector[self.registry[name]] = 1.0 if val else 0.0

        # Categorical features (one-hot)
        for name, values in CATEGORICAL_FEATURES.items():
            val = features.get(name, "Unknown")
            for v in values:
                key = f"{name}_{v}"
                if key in self.registry:
                    vector[self.registry[key]] = 1.0 if val == v else 0.0

        # Flow features
        if flow_state:
            for name, min_val, max_val in FLOW_FEATURES:
                if name in self.registry:
                    val = flow_state.get(name, 0)
                    if val is not None:
                        normalized = (float(val) - min_val) / (max_val - min_val)
                        vector[self.registry[name]] = max(0, min(1, normalized))

        return vector

    def get_feature_names(self) -> List[str]:
        """Get ordered list of feature names."""
        names = [""] * self.vector_size
        for name, idx in self.registry.items():
            names[idx] = name
        return names

    def save_config(self, path: str) -> None:
        """Save feature registry to JSON."""
        config = {
            "vector_size": self.vector_size,
            "registry": self.registry,
            "numeric_features": NUMERIC_FEATURES,
            "boolean_features": BOOLEAN_FEATURES,
            "categorical_features": CATEGORICAL_FEATURES,
            "flow_features": FLOW_FEATURES,
        }
        with open(path, "w") as f:
            json.dump(config, f, indent=2)

    def load_config(self, path: str) -> None:
        """Load feature registry from JSON."""
        with open(path) as f:
            config = json.load(f)
        self.registry = config["registry"]
        self.vector_size = config["vector_size"]


def create_feature_vector(
    dpi_result: DPIResult, flow_state: Optional[Dict] = None
) -> Tuple[np.ndarray, FeatureVector]:
    """Convenience function to create a feature vector.

    Returns:
        Tuple of (vector, registry) for inspection
    """
    fv = FeatureVector()
    vector = fv.build_vector(dpi_result, flow_state)
    return vector, fv


def extract_if_features(flow: Dict) -> np.ndarray:
    """Extract 8 features for Isolation Forest model.

    These match the current trained model (model_00000000_000000.pkl).
    Features: bytes_in, bytes_out, packets_in, packets_out, duration,
              src_port, dst_port, protocol_encoded

    Args:
        flow: Flow dict with keys like bytes_in, bytes_out, etc.

    Returns:
        numpy array of shape (1, 8)
    """
    protocol_map = {"TCP": 1, "UDP": 2, "ICMP": 3}

    return np.array(
        [
            [
                flow.get("bytes_in", 0),
                flow.get("bytes_out", 0),
                flow.get("packets_in", 1),
                flow.get("packets_out", 1),
                flow.get("duration", 0),
                flow.get("src_port", 0),
                flow.get("dst_port", 0),
                protocol_map.get(flow.get("protocol", "OTHER"), 0),
            ]
        ],
        dtype=np.float64,
    )


def extract_67_features(dpi_result: DPIResult, flow_state: Optional[Dict] = None) -> np.ndarray:
    """Extract 67 features for advanced models.

    Uses the full DPI feature extraction for training new models.
    This is the target feature set for retrained IF and future models.

    Args:
        dpi_result: DPI extraction result
        flow_state: Optional flow state dict

    Returns:
        numpy array of shape (1, 67)
    """
    fv = FeatureVector()
    return fv.build_vector(dpi_result, flow_state).reshape(1, -1)


NSL_KDD_SERVICE_MAP = {
    20: "ftp_data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    27017: "mongodb",
    8080: "http",
    8443: "https",
}


def _get_service_from_port(port: int, protocol: str) -> str:
    """Map port to NSL-KDD service name."""
    if port in NSL_KDD_SERVICE_MAP:
        return NSL_KDD_SERVICE_MAP[port]
    if protocol == "TCP":
        return "private" if port > 1023 else "other"
    if protocol == "UDP":
        return "private" if port > 1023 else "other"
    if protocol == "ICMP":
        return "eco_i"
    return "other"


def _encode_protocol(protocol: str) -> int:
    """Encode protocol type for NSL-KDD."""
    protocol = protocol.upper() if isinstance(protocol, str) else "OTHER"
    mapping = {"TCP": 0, "UDP": 1, "ICMP": 2}
    return mapping.get(protocol, 3)


def _encode_flag(packet: Dict) -> int:
    """Encode TCP flags to NSL-KDD flag value."""
    if packet.get("protocol", "").upper() != "TCP":
        return 0

    flags = packet.get("tcp_flags", {})
    syn = flags.get("syn", False) if isinstance(flags, dict) else False
    ack = flags.get("ack", False) if isinstance(flags, dict) else False
    fin = flags.get("fin", False) if isinstance(flags, dict) else False
    rst = flags.get("rst", False) if isinstance(flags, dict) else False
    flags.get("psh", False) if isinstance(flags, dict) else False

    if syn and not ack:
        return 0  # S0 - Connection attempt
    if syn and ack:
        return 1  # S1 - Connection established
    if fin and ack:
        return 2  # SF - Normal termination
    if rst:
        return 3  # REJ - Connection rejected
    if ack and not syn:
        return 4  # S2 - Connection established (no SYN)
    if fin:
        return 5  # S3 - Connection termination
    return 6  # OTH - Other


def extract_nslkdd_features(packet: Dict) -> np.ndarray:
    """Extract 41 NSL-KDD features from a packet.

    Maps packet fields to NSL-KDD features where possible. Features requiring
    flow-level context (count, rate features) default to zero.

    Args:
        packet: Dict with packet fields. Expected keys:
            - protocol: str (TCP/UDP/ICMP)
            - src_port: int
            - dst_port: int
            - src_bytes: int (payload size from source)
            - dst_bytes: int (payload size to source)
            - duration: float (connection duration)
            - tcp_flags: dict with syn/ack/fin/rst/psh/urg booleans
            - ttl: int
            - wrong_fragment: int
            - urgent: int

    Returns:
        numpy array of shape (41,) with NSL-KDD features
    """
    features = np.zeros(41, dtype=np.float32)

    protocol = packet.get("protocol", "TCP")
    src_port = packet.get("src_port", 0)
    dst_port = packet.get("dst_port", 0)

    features[0] = float(packet.get("duration", 0))
    features[1] = float(_encode_protocol(protocol))
    service = _get_service_from_port(dst_port, protocol)
    service_map = {
        "ftp_data": 0,
        "ftp": 1,
        "ssh": 2,
        "telnet": 3,
        "smtp": 4,
        "domain": 5,
        "http": 6,
        "pop3": 7,
        "imap": 8,
        "https": 9,
        "private": 10,
        "other": 11,
        "eco_i": 12,
    }
    features[2] = float(service_map.get(service, 11))
    features[3] = float(_encode_flag(packet))
    features[4] = float(packet.get("src_bytes", packet.get("payload_size", 0)))
    features[5] = float(packet.get("dst_bytes", 0))
    features[6] = (
        1.0
        if src_port == dst_port and packet.get("src_ip", "") == packet.get("dst_ip", "")
        else 0.0
    )
    features[7] = float(packet.get("wrong_fragment", 0))
    features[8] = float(packet.get("urgent", 0))
    features[9] = float(packet.get("hot", 0))
    features[10] = float(packet.get("num_failed_logins", 0))
    features[11] = float(packet.get("logged_in", 0))
    features[12] = float(packet.get("num_compromised", 0))
    features[13] = float(packet.get("root_shell", 0))
    features[14] = float(packet.get("su_attempted", 0))
    features[15] = float(packet.get("num_root", 0))
    features[16] = float(packet.get("num_file_creations", 0))
    features[17] = float(packet.get("num_shells", 0))
    features[18] = float(packet.get("num_access_files", 0))
    features[19] = float(packet.get("num_outbound_cmds", 0))
    features[20] = float(packet.get("is_host_login", 0))
    features[21] = float(packet.get("is_guest_login", 0))
    features[22] = float(packet.get("count", 0))
    features[23] = float(packet.get("srv_count", 0))
    features[24] = float(packet.get("serror_rate", 0))
    features[25] = float(packet.get("srv_serror_rate", 0))
    features[26] = float(packet.get("rerror_rate", 0))
    features[27] = float(packet.get("srv_rerror_rate", 0))
    features[28] = float(packet.get("same_srv_rate", 0))
    features[29] = float(packet.get("diff_srv_rate", 0))
    features[30] = float(packet.get("srv_diff_host_rate", 0))
    features[31] = float(packet.get("dst_host_count", 0))
    features[32] = float(packet.get("dst_host_srv_count", 0))
    features[33] = float(packet.get("dst_host_same_srv_rate", 0))
    features[34] = float(packet.get("dst_host_diff_srv_rate", 0))
    features[35] = float(packet.get("dst_host_same_src_port_rate", 0))
    features[36] = float(packet.get("dst_host_srv_diff_host_rate", 0))
    features[37] = float(packet.get("dst_host_serror_rate", 0))
    features[38] = float(packet.get("dst_host_srv_serror_rate", 0))
    features[39] = float(packet.get("dst_host_rerror_rate", 0))
    features[40] = float(packet.get("dst_host_srv_rerror_rate", 0))

    return features
