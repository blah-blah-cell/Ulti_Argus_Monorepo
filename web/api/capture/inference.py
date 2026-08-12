"""Build the truthful observation consumed by signatures and the optional baseline."""

from __future__ import annotations

import hashlib
import math
import time
from statistics import fmean, pstdev
from typing import Any


def _mean(values: list[float | int]) -> float:
    return round(fmean(values), 4) if values else 0.0


def _std(values: list[float | int]) -> float:
    return round(pstdev(values), 4) if len(values) > 1 else 0.0


def build_observation(
    flow: dict[str, Any], dpi_app: str, pattern_matches: list[dict[str, Any]]
) -> dict[str, Any]:
    """Return observed metrics and signature evidence, never a benign verdict."""
    duration = max(float(flow.get("duration", 0.0)), 0.0)
    sizes = list(flow.get("pkt_sizes", []))
    arrivals = list(flow.get("inter_arrivals", []))
    windows = list(flow.get("tcp_windows", []))
    payloads = list(flow.get("payloads", []))
    payload = payloads[0] if payloads else b""
    bytes_in = int(flow.get("bytes_in", 0))
    bytes_out = int(flow.get("bytes_out", 0))
    packets_in = int(flow.get("packets_in", 0))
    packets_out = int(flow.get("packets_out", 0))
    status = "SUSPICIOUS" if pattern_matches else "UNASSESSED"

    return {
        "flow_id": flow.get("flow_id", ""),
        "src_ip": flow.get("src_ip", ""),
        "dst_ip": flow.get("dst_ip", ""),
        "src_port": int(flow.get("src_port", 0)),
        "dst_port": int(flow.get("dst_port", 0)),
        "protocol": flow.get("protocol", "OTHER"),
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "packets_in": packets_in,
        "packets_out": packets_out,
        "duration": round(duration, 4),
        "timestamp": float(flow.get("last_seen", time.time())),
        "dpi_app": flow.get("dpi_app", dpi_app),
        "dpi_tls_version": flow.get("dpi_tls_version"),
        "dpi_http_method": flow.get("dpi_http_method"),
        "dpi_http_host": flow.get("dpi_http_host"),
        "dpi_http_user_agent": flow.get("dpi_http_user_agent"),
        "dpi_dns_query": flow.get("dpi_dns_query"),
        "dpi_dns_type": flow.get("dpi_dns_type"),
        "dpi_patterns": pattern_matches,
        "pkt_size_min": min(sizes) if sizes else 0,
        "pkt_size_max": max(sizes) if sizes else 0,
        "pkt_size_mean": _mean(sizes),
        "pkt_size_std": _std(sizes),
        "inter_arrival_mean": _mean(arrivals),
        "inter_arrival_std": _std(arrivals),
        "tcp_window_min": min(windows) if windows else 0,
        "tcp_window_max": max(windows) if windows else 0,
        "tcp_window_mean": _mean(windows),
        "tcp_syn_count": int(flow.get("tcp_syn_count", 0)),
        "tcp_syn_ack_count": int(flow.get("tcp_syn_ack_count", 0)),
        "tcp_fin_count": int(flow.get("tcp_fin_count", 0)),
        "tcp_rst_count": int(flow.get("tcp_rst_count", 0)),
        "tcp_ack_count": int(flow.get("tcp_ack_count", 0)),
        "bytes_per_second": round((bytes_in + bytes_out) / max(duration, 0.001), 2),
        "packets_per_second": round(
            (packets_in + packets_out) / max(duration, 0.001), 2
        ),
        "payload_size": sum(len(item) for item in payloads),
        "payloads_count": len(payloads),
        "dpi_payload_hash": hashlib.sha256(payload).hexdigest()[:16] if payload else None,
        "route": "COMMUNITY_OBSERVE_ONLY",
        "layer": "SIGNATURES" if pattern_matches else "OBSERVATION",
        "status": status,
        "decision_provenance": {
            "detector": "signature_rules" if pattern_matches else None,
            "trained_model": False,
            "decision_time": "online",
        },
        "health": "degraded" if not math.isfinite(duration) else "healthy",
    }
