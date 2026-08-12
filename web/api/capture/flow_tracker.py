"""Bounded bidirectional flow aggregation for observed packets."""

from __future__ import annotations

import hashlib
import threading
import time
from typing import Any

from web.api.capture.dpi import dpi_identify_protocol, dpi_scan_patterns


class FlowTracker:
    """Aggregate packets until idle timeout or TCP termination."""

    def __init__(self, timeout: float = 5.0, max_flows: int = 10_000):
        self.timeout = timeout
        self.max_flows = max_flows
        self.flows: dict[tuple[Any, ...], dict[str, Any]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(info: dict[str, Any]) -> tuple[Any, ...]:
        left = (str(info.get("src_ip", "")), int(info.get("src_port", 0)))
        right = (str(info.get("dst_ip", "")), int(info.get("dst_port", 0)))
        return (*sorted((left, right)), str(info.get("protocol", "OTHER")))

    @staticmethod
    def _new_flow(info: dict[str, Any], now: float) -> dict[str, Any]:
        identity = (
            f"{info.get('src_ip')}:{info.get('src_port', 0)}-"
            f"{info.get('dst_ip')}:{info.get('dst_port', 0)}-"
            f"{info.get('protocol')}-{now:.9f}"
        )
        return {
            "flow_id": hashlib.sha256(identity.encode()).hexdigest()[:20],
            "src_ip": info.get("src_ip", ""),
            "dst_ip": info.get("dst_ip", ""),
            "src_port": int(info.get("src_port", 0)),
            "dst_port": int(info.get("dst_port", 0)),
            "protocol": info.get("protocol", "OTHER"),
            "first_seen": now,
            "last_seen": now,
            "duration": 0.0,
            "bytes_in": 0,
            "bytes_out": 0,
            "packets_in": 0,
            "packets_out": 0,
            "pkt_sizes": [],
            "inter_arrivals": [],
            "tcp_windows": [],
            "ip_ttls": [],
            "payloads": [],
            "dpi_results": [],
            "pattern_matches": [],
            "tcp_syn_count": 0,
            "tcp_syn_ack_count": 0,
            "tcp_fin_count": 0,
            "tcp_rst_count": 0,
            "tcp_ack_count": 0,
            "tcp_null_count": 0,
            "tcp_xmas_count": 0,
        }

    def update(self, info: dict[str, Any]) -> list[dict[str, Any]]:
        now = float(info.get("timestamp", time.time()))
        key = self._key(info)
        with self._lock:
            completed = self._expire(now)
            if key not in self.flows and len(self.flows) >= self.max_flows:
                oldest = min(self.flows, key=lambda item: self.flows[item]["last_seen"])
                completed.append(self.flows.pop(oldest))
            flow = self.flows.setdefault(key, self._new_flow(info, now))
            reverse = info.get("src_ip") != flow["src_ip"] or int(
                info.get("src_port", 0)
            ) != flow["src_port"]
            elapsed = max(0.0, now - float(flow["last_seen"]))
            if flow["pkt_sizes"]:
                flow["inter_arrivals"].append(elapsed)
            flow["last_seen"] = now
            flow["duration"] = max(0.0, now - float(flow["first_seen"]))
            length = max(0, int(info.get("length", 0)))
            flow["pkt_sizes"].append(length)
            flow["ip_ttls"].append(int(info.get("ip_ttl", 0)))
            direction = "out" if reverse else "in"
            flow[f"bytes_{direction}"] += length
            flow[f"packets_{direction}"] += 1
            window = info.get("tcp_window")
            if window is not None:
                flow["tcp_windows"].append(int(window))
            for source, target in (
                ("is_syn", "tcp_syn_count"),
                ("is_syn_ack", "tcp_syn_ack_count"),
                ("is_fin", "tcp_fin_count"),
                ("is_rst", "tcp_rst_count"),
                ("is_ack", "tcp_ack_count"),
                ("is_null", "tcp_null_count"),
                ("is_xmas", "tcp_xmas_count"),
            ):
                flow[target] += int(bool(info.get(source)))
            payload = bytes(info.get("payload", b""))[:2048]
            if payload:
                if len(flow["payloads"]) < 4:
                    flow["payloads"].append(payload)
                dpi = dpi_identify_protocol(
                    payload, flow["dst_port"], flow["src_port"]
                )
                flow["dpi_results"].append(dpi)
                flow["dpi_app"] = dpi.get("app_id", "Unknown")
                for match in dpi_scan_patterns(payload):
                    if match not in flow["pattern_matches"]:
                        flow["pattern_matches"].append(match)
            if info.get("is_fin") or info.get("is_rst"):
                completed.append(self.flows.pop(key))
            return completed

    def _expire(self, now: float) -> list[dict[str, Any]]:
        keys = [
            key
            for key, flow in self.flows.items()
            if now - float(flow["last_seen"]) >= self.timeout
        ]
        return [self.flows.pop(key) for key in keys]

    def flush(self) -> list[dict[str, Any]]:
        with self._lock:
            completed = list(self.flows.values())
            self.flows.clear()
            return completed

    def active_count(self) -> int:
        with self._lock:
            return len(self.flows)
