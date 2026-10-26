"""Scapy packet -> flow-info dict adapter.

The scapy import is intentionally inside the function so this module can be
imported on systems without scapy (e.g. CI lint hosts).
"""
from __future__ import annotations

import time

from web.api.capture.constants import PROTOCOL_MAP


def extract_packet(pkt) -> dict | None:
    """Layer 0: Extract packet info with FULL DPI feature extraction."""
    try:
        from scapy.layers.inet import ICMP, IP, TCP, UDP

        try:
            from scapy.layers.inet6 import IPv6
        except ImportError:
            IPv6 = None

        if isinstance(pkt, (bytes, bytearray)):
            pkt = IP(pkt)

        info = {"length": len(pkt), "direction": "in", "timestamp": time.time()}

        if IP in pkt:
            ip_layer = pkt[IP]
            info["src_ip"] = ip_layer.src
            info["dst_ip"] = ip_layer.dst
            info["protocol"] = PROTOCOL_MAP.get(ip_layer.proto, "OTHER")
            info["ip_ttl"] = ip_layer.ttl
            info["ip_id"] = ip_layer.id
            info["ip_flags_df"] = bool(ip_layer.flags.DF)
            info["ip_flags_mf"] = bool(ip_layer.flags.MF)
            info["ip_fragment_offset"] = ip_layer.frag
            info["ip_total_length"] = ip_layer.len
            info["ip_version"] = ip_layer.version
            info["ip_ihl"] = ip_layer.ihl
        elif IPv6 and IPv6 in pkt:
            ipv6_layer = pkt[IPv6]
            info["src_ip"] = ipv6_layer.src
            info["dst_ip"] = ipv6_layer.dst
            info["protocol"] = PROTOCOL_MAP.get(ipv6_layer.nh, "OTHER")
            info["ip_ttl"] = ipv6_layer.hlim
            info["ip_id"] = 0
            info["ip_flags_df"] = True
            info["ip_flags_mf"] = False
            info["ip_fragment_offset"] = 0
            info["ip_total_length"] = ipv6_layer.plen
            info["ip_version"] = 6
            info["ip_ihl"] = 40
        else:
            return None

        if TCP in pkt:
            tcp_layer = pkt[TCP]
            info["src_port"] = tcp_layer.sport
            info["dst_port"] = tcp_layer.dport
            info["protocol"] = "TCP"
            info["tcp_flags"] = int(tcp_layer.flags)
            info["tcp_window"] = tcp_layer.window
            info["tcp_seq"] = tcp_layer.seq
            info["tcp_ack"] = tcp_layer.ack
            info["tcp_urgent_ptr"] = tcp_layer.urgptr
            info["tcp_options_len"] = len(tcp_layer.options) if tcp_layer.options else 0
            info["is_syn"] = bool(tcp_layer.flags.S)
            info["is_syn_ack"] = bool(tcp_layer.flags.S and tcp_layer.flags.A)
            info["is_fin"] = bool(tcp_layer.flags.F)
            info["is_rst"] = bool(tcp_layer.flags.R)
            info["is_psh"] = bool(tcp_layer.flags.P)
            info["is_ack"] = bool(tcp_layer.flags.A)
            info["is_urg"] = bool(tcp_layer.flags.U)
            info["is_xmas"] = bool(
                tcp_layer.flags.F and tcp_layer.flags.P and tcp_layer.flags.U
            )
            info["is_null"] = int(tcp_layer.flags) == 0
            if tcp_layer.payload:
                info["payload"] = bytes(tcp_layer.payload)
        elif UDP in pkt:
            udp_layer = pkt[UDP]
            info["src_port"] = udp_layer.sport
            info["dst_port"] = udp_layer.dport
            info["protocol"] = "UDP"
            info["udp_length"] = udp_layer.len
            if udp_layer.payload:
                info["payload"] = bytes(udp_layer.payload)
        elif ICMP in pkt:
            icmp_layer = pkt[ICMP]
            info["src_port"] = 0
            info["dst_port"] = 0
            info["protocol"] = "ICMP"
            info["icmp_type"] = icmp_layer.type
            info["icmp_code"] = icmp_layer.code
        else:
            info["src_port"] = 0
            info["dst_port"] = 0

        if hasattr(pkt, "_wireshark_features"):
            info["wireshark_features"] = pkt._wireshark_features

        return info
    except Exception:  # noqa: BLE001
        return None
