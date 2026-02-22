
import pytest
import time
from unittest.mock import MagicMock, patch
import sys

# Mock scapy before importing collector if it's not available
# But in this environment we have scapy installed.

from argus_v.retina.collector import CaptureEngine, PacketInfo

class TestCaptureEngineUnit:
    def test_convert_scapy_packet_tcp(self):
        """Test converting a TCP packet."""
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, TCP

        # Create a real scapy packet
        packet = Ether() / IP(src="192.168.1.1", dst="192.168.1.2", proto=6) / TCP(sport=1234, dport=80)

        engine = CaptureEngine(interface="eth0", use_scapy=True)

        # Call the method
        info = engine._convert_scapy_packet(packet)

        assert info is not None
        assert info.src_ip == "192.168.1.1"
        assert info.dst_ip == "192.168.1.2"
        assert info.src_port == 1234
        assert info.dst_port == 80
        assert info.protocol == "TCP"
        assert info.interface == "eth0"

    def test_convert_scapy_packet_udp(self):
        """Test converting a UDP packet."""
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, UDP

        packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2", proto=17) / UDP(sport=53, dport=5353)

        engine = CaptureEngine(interface="eth0", use_scapy=True)

        info = engine._convert_scapy_packet(packet)

        assert info is not None
        assert info.protocol == "UDP"
        assert info.src_port == 53
        assert info.dst_port == 5353

    def test_convert_scapy_packet_icmp(self):
        """Test converting an ICMP packet."""
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, ICMP

        packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()

        engine = CaptureEngine(interface="eth0", use_scapy=True)

        info = engine._convert_scapy_packet(packet)

        assert info is not None
        assert info.protocol == "ICMP"
        assert info.src_port is None
        assert info.dst_port is None

    def test_convert_scapy_packet_ipv6(self):
        """Test converting an IPv6 packet."""
        from scapy.layers.l2 import Ether
        from scapy.layers.inet6 import IPv6
        from scapy.layers.inet import TCP

        packet = Ether() / IPv6(src="fe80::1", dst="fe80::2") / TCP(sport=8080, dport=80)

        engine = CaptureEngine(interface="eth0", use_scapy=True)

        info = engine._convert_scapy_packet(packet)

        assert info is not None
        assert info.src_ip == "fe80::1"
        assert info.dst_ip == "fe80::2"
        # Protocol logic in _convert_scapy_packet for IPv6 sets protocol to "IPv6" and doesn't extract ports
        # Let's check the code logic again.
        # if IP in packet: ...
        # elif IPv6 in packet: ... protocol = "IPv6"

        assert info.protocol == "IPv6"
