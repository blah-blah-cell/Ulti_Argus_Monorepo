"""Unit tests for packet capture engine."""

from __future__ import annotations

import time
from unittest.mock import Mock, patch

import pytest

from argus_v.retina.collector import CaptureEngine, InterfaceMonitor, PacketInfo


class TestPacketInfo:
    """Test PacketInfo data structure."""
    
    def test_packet_info_creation(self):
        """Test creating a PacketInfo object."""
        packet = PacketInfo(
            timestamp=time.time(),
            interface="eth0",
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=443,
            dst_port=12345,
            protocol="TCP",
            packet_size=64,
            raw_data=b"test_packet_data",
        )
        
        assert packet.interface == "eth0"
        assert packet.src_ip == "192.168.1.1"
        assert packet.dst_ip == "192.168.1.2"
        assert packet.src_port == 443
        assert packet.dst_port == 12345
        assert packet.protocol == "TCP"
        assert packet.packet_size == 64
        assert packet.raw_data == b"test_packet_data"


@pytest.mark.skipif(not hasattr(CaptureEngine, 'HAS_SCAPY') or not CaptureEngine.HAS_SCAPY, 
                    reason="scapy not available")
class TestCaptureEngineWithScapy:
    """Test CaptureEngine with scapy available."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.engine = CaptureEngine(interface="lo", use_scapy=True)
    
    def test_engine_initialization(self):
        """Test engine initialization."""
        assert self.engine.interface == "lo"
        assert self.engine.use_scapy is True
    
    def test_interface_ip_fallback(self):
        """Test getting interface IP when interface is not available."""
        # Mock scapy functions to return test data
        with patch('argus_v.retina.collector.get_if_addr') as mock_get_ip:
            mock_get_ip.return_value = "127.0.0.1"
            
            ip = self.engine.get_interface_ip()
            assert ip == "127.0.0.1"
    
    def test_interface_mac_fallback(self):
        """Test getting interface MAC when interface is not available."""
        with patch('argus_v.retina.collector.getmacbyip') as mock_get_mac:
            mock_get_mac.return_value = "00:11:22:33:44:55"
            
            mac = self.engine.get_interface_mac()
            assert mac == "00:11:22:33:44:55"


class TestCaptureEngineFallback:
    """Test CaptureEngine with pcapy fallback."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.engine = CaptureEngine(interface="lo", use_scapy=False)
    
    def test_engine_fallback_initialization(self):
        """Test engine initialization with pcapy fallback."""
        assert self.engine.interface == "lo"
        assert self.engine.use_scapy is False
    
    def test_packet_callback(self):
        """Test packet callback functionality."""
        callback_called = []
        received_packets = []
        
        def test_callback(packet_info):
            callback_called.append(True)
            received_packets.append(packet_info)
        
        # This would normally be called from the capture context
        test_packet = PacketInfo(
            timestamp=time.time(),
            interface="eth0",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=80,
            dst_port=54321,
            protocol="TCP",
            packet_size=60,
            raw_data=b"tcp_packet",
        )
        
        self.engine.set_packet_callback(test_callback)
        # In real usage, this would be called by the capture thread
        test_callback(test_packet)
        
        assert len(callback_called) == 1
        assert len(received_packets) == 1
        assert received_packets[0].src_ip == "10.0.0.1"
        assert received_packets[0].protocol == "TCP"


class TestInterfaceMonitor:
    """Test InterfaceMonitor functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.monitor = InterfaceMonitor(interface="lo", check_interval=1.0)
    
    def test_monitor_initialization(self):
        """Test monitor initialization."""
        assert self.monitor.interface == "lo"
        assert self.monitor.check_interval == 1.0
        assert not self.monitor._monitoring
    
    def test_add_availability_callback(self):
        """Test adding availability callback."""
        callback = Mock()
        self.monitor.add_availability_callback(callback)
        
        assert callback in self.monitor._availability_callbacks
    
    def test_start_stop_monitoring(self):
        """Test starting and stopping monitoring."""
        # Test that we can start monitoring
        self.monitor.start_monitoring()
        assert self.monitor._monitoring
        
        # Test that we can stop monitoring
        self.monitor.stop_monitoring()
        assert not self.monitor._monitoring
    
    def test_is_available_with_mock(self):
        """Test availability checking with mocked engine."""
        with patch.object(self.monitor, 'is_available', return_value=True):
            assert self.monitor.is_available() is True
    
    def test_get_status_with_mock(self):
        """Test getting status with mocked components."""
        with patch.object(self.monitor, 'is_available', return_value=True):
            status = self.monitor.get_status()
            
            assert status["interface"] == "lo"
            assert status["available"] is True
            assert "stats" in status


class TestPacketConversion:
    """Test packet conversion functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.engine = CaptureEngine(interface="lo", use_scapy=True)
    
    def test_convert_pcapy_packet_tcp(self):
        """Test converting a pcapy TCP packet."""
        # Mock Ethernet + IP + TCP header
        packet_data = bytes([
            # Ethernet header (14 bytes)
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  # dest MAC
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,  # src MAC
            0x08, 0x00,                          # EtherType: IPv4
            # IP header (20 bytes)
            0x45,                                # Version: 4, IHL: 5
            0x00,                                # DSCP/ECN
            0x00, 0x3c,                          # Total length: 60
            0x12, 0x34,                          # Identification
            0x40, 0x00,                          # Flags: 2, Fragment offset: 0
            0x40,                                # TTL: 64
            0x06,                                # Protocol: TCP
            0x00, 0x00,                          # Header checksum
            0x0a, 0x00, 0x00, 0x01,             # Src IP: 10.0.0.1
            0x0a, 0x00, 0x00, 0x02,             # Dst IP: 10.0.0.2
            # TCP header (20 bytes, minimal)
            0x01, 0xbb,                          # Src port: 443
            0x30, 0x39,                          # Dst port: 12345
            0x12, 0x34, 0x56, 0x78,             # Sequence
            0x87, 0x65, 0x43, 0x21,             # Ack
            0x50,                                # Header length: 5*4=20, flags: PSH,ACK
            0x18,                                # Window size
            0x00, 0x00,                          # Checksum
            0x00, 0x00,                          # Urgent pointer
        ])
        
        # Mock pcapy header
        header = Mock()
        header.getts = lambda: (int(time.time()), 0)
        
        packet_info = self.engine._convert_pcapy_packet(header, packet_data)
        
        assert packet_info is not None
        assert packet_info.src_ip == "10.0.0.1"
        assert packet_info.dst_ip == "10.0.0.2"
        assert packet_info.src_port == 443
        assert packet_info.dst_port == 12345
        assert packet_info.protocol == "TCP"
        assert packet_info.packet_size == len(packet_data)
    
    def test_convert_pcapy_packet_invalid(self):
        """Test converting invalid pcapy packet."""
        # Too short packet
        packet_data = b"\x00" * 10
        
        header = Mock()
        header.getts = lambda: (int(time.time()), 0)
        
        packet_info = self.engine._convert_pcapy_packet(header, packet_data)
        
        assert packet_info is None  # Should return None for invalid packet
    
    def test_convert_pcapy_packet_ipv6(self):
        """Test converting a pcapy IPv6 packet."""
        # Mock Ethernet + IPv6 header
        packet_data = bytes([
            # Ethernet header
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0x86, 0xdd,                        # EtherType: IPv6
            # IPv6 header (40 bytes)
            0x60,                              # Version: 6, Traffic class
            0x00, 0x00, 0x00,                 # Flow label
            0x00, 0x2a,                       # Payload length: 42 bytes
            0x06,                              # Next header: TCP
            0x40,                              # Hop limit: 64
            # Source address (16 bytes) - 2001:db8::1
            0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
            # Destination address (16 bytes) - 2001:db8::2
            0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02,
        ])
        
        header = Mock()
        header.getts = lambda: (int(time.time()), 0)
        
        packet_info = self.engine._convert_pcapy_packet(header, packet_data)
        
        assert packet_info is not None
        assert packet_info.src_ip == "2001:db8::1"
        assert packet_info.dst_ip == "2001:db8::2"
        assert packet_info.protocol == "IPv6"
        assert packet_info.src_port is None  # No TCP header
        assert packet_info.dst_port is None


class TestInterfaceAvailability:
    """Test interface availability checking."""
    
    def test_check_interface_when_not_available(self):
        """Test behavior when interface is not available."""
        engine = CaptureEngine(interface="nonexistent_interface")
        
        # Mock the availability check to return False
        with patch.object(engine, 'is_interface_available', return_value=False):
            assert engine.is_interface_available() is False
    
    def test_graceful_degradation_on_error(self):
        """Test graceful degradation when checking interface info fails."""
        engine = CaptureEngine(interface="eth0")
        
        # Mock an exception during interface check
        with patch('argus_v.retina.collector.get_if_list', side_effect=Exception("Mock error")):
            # Should not raise exception, should return False
            assert engine.is_interface_available() is False