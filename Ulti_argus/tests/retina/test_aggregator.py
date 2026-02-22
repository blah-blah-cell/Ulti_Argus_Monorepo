"""Unit tests for window aggregation."""

from __future__ import annotations

import time
from unittest.mock import Mock

from argus_v.retina.aggregator import (
    FlowKey,
    FlowStats,
    PacketBatcher,
    WindowAggregator,
    WindowStats,
)
from argus_v.retina.collector import PacketInfo


class TestFlowKey:
    """Test FlowKey data structure."""
    
    def test_flow_key_creation(self):
        """Test creating a FlowKey."""
        flow_key = FlowKey(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=443,
            dst_port=12345,
            protocol="TCP",
        )
        
        assert flow_key.src_ip == "10.0.0.1"
        assert flow_key.dst_ip == "10.0.0.2"
        assert flow_key.src_port == 443
        assert flow_key.dst_port == 12345
        assert flow_key.protocol == "TCP"
    
    def test_flow_key_hash(self):
        """Test FlowKey hashing."""
        flow_key1 = FlowKey("10.0.0.1", "10.0.0.2", 443, 12345, "TCP")
        flow_key2 = FlowKey("10.0.0.1", "10.0.0.2", 443, 12345, "TCP")
        flow_key3 = FlowKey("10.0.0.1", "10.0.0.2", 80, 12345, "TCP")
        
        assert hash(flow_key1) == hash(flow_key2)
        assert hash(flow_key1) != hash(flow_key3)
        
        # Should work as dict keys
        flow_dict = {flow_key1: "test"}
        assert flow_dict[flow_key2] == "test"


class TestFlowStats:
    """Test FlowStats data structure."""
    
    def test_flow_stats_creation(self):
        """Test creating FlowStats."""
        current_time = time.time()
        flow_key = FlowKey("10.0.0.1", "10.0.0.2", 443, 12345, "TCP")
        
        flow_stats = FlowStats(
            flow_key=flow_key,
            packet_count=10,
            byte_count=1500,
            first_seen=current_time,
            last_seen=current_time + 5.0,
        )
        
        assert flow_stats.flow_key == flow_key
        assert flow_stats.packet_count == 10
        assert flow_stats.byte_count == 1500
        assert flow_stats.duration_seconds == 5.0
        assert flow_stats.avg_packet_size == 150.0


class TestWindowStats:
    """Test WindowStats data structure."""
    
    def test_window_stats_creation(self):
        """Test creating WindowStats."""
        current_time = time.time()
        
        window_stats = WindowStats(
            start_time=current_time,
            end_time=current_time + 5.0,
            duration_seconds=5.0,
            packet_count=100,
            byte_count=15000,
            unique_flows=5,
            protocols={"TCP": 80, "UDP": 20},
            rate_pps=20.0,
            rate_bps=24000.0,
        )
        
        assert window_stats.start_time == current_time
        assert window_stats.end_time == current_time + 5.0
        assert window_stats.duration_seconds == 5.0
        assert window_stats.packet_count == 100
        assert window_stats.byte_count == 15000
        assert window_stats.unique_flows == 5
        assert window_stats.protocols == {"TCP": 80, "UDP": 20}
        assert window_stats.rate_pps == 20.0
        assert window_stats.rate_bps == 24000.0
    
    def test_window_stats_to_dict(self):
        """Test WindowStats to_dict conversion."""
        current_time = time.time()
        
        window_stats = WindowStats(
            start_time=current_time,
            end_time=current_time + 5.0,
            duration_seconds=5.0,
            packet_count=100,
            byte_count=15000,
            unique_flows=5,
            protocols={"TCP": 80, "UDP": 20},
            rate_pps=20.0,
            rate_bps=24000.0,
        )
        
        result = window_stats.to_dict()
        
        assert "window_start" in result
        assert "window_end" in result
        assert "duration_seconds" in result
        assert result["packet_count"] == 100
        assert result["byte_count"] == 15000
        assert result["unique_flows"] == 5
        assert result["rate_pps"] == 20.0


class TestWindowAggregator:
    """Test WindowAggregator functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.aggregator = WindowAggregator(
            window_seconds=5,
            anonymization_salt=b"test_salt",
        )
    
    def test_aggregator_initialization(self):
        """Test aggregator initialization."""
        assert self.aggregator.window_seconds == 5
        assert self.aggregator.anonymization_salt == b"test_salt"
        assert not self.aggregator._processing
    
    def test_add_window_completed_callback(self):
        """Test adding window completion callback."""
        callback = Mock()
        self.aggregator.add_window_completed_callback(callback)
        
        assert callback in self.aggregator._window_completed_callbacks
    
    def test_start_stop(self):
        """Test starting and stopping the aggregator."""
        # Start the aggregator
        self.aggregator.start()
        assert self.aggregator._processing
        
        # Stop the aggregator
        self.aggregator.stop()
        assert not self.aggregator._processing
    
    def test_add_packet(self):
        """Test adding packets to the aggregator."""
        self.aggregator.start()
        
        # Create a test packet
        packet = PacketInfo(
            timestamp=time.time(),
            interface="eth0",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=443,
            dst_port=12345,
            protocol="TCP",
            packet_size=64,
            raw_data=b"test_packet",
        )
        
        # Add packet
        result = self.aggregator.add_packet(packet)
        assert result is True
        
        # Check statistics
        stats = self.aggregator.get_stats()
        assert stats["packets_processed"] == 1
        
        self.aggregator.stop()
    
    def test_packet_batching_and_flow_tracking(self):
        """Test packet batching and flow tracking."""
        self.aggregator.start()
        
        # Add multiple packets for the same flow
        for i in range(5):
            packet = PacketInfo(
                timestamp=time.time(),
                interface="eth0",
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=443,
                dst_port=12345,
                protocol="TCP",
                packet_size=64 + i,
                raw_data=f"packet_{i}".encode(),
            )
            self.aggregator.add_packet(packet)
        
        # Check statistics
        stats = self.aggregator.get_stats()
        assert stats["packets_processed"] == 5
        
        # Force flush to check window completion
        self.aggregator._flush_current_window()
        
        self.aggregator.stop()
    
    def test_multiple_flows(self):
        """Test aggregation of multiple flows."""
        self.aggregator.start()
        
        # Add packets from different flows
        flows = [
            ("10.0.0.1", "10.0.0.2", 443, 12345, "TCP"),
            ("10.0.0.3", "10.0.0.4", 80, 54321, "TCP"),
            ("10.0.0.5", "10.0.0.6", 53, 5353, "UDP"),
        ]
        
        for src_ip, dst_ip, src_port, dst_port, protocol in flows:
            packet = PacketInfo(
                timestamp=time.time(),
                interface="eth0",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_size=64,
                raw_data=b"test_packet",
            )
            self.aggregator.add_packet(packet)
        
        # Force flush to check window completion
        self.aggregator._flush_current_window()
        
        stats = self.aggregator.get_stats()
        assert stats["flows_tracked"] == 3
        
        self.aggregator.stop()
    
    def test_protocol_tracking(self):
        """Test protocol tracking in windows."""
        self.aggregator.start()
        
        # Add packets with different protocols
        protocols = ["TCP", "UDP", "ICMP", "TCP"]
        
        for protocol in protocols:
            packet = PacketInfo(
                timestamp=time.time(),
                interface="eth0",
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=80 if protocol == "TCP" else None,
                dst_port=12345 if protocol == "TCP" else None,
                protocol=protocol,
                packet_size=64,
                raw_data=b"test_packet",
            )
            self.aggregator.add_packet(packet)
        
        # Force flush
        self.aggregator._flush_current_window()
        
        self.aggregator.stop()
    
    def test_window_completion_callback(self):
        """Test window completion callback."""
        callback = Mock()
        self.aggregator.add_window_completed_callback(callback)
        
        self.aggregator.start()
        
        # Add a packet to trigger window creation
        packet = PacketInfo(
            timestamp=time.time(),
            interface="eth0",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=443,
            dst_port=12345,
            protocol="TCP",
            packet_size=64,
            raw_data=b"test_packet",
        )
        self.aggregator.add_packet(packet)
        
        # Force flush to trigger callback
        self.aggregator._flush_current_window()
        
        # Check callback was called
        callback.assert_called_once()
        
        self.aggregator.stop()
    
    def test_get_stats(self):
        """Test getting statistics."""
        # Test initial stats
        stats = self.aggregator.get_stats()
        assert stats["packets_processed"] == 0
        assert stats["packets_dropped"] == 0
        assert stats["windows_completed"] == 0
        assert stats["flows_tracked"] == 0
        assert stats["current_window_packets"] == 0
    
    def test_flow_timeout_cleanup(self):
        """Test cleanup of expired flows."""
        self.aggregator.flow_timeout_seconds = 1  # Short timeout
        
        self.aggregator.start()
        
        # Add a packet
        packet = PacketInfo(
            timestamp=time.time(),
            interface="eth0",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=443,
            dst_port=12345,
            protocol="TCP",
            packet_size=64,
            raw_data=b"test_packet",
        )
        self.aggregator.add_packet(packet)
        
        # Wait for timeout
        time.sleep(2)
        
        # Trigger cleanup
        self.aggregator._cleanup_expired_flows(time.time())
        
        self.aggregator.stop()


class TestPacketBatcher:
    """Test PacketBatcher functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.aggregator = Mock()
        self.batcher = PacketBatcher(
            aggregator=self.aggregator,
            batch_size=3,
            batch_timeout_ms=100,
        )
    
    def test_batcher_initialization(self):
        """Test batcher initialization."""
        assert self.batcher.aggregator is self.aggregator
        assert self.batcher.batch_size == 3
        assert self.batcher.batch_timeout_ms == 100
    
    def test_add_packet_batch_flush(self):
        """Test packet addition that triggers batch flush."""
        # Add packets up to batch size
        for i in range(3):
            packet = PacketInfo(
                timestamp=time.time(),
                interface="eth0",
                src_ip=f"10.0.0.{i+1}",
                dst_ip="10.0.0.10",
                src_port=80 + i,
                dst_port=12345,
                protocol="TCP",
                packet_size=64,
                raw_data=f"packet_{i}".encode(),
            )
            self.batcher.add_packet(packet)
        
        # Check that add_packet was called 3 times on aggregator
        assert self.aggregator.add_packet.call_count == 3
    
    def test_add_packet_timeout_flush(self):
        """Test packet addition that triggers timeout-based flush."""
        # Add packet that doesn't fill batch
        packet = PacketInfo(
            timestamp=time.time(),
            interface="eth0",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=443,
            dst_port=12345,
            protocol="TCP",
            packet_size=64,
            raw_data=b"test_packet",
        )
        
        self.batcher.add_packet(packet)
        
        # Wait for timeout
        time.sleep(0.2)
        
        # Should trigger flush (with small buffer for timing)
        assert self.aggregator.add_packet.call_count >= 1
    
    def test_flush(self):
        """Test forced flush."""
        # Add a packet to the batch
        packet = PacketInfo(
            timestamp=time.time(),
            interface="eth0",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=443,
            dst_port=12345,
            protocol="TCP",
            packet_size=64,
            raw_data=b"test_packet",
        )
        
        self.batcher.add_packet(packet)
        
        # Force flush
        self.batcher.flush()
        
        # Check that packet was processed
        assert self.aggregator.add_packet.call_count == 1


class TestAggregatorIntegration:
    """Integration tests for the aggregator."""
    
    def test_realistic_packet_stream(self):
        """Test aggregation with a realistic packet stream."""
        aggregator = WindowAggregator(window_seconds=2)
        aggregator.start()
        
        # Simulate a stream of packets over 5 seconds
        start_time = time.time()
        packet_count = 0
        
        def simulate_packet_stream():
            nonlocal packet_count
            current_time = start_time
            
            while current_time < start_time + 5:
                # Add a packet every 0.1 seconds
                packet = PacketInfo(
                    timestamp=current_time,
                    interface="eth0",
                    src_ip="10.0.0.1",
                    dst_ip="10.0.0.2",
                    src_port=443,
                    dst_port=12345,
                    protocol="TCP",
                    packet_size=64,
                    raw_data=b"test_packet",
                )
                aggregator.add_packet(packet)
                packet_count += 1
                current_time += 0.1
        
        simulate_packet_stream()
        
        # Wait for window processing
        time.sleep(1)
        
        # Check statistics
        stats = aggregator.get_stats()
        assert stats["packets_processed"] == packet_count
        
        aggregator.stop()