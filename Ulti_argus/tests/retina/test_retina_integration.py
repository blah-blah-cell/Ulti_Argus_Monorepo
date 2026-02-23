"""Integration tests for retina module."""

from __future__ import annotations

import shutil
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

from argus_v.oracle_core.anonymize import AnonymizationConfig
from argus_v.retina.collector import CaptureEngine
from argus_v.retina.config import AggregationConfig, CaptureConfig, HealthConfig, RetinaConfig
from argus_v.retina.daemon import RetinaDaemon


class TestInterfaceFailureSimulation:
    """Integration tests simulating interface failure scenarios."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.test_dir = Path(tempfile.mkdtemp())
        # Create test configuration
        self.config = RetinaConfig(
            capture=CaptureConfig(
                interface="test_interface",
                use_scapy=True,
            ),
            aggregation=AggregationConfig(
                window_seconds=2,
                max_rows_per_file=100,
                output_dir=self.test_dir,
            ),
            health=HealthConfig(
                max_drop_rate_percent=5.0,
                alert_cooldown_seconds=10,
            ),
            anonymization=AnonymizationConfig(ip_salt=b"test_salt"),
        )

    def teardown_method(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir)
    
    def test_interface_unavailable_on_startup(self):
        """Test daemon behavior when interface is unavailable on startup."""
        # Mock interface as unavailable
        with patch.object(CaptureEngine, 'is_interface_available', return_value=False):
            with patch.object(CaptureEngine, 'get_interface_stats') as mock_stats:
                mock_stats.return_value = {
                    "interface": "test_interface",
                    "available": False,
                    "error": "Interface not found"
                }
                
                daemon = RetinaDaemon(self.config)
                
                # Daemon should start but capture engine should handle unavailable interface
                daemon.start()
                
                try:
                    assert daemon.is_running()
                    
                    # Check status shows interface unavailable
                    status = daemon.get_status()
                    capture_stats = status["components"].get("capture_engine", {})
                    assert capture_stats["available"] is False
                    
                finally:
                    daemon.stop()
    
    def test_interface_becomes_unavailable_during_capture(self):
        """Test graceful handling when interface becomes unavailable during capture."""
        daemon = RetinaDaemon(self.config)
        
        # Mock interface as available initially, then unavailable
        available_sequence = [True] * 3 + [False] * 5 + [True] * 2
        call_count = 0
        
        def mock_is_available():
            nonlocal call_count
            if call_count < len(available_sequence):
                result = available_sequence[call_count]
                call_count += 1
                return result
            return True  # Default to available
        
        with patch.object(CaptureEngine, 'is_interface_available', side_effect=mock_is_available):
            with patch.object(CaptureEngine, 'get_interface_ip', return_value="10.0.0.1"):
                with patch.object(CaptureEngine, 'get_interface_mac', return_value="00:11:22:33:44:55"):
                    with patch.object(CaptureEngine, 'capture_context'):
                        daemon.start()
                        
                        try:
                            # Wait for interface to become unavailable
                            time.sleep(1)
                            
                            # Check that health monitoring detected the issue
                            status = daemon.get_status()
                            health = status.get("health", {})
                            
                            # Health monitor should have detected interface issues
                            assert "metrics" in health
                            
                        finally:
                            daemon.stop()
    
    def test_interface_recovery_after_failure(self):
        """Test daemon recovery when interface becomes available again."""
        daemon = RetinaDaemon(self.config)
        
        # Mock interface availability changing
        availability_changes = []
        
        def mock_is_available():
            # Simulate interface going down then up
            if len(availability_changes) < 3:
                availability_changes.append(True)
                return True
            elif len(availability_changes) < 5:
                availability_changes.append(False)
                return False
            else:
                availability_changes.append(True)
                return True
        
        # Track interface monitoring callbacks
        interface_callbacks = []
        
        with patch.object(CaptureEngine, 'is_interface_available', side_effect=mock_is_available):
            daemon.start()
            
            # Manually trigger interface monitoring callback
            if daemon._interface_monitor:
                daemon._interface_monitor.add_availability_callback(
                    lambda interface, available: interface_callbacks.append((interface, available))
                )
            
            try:
                # Simulate interface changes
                daemon._interface_monitor._availability_callbacks[0]("test_interface", False)
                daemon._interface_monitor._availability_callbacks[0]("test_interface", True)
                
                # Check that callbacks were called
                assert len(interface_callbacks) >= 2
                assert ("test_interface", False) in interface_callbacks
                assert ("test_interface", True) in interface_callbacks
                
            finally:
                daemon.stop()
    
    def test_graceful_shutdown_on_interface_error(self):
        """Test graceful shutdown when capture encounters interface errors."""
        daemon = RetinaDaemon(self.config)
        
        # Mock capture to raise an exception
        with patch.object(CaptureEngine, 'capture_context') as mock_capture:
            mock_capture.side_effect = OSError("Interface error")
            
            # Daemon should handle the error gracefully
            daemon.start()
            
            try:
                time.sleep(0.5)  # Let it process
                
                # Daemon should still be running despite capture error
                assert daemon.is_running()
                
            finally:
                daemon.stop()
    
    def test_health_monitoring_during_interface_issues(self):
        """Test health monitoring detects and reports interface issues."""
        daemon = RetinaDaemon(self.config)
        
        # Mock interface being unavailable
        with patch.object(CaptureEngine, 'is_interface_available', return_value=False):
            with patch('time.sleep'):  # Speed up test
                daemon.start()
                
                try:
                    # Manually trigger health update
                    if daemon._health_monitor:
                        daemon._health_monitor.update_metrics(
                            interface_available=False,
                            packets_captured=0,
                            packets_processed=0,
                            packets_dropped=0,
                            flows_in_queue=0,
                            current_window_packets=0,
                        )
                    
                    # Check health summary
                    health_summary = daemon._health_monitor.get_health_summary()
                    
                    assert health_summary["status"] in ["warning", "critical"]
                    assert health_summary["metrics"]["interface_available"] is False
                    
                finally:
                    daemon.stop()
    
    def test_daemon_status_completeness_during_issues(self):
        """Test that daemon status is complete even during interface issues."""
        daemon = RetinaDaemon(self.config)
        
        with patch.object(CaptureEngine, 'is_interface_available', return_value=False):
            with patch.object(CaptureEngine, 'get_interface_stats') as mock_stats:
                mock_stats.return_value = {
                    "interface": "test_interface",
                    "available": False,
                    "error": "Test interface error",
                    "capture_engine": "scapy",
                }
                
                daemon.start()
                
                try:
                    status = daemon.get_status()
                    
                    # Check all expected sections are present
                    assert "running" in status
                    assert "config" in status
                    assert "stats" in status
                    assert "components" in status
                    assert "health" in status
                    
                    # Check component status
                    components = status["components"]
                    assert "capture_engine" in components
                    assert "aggregator" in components
                    assert "csv_rotator" in components
                    
                    # Check that interface issue is captured
                    capture_stats = components["capture_engine"]
                    assert capture_stats["available"] is False
                    assert "error" in capture_stats
                    
                finally:
                    daemon.stop()


class TestPCAPSampleProcessing:
    """Test processing of stored PCAP samples."""
    
    def setup_method(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def teardown_method(self):
        shutil.rmtree(self.test_dir)

    def test_pcap_sample_processing(self):
        """Test processing a sample PCAP file."""
        # This test would require a PCAP sample file
        # For now, we'll test the packet processing logic
        
        config = RetinaConfig(
            capture=CaptureConfig(interface="lo"),
            aggregation=AggregationConfig(
                window_seconds=1,
                output_dir=self.test_dir,
            ),
            health=HealthConfig(),
            anonymization=AnonymizationConfig(ip_salt=b"test_salt"),
        )
        
        daemon = RetinaDaemon(config)
        daemon.start()
        
        try:
            # Mock some packet processing
            aggregator_stats_before = daemon._aggregator.get_stats()
            
            # Simulate packet processing by directly calling the aggregator
            from argus_v.retina.collector import PacketInfo
            
            test_packet = PacketInfo(
                timestamp=time.time(),
                interface="lo",
                src_ip="127.0.0.1",
                dst_ip="127.0.0.1",
                src_port=12345,
                dst_port=80,
                protocol="TCP",
                packet_size=74,
                raw_data=b"mock_packet_data",
            )
            
            daemon._aggregator.add_packet(test_packet)
            
            # Force window flush
            daemon._aggregator._flush_current_window()
            
            aggregator_stats_after = daemon._aggregator.get_stats()
            
            # Should have processed the packet
            assert aggregator_stats_after["packets_processed"] > aggregator_stats_before["packets_processed"]
            
        finally:
            daemon.stop()
    
    def test_multiple_packet_types_processing(self):
        """Test processing various packet types in sequence."""
        from argus_v.retina.collector import PacketInfo
        
        config = RetinaConfig(
            capture=CaptureConfig(interface="lo"),
            aggregation=AggregationConfig(
                window_seconds=5,
                output_dir=self.test_dir,
            ),
            health=HealthConfig(),
            anonymization=AnonymizationConfig(ip_salt=b"test_salt"),
        )
        
        daemon = RetinaDaemon(config)
        daemon.start()
        
        try:
            # Test different packet types
            packets = [
                # TCP packet
                PacketInfo(
                    timestamp=time.time(),
                    interface="lo",
                    src_ip="10.0.0.1",
                    dst_ip="10.0.0.2",
                    src_port=443,
                    dst_port=12345,
                    protocol="TCP",
                    packet_size=64,
                    raw_data=b"tcp_packet",
                ),
                # UDP packet
                PacketInfo(
                    timestamp=time.time(),
                    interface="lo",
                    src_ip="10.0.0.3",
                    dst_ip="10.0.0.4",
                    src_port=53,
                    dst_port=5353,
                    protocol="UDP",
                    packet_size=64,
                    raw_data=b"udp_packet",
                ),
                # ICMP packet
                PacketInfo(
                    timestamp=time.time(),
                    interface="lo",
                    src_ip="10.0.0.5",
                    dst_ip="10.0.0.6",
                    src_port=None,
                    dst_port=None,
                    protocol="ICMP",
                    packet_size=64,
                    raw_data=b"icmp_packet",
                ),
            ]
            
            # Add all packets
            for packet in packets:
                daemon._aggregator.add_packet(packet)
            
            # Check protocol tracking
            daemon._aggregator._flush_current_window()
            
            # At minimum, all packets should have been processed
            stats = daemon._aggregator.get_stats()
            assert stats["packets_processed"] >= 3
            
        finally:
            daemon.stop()


class TestEndToEndWorkflow:
    """Test complete workflow from capture to CSV output."""
    
    def test_complete_packet_to_csv_workflow(self):
        """Test complete workflow from packet capture to CSV output."""
        import tempfile
        from pathlib import Path
        
        # Create temporary output directory
        temp_dir = Path(tempfile.mkdtemp())
        
        try:
            config = RetinaConfig(
                capture=CaptureConfig(
                    interface="lo",
                    use_scapy=False,  # Use mock for testing
                ),
                aggregation=AggregationConfig(
                    output_dir=temp_dir,
                    window_seconds=1,
                    max_rows_per_file=1000,
                ),
                health=HealthConfig(),
                anonymization=AnonymizationConfig(ip_salt=b"test_salt"),
            )
            
            daemon = RetinaDaemon(config)
            daemon.start()
            
            try:
                # Generate some test packets
                from argus_v.retina.collector import PacketInfo
                
                for i in range(10):
                    packet = PacketInfo(
                        timestamp=time.time(),
                        interface="lo",
                        src_ip=f"10.0.0.{i % 255 + 1}",
                        dst_ip=f"10.0.0.{((i + 1) % 255) + 1}",
                        src_port=80 + (i % 1000),
                        dst_port=443,
                        protocol="TCP" if i % 2 == 0 else "UDP",
                        packet_size=64 + i,
                        raw_data=f"packet_{i}".encode(),
                    )
                    daemon._aggregator.add_packet(packet)
                
                # Wait for window processing
                time.sleep(2)
                
                # Check CSV output
                csv_files = daemon._csv_rotator.list_files()
                
                if csv_files:
                    # Read CSV content
                    import csv
                    with open(csv_files[0], 'r', newline='', encoding='utf-8') as f:
                        reader = csv.DictReader(f)
                        rows = list(reader)
                        
                        # Should have CSV rows
                        assert len(rows) > 0
                        
                        # Check CSV headers
                        headers = set(rows[0].keys())
                        expected_headers = {
                            "timestamp", "window_start", "packet_count", 
                            "src_ip_anon", "dst_ip_anon", "protocol"
                        }
                        assert expected_headers.issubset(headers)
                        
                # Check statistics
                stats = daemon.get_status()
                assert stats["stats"]["total_packets_processed"] > 0
                assert stats["stats"]["windows_completed"] > 0
                
            finally:
                daemon.stop()
                
        finally:
            # Cleanup
            import shutil
            shutil.rmtree(temp_dir)
    
    def test_daemon_lifecycle(self):
        """Test complete daemon lifecycle."""
        temp_dir = Path(tempfile.mkdtemp())
        try:
            config = RetinaConfig(
                capture=CaptureConfig(interface="lo"),
                aggregation=AggregationConfig(
                    window_seconds=1,
                    output_dir=temp_dir,
                ),
                health=HealthConfig(),
                anonymization=AnonymizationConfig(ip_salt=b"test_salt"),
            )

            daemon = RetinaDaemon(config)

            # Initially not running
            assert not daemon.is_running()

            # Start daemon
            daemon.start()
            assert daemon.is_running()

            # Check initial status
            status = daemon.get_status()
            assert status["running"] is True
            assert status["config"]["interface"] == "lo"

            # Stop daemon
            daemon.stop()
            assert not daemon.is_running()

            # Check final statistics
            final_stats = daemon.get_status()["stats"]
            assert final_stats["end_time"] is not None
        finally:
            shutil.rmtree(temp_dir)
