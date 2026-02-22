"""Main retina daemon that orchestrates all components."""

from __future__ import annotations

import logging
import threading
import time
from typing import Optional

from ..hermes.uploader import FirebaseUploader
from ..oracle_core.logging import log_event
from .aggregator import PacketBatcher, WindowAggregator
from .collector import CaptureEngine, InterfaceMonitor
from .config import RetinaConfig
from .csv_rotator import FirebaseCSVStager, MythologicalCSVRotator
from .health_monitor import HealthMonitor


class RetinaDaemon:
    """Main daemon that orchestrates packet capture, aggregation, and storage."""
    
    def __init__(self, config: RetinaConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Component state
        self._capture_engine: Optional[CaptureEngine] = None
        self._interface_monitor: Optional[InterfaceMonitor] = None
        self._aggregator: Optional[WindowAggregator] = None
        self._batcher: Optional[PacketBatcher] = None
        self._csv_rotator: Optional[MythologicalCSVRotator] = None
        self._csv_stager: Optional[FirebaseCSVStager] = None
        self._firebase_uploader: Optional[FirebaseUploader] = None
        self._health_monitor: Optional[HealthMonitor] = None
        
        # Control
        self._running = False
        self._worker_threads: list[threading.Thread] = []
        self._stop_event = threading.Event()
        
        # Internal state
        self._stats = {
            "start_time": None,
            "end_time": None,
            "total_packets_captured": 0,
            "total_packets_processed": 0,
            "total_packets_dropped": 0,
            "windows_completed": 0,
            "files_written": 0,
            "alerts_generated": 0,
        }
        
        # Ensure output directories exist
        self.config.ensure_output_dirs()
    
    def start(self) -> None:
        """Start the retina daemon."""
        if self._running:
            self.logger.warning("Daemon is already running")
            return
        
        self.logger.info("Starting Argus_V Retina daemon")
        log_event(self.logger, "Retina daemon starting", level="INFO")
        
        try:
            # Initialize components
            self._initialize_components()
            
            # Set up health monitoring callbacks
            self._setup_health_callbacks()
            
            # Start components
            self._start_components()
            
            # Start main daemon loop
            self._running = True
            self._stats["start_time"] = time.time()
            
            self.logger.info("Retina daemon started successfully")
            log_event(self.logger, "Retina daemon started", level="INFO")
            
        except Exception as e:
            self.logger.error(f"Failed to start daemon: {e}")
            self.stop()
            raise
    
    def stop(self) -> None:
        """Stop the retina daemon gracefully."""
        if not self._running:
            return
        
        self.logger.info("Stopping Argus_V Retina daemon")
        log_event(self.logger, "Retina daemon stopping", level="INFO")
        
        self._running = False
        self._stop_event.set()
        
        try:
            # Stop components in reverse order
            self._stop_components()
            
            # Clean up resources
            self._cleanup()
            
            self._stats["end_time"] = time.time()
            
            # Log final statistics
            uptime = self._stats["end_time"] - self._stats["start_time"]
            self.logger.info(
                f"Daemon stopped - Uptime: {uptime:.1f}s, "
                f"Packets: {self._stats['total_packets_captured']} captured, "
                f"{self._stats['total_packets_processed']} processed, "
                f"Windows: {self._stats['windows_completed']}, "
                f"Files: {self._stats['files_written']}"
            )
            
            log_event(self.logger, "Retina daemon stopped", level="INFO",
                     uptime_seconds=uptime,
                     total_packets_captured=self._stats["total_packets_captured"],
                     total_packets_processed=self._stats["total_packets_processed"],
                     windows_completed=self._stats["windows_completed"],
                     files_written=self._stats["files_written"])
            
        except Exception as e:
            self.logger.error(f"Error during daemon shutdown: {e}")
    
    def is_running(self) -> bool:
        """Check if the daemon is running."""
        return self._running
    
    def get_status(self) -> dict:
        """Get current daemon status."""
        status = {
            "running": self._running,
            "config": {
                "interface": self.config.capture.interface,
                "window_seconds": self.config.aggregation.window_seconds,
                "output_dir": str(self.config.aggregation.output_dir),
                "enabled": self.config.enabled,
            },
            "stats": dict(self._stats),
            "components": {},
            "health": {},
        }
        
        if self._health_monitor:
            status["health"] = self._health_monitor.get_health_summary()
        
        if self._capture_engine:
            status["components"]["capture_engine"] = self._capture_engine.get_interface_stats()
        
        if self._aggregator:
            status["components"]["aggregator"] = self._aggregator.get_stats()
        
        if self._csv_rotator:
            status["components"]["csv_rotator"] = self._csv_rotator.get_stats()
        
        if self._interface_monitor:
            status["components"]["interface_monitor"] = self._interface_monitor.get_status()
        
        return status
    
    def _initialize_components(self) -> None:
        """Initialize all daemon components."""
        self.logger.debug("Initializing components")
        
        # Initialize capture engine
        self._capture_engine = CaptureEngine(
            interface=self.config.capture.interface,
            use_scapy=self.config.capture.use_scapy,
        )
        
        # Initialize interface monitor
        self._interface_monitor = InterfaceMonitor(
            interface=self.config.capture.interface,
        )
        
        # Initialize window aggregator
        self._aggregator = WindowAggregator(
            window_seconds=self.config.aggregation.window_seconds,
            anonymization_salt=self.config.anonymization.ip_salt,
            flow_timeout_seconds=300,  # Add a default flow timeout
        )
        
        # Initialize packet batcher for performance
        self._batcher = PacketBatcher(self._aggregator)
        
        # Initialize CSV rotator
        self._csv_rotator = MythologicalCSVRotator(
            output_dir=self.config.aggregation.output_dir,
            max_rows_per_file=self.config.aggregation.max_rows_per_file,
            file_rotation_count=self.config.aggregation.file_rotation_count,
        )
        
        # Initialize CSV stager for Firebase
        staging_dir = self.config.aggregation.output_dir / "staging"
        self._csv_stager = FirebaseCSVStager(self._csv_rotator, staging_dir)
        
        # Initialize Firebase uploader
        if self.config.firebase.enabled:
            try:
                self._firebase_uploader = FirebaseUploader(
                    bucket_name=self.config.firebase.bucket_name,
                    credentials_path=self.config.firebase.credentials_path,
                    upload_prefix=self.config.firebase.upload_prefix,
                )
                self.logger.info("Firebase uploader initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Firebase uploader: {e}")

        # Initialize health monitor
        self._health_monitor = HealthMonitor(
            max_drop_rate_percent=self.config.health.max_drop_rate_percent,
            max_flow_queue_size=self.config.health.max_flow_queue_size,
            alert_cooldown_seconds=self.config.health.alert_cooldown_seconds,
            enable_drop_monitoring=self.config.health.enable_drop_monitoring,
            enable_queue_monitoring=self.config.health.enable_queue_monitoring,
        )
    
    def _setup_health_callbacks(self) -> None:
        """Set up health monitoring callbacks."""
        
        def on_window_completed(window_stats):
            """Handle completed window statistics."""
            try:
                # Get flow data for CSV output
                flow_data = self._get_flow_data_for_window(window_stats)
                
                # Write to CSV
                self._csv_rotator.write_window_stats(window_stats, flow_data)
                self._stats["windows_completed"] += 1
                
                # Log completion
                self.logger.debug(
                    f"Window completed: {window_stats.packet_count} packets, "
                    f"{window_stats.byte_count} bytes, {window_stats.unique_flows} flows"
                )
                
            except Exception as e:
                self.logger.error(f"Error processing completed window: {e}")
        
        def on_health_alert(alert):
            """Handle health alerts."""
            self._stats["alerts_generated"] += 1
            
            self.logger.warning(
                f"Health alert [{alert.severity}]: {alert.message}"
            )
            
            # TODO: Could add additional alert mechanisms here
            # (email, webhook, etc.)
        
        def on_alert_resolved(alert):
            """Handle resolved alerts."""
            self.logger.info(f"Health alert resolved: {alert.alert_type}")
        
        def on_interface_available(interface: str, available: bool):
            """Handle interface availability changes."""
            if available:
                self.logger.info(f"Interface {interface} is now available")
                log_event(self.logger, "Interface available", level="INFO", interface=interface)
            else:
                self.logger.warning(f"Interface {interface} is no longer available")
                log_event(self.logger, "Interface unavailable", level="WARNING", interface=interface)
        
        # Register callbacks
        if self._aggregator:
            self._aggregator.add_window_completed_callback(on_window_completed)
        
        if self._health_monitor:
            self._health_monitor.add_alert_callback(on_health_alert)
            self._health_monitor.add_resolution_callback(on_alert_resolved)
        
        if self._interface_monitor:
            self._interface_monitor.add_availability_callback(on_interface_available)
    
    def _start_components(self) -> None:
        """Start all daemon components."""
        self.logger.debug("Starting components")
        
        # Start interface monitoring
        if self._interface_monitor:
            self._interface_monitor.start_monitoring()
        
        # Start health monitoring
        if self._health_monitor:
            self._health_monitor.start_monitoring()
        
        # Start aggregator
        if self._aggregator:
            self._aggregator.start()
        
        # Start packet capture (this will start in a separate thread)
        if self._capture_engine:
            self._start_packet_capture()
        
        # Start monitoring threads
        self._start_monitoring_threads()
    
    def _stop_components(self) -> None:
        """Stop all daemon components."""
        self.logger.debug("Stopping components")
        
        # Stop packet capture
        if self._capture_engine:
            self._capture_engine.stop_capture()
        
        # Stop aggregator
        if self._aggregator:
            self._aggregator.stop()
        
        # Stop health monitoring
        if self._health_monitor:
            self._health_monitor.stop_monitoring()
        
        # Stop interface monitoring
        if self._interface_monitor:
            self._interface_monitor.stop_monitoring()
    
    def _cleanup(self) -> None:
        """Clean up resources."""
        self.logger.debug("Cleaning up resources")
        
        # Close CSV rotator
        if self._csv_rotator:
            self._csv_rotator.__exit__(None, None, None)
        
        # Wait for worker threads to finish
        for thread in self._worker_threads:
            if thread.is_alive():
                thread.join(timeout=5.0)
        
        self._worker_threads.clear()
    
    def _start_packet_capture(self) -> None:
        """Start packet capture in a separate thread."""
        def capture_worker():
            """Worker thread for packet capture."""
            try:
                self.logger.info(f"Starting packet capture on {self.config.capture.interface}")
                
                def packet_callback(packet_info):
                    """Handle captured packet."""
                    # Update statistics
                    self._stats["total_packets_captured"] += 1
                    
                    # Add to batcher for aggregation
                    if self._batcher:
                        self._batcher.add_packet(packet_info)
                    
                    # Update health metrics periodically
                    self._update_health_metrics_periodically()
                
                # Start capture with context manager for automatic cleanup
                with self._capture_engine.capture_context(
                    packet_callback,
                    snaplen=self.config.capture.snaplen,
                    promiscuous=self.config.capture.promiscuous,
                    timeout_ms=self.config.capture.timeout_ms,
                ):
                    # Keep the thread alive while capture is active
                    while self._running and self._capture_engine._capture_thread:
                        time.sleep(1.0)
                
            except Exception as e:
                self.logger.error(f"Packet capture error: {e}")
                log_event(self.logger, "Packet capture failed", level="ERROR", error=str(e))
        
        # Start capture worker thread
        capture_thread = threading.Thread(target=capture_worker, daemon=True)
        capture_thread.start()
        self._worker_threads.append(capture_thread)
    
    def _start_monitoring_threads(self) -> None:
        """Start additional monitoring threads."""
        
        def health_update_worker():
            """Worker thread for periodic health updates."""
            while self._running:
                try:
                    if self._health_monitor and self._aggregator and self._capture_engine:
                        stats = self._aggregator.get_stats()
                        
                        self._health_monitor.update_metrics(
                            interface_available=self._capture_engine.is_interface_available(),
                            packets_captured=self._stats["total_packets_captured"],
                            packets_processed=stats["packets_processed"],
                            packets_dropped=stats["packets_dropped"],
                            flows_in_queue=stats["queue_size"],
                            current_window_packets=stats["current_window_packets"],
                        )
                    
                    time.sleep(5.0)  # Update every 5 seconds
                    
                except Exception as e:
                    self.logger.error(f"Health update error: {e}")
                    time.sleep(5.0)
        
        # Start monitoring threads
        health_thread = threading.Thread(target=health_update_worker, daemon=True)
        health_thread.start()
        self._worker_threads.append(health_thread)
        
        staging_thread = threading.Thread(target=self._firebase_staging_worker, daemon=True)
        staging_thread.start()
        self._worker_threads.append(staging_thread)
    
    def _firebase_staging_worker(self) -> None:
        """Worker thread for staging files for Firebase upload."""
        while self._running:
            try:
                if self._csv_stager:
                    staged_files = self._csv_stager.stage_completed_files()

                    # Upload files if uploader is available
                    if self._firebase_uploader and staged_files:
                        for file_path in staged_files:
                            self.logger.info(f"Staged file for Firebase upload: {file_path}")

                            # Attempt upload
                            if self._firebase_uploader.upload_file(file_path):
                                # Mark as uploaded on success
                                self._csv_stager.mark_uploaded(file_path)
                            else:
                                self.logger.warning(f"Failed to upload {file_path}, will retry later")

                time.sleep(60.0)  # Check every minute

            except Exception as e:
                self.logger.error(f"Firebase staging error: {e}")
                time.sleep(60.0)

    def _update_health_metrics_periodically(self) -> None:
        """Update health metrics periodically (called from packet callback)."""
        # This is a simple implementation - in practice you might want to
        # throttle these updates to avoid overhead on high packet rates
        if self._health_monitor and self._aggregator:
            # Update every 100 packets to reduce overhead
            if self._stats["total_packets_captured"] % 100 == 0:
                stats = self._aggregator.get_stats()
                
                self._health_monitor.update_metrics(
                    interface_available=self._capture_engine.is_interface_available(),
                    packets_captured=self._stats["total_packets_captured"],
                    packets_processed=stats["packets_processed"],
                    packets_dropped=stats["packets_dropped"],
                    flows_in_queue=stats["queue_size"],
                    current_window_packets=stats["current_window_packets"],
                )
    
    def _get_flow_data_for_window(self, window_stats) -> list:
        """Get flow data for CSV output from a window."""
        # This is a simplified implementation
        # In practice, you might want to get this data from the aggregator
        # or track flows separately
        
        flows = []
        
        # For now, create some example flow data
        # In a real implementation, you'd get this from the aggregator
        flow_example = {
            "src_ip": "ip_example_source_hash",
            "dst_ip": "ip_example_dest_hash", 
            "protocol": "TCP",
            "src_port": 443,
            "dst_port": 12345,
            "src_packets": window_stats.packet_count // 2,
            "src_bytes": window_stats.byte_count // 2,
            "dst_packets": window_stats.packet_count // 2,
            "dst_bytes": window_stats.byte_count // 2,
        }
        flows.append(flow_example)
        
        return flows