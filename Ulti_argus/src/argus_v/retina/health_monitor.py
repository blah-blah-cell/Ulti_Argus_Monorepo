"""Health monitoring and alerting for packet capture operations."""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class HealthMetrics:
    """Current health metrics snapshot."""
    
    timestamp: float
    interface_available: bool
    packets_captured: int
    packets_processed: int
    packets_dropped: int
    flows_in_queue: int
    current_window_packets: int
    drop_rate_percent: float
    capture_rate_pps: float
    processing_rate_pps: float
    memory_usage_mb: float
    cpu_usage_percent: float
    disk_usage_percent: float


@dataclass
class HealthAlert:
    """Health alert notification."""
    
    alert_type: str
    severity: str  # "warning", "critical"
    message: str
    timestamp: float
    metrics: HealthMetrics
    resolved: bool = False
    resolved_at: Optional[float] = None


class HealthMonitor:
    """Monitors capture health and emits alerts when thresholds are exceeded."""
    
    def __init__(
        self,
        max_drop_rate_percent: float = 1.0,
        max_flow_queue_size: int = 1000,
        alert_cooldown_seconds: int = 300,
        enable_drop_monitoring: bool = True,
        enable_queue_monitoring: bool = True,
    ):
        self.max_drop_rate_percent = max_drop_rate_percent
        self.max_flow_queue_size = max_flow_queue_size
        self.alert_cooldown_seconds = alert_cooldown_seconds
        self.enable_drop_monitoring = enable_drop_monitoring
        self.enable_queue_monitoring = enable_queue_monitoring
        
        # Thread safety
        self._lock = threading.RLock()
        
        # State tracking
        self._metrics_history: deque = deque(maxlen=60)  # Last 60 snapshots
        self._alert_history: deque = deque(maxlen=100)   # Last 100 alerts
        self._last_alert_times: Dict[str, float] = {}    # Type -> timestamp
        
        # Monitoring callbacks
        self._alert_callbacks: List[Callable[[HealthAlert], None]] = []
        self._resolution_callbacks: List[Callable[[HealthAlert], None]] = []
        
        # Control
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Current state
        self._current_metrics: Optional[HealthMetrics] = None
        self._resolved_alerts: Dict[str, HealthAlert] = {}
    
    def add_alert_callback(self, callback: Callable[[HealthAlert], None]) -> None:
        """Add callback for health alerts."""
        with self._lock:
            self._alert_callbacks.append(callback)
    
    def add_resolution_callback(self, callback: Callable[[HealthAlert], None]) -> None:
        """Add callback for alert resolutions."""
        with self._lock:
            self._resolution_callbacks.append(callback)
    
    def start_monitoring(self) -> None:
        """Start health monitoring."""
        if self._monitoring:
            return
        
        self._monitoring = True
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(target=self._monitor_worker, daemon=True)
        self._monitor_thread.start()
        logger.info("Started health monitoring")
    
    def stop_monitoring(self) -> None:
        """Stop health monitoring."""
        if not self._monitoring:
            return
        
        self._monitoring = False
        self._stop_event.set()
        
        if self._monitor_thread:
            self._monitor_thread.join(timeout=10.0)
        
        logger.info("Stopped health monitoring")
    
    def update_metrics(
        self,
        interface_available: bool,
        packets_captured: int,
        packets_processed: int,
        packets_dropped: int,
        flows_in_queue: int,
        current_window_packets: int,
    ) -> None:
        """Update current metrics snapshot."""
        try:
            # Get system metrics
            memory_usage = self._get_memory_usage()
            cpu_usage = self._get_cpu_usage()
            disk_usage = self._get_disk_usage()
            
            # Calculate rates from history
            capture_rate, processing_rate, drop_rate = self._calculate_rates(
                packets_captured, packets_processed, packets_dropped
            )
            
            # Create metrics snapshot
            metrics = HealthMetrics(
                timestamp=time.time(),
                interface_available=interface_available,
                packets_captured=packets_captured,
                packets_processed=packets_processed,
                packets_dropped=packets_dropped,
                flows_in_queue=flows_in_queue,
                current_window_packets=current_window_packets,
                drop_rate_percent=drop_rate,
                capture_rate_pps=capture_rate,
                processing_rate_pps=processing_rate,
                memory_usage_mb=memory_usage,
                cpu_usage_percent=cpu_usage,
                disk_usage_percent=disk_usage,
            )
            
            with self._lock:
                self._current_metrics = metrics
                self._metrics_history.append(metrics)
                
                # Check for health issues
                self._check_health_thresholds(metrics)
                
        except Exception as e:
            logger.error(f"Error updating health metrics: {e}")
    
    def get_current_health(self) -> Optional[HealthMetrics]:
        """Get current health metrics."""
        with self._lock:
            return self._current_metrics
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get health summary statistics."""
        with self._lock:
            recent_metrics = list(self._metrics_history)[-10:]  # Last 10 snapshots
            
            if not recent_metrics:
                return {"status": "no_data"}
            
            # Calculate trends
            avg_drop_rate = sum(m.drop_rate_percent for m in recent_metrics) / len(recent_metrics)
            avg_queue_size = sum(m.flows_in_queue for m in recent_metrics) / len(recent_metrics)
            avg_capture_rate = sum(m.capture_rate_pps for m in recent_metrics) / len(recent_metrics)
            
            # Determine overall health status
            status = "healthy"
            if avg_drop_rate > self.max_drop_rate_percent * 0.5:
                status = "warning"
            if avg_drop_rate > self.max_drop_rate_percent:
                status = "critical"
            
            return {
                "status": status,
                "timestamp": time.time(),
                "metrics": {
                    "avg_drop_rate_percent": round(avg_drop_rate, 2),
                    "avg_queue_size": round(avg_queue_size, 1),
                    "avg_capture_rate_pps": round(avg_capture_rate, 2),
                    "interface_available": self._current_metrics.interface_available if self._current_metrics else False,
                    "memory_usage_mb": self._current_metrics.memory_usage_mb if self._current_metrics else 0.0,
                    "cpu_usage_percent": self._current_metrics.cpu_usage_percent if self._current_metrics else 0.0,
                    "disk_usage_percent": self._current_metrics.disk_usage_percent if self._current_metrics else 0.0,
                },
                "active_alerts": len([a for a in self._alert_history if not a.resolved]),
                "total_alerts": len(self._alert_history),
            }
    
    def get_recent_alerts(self, count: int = 10) -> List[HealthAlert]:
        """Get recent alerts."""
        with self._lock:
            return list(self._alert_history)[-count:]
    
    def _monitor_worker(self) -> None:
        """Worker thread for periodic health monitoring."""
        while not self._stop_event.is_set() and self._monitoring:
            try:
                # Update metrics with system resource usage even if no packets
                if self._current_metrics:
                    self.update_metrics(
                        interface_available=self._current_metrics.interface_available,
                        packets_captured=self._current_metrics.packets_captured,
                        packets_processed=self._current_metrics.packets_processed,
                        packets_dropped=self._current_metrics.packets_dropped,
                        flows_in_queue=self._current_metrics.flows_in_queue,
                        current_window_packets=self._current_metrics.current_window_packets,
                    )
                
                # Check for resolved alerts
                self._check_resolved_alerts()
                
                # Sleep for monitoring interval
                self._stop_event.wait(30.0)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in health monitoring worker: {e}")
                self._stop_event.wait(30.0)
    
    def _calculate_rates(
        self, 
        packets_captured: int, 
        packets_processed: int, 
        packets_dropped: int
    ) -> Tuple[float, float, float]:
        """Calculate capture, processing and drop rates from history."""
        with self._lock:
            if len(self._metrics_history) < 2:
                return 0.0, 0.0, 0.0
            
            # Get previous snapshot
            prev = self._metrics_history[-2]
            time_delta = self._current_metrics.timestamp - prev.timestamp
            
            if time_delta <= 0:
                return 0.0, 0.0, 0.0
            
            # Calculate rates
            capture_rate = (packets_captured - prev.packets_captured) / time_delta
            processing_rate = (packets_processed - prev.packets_processed) / time_delta
            drop_rate = (packets_dropped - prev.packets_dropped) / time_delta
            
            # Calculate drop rate as percentage of total
            total_packets = packets_captured - prev.packets_captured
            drop_rate_percent = (drop_rate / capture_rate * 100) if capture_rate > 0 else 0.0
            
            return capture_rate, processing_rate, drop_rate_percent
    
    def _check_health_thresholds(self, metrics: HealthMetrics) -> None:
        """Check metrics against health thresholds."""
        timestamp = time.time()
        
        # Drop rate monitoring
        if self.enable_drop_monitoring and metrics.drop_rate_percent > self.max_drop_rate_percent:
            self._trigger_alert(
                alert_type="high_drop_rate",
                severity="critical" if metrics.drop_rate_percent > self.max_drop_rate_percent * 2 else "warning",
                message=f"Drop rate {metrics.drop_rate_percent:.1f}% exceeds threshold {self.max_drop_rate_percent}%",
                metrics=metrics,
                timestamp=timestamp,
            )
        
        # Queue size monitoring
        if self.enable_queue_monitoring and metrics.flows_in_queue > self.max_flow_queue_size:
            self._trigger_alert(
                alert_type="queue_overflow",
                severity="warning",
                message=f"Flow queue size {metrics.flows_in_queue} exceeds threshold {self.max_flow_queue_size}",
                metrics=metrics,
                timestamp=timestamp,
            )
        
        # Interface availability
        if not metrics.interface_available:
            self._trigger_alert(
                alert_type="interface_unavailable",
                severity="critical",
                message="Capture interface is not available",
                metrics=metrics,
                timestamp=timestamp,
            )
        
        # High CPU usage
        if metrics.cpu_usage_percent > 90.0:
            self._trigger_alert(
                alert_type="high_cpu",
                severity="warning",
                message=f"CPU usage {metrics.cpu_usage_percent:.1f}% is very high",
                metrics=metrics,
                timestamp=timestamp,
            )
        
        # High memory usage
        if metrics.memory_usage_mb > 1024.0:  # 1GB
            self._trigger_alert(
                alert_type="high_memory",
                severity="warning",
                message=f"Memory usage {metrics.memory_usage_mb:.0f}MB is high",
                metrics=metrics,
                timestamp=timestamp,
            )
        
        # High disk usage
        if metrics.disk_usage_percent > 90.0:
            self._trigger_alert(
                alert_type="high_disk_usage",
                severity="critical",
                message=f"Disk usage {metrics.disk_usage_percent:.1f}% is critically high",
                metrics=metrics,
                timestamp=timestamp,
            )
    
    def _check_resolved_alerts(self) -> None:
        """Check if any active alerts have been resolved."""
        with self._lock:
            if not self._current_metrics:
                return
            
            current = self._current_metrics
            resolved_types = []
            
            for alert_type, alert in self._resolved_alerts.items():
                # Check if the condition that caused the alert is now resolved
                resolved = False
                
                if alert_type == "high_drop_rate":
                    resolved = current.drop_rate_percent <= self.max_drop_rate_percent * 0.5
                elif alert_type == "queue_overflow":
                    resolved = current.flows_in_queue <= self.max_flow_queue_size * 0.8
                elif alert_type == "interface_unavailable":
                    resolved = current.interface_available
                elif alert_type == "high_cpu":
                    resolved = current.cpu_usage_percent <= 70.0
                elif alert_type == "high_memory":
                    resolved = current.memory_usage_mb <= 512.0
                elif alert_type == "high_disk_usage":
                    resolved = current.disk_usage_percent <= 80.0
                
                if resolved:
                    resolved_types.append(alert_type)
                    alert.resolved = True
                    alert.resolved_at = time.time()
                    
                    # Notify resolution callbacks
                    for callback in self._resolution_callbacks:
                        try:
                            callback(alert)
                        except Exception as e:
                            logger.error(f"Error in alert resolution callback: {e}")
            
            # Clean up resolved alerts
            for alert_type in resolved_types:
                del self._resolved_alerts[alert_type]
    
    def _trigger_alert(
        self, 
        alert_type: str, 
        severity: str, 
        message: str, 
        metrics: HealthMetrics, 
        timestamp: float
    ) -> None:
        """Trigger a health alert with cooldown protection."""
        # Check cooldown
        last_alert_time = self._last_alert_times.get(alert_type, 0)
        if timestamp - last_alert_time < self.alert_cooldown_seconds:
            return
        
        # Create alert
        alert = HealthAlert(
            alert_type=alert_type,
            severity=severity,
            message=message,
            timestamp=timestamp,
            metrics=metrics,
        )
        
        # Record alert
        with self._lock:
            self._alert_history.append(alert)
            self._last_alert_times[alert_type] = timestamp
            
            # Store as resolved alert if there's an active one
            if alert_type in self._resolved_alerts:
                del self._resolved_alerts[alert_type]
            
            self._resolved_alerts[alert_type] = alert
        
        # Notify callbacks
        for callback in self._alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
        
        # Log the alert
        if severity == "critical":
            logger.critical(f"HEALTH ALERT [{alert_type}]: {message}")
        else:
            logger.warning(f"HEALTH ALERT [{alert_type}]: {message}")
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / (1024 * 1024)
        except ImportError:
            # Fallback if psutil is not available
            return 0.0
        except Exception:
            return 0.0
    
    def _get_cpu_usage(self) -> float:
        """Get current CPU usage percentage."""
        try:
            import psutil
            return psutil.cpu_percent(interval=None)
        except ImportError:
            return 0.0
        except Exception:
            return 0.0
    
    def _get_disk_usage(self) -> float:
        """Get disk usage percentage for the current directory."""
        try:
            import psutil
            current_dir = Path.cwd()
            usage = psutil.disk_usage(str(current_dir))
            return (usage.used / usage.total) * 100
        except ImportError:
            return 0.0
        except Exception:
            return 0.0