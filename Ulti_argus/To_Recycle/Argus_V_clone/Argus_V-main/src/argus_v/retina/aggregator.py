"""Window-based packet aggregation with metrics computation."""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from queue import Queue
from typing import Any, Callable, Dict, List, Optional

from ..oracle_core.anonymize import hash_ip, round_epoch_seconds
from .collector import PacketInfo

logger = logging.getLogger(__name__)


@dataclass
class WindowStats:
    """Statistics for a time window."""
    
    start_time: float
    end_time: float
    duration_seconds: float
    packet_count: int
    byte_count: int
    unique_flows: int
    protocols: Dict[str, int]  # protocol -> count
    rate_pps: float  # packets per second
    rate_bps: float  # bytes per second
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for CSV output."""
        return {
            "window_start": datetime.fromtimestamp(self.start_time, tz=timezone.utc).isoformat(),
            "window_end": datetime.fromtimestamp(self.end_time, tz=timezone.utc).isoformat(),
            "duration_seconds": self.duration_seconds,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "unique_flows": self.unique_flows,
            "rate_pps": round(self.rate_pps, 2),
            "rate_bps": round(self.rate_bps, 2),
            "protocol_counts": self.protocols,
        }


@dataclass
class FlowKey:
    """Uniquely identifies a network flow."""
    
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    
    def __hash__(self) -> int:
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))


@dataclass
class FlowStats:
    """Statistics for a network flow within a window."""
    
    flow_key: FlowKey
    packet_count: int
    byte_count: int
    first_seen: float
    last_seen: float
    
    @property
    def duration_seconds(self) -> float:
        return self.last_seen - self.first_seen
    
    @property
    def avg_packet_size(self) -> float:
        return self.byte_count / self.packet_count if self.packet_count > 0 else 0.0


class WindowAggregator:
    """Aggregates packets into time windows and computes metrics."""
    
    def __init__(
        self,
        window_seconds: int = 5,
        anonymization_salt: bytes = b"default_salt",
        flow_timeout_seconds: int = 300,
    ):
        self.window_seconds = window_seconds
        self.anonymization_salt = anonymization_salt
        self.flow_timeout_seconds = flow_timeout_seconds
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Current window state
        self._current_window_start: Optional[float] = None
        self._current_window_packets = 0
        self._current_window_bytes = 0
        self._current_window_flows: Dict[FlowKey, FlowStats] = {}
        self._current_window_protocols = defaultdict(int)
        
        # Packet processing
        self._packet_queue: Queue[PacketInfo] = Queue(maxsize=10000)
        self._processing = False
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Window callbacks
        self._window_completed_callbacks: List[Callable[[WindowStats], None]] = []
        
        # Statistics
        self._stats = {
            "packets_processed": 0,
            "packets_dropped": 0,
            "windows_completed": 0,
            "flows_tracked": 0,
        }
    
    def add_window_completed_callback(self, callback: Callable[[WindowStats], None]) -> None:
        """Add callback for when a window is completed."""
        with self._lock:
            self._window_completed_callbacks.append(callback)
    
    def start(self) -> None:
        """Start the aggregation worker."""
        if self._processing:
            return
        
        self._processing = True
        self._stop_event.clear()
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()
        logger.info(f"Started window aggregator with {self.window_seconds}s windows")
    
    def stop(self) -> None:
        """Stop the aggregation worker and flush current window."""
        if not self._processing:
            return
        
        logger.info("Stopping window aggregator...")
        self._processing = False
        self._stop_event.set()
        
        # Flush current window
        self._flush_current_window()
        
        # Wait for worker thread
        if self._worker_thread:
            self._worker_thread.join(timeout=10.0)
        
        logger.info("Window aggregator stopped")
    
    def add_packet(self, packet: PacketInfo) -> bool:
        """Add a packet to the aggregation queue."""
        try:
            self._packet_queue.put_nowait(packet)
            return True
        except:
            # Queue full, packet dropped
            with self._lock:
                self._stats["packets_dropped"] += 1
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        with self._lock:
            return {
                **self._stats,
                "current_window_start": self._current_window_start,
                "current_window_packets": self._current_window_packets,
                "current_window_bytes": self._current_window_bytes,
                "current_window_flows": len(self._current_window_flows),
                "queue_size": self._packet_queue.qsize(),
                "processing": self._processing,
            }
    
    def _worker_loop(self) -> None:
        """Main worker loop for packet processing."""
        while not self._stop_event.is_set() and self._processing:
            try:
                # Get packet with timeout
                try:
                    packet = self._packet_queue.get(timeout=1.0)
                except:
                    continue
                
                # Process the packet
                self._process_packet(packet)
                
            except Exception as e:
                logger.error(f"Error in aggregation worker: {e}")
                time.sleep(0.1)
    
    def _process_packet(self, packet: PacketInfo) -> None:
        """Process a single packet."""
        current_time = time.time()
        
        # Initialize window if needed
        if self._current_window_start is None:
            self._current_window_start = self._get_window_start(current_time)
        
        # Check if we need to start a new window
        window_start = self._get_window_start(current_time)
        if window_start != self._current_window_start:
            # Flush current window and start new one
            self._flush_current_window()
            self._current_window_start = window_start
            self._current_window_packets = 0
            self._current_window_bytes = 0
            self._current_window_flows.clear()
            self._current_window_protocols.clear()
        
        # Update counters
        with self._lock:
            self._stats["packets_processed"] += 1
            self._current_window_packets += 1
            self._current_window_bytes += packet.packet_size
            self._current_window_protocols[packet.protocol] += 1
        
        # Update flow statistics
        self._update_flow_stats(packet, current_time)
    
    def _get_window_start(self, timestamp: float) -> float:
        """Get the start time of the window for a given timestamp."""
        return round_epoch_seconds(
            int(timestamp), 
            resolution_seconds=self.window_seconds, 
            mode="floor"
        )
    
    def _update_flow_stats(self, packet: PacketInfo, timestamp: float) -> None:
        """Update flow statistics for the current window."""
        # Anonymize IP addresses
        src_ip_anon = hash_ip(packet.src_ip, salt=self.anonymization_salt)
        dst_ip_anon = hash_ip(packet.dst_ip, salt=self.anonymization_salt)
        
        # Create flow key
        flow_key = FlowKey(
            src_ip=src_ip_anon,
            dst_ip=dst_ip_anon,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
        )
        
        with self._lock:
            # Update or create flow stats
            if flow_key in self._current_window_flows:
                flow = self._current_window_flows[flow_key]
                flow.packet_count += 1
                flow.byte_count += packet.packet_size
                flow.last_seen = timestamp
            else:
                flow = FlowStats(
                    flow_key=flow_key,
                    packet_count=1,
                    byte_count=packet.packet_size,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
                self._current_window_flows[flow_key] = flow
                self._stats["flows_tracked"] += 1
    
    def _flush_current_window(self) -> None:
        """Flush the current window and compute final statistics."""
        if self._current_window_start is None:
            return
        
        current_time = time.time()
        window_end = self._current_window_start + self.window_seconds
        duration = window_end - self._current_window_start
        
        # Clean up expired flows
        self._cleanup_expired_flows(current_time)
        
        # Compute final window stats
        with self._lock:
            protocols = dict(self._current_window_protocols)
            packet_count = self._current_window_packets
            byte_count = self._current_window_bytes
            unique_flows = len(self._current_window_flows)
        
        # Calculate rates
        rate_pps = packet_count / duration if duration > 0 else 0.0
        rate_bps = byte_count * 8 / duration if duration > 0 else 0.0  # bits per second
        
        # Create window stats
        window_stats = WindowStats(
            start_time=self._current_window_start,
            end_time=window_end,
            duration_seconds=duration,
            packet_count=packet_count,
            byte_count=byte_count,
            unique_flows=unique_flows,
            protocols=protocols,
            rate_pps=rate_pps,
            rate_bps=rate_bps,
        )
        
        # Update statistics
        with self._lock:
            self._stats["windows_completed"] += 1
        
        # Notify callbacks
        for callback in self._window_completed_callbacks:
            try:
                callback(window_stats)
            except Exception as e:
                logger.error(f"Error in window completed callback: {e}")
        
        logger.debug(
            f"Window completed: {packet_count} packets, {byte_count} bytes, "
            f"{unique_flows} flows, {rate_pps:.2f} pps"
        )
    
    def _cleanup_expired_flows(self, current_time: float) -> None:
        """Remove expired flows from current window."""
        cutoff_time = current_time - self.flow_timeout_seconds
        
        expired_flows = [
            key for key, flow in self._current_window_flows.items()
            if flow.last_seen < cutoff_time
        ]
        
        for key in expired_flows:
            del self._current_window_flows[key]
        
        if expired_flows:
            logger.debug(f"Cleaned up {len(expired_flows)} expired flows")


class PacketBatcher:
    """Batches packets before aggregation for better performance."""
    
    def __init__(
        self, 
        aggregator: WindowAggregator,
        batch_size: int = 100,
        batch_timeout_ms: int = 100,
    ):
        self.aggregator = aggregator
        self.batch_size = batch_size
        self.batch_timeout_ms = batch_timeout_ms
        
        self._batch: List[PacketInfo] = []
        self._batch_lock = threading.Lock()
        self._batch_timer: Optional[threading.Timer] = None
    
    def add_packet(self, packet: PacketInfo) -> None:
        """Add packet to batch."""
        with self._batch_lock:
            self._batch.append(packet)
            
            # If batch is full, flush immediately
            if len(self._batch) >= self.batch_size:
                self._flush_batch()
            else:
                # Set timer to flush batch after timeout
                self._schedule_flush()
    
    def flush(self) -> None:
        """Force flush current batch."""
        with self._batch_lock:
            self._flush_batch()
    
    def _schedule_flush(self) -> None:
        """Schedule batch flush after timeout."""
        if self._batch_timer:
            self._batch_timer.cancel()
        
        self._batch_timer = threading.Timer(
            self.batch_timeout_ms / 1000.0,
            self._flush_batch,
        )
        self._batch_timer.daemon = True
        self._batch_timer.start()
    
    def _flush_batch(self) -> None:
        """Flush current batch to aggregator."""
        if not self._batch:
            return
        
        batch = self._batch.copy()
        self._batch.clear()
        
        if self._batch_timer:
            self._batch_timer.cancel()
            self._batch_timer = None
        
        # Add all packets to aggregator
        for packet in batch:
            self.aggregator.add_packet(packet)