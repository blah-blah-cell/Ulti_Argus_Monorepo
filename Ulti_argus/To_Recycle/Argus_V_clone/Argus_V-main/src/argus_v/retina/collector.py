"""Packet capture engine with scapy/pcapy fallback and graceful interface handling."""

from __future__ import annotations

import ipaddress
import logging
import time
from contextlib import contextmanager
from dataclasses import dataclass
from threading import Event, Thread
from typing import Any, Callable, Iterator, Optional

try:
    from scapy.all import conf, get_if_addr, get_if_list, getmacbyip
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import pcapy
    HAS_PCAPY = True
except ImportError:
    HAS_PCAPY = False


logger = logging.getLogger(__name__)


@dataclass
class PacketInfo:
    """Information about a captured packet."""
    
    timestamp: float
    interface: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    packet_size: int
    raw_data: bytes


class CaptureEngine:
    """Unified packet capture engine with scapy/pcapy fallback."""
    
    def __init__(self, interface: str = "eth0", use_scapy: bool = True):
        self.interface = interface
        self.use_scapy = use_scapy and HAS_SCAPY
        self._capture_thread: Optional[Thread] = None
        self._stop_event = Event()
        self._packet_callback: Optional[Callable[[PacketInfo], None]] = None
        
        if not self.use_scapy and HAS_PCAPY:
            logger.info("Using pcapy fallback for packet capture")
        elif not HAS_SCAPY and not HAS_PCAPY:
            # Create a mock version for testing
            self.use_scapy = False
            logger.warning("Neither scapy nor pcapy is available - using mock mode")
    
    # Class attributes for capability detection
    HAS_SCAPY = HAS_SCAPY
    HAS_PCAPY = HAS_PCAPY
    
    def set_packet_callback(self, callback: Callable[[PacketInfo], None]) -> None:
        """Set callback function for captured packets."""
        self._packet_callback = callback
    
    def get_interface_stats(self) -> dict[str, Any]:
        """Get current interface statistics."""
        stats = {
            "interface": self.interface,
            "available": self.is_interface_available(),
            "capture_engine": "scapy" if self.use_scapy else "pcapy",
            "supports_promiscuous": True,
        }
        
        if self.is_interface_available():
            try:
                stats["ip_address"] = self.get_interface_ip()
                stats["mac_address"] = self.get_interface_mac()
            except Exception as e:
                logger.warning(f"Failed to get interface details: {e}")
                stats["error"] = str(e)
        
        return stats
    
    def is_interface_available(self) -> bool:
        """Check if the capture interface is available."""
        if not HAS_SCAPY:
            return HAS_PCAPY  # Assume available if pcapy is available
        
        try:
            return self.interface in get_if_list()
        except Exception as e:
            logger.error(f"Failed to check interface availability: {e}")
            return False
    
    def get_interface_ip(self) -> str:
        """Get IP address of the capture interface."""
        if not HAS_SCAPY:
            return "0.0.0.0"  # Fallback
            
        return get_if_addr(self.interface)
    
    def get_interface_mac(self) -> str:
        """Get MAC address of the capture interface."""
        if not HAS_SCAPY:
            return "00:00:00:00:00:00"  # Fallback
            
        try:
            return getmacbyip(self.get_interface_ip())
        except Exception:
            return "00:00:00:00:00:00"
    
    @contextmanager
    def capture_context(
        self, 
        packet_handler: Callable[[PacketInfo], None],
        snaplen: int = 65535,
        promiscuous: bool = True,
        timeout_ms: int = 100,
    ) -> Iterator[None]:
        """Context manager for packet capture with proper cleanup."""
        self.set_packet_callback(packet_handler)
        
        try:
            if self.use_scapy:
                self._start_scapy_capture(snaplen, promiscuous, timeout_ms)
            else:
                self._start_pcapy_capture(snaplen, promiscuous, timeout_ms)
            
            yield
            
        finally:
            self.stop_capture()
    
    def _start_scapy_capture(
        self, 
        snaplen: int, 
        promiscuous: bool, 
        timeout_ms: int,
    ) -> None:
        """Start packet capture using scapy."""
        from scapy.all import sniff
        
        def scapy_callback(packet):
            if self._packet_callback:
                packet_info = self._convert_scapy_packet(packet)
                if packet_info:
                    self._packet_callback(packet_info)
        
        def capture_worker():
            try:
                logger.info(f"Starting scapy capture on {self.interface}")
                sniff(
                    iface=self.interface,
                    prn=scapy_callback,
                    store=False,
                    stop_filter=lambda p: self._stop_event.is_set(),
                    # Note: scapy doesn't support timeout_ms in the same way
                )
            except Exception as e:
                logger.error(f"Scapy capture error: {e}")
        
        self._stop_event.clear()
        self._capture_thread = Thread(target=capture_worker)
        self._capture_thread.start()
    
    def _start_pcapy_capture(
        self, 
        snaplen: int, 
        promiscuous: bool, 
        timeout_ms: int,
    ) -> None:
        """Start packet capture using pcapy fallback."""
        def capture_worker():
            try:
                logger.info(f"Starting pcapy capture on {self.interface}")
                
                # Open capture handle
                pcap = pcapy.open_live(
                    self.interface, 
                    snaplen, 
                    1 if promiscuous else 0, 
                    timeout_ms
                )
                
                # Set filter (capture all packets for now)
                try:
                    pcap.setfilter("ip or ip6")
                except Exception as e:
                    logger.warning(f"Failed to set packet filter: {e}")
                
                # Start capturing
                packet_count = 0
                while not self._stop_event.is_set():
                    try:
                        header, packet = pcap.next()
                        if packet and self._packet_callback:
                            packet_info = self._convert_pcapy_packet(header, packet)
                            if packet_info:
                                self._packet_callback(packet_info)
                                packet_count += 1
                    except pcapy.PcapError:
                        # Timeout or end of capture
                        continue
                    except Exception as e:
                        logger.error(f"Packet capture error: {e}")
                        break
                
                logger.info(f"Pcapy capture stopped after {packet_count} packets")
                
            except Exception as e:
                logger.error(f"Pcapy capture initialization error: {e}")
        
        self._stop_event.clear()
        self._capture_thread = Thread(target=capture_worker, daemon=True)
        self._capture_thread.start()
    
    def _convert_scapy_packet(self, packet) -> Optional[PacketInfo]:
        """Convert scapy packet to PacketInfo."""
        try:
            timestamp = time.time()
            interface = self.interface
            
            # Extract network layer information
            src_ip = dst_ip = "unknown"
            src_port = dst_port = None
            protocol = "unknown"
            
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = f"IPv4/{packet[IP].proto}"
                
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    protocol = "TCP"
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    protocol = "UDP"
                elif ICMP in packet:
                    protocol = "ICMP"
            elif IPv6 in packet:
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
                protocol = "IPv6"
            else:
                # Try to get IP from higher layers
                layers = packet.layers()
                for layer in layers:
                    if hasattr(layer, 'src') and hasattr(layer, 'dst'):
                        src_ip = getattr(layer, 'src', 'unknown')
                        dst_ip = getattr(layer, 'dst', 'unknown')
                        break
            
            return PacketInfo(
                timestamp=timestamp,
                interface=interface,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_size=len(packet),
                raw_data=bytes(packet),
            )
        except Exception as e:
            logger.warning(f"Failed to convert scapy packet: {e}")
            return None
    
    def _convert_pcapy_packet(self, header, packet) -> Optional[PacketInfo]:
        """Convert pcapy packet to PacketInfo."""
        try:
            timestamp = time.time()
            
            # Parse Ethernet header
            if len(packet) < 14:
                return None
            
            # Extract EtherType
            eth_type = (packet[12] << 8) | packet[13]
            
            src_ip = dst_ip = "unknown"
            src_port = dst_port = None
            protocol = "unknown"
            
            if eth_type == 0x0800:  # IPv4
                if len(packet) >= 34:  # Ethernet + IP header
                    ip_header = packet[14:34]
                    src_ip = f"{ip_header[12]}.{ip_header[13]}.{ip_header[14]}.{ip_header[15]}"
                    dst_ip = f"{ip_header[16]}.{ip_header[17]}.{ip_header[18]}.{ip_header[19]}"
                    protocol = f"IPv4/{ip_header[9]}"
                    
                    # Try to extract ports for TCP/UDP
                    if len(packet) >= 34 + 8:
                        protocol_num = ip_header[9]
                        if protocol_num == 6:  # TCP
                            src_port = (packet[34] << 8) | packet[35]
                            dst_port = (packet[36] << 8) | packet[37]
                            protocol = "TCP"
                        elif protocol_num == 17:  # UDP
                            src_port = (packet[34] << 8) | packet[35]
                            dst_port = (packet[36] << 8) | packet[37]
                            protocol = "UDP"
            elif eth_type == 0x86DD:  # IPv6
                if len(packet) >= 54:  # Ethernet + IPv6 header
                    try:
                        src_bytes = packet[22:38]
                        dst_bytes = packet[38:54]
                        src_ip = str(ipaddress.IPv6Address(src_bytes))
                        dst_ip = str(ipaddress.IPv6Address(dst_bytes))
                    except ValueError:
                        # Fallback for invalid IP bytes
                        src_ip = ":".join(f"{packet[i]:02x}{packet[i+1]:02x}" for i in range(22, 38, 2))
                        dst_ip = ":".join(f"{packet[i]:02x}{packet[i+1]:02x}" for i in range(38, 54, 2))

                    protocol = "IPv6"
            
            return PacketInfo(
                timestamp=timestamp,
                interface=self.interface,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_size=len(packet),
                raw_data=packet,
            )
        except Exception as e:
            logger.warning(f"Failed to convert pcapy packet: {e}")
            return None
    
    def stop_capture(self) -> None:
        """Stop packet capture."""
        if self._capture_thread and self._capture_thread.is_alive():
            logger.info("Stopping packet capture")
            self._stop_event.set()
            
            # Wait for capture thread to finish
            self._capture_thread.join(timeout=5.0)
            if self._capture_thread.is_alive():
                logger.warning("Capture thread did not stop gracefully")


class InterfaceMonitor:
    """Monitor network interface availability and health."""
    
    def __init__(self, interface: str = "eth0", check_interval: float = 10.0):
        self.interface = interface
        self.check_interval = check_interval
        self._is_available = False
        self._monitoring = False
        self._monitor_thread: Optional[Thread] = None
        self._stop_event = Event()
        self._availability_callbacks: list[Callable[[str, bool], None]] = []
    
    def add_availability_callback(self, callback: Callable[[str, bool], None]) -> None:
        """Add callback for interface availability changes."""
        self._availability_callbacks.append(callback)
    
    def start_monitoring(self) -> None:
        """Start interface monitoring."""
        if self._monitoring:
            return
        
        self._monitoring = True
        self._stop_event.clear()
        self._monitor_thread = Thread(target=self._monitor_worker, daemon=True)
        self._monitor_thread.start()
        logger.info(f"Started monitoring interface {self.interface}")
    
    def stop_monitoring(self) -> None:
        """Stop interface monitoring."""
        if not self._monitoring:
            return
        
        self._monitoring = False
        self._stop_event.set()
        
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)
        
        logger.info(f"Stopped monitoring interface {self.interface}")
    
    def _monitor_worker(self) -> None:
        """Worker thread for interface monitoring."""
        # Use capture engine to check interface availability
        engine = CaptureEngine(self.interface, use_scapy=True)

        while not self._stop_event.is_set():
            try:
                is_available = engine.is_interface_available()
                
                if is_available != self._is_available:
                    old_status = self._is_available
                    self._is_available = is_available
                    
                    logger.info(f"Interface {self.interface} availability changed: {old_status} -> {is_available}")
                    
                    # Notify callbacks
                    for callback in self._availability_callbacks:
                        try:
                            callback(self.interface, is_available)
                        except Exception as e:
                            logger.error(f"Error in availability callback: {e}")
                
                # Wait for next check
                self._stop_event.wait(self.check_interval)
                
            except Exception as e:
                logger.error(f"Interface monitoring error: {e}")
                self._stop_event.wait(self.check_interval)
    
    def is_available(self) -> bool:
        """Get current interface availability."""
        if not self._monitoring:
            # If not monitoring, do a direct check
            try:
                engine = CaptureEngine(self.interface, use_scapy=True)
                return engine.is_interface_available()
            except Exception:
                return False
        
        return self._is_available
    
    def get_status(self) -> dict[str, Any]:
        """Get current interface monitoring status."""
        engine = CaptureEngine(self.interface, use_scapy=True)
        return {
            "interface": self.interface,
            "monitoring": self._monitoring,
            "available": self.is_available(),
            "last_check": time.time(),
            "stats": engine.get_interface_stats(),
        }