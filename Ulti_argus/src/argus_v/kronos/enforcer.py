"""Kronos eBPF Enforcer — Manages the Kernel BLOCKLIST Map.

DeepPacketSentinel (Rust) creates an eBPF map named `BLOCKLIST` (type: Hash).
To achieve zero-latency drops without traversing the Linux networking stack,
Aegis uses this class to inject malicious IPs directly into the map using the
system `bpftool` command.
"""

from __future__ import annotations

import logging
import socket
import subprocess
from typing import Optional

from ..oracle_core.logging import log_event

logger = logging.getLogger(__name__)

# Fallback path if auto-detection fails
_DEFAULT_MAP_NAME = "BLOCKLIST"


class KronosEnforcer:
    """Wrapper around bpftool to manipulate the DeepPacketSentinel eBPF map."""

    def __init__(self, map_name: str = _DEFAULT_MAP_NAME):
        self.map_name = map_name
        self._map_id: Optional[str] = None
        self._available: bool = self._check_availability()
        
        if self._available:
            self._map_id = self._find_map_id()

    def _check_availability(self) -> bool:
        """Check if bpftool is installed and accessible."""
        try:
            res = subprocess.run(
                ["bpftool", "version"],
                capture_output=True,
                check=True,
                timeout=2,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            log_event(logger, "bpftool_not_found", level="warning")
            return False

    def _find_map_id(self) -> Optional[str]:
        """Find the numeric eBPF map ID for the BLOCKLIST map."""
        if not self._available:
            return None

        try:
            # Output format: JSON array of maps
            res = subprocess.run(
                ["bpftool", "map", "show", "name", self.map_name, "-j"],
                capture_output=True,
                text=True,
                check=True,
                timeout=2,
            )
            import json
            maps = json.loads(res.stdout)
            if maps and isinstance(maps, list):
                # Take the first matching map
                map_id = str(maps[0].get("id"))
                log_event(
                    logger, "ebpf_map_found", level="info", 
                    map_name=self.map_name, map_id=map_id
                )
                return map_id
        except Exception as e:
            log_event(
                logger, "ebpf_map_discovery_failed", level="warning", 
                map_name=self.map_name, error=str(e)
            )
        return None

    def _ip_to_hex_bytes(self, ip_address: str) -> str:
        """Convert an IPv4 string (e.g., '192.168.1.5') to bpftool hex byte string representation.
        
        DeepPacketSentinel stores IPs as Big-Endian u32 in the map.
        bpftool expects byte arrays as: `hex byte byte byte byte`
        Example: 192.168.1.5 -> `00 00 00 00` (network order converted to bpftool fmt).
        """
        # Convert IP string to 4-byte packed network-order bytes
        packed = socket.inet_aton(ip_address)
        # Format as space-separated hex bytes for bpftool (e.g., "c0 a8 01 05")
        return " ".join(f"{b:02x}" for b in packed)

    def block_ip(self, ip_address: str) -> bool:
        """Add an IP to the eBPF BLOCKLIST map to drop it at the kernel level."""
        if not self._available:
            return False
            
        # Re-resolve map ID if it was lost or not found initially
        if not self._map_id:
            self._map_id = self._find_map_id()
            if not self._map_id:
                return False

        try:
            hex_ip = self._ip_to_hex_bytes(ip_address)
            # Value is a u32, we just set it to 1 (01 00 00 00 in little-endian for a simple counter/flag, 
            # though DPS just checks if the key exists via .get() so any value works).
            value_hex = "01 00 00 00"

            # Execute: bpftool map update id <MAP_ID> key <IP_HEX> value <VAL_HEX>
            cmd = [
                "bpftool", "map", "update", "id", self._map_id,
                "key", "hex"
            ] + hex_ip.split() + ["value", "hex"] + value_hex.split()

            res = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            
            if res.returncode == 0:
                log_event(
                    logger, "ebpf_block_applied", level="info", 
                    ip=ip_address, hex_key=hex_ip
                )
                return True
            else:
                log_event(
                    logger, "ebpf_block_failed", level="error", 
                    ip=ip_address, stderr=res.stderr.strip()
                )
                return False

        except Exception as e:
            log_event(
                logger, "ebpf_block_exception", level="error", 
                ip=ip_address, error=str(e)
            )
            return False

    def unblock_ip(self, ip_address: str) -> bool:
        """Remove an IP from the eBPF BLOCKLIST map."""
        if not self._available or not self._map_id:
            return False

        try:
            hex_ip = self._ip_to_hex_bytes(ip_address)

            # Execute: bpftool map delete id <MAP_ID> key <IP_HEX>
            cmd = [
                "bpftool", "map", "delete", "id", self._map_id,
                "key", "hex"
            ] + hex_ip.split()

            res = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            
            # bpftool returns 0 if deleted, might return non-zero if key didn't exist
            if res.returncode == 0:
                log_event(
                    logger, "ebpf_unblock_applied", level="info", 
                    ip=ip_address
                )
                return True
            else:
                log_event(
                    logger, "ebpf_unblock_failed", level="warning", 
                    ip=ip_address, stderr=res.stderr.strip()
                )
                return False

        except Exception as e:
            log_event(
                logger, "ebpf_unblock_exception", level="error", 
                ip=ip_address, error=str(e)
            )
            return False
