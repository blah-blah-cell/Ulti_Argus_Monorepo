"""Argus Community capture and flow aggregation module.

Packet collection and analysis for network monitoring.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .aggregator import PacketBatcher, WindowAggregator
from .collector import CaptureEngine, InterfaceMonitor, PacketInfo
from .config import AggregationConfig, CaptureConfig, HealthConfig, RetinaConfig
from .csv_rotator import MythologicalCSVRotator
from .daemon import RetinaDaemon
from .health_monitor import HealthAlert, HealthMetrics, HealthMonitor

__all__ = [
    "CaptureEngine",
    "InterfaceMonitor",
    "PacketInfo",
    "WindowAggregator",
    "PacketBatcher",
    "MythologicalCSVRotator",
    "HealthMonitor",
    "HealthMetrics",
    "HealthAlert",
    "RetinaDaemon",
    "RetinaConfig",
    "CaptureConfig",
    "AggregationConfig",
    "HealthConfig",
]
