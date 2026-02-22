"""Kronos — Trained meta-router for dual-model offloading.

Sits between DeepPacketSentinel (Rust/eBPF) and the IF + CNN models,
intelligently routing each flow to the cheapest path that still produces
a correct verdict.

Public API
----------
KronosRouter      — trained gradient-boosted routing model
IPHistoryStore    — per-IP rolling score & interval memory
TemporalContext   — time-of-day / heartbeat / boot-window signals
KronosTrainer     — fits/updates the routing model (called by Mnemosyne)
IPCListener       — Unix-socket receiver for flows from DPS (Rust)
"""

from .router import KronosRouter, RoutingPath
from .ip_history import IPHistoryStore
from .temporal import TemporalContext
from .trainer import KronosTrainer
from .ipc_listener import IPCListener

__all__ = [
    "KronosRouter",
    "RoutingPath",
    "IPHistoryStore",
    "TemporalContext",
    "KronosTrainer",
    "IPCListener",
]
