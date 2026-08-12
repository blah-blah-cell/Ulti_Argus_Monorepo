"""Mutable runtime state for the live-capture pipeline.

The legacy ``live_capture.py`` had several module-level mutable objects
(``stats``, ``results``, ``results_lock``, ``tracker``, ``_detection_mode``)
that were read and written by many functions via ``global`` declarations.
Centralizing them in this small module avoids the need for ``global`` once
the code is split into multiple files: other modules simply
``from web.api.capture import state`` and access ``state.stats[...]``.

This module performs no work on import — it only constructs default-empty
containers.
"""
from __future__ import annotations

import threading
from typing import Any, Dict, List

from web.api.capture.flow_tracker import FlowTracker

# Flow tracker shared across the pipeline.
tracker: FlowTracker = FlowTracker(timeout=5.0)

# Recent flow analysis results (capped at MAX_RESULTS in runtime.packet_callback).
results: List[Dict[str, Any]] = []
results_lock = threading.Lock()

# Aggregate observed counters surfaced via get_stats().
stats: Dict[str, int] = {
    "packets": 0,
    "bytes": 0,
    "flows": 0,
    "layer0_captured": 0,
    "layer0_dpi_identified": 0,
    "layer0_patterns_found": 0,
    "pattern_matches": 0,
}


