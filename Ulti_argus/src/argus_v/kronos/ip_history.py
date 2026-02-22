"""Kronos IP History Store — Per-IP behavioral memory.

Tracks each source IP's IsolationForest score history and inter-packet
arrival intervals in a bounded rolling window.  Kronos uses this to
compute the "behavioral delta" — how much an IP has deviated from its
own historical baseline — rather than relying on an absolute threshold.

This is what lets Kronos distinguish:
  - A known-good printer that's always slightly noisy  → fast pass
  - A known-quiet device that suddenly goes loud       → escalate
  - A brand-new IP with an anomalous first flow        → escalate
"""

from __future__ import annotations

import logging
import pickle
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

from ..oracle_core.logging import log_event

logger = logging.getLogger(__name__)

# How many flows to remember per IP
_DEFAULT_MAX_FLOWS = 100

# How many seconds of history to keep (flows older than this are dropped)
_DEFAULT_WINDOW_SECONDS = 3600  # 1 hour


@dataclass
class IPRecord:
    """Rolling history for a single IP address."""
    scores: deque = field(default_factory=lambda: deque(maxlen=_DEFAULT_MAX_FLOWS))
    intervals: deque = field(default_factory=lambda: deque(maxlen=_DEFAULT_MAX_FLOWS))
    last_seen: float = field(default_factory=time.time)
    flow_count: int = 0

    @property
    def mean_score(self) -> Optional[float]:
        """Mean IF score over the history window. None if no history."""
        if not self.scores:
            return None
        return sum(self.scores) / len(self.scores)

    @property
    def mean_interval(self) -> Optional[float]:
        """Mean inter-arrival interval in seconds. None if insufficient history."""
        if len(self.intervals) < 2:
            return None
        return sum(self.intervals) / len(self.intervals)

    def score_delta(self, current_score: float) -> Optional[float]:
        """How far is current_score from this IP's historical mean?

        Positive delta = current score is BETTER than usual (more normal).
        Negative delta = current score is WORSE than usual (more anomalous).
        Returns None if no history yet.
        """
        mean = self.mean_score
        if mean is None:
            return None
        return current_score - mean

    def interval_delta(self, current_interval: float) -> Optional[float]:
        """How far is current_interval from this IP's typical rhythm?

        Large positive delta = packet arrived much later than usual.
        Large negative delta = packet arrived much earlier (burst).
        Returns None if no interval history yet.
        """
        mean = self.mean_interval
        if mean is None:
            return None
        return current_interval - mean


class IPHistoryStore:
    """Thread-safe store of per-IP rolling behavioral history.

    Args:
        max_flows_per_ip: Maximum number of flows to remember per IP.
        window_seconds:   Flows older than this are evicted on access.
        persist_path:     If given, history is saved here on shutdown and
                          reloaded on startup so Kronos doesn't start blind
                          after a restart.
    """

    def __init__(
        self,
        max_flows_per_ip: int = _DEFAULT_MAX_FLOWS,
        window_seconds: float = _DEFAULT_WINDOW_SECONDS,
        persist_path: Optional[str] = None,
    ):
        self.max_flows_per_ip = max_flows_per_ip
        self.window_seconds = window_seconds
        self.persist_path = Path(persist_path) if persist_path else None

        self._store: Dict[str, IPRecord] = {}
        self._lock = threading.RLock()

        if self.persist_path and self.persist_path.exists():
            self._load()

        log_event(
            logger,
            "ip_history_store_initialized",
            level="info",
            max_flows_per_ip=max_flows_per_ip,
            window_seconds=window_seconds,
            persist_path=str(persist_path),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(
        self,
        ip: str,
        if_score: float,
        timestamp: Optional[float] = None,
    ) -> IPRecord:
        """Record a new flow observation for an IP.

        Args:
            ip:         Source IP string.
            if_score:   IsolationForest decision_function score for this flow.
            timestamp:  Unix timestamp of the flow (defaults to now).

        Returns:
            The updated IPRecord for this IP (after recording the new flow).
        """
        now = timestamp or time.time()

        with self._lock:
            if ip not in self._store:
                self._store[ip] = IPRecord(
                    scores=deque(maxlen=self.max_flows_per_ip),
                    intervals=deque(maxlen=self.max_flows_per_ip),
                )

            record = self._store[ip]
            interval = now - record.last_seen
            record.intervals.append(interval)
            record.scores.append(if_score)
            record.last_seen = now
            record.flow_count += 1

            return record

    def get(self, ip: str) -> Optional[IPRecord]:
        """Retrieve the current history record for an IP, or None if unseen."""
        with self._lock:
            return self._store.get(ip)

    def is_known(self, ip: str) -> bool:
        """Return True if we have seen this IP before."""
        with self._lock:
            return ip in self._store

    def score_delta(self, ip: str, current_score: float) -> Optional[float]:
        """Compute the delta between current_score and IP's historical mean.

        Returns None if we haven't seen enough flows from this IP yet.
        """
        with self._lock:
            record = self._store.get(ip)
            if record is None:
                return None
            return record.score_delta(current_score)

    def evict_stale(self) -> int:
        """Remove IPs not seen within the history window. Returns eviction count."""
        cutoff = time.time() - self.window_seconds
        with self._lock:
            stale = [ip for ip, rec in self._store.items() if rec.last_seen < cutoff]
            for ip in stale:
                del self._store[ip]
        if stale:
            log_event(
                logger,
                "ip_history_evicted_stale",
                level="debug",
                count=len(stale),
            )
        return len(stale)

    def size(self) -> int:
        """Number of IPs currently tracked."""
        with self._lock:
            return len(self._store)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self) -> None:
        """Persist the history store to disk."""
        if not self.persist_path:
            return
        try:
            self.persist_path.parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                snapshot = dict(self._store)
            with open(self.persist_path, "wb") as f:
                pickle.dump(snapshot, f)
            log_event(
                logger,
                "ip_history_saved",
                level="info",
                path=str(self.persist_path),
                ip_count=len(snapshot),
            )
        except Exception as e:
            log_event(
                logger,
                "ip_history_save_failed",
                level="error",
                error=str(e),
            )

    def _load(self) -> None:
        """Load persisted history from disk."""
        try:
            with open(self.persist_path, "rb") as f:
                snapshot = pickle.load(f)
            with self._lock:
                self._store = snapshot
            log_event(
                logger,
                "ip_history_loaded",
                level="info",
                path=str(self.persist_path),
                ip_count=len(snapshot),
            )
        except Exception as e:
            log_event(
                logger,
                "ip_history_load_failed",
                level="warning",
                error=str(e),
            )
