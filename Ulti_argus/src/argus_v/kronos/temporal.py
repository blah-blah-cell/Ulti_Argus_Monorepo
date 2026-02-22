"""Kronos Temporal Context — Time-aware traffic signal extractor.

Extracts contextual signals that tell Kronos *when* a packet is arriving,
not just what it looks like.  These signals are features the trained
routing model uses to learn patterns like:

  - "At 3AM, NTP packets are always heartbeats → fast pass"
  - "At boot time, DHCP bursts are expected → relax thresholds"
  - "This IP sends a packet every ~60s like clockwork → it's a cron job"

No rules are hard-coded here — the model learns these associations from
data.  This module just extracts the raw signals as numeric features.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from ..oracle_core.logging import log_event

logger = logging.getLogger(__name__)

# How long after system startup counts as the "boot window"
_BOOT_WINDOW_SECONDS = 120

# Inter-arrival delta below this is considered a "burst" (seconds)
_BURST_THRESHOLD_SECONDS = 0.1

# Inter-arrival delta above this is considered "slow / scheduled" (seconds)
_SLOW_THRESHOLD_SECONDS = 30.0


@dataclass
class TemporalFeatures:
    """Numeric temporal feature vector for Kronos model input."""
    hour_of_day: int           # 0–23
    day_of_week: int           # 0 (Mon) – 6 (Sun)
    is_night: int              # 1 if 0 ≤ hour < 6, else 0
    is_business_hours: int     # 1 if 8 ≤ hour < 18 on weekday
    in_boot_window: int        # 1 if system started < _BOOT_WINDOW_SECONDS ago
    interval_raw: float        # Raw inter-arrival interval (seconds)
    interval_delta: float      # Delta from IP's mean interval (0 if unknown)
    is_burst: int              # 1 if interval < burst threshold
    is_slow: int               # 1 if interval > slow threshold (scheduled?)
    is_periodic: int           # 1 if IP has a stable heartbeat rhythm

    def to_dict(self) -> dict:
        return {
            "hour_of_day": self.hour_of_day,
            "day_of_week": self.day_of_week,
            "is_night": self.is_night,
            "is_business_hours": self.is_business_hours,
            "in_boot_window": self.in_boot_window,
            "interval_raw": self.interval_raw,
            "interval_delta": self.interval_delta,
            "is_burst": self.is_burst,
            "is_slow": self.is_slow,
            "is_periodic": self.is_periodic,
        }


class TemporalContext:
    """Extracts time-of-day and rhythm context signals for Kronos.

    Args:
        startup_time: Unix timestamp when Argus started (defaults to now).
        burst_threshold: Interval below this → burst flag (seconds).
        slow_threshold:  Interval above this → scheduled/slow flag (seconds).
        periodic_cv_threshold: Coefficient of variation below which an IP's
            interval is considered "periodic" (stable heartbeat).
            CV = std/mean; lower = more stable.
    """

    def __init__(
        self,
        startup_time: Optional[float] = None,
        burst_threshold: float = _BURST_THRESHOLD_SECONDS,
        slow_threshold: float = _SLOW_THRESHOLD_SECONDS,
        periodic_cv_threshold: float = 0.25,
    ):
        self.startup_time = startup_time or time.time()
        self.burst_threshold = burst_threshold
        self.slow_threshold = slow_threshold
        self.periodic_cv_threshold = periodic_cv_threshold

        log_event(
            logger,
            "temporal_context_initialized",
            level="info",
            startup_time=self.startup_time,
        )

    def extract(
        self,
        interval_raw: float,
        ip_mean_interval: Optional[float] = None,
        ip_intervals: Optional[list] = None,
        now: Optional[float] = None,
    ) -> TemporalFeatures:
        """Extract temporal features for a single flow event.

        Args:
            interval_raw:     Seconds since the last packet from this IP.
            ip_mean_interval: This IP's historical mean interval (from IPHistoryStore).
            ip_intervals:     Full interval history list for this IP (to compute CV).
            now:              Current Unix timestamp (defaults to time.time()).

        Returns:
            TemporalFeatures dataclass with all computed signals.
        """
        now = now or time.time()
        dt = datetime.fromtimestamp(now)

        hour = dt.hour
        dow = dt.weekday()  # 0=Monday, 6=Sunday

        is_night = int(0 <= hour < 6)
        is_biz = int((8 <= hour < 18) and (dow < 5))
        in_boot = int((now - self.startup_time) < _BOOT_WINDOW_SECONDS)

        # Interval delta vs IP history
        if ip_mean_interval is not None and ip_mean_interval > 0:
            interval_delta = interval_raw - ip_mean_interval
        else:
            interval_delta = 0.0

        is_burst = int(interval_raw < self.burst_threshold)
        is_slow = int(interval_raw > self.slow_threshold)

        # Periodicity: low coefficient of variation → stable heartbeat
        is_periodic = 0
        if ip_intervals and len(ip_intervals) >= 5:
            import statistics
            try:
                mean_iv = statistics.mean(ip_intervals)
                if mean_iv > 0:
                    stdev_iv = statistics.stdev(ip_intervals)
                    cv = stdev_iv / mean_iv
                    is_periodic = int(cv < self.periodic_cv_threshold)
            except statistics.StatisticsError:
                pass

        return TemporalFeatures(
            hour_of_day=hour,
            day_of_week=dow,
            is_night=is_night,
            is_business_hours=is_biz,
            in_boot_window=in_boot,
            interval_raw=interval_raw,
            interval_delta=interval_delta,
            is_burst=is_burst,
            is_slow=is_slow,
            is_periodic=is_periodic,
        )
