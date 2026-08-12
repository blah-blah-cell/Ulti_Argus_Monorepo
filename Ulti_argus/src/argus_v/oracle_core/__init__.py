"""Shared privacy, validation, and logging utilities.

Includes:
- structured logging with privacy guardrails
- anonymization primitives
"""

from __future__ import annotations

from .anonymize import HashAnonymizer, hash_ip, round_datetime, round_epoch_seconds
from .logging import configure_logging, log_event

__all__ = [
    "configure_logging",
    "HashAnonymizer",
    "hash_ip",
    "log_event",
    "round_datetime",
    "round_epoch_seconds",
]
