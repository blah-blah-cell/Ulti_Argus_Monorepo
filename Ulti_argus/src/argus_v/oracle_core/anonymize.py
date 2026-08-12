from __future__ import annotations

import hashlib
import hmac
import ipaddress
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal


@dataclass(frozen=True, slots=True)
class AnonymizationConfig:
    ip_salt: bytes
    timestamp_round_seconds: int = 60


def _salt_to_bytes(salt: str | bytes) -> bytes:
    if isinstance(salt, bytes):
        salt_bytes = salt
    elif isinstance(salt, str):
        salt_bytes = salt.encode("utf-8")
    else:
        raise TypeError("salt must be str|bytes")

    if len(salt_bytes) < 8:
        raise ValueError("salt must be at least 8 bytes")
    return salt_bytes


def hash_ip(ip: str, *, salt: str | bytes, prefix: str = "ip_", hex_chars: int = 32) -> str:
    """Return a stable, salted, one-way identifier for an IP address.

    This is intentionally not reversible. A non-trivial salt is required.
    """

    ip_obj = ipaddress.ip_address(ip)
    salt_bytes = _salt_to_bytes(salt)

    digest = hmac.new(salt_bytes, ip_obj.packed, hashlib.sha256).hexdigest()
    if hex_chars <= 0:
        raise ValueError("hex_chars must be > 0")
    if hex_chars > len(digest):
        raise ValueError("hex_chars too large")
    return f"{prefix}{digest[:hex_chars]}"


class HashAnonymizer:
    """Helper class for IP anonymization with a fixed salt."""

    def __init__(self, salt: str | bytes):
        self._salt = salt

    def anonymize_ip(self, ip: str) -> str:
        """Anonymize an IP address using the fixed salt."""
        return hash_ip(ip, salt=self._salt)


RoundMode = Literal["floor", "nearest"]


def round_epoch_seconds(
    epoch_seconds: int | float,
    *,
    resolution_seconds: int,
    mode: RoundMode = "floor",
) -> int:
    if resolution_seconds <= 0:
        raise ValueError("resolution_seconds must be > 0")

    x = float(epoch_seconds) / float(resolution_seconds)

    if mode == "floor":
        rounded = math.floor(x)
    elif mode == "nearest":
        rounded = int(round(x))
    else:
        raise ValueError(f"unsupported mode: {mode}")

    return int(rounded * resolution_seconds)


def round_datetime(dt: datetime, *, resolution_seconds: int, mode: RoundMode = "floor") -> datetime:
    """Round a datetime to a fixed cadence.

    Naive datetimes are treated as UTC.
    """

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    epoch = dt.timestamp()
    rounded = round_epoch_seconds(epoch, resolution_seconds=resolution_seconds, mode=mode)
    return datetime.fromtimestamp(rounded, tz=timezone.utc)
