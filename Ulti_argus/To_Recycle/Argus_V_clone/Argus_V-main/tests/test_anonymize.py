from __future__ import annotations

from datetime import datetime, timezone

import pytest

from argus_v.oracle_core.anonymize import hash_ip, round_datetime


def test_hash_ip_is_deterministic_for_same_salt() -> None:
    a = hash_ip("192.0.2.1", salt="correct-horse-battery-staple")
    b = hash_ip("192.0.2.1", salt="correct-horse-battery-staple")
    assert a == b


def test_hash_ip_changes_with_salt() -> None:
    a = hash_ip("192.0.2.1", salt="salt-salt-salt")
    b = hash_ip("192.0.2.1", salt="different-salt")
    assert a != b


def test_hash_ip_requires_nontrivial_salt() -> None:
    with pytest.raises(ValueError):
        hash_ip("192.0.2.1", salt="")

    with pytest.raises(ValueError):
        hash_ip("192.0.2.1", salt="short")


def test_hash_ip_validates_ip() -> None:
    with pytest.raises(ValueError):
        hash_ip("not-an-ip", salt="correct-horse-battery-staple")


def test_hash_ip_is_not_plaintext_or_ip_like() -> None:
    out = hash_ip("192.0.2.1", salt="correct-horse-battery-staple")
    assert "192.0.2.1" not in out
    assert out.startswith("ip_")
    assert "." not in out


def test_round_datetime_floor() -> None:
    dt = datetime(2025, 1, 1, 12, 34, 56, tzinfo=timezone.utc)
    assert round_datetime(dt, resolution_seconds=60) == datetime(
        2025, 1, 1, 12, 34, 0, tzinfo=timezone.utc
    )
    assert round_datetime(dt, resolution_seconds=300) == datetime(
        2025, 1, 1, 12, 30, 0, tzinfo=timezone.utc
    )


def test_round_datetime_nearest() -> None:
    dt = datetime(2025, 1, 1, 12, 34, 31, tzinfo=timezone.utc)
    # nearest minute (12:35:00)
    assert round_datetime(dt, resolution_seconds=60, mode="nearest") == datetime(
        2025, 1, 1, 12, 35, 0, tzinfo=timezone.utc
    )
