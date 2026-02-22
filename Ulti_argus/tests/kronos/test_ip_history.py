from __future__ import annotations
import sys
from unittest.mock import MagicMock

# Mock dependencies that are not available in the environment
sys.modules["numpy"] = MagicMock()
sys.modules["pandas"] = MagicMock()
sys.modules["yaml"] = MagicMock()
sys.modules["sklearn"] = MagicMock()
sys.modules["sklearn.preprocessing"] = MagicMock()
sys.modules["skops"] = MagicMock()
sys.modules["skops.io"] = MagicMock()

import time
from pathlib import Path
import pytest
from argus_v.kronos.ip_history import IPHistoryStore, IPRecord

def test_ip_record_basics():
    record = IPRecord()
    assert record.flow_count == 0
    assert record.mean_score is None
    assert record.mean_interval is None

    record.scores.append(0.5)
    assert record.mean_score == 0.5

    record.scores.append(1.5)
    assert record.mean_score == 1.0

    record.intervals.append(1.0)
    assert record.mean_interval is None  # Needs at least 2 intervals

    record.intervals.append(3.0)
    assert record.mean_interval == 2.0

def test_ip_record_deltas():
    record = IPRecord()
    assert record.score_delta(0.5) is None
    assert record.interval_delta(0.5) is None

    record.scores.append(1.0)
    assert abs(record.score_delta(1.2) - 0.2) < 1e-9
    assert abs(record.score_delta(0.8) - (-0.2)) < 1e-9

    record.intervals.append(1.0)
    record.intervals.append(3.0) # mean = 2.0
    assert abs(record.interval_delta(2.5) - 0.5) < 1e-9
    assert abs(record.interval_delta(1.5) - (-0.5)) < 1e-9

def test_ip_record_rolling_window():
    # Test that maxlen is respected
    record = IPRecord(scores=None, intervals=None)
    # Actually IPRecord dataclass has default_factory for scores and intervals
    # but they use _DEFAULT_MAX_FLOWS (100).
    # We can pass them in __init__.
    from collections import deque
    record = IPRecord(
        scores=deque(maxlen=3),
        intervals=deque(maxlen=3)
    )

    for i in range(5):
        record.scores.append(float(i))

    assert len(record.scores) == 3
    assert list(record.scores) == [2.0, 3.0, 4.0]
    assert record.mean_score == 3.0

def test_ip_history_store_record():
    store = IPHistoryStore(max_flows_per_ip=5)
    ip = "192.168.1.1"

    t0 = time.time()
    rec1 = store.record(ip, 0.8, timestamp=t0)
    assert rec1.flow_count == 1
    assert rec1.last_seen == t0
    assert len(rec1.scores) == 1
    assert rec1.scores[0] == 0.8

    t1 = t0 + 10.0
    rec2 = store.record(ip, 0.6, timestamp=t1)
    assert rec2.flow_count == 2
    assert rec2.last_seen == t1
    assert len(rec2.scores) == 2
    assert rec2.scores[1] == 0.6
    assert rec2.intervals[1] == 10.0

def test_ip_history_store_get_known():
    store = IPHistoryStore()
    ip = "10.0.0.1"
    assert not store.is_known(ip)
    assert store.get(ip) is None

    store.record(ip, 0.5)
    assert store.is_known(ip)
    assert store.get(ip) is not None
    assert store.size() == 1

def test_ip_history_store_score_delta():
    store = IPHistoryStore()
    ip = "192.168.1.100"

    # Unknown IP
    assert store.score_delta(ip, 0.5) is None

    # Record first flow
    store.record(ip, 1.0)
    # mean is 1.0
    assert abs(store.score_delta(ip, 1.2) - 0.2) < 1e-9

def test_ip_history_store_eviction():
    store = IPHistoryStore(window_seconds=60)
    now = time.time()

    store.record("1.1.1.1", 0.5, timestamp=now - 100) # Stale
    store.record("2.2.2.2", 0.5, timestamp=now - 10)  # Fresh

    assert store.size() == 2
    evicted = store.evict_stale()
    assert evicted == 1
    assert store.size() == 1
    assert store.is_known("2.2.2.2")
    assert not store.is_known("1.1.1.1")

def test_ip_history_store_persistence(tmp_path):
    persist_path = tmp_path / "history.pkl"
    store = IPHistoryStore(persist_path=str(persist_path))

    store.record("1.2.3.4", 0.7)
    store.save()

    assert persist_path.exists()

    # Load into a new store
    new_store = IPHistoryStore(persist_path=str(persist_path))
    assert new_store.is_known("1.2.3.4")
    rec = new_store.get("1.2.3.4")
    assert rec.scores[0] == 0.7

def test_ip_history_store_persistence_no_path():
    # Should not raise
    store = IPHistoryStore(persist_path=None)
    store.record("1.2.3.4", 0.7)
    store.save()

def test_ip_history_store_load_fail(tmp_path, caplog):
    # Test loading non-existent or corrupt file
    corrupt_path = tmp_path / "corrupt.pkl"
    corrupt_path.write_text("not a pickle")

    store = IPHistoryStore(persist_path=str(corrupt_path))

    assert "ip_history_load_failed" in caplog.text

def test_ip_history_store_save_fail(tmp_path, caplog):
    # Test saving to a path that is not writable
    bad_path = tmp_path / "subdir" / "history.pkl"
    # Make 'subdir' a file instead of a directory to cause mkdir/open to fail
    (tmp_path / "subdir").touch()

    store = IPHistoryStore(persist_path=str(bad_path))
    store.record("1.2.3.4", 0.7)
    store.save()

    assert "ip_history_save_failed" in caplog.text

def test_ip_history_store_thread_safety():
    import threading
    store = IPHistoryStore()
    ip = "1.2.3.4"

    def worker():
        for i in range(100):
            store.record(ip, float(i))
            store.get(ip)
            store.is_known(ip)
            store.size()

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert store.get(ip).flow_count == 1000
