import sys
import unittest
from unittest.mock import MagicMock, patch

# Mock rich modules before importing tui
sys.modules["rich"] = MagicMock()
sys.modules["rich.align"] = MagicMock()
sys.modules["rich.console"] = MagicMock()
sys.modules["rich.layout"] = MagicMock()
sys.modules["rich.live"] = MagicMock()
sys.modules["rich.panel"] = MagicMock()
sys.modules["rich.table"] = MagicMock()
sys.modules["rich.text"] = MagicMock()

# Mock other production dependencies that might be missing in test env
sys.modules["yaml"] = MagicMock()
sys.modules["scapy"] = MagicMock()
sys.modules["pandas"] = MagicMock()
sys.modules["numpy"] = MagicMock()
sys.modules["sklearn"] = MagicMock()
sys.modules["sklearn.ensemble"] = MagicMock()
sys.modules["skops"] = MagicMock()
sys.modules["skops.io"] = MagicMock()
sys.modules["firebase_admin"] = MagicMock()
sys.modules["firebase_admin.credentials"] = MagicMock()
sys.modules["firebase_admin.storage"] = MagicMock()
sys.modules["google.cloud"] = MagicMock()
sys.modules["google.cloud.storage"] = MagicMock()

import pytest
import json
import sqlite3
import tempfile
import shutil
from pathlib import Path
import os

# Verify imports work after mocking rich
# Note: We must ensure PYTHONPATH includes src/ when running tests
try:
    from argus_v.aegis.tui import AegisDashboard, main
    from argus_v.aegis.config import AegisConfig
except ImportError:
    # Fallback if running from repo root without explicit PYTHONPATH
    sys.path.append(os.path.join(os.getcwd(), 'Ulti_argus', 'src'))
    from argus_v.aegis.tui import AegisDashboard, main
    from argus_v.aegis.config import AegisConfig

@pytest.fixture
def temp_paths():
    tmp_dir = tempfile.mkdtemp()
    stats_file = Path(tmp_dir) / "stats.json"
    state_file = Path(tmp_dir) / "state.json"
    blacklist_db = Path(tmp_dir) / "blacklist.db"

    yield stats_file, state_file, blacklist_db

    shutil.rmtree(tmp_dir)

@pytest.fixture
def mock_config(temp_paths):
    stats_file, state_file, blacklist_db = temp_paths

    config = MagicMock()
    config.stats_file = str(stats_file)
    config.state_file = str(state_file)
    # Correct access pattern for refactored tui.py
    config.enforcement.blacklist_db_path = str(blacklist_db)

    return config

@pytest.fixture
def dashboard(mock_config):
    with patch("argus_v.aegis.tui.load_aegis_config", return_value=mock_config):
        # We also need to mock get_default_config_path if we don't pass path
        with patch("argus_v.aegis.tui.get_default_config_path", return_value="/tmp/argus/config.yaml"):
            db = AegisDashboard()
            return db

def test_initialization(dashboard, temp_paths):
    stats_file, state_file, blacklist_db = temp_paths
    assert dashboard.stats_file == stats_file
    assert dashboard.state_file == state_file
    assert dashboard.blacklist_db == blacklist_db

def test_read_stats(dashboard, temp_paths):
    stats_file, _, _ = temp_paths

    # Missing file
    assert dashboard._read_stats() == {}

    # Invalid JSON
    stats_file.write_text("invalid json")
    assert dashboard._read_stats() == {}

    # Valid JSON
    data = {"key": "value"}
    stats_file.write_text(json.dumps(data))
    assert dashboard._read_stats() == data

def test_read_engine_state(dashboard, temp_paths):
    _, state_file, _ = temp_paths

    # Missing file
    assert dashboard._read_engine_state() == "Not Running / Unknown"

    # Invalid JSON
    state_file.write_text("invalid")
    assert dashboard._read_engine_state() == "Not Running / Unknown"

    # Valid JSON
    state_file.write_text(json.dumps({"state": "RUNNING"}))
    assert dashboard._read_engine_state() == "RUNNING"

def test_read_active_blocks(dashboard, temp_paths):
    _, _, blacklist_db = temp_paths

    # Missing DB
    assert dashboard._read_active_blocks() == []

    # Create DB
    conn = sqlite3.connect(blacklist_db)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE blacklist (
            ip_address TEXT,
            reason TEXT,
            risk_level TEXT,
            source TEXT,
            created_at TEXT,
            hit_count INTEGER,
            is_active BOOLEAN
        )
    """)

    # Insert Data
    c.execute("""
        INSERT INTO blacklist VALUES
        ('1.2.3.4', 'malware', 'critical', 'model', '2023-01-01T12:00:00', 5, 1)
    """)
    c.execute("""
        INSERT INTO blacklist VALUES
        ('5.6.7.8', 'scan', 'medium', 'manual', '2023-01-02T12:00:00', 1, 0)
    """)
    conn.commit()
    conn.close()

    # Verify we only get active blocks
    blocks = dashboard._read_active_blocks()
    assert len(blocks) == 1
    assert blocks[0][0] == '1.2.3.4'

def test_make_header(dashboard):
    # Mock _read_engine_state
    with patch.object(dashboard, "_read_engine_state", return_value="RUNNING"):
        panel = dashboard.make_header()
        # Verify it returns a Panel (mock object)
        assert isinstance(panel, MagicMock)
        # Since we mocked Panel, we can't easily check content unless we inspect calls
        # But we can check that sys.modules["rich.panel"].Panel was called
        sys.modules["rich.panel"].Panel.assert_called()

def test_make_stats_panel(dashboard):
    with patch.object(dashboard, "_read_stats", return_value={"total_flows_processed": 100}):
        panel = dashboard.make_stats_panel()
        sys.modules["rich.panel"].Panel.assert_called()

def test_make_blocklist_table(dashboard):
    with patch.object(dashboard, "_read_active_blocks", return_value=[
        ('1.2.3.4', 'reason', 'critical', 'source', '2023-01-01', 1)
    ]):
        panel = dashboard.make_blocklist_table()
        sys.modules["rich.panel"].Panel.assert_called()

def test_generate_layout(dashboard):
    layout = dashboard.generate_layout()
    # Check if Layout was instantiated
    sys.modules["rich.layout"].Layout.assert_called()

def test_run(dashboard):
    # Mock Live context manager
    mock_live = sys.modules["rich.live"].Live.return_value
    mock_live.__enter__.return_value = MagicMock()

    # Mock time.sleep to raise exception after 1 call to break loop
    with patch("time.sleep", side_effect=KeyboardInterrupt):
        dashboard.run()

    # Verify Live was initialized
    sys.modules["rich.live"].Live.assert_called()

def test_main():
    with patch("argus_v.aegis.tui.AegisDashboard") as MockDashboard:
        mock_instance = MockDashboard.return_value

        # Patch argparse to prevent it from parsing actual sys.argv
        with patch("argparse.ArgumentParser.parse_args", return_value=MagicMock(config=None)):
            main()

        MockDashboard.assert_called()
        mock_instance.run.assert_called_once()
