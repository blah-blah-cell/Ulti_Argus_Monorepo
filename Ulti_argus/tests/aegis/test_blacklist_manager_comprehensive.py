import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# Helper to mock dependencies if they are missing
def mock_if_missing(name, setup_func=None):
#     if name not in sys.modules:
        try:
            __import__(name)
        except ImportError:
            m = MagicMock()
            if setup_func:
                setup_func(m)
#             sys.modules[name] = m
            return m
#     return sys.modules[name]

# Setup mock modules
def setup_yaml(m):
    m.safe_load.return_value = {}
mock_if_missing('yaml', setup_yaml)

def setup_numpy(m):
    m.float64 = float
    m.bool_ = bool
mock_if_missing('numpy', setup_numpy)
mock_if_missing('numpy.core')
mock_if_missing('numpy.core.multiarray')

mock_if_missing('pandas')

mock_if_missing('sklearn')
mock_if_missing('sklearn.ensemble')
mock_if_missing('sklearn.preprocessing')
mock_if_missing('sklearn.linear_model')
mock_if_missing('sklearn.metrics')
mock_if_missing('sklearn.base')

mock_if_missing('skops')
mock_if_missing('skops.io')

mock_if_missing('scapy')
mock_if_missing('scapy.all')

mock_if_missing('firebase_admin')
mock_if_missing('firebase_admin.credentials')
mock_if_missing('firebase_admin.storage')

mock_if_missing('google')
mock_if_missing('google.cloud')
mock_if_missing('google.cloud.storage')

# Now safe to import BlacklistManager
from argus_v.aegis.blacklist_manager import (
    BlacklistManager,
)


# Register adapters for sqlite3 to handle datetime if needed
def adapt_datetime(dt):
    # Use space separator to match SQLite CURRENT_TIMESTAMP format (YYYY-MM-DD HH:MM:SS)
    return dt.isoformat(sep=' ', timespec='seconds')

def convert_datetime(s):
    return datetime.fromisoformat(s.decode())

sqlite3.register_adapter(datetime, adapt_datetime)
sqlite3.register_converter("timestamp", convert_datetime)

@pytest.fixture
def mock_config(tmp_path):
    """Mock configuration for BlacklistManager."""
    config = MagicMock()
    config.blacklist_db_path = str(tmp_path / "blacklist.db")
    config.blacklist_json_path = str(tmp_path / "blacklist.json")
    config.anonymization_salt = "test-salt"
    config.iptables_chain_name = "AEGIS-TEST-CHAIN"
    config.emergency_stop_file = str(tmp_path / "emergency.stop")
    return config

@pytest.fixture
def blacklist_manager(mock_config):
    """Initialize BlacklistManager with mocked dependencies."""
    # Ensure clean state
    if Path(mock_config.blacklist_db_path).exists():
        Path(mock_config.blacklist_db_path).unlink()

    with patch("argus_v.aegis.blacklist_manager.log_event"):
        manager = BlacklistManager(mock_config)
        yield manager

class TestBlacklistManager:

    def test_init_creates_directories_and_db(self, mock_config):
        """Test that initialization creates necessary directories and database tables."""
        with patch("argus_v.aegis.blacklist_manager.log_event"):
            BlacklistManager(mock_config)

        assert Path(mock_config.blacklist_db_path).parent.exists()
        assert Path(mock_config.blacklist_db_path).exists()

        with sqlite3.connect(mock_config.blacklist_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cursor.fetchall()}
            assert "blacklist" in tables
            assert "sync_log" in tables
            assert "emergency_stops" in tables

    def test_init_missing_salt_raises_error(self, mock_config):
        """Test that missing anonymization salt raises ValueError."""
        mock_config.anonymization_salt = None
        with pytest.raises(ValueError, match="Anonymization salt must be configured"):
            BlacklistManager(mock_config)

    def test_add_to_blacklist_valid(self, blacklist_manager):
        """Test adding a valid IP to the blacklist."""
        ip = "192.168.1.100"
        reason = "Test reason"
        result = blacklist_manager.add_to_blacklist(ip, reason)

        assert result is True

        # Verify in DB via helper method to avoid raw SQL assumptions
        assert blacklist_manager.is_blacklisted(ip)

        entries = blacklist_manager.get_blacklist_entries(active_only=True)
        assert len(entries) == 1
        # The stored IP is anonymized, so we check existence via is_blacklisted

    def test_add_to_blacklist_invalid_ip(self, blacklist_manager):
        """Test adding an invalid IP address."""
        result = blacklist_manager.add_to_blacklist("invalid-ip", "reason")
        assert result is False

    def test_add_to_blacklist_invalid_risk_level(self, blacklist_manager):
        """Test adding with an invalid risk level."""
        result = blacklist_manager.add_to_blacklist("192.168.1.101", "reason", risk_level="invalid")
        assert result is False

    def test_add_to_blacklist_with_ttl(self, blacklist_manager):
        """Test adding an IP with a TTL."""
        ip = "192.168.1.102"
        ttl = 1
        blacklist_manager.add_to_blacklist(ip, "reason", ttl_hours=ttl)

        entries = blacklist_manager.get_blacklist_entries()
        assert len(entries) == 1
        expires_at = entries[0]['expires_at']
        assert expires_at is not None

        # Parse expiry time
        if isinstance(expires_at, str):
            expiry_time = datetime.fromisoformat(expires_at)
        else:
            expiry_time = expires_at

        # Check if expiry is roughly 1 hour from now
        now = datetime.now()
        expected = now + timedelta(hours=ttl)
        # Allow 5 seconds difference
        assert abs((expiry_time - expected).total_seconds()) < 5

    @patch("argus_v.aegis.blacklist_manager.BlacklistManager._enforce_blacklist_entry")
    def test_add_to_blacklist_enforce(self, mock_enforce, blacklist_manager):
        """Test that enforce=True triggers enforcement."""
        ip = "192.168.1.103"
        blacklist_manager.add_to_blacklist(ip, "reason", enforce=True)

        mock_enforce.assert_called_once()
        # IP passed to enforce should be the anonymized one
        args, _ = mock_enforce.call_args
        assert args[1] == "reason"

    def test_remove_from_blacklist_success(self, blacklist_manager):
        """Test successfully removing an IP from the blacklist."""
        ip = "192.168.1.104"
        blacklist_manager.add_to_blacklist(ip, "reason")
        assert blacklist_manager.is_blacklisted(ip)

        result = blacklist_manager.remove_from_blacklist(ip)
        assert result is True
        assert not blacklist_manager.is_blacklisted(ip)

        # Check it is marked inactive in DB
        # Use anonymizer to check raw DB state if needed
        anonymized_ip = blacklist_manager.anonymizer.anonymize_ip(ip)

        with sqlite3.connect(blacklist_manager._sqlite_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT is_active FROM blacklist WHERE ip_address=?", (anonymized_ip,))
            is_active = cursor.fetchone()[0]
            # sqlite stores booleans as 0/1
            assert not is_active

    def test_remove_from_blacklist_not_found(self, blacklist_manager):
        """Test removing a non-existent IP."""
        result = blacklist_manager.remove_from_blacklist("10.0.0.1")
        assert result is False

    def test_is_blacklisted_expired(self, blacklist_manager):
        """Test that expired entries are treated as not blacklisted and deactivated."""
        ip = "192.168.1.105"
        # Manually insert an expired entry
        anonymized_ip = blacklist_manager.anonymizer.anonymize_ip(ip)
        expired_time = datetime.now() - timedelta(hours=1)

        with sqlite3.connect(blacklist_manager._sqlite_db_path) as conn:
            cursor = conn.cursor()
            # Use isoformat string with space separator for compatibility with CURRENT_TIMESTAMP
            cursor.execute("""
                INSERT INTO blacklist (ip_address, expires_at, is_active)
                VALUES (?, ?, ?)
            """, (anonymized_ip, expired_time.isoformat(sep=' ', timespec='seconds'), 1)) # 1 for True
            conn.commit()

        assert blacklist_manager.is_blacklisted(ip) is False

        # Check DB updated
        with sqlite3.connect(blacklist_manager._sqlite_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT is_active FROM blacklist WHERE ip_address=?", (anonymized_ip,))
            is_active = cursor.fetchone()[0]
            assert not is_active

    def test_get_blacklist_entries_filtering(self, blacklist_manager):
        """Test filtering of blacklist entries."""
        ip1 = "192.168.1.106"
        ip2 = "192.168.1.107"

        blacklist_manager.add_to_blacklist(ip1, "reason1", risk_level="low", source="manual")
        blacklist_manager.add_to_blacklist(ip2, "reason2", risk_level="high", source="prediction")

        # Filter by risk
        high_risk = blacklist_manager.get_blacklist_entries(risk_level="high")
        assert len(high_risk) == 1
        assert high_risk[0]['risk_level'] == "high"

        # Filter by source
        manual = blacklist_manager.get_blacklist_entries(source="manual")
        assert len(manual) == 1
        assert manual[0]['source'] == "manual"

    def test_cleanup_expired_entries(self, blacklist_manager):
        """Test cleanup of expired entries."""
        # Insert expired entries
        with sqlite3.connect(blacklist_manager._sqlite_db_path) as conn:
            cursor = conn.cursor()
            expired_time = (datetime.now() - timedelta(hours=1)).isoformat(sep=' ', timespec='seconds')
            cursor.execute("INSERT INTO blacklist (ip_address, expires_at, is_active) VALUES ('ip1', ?, 1)", (expired_time,))
            cursor.execute("INSERT INTO blacklist (ip_address, expires_at, is_active) VALUES ('ip2', ?, 1)", (expired_time,))
            # Valid entry
            future_time = (datetime.now() + timedelta(hours=1)).isoformat(sep=' ', timespec='seconds')
            cursor.execute("INSERT INTO blacklist (ip_address, expires_at, is_active) VALUES ('ip3', ?, 1)", (future_time,))
            conn.commit()

        cleaned = blacklist_manager.cleanup_expired_entries()
        assert cleaned == 2

        # Verify count
        stats = blacklist_manager.get_statistics()
        assert stats['expired_entries'] >= 2

    def test_emergency_stop_restore(self, blacklist_manager):
        """Test emergency stop and restore functionality."""
        # Note: _is_dry_run_mode currently defaults to True, so we skip asserting its initial state

        # Activate emergency stop
        result = blacklist_manager.emergency_stop("Test Stop")
        assert result is True
        assert Path(blacklist_manager.config.emergency_stop_file).exists()
        assert blacklist_manager._is_dry_run_mode()

        # Check DB log
        with sqlite3.connect(blacklist_manager._sqlite_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT reason FROM emergency_stops WHERE stopped_by='manual'")
            assert cursor.fetchone()[0] == "Test Stop"

        # Restore
        result = blacklist_manager.emergency_restore("Test Restore")
        assert result is True
        assert not Path(blacklist_manager.config.emergency_stop_file).exists()

        # Check DB log updated
        with sqlite3.connect(blacklist_manager._sqlite_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT restored_by FROM emergency_stops WHERE reason='Test Stop'")
            # The code sets restored_by to the reason string passed to emergency_restore
            assert cursor.fetchone()[0] == "Test Restore"

    def test_iptables_add(self, blacklist_manager):
        """Test adding rule to iptables."""
        ip = "192.168.1.108"

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0

            result = blacklist_manager._add_to_iptables(ip, "reason", "high")
            assert result is True

            # Check calls
            # First call checks version
            # Second call adds rule
            calls = mock_run.call_args_list
            assert len(calls) >= 1

            # Find the actual add command
            add_call = None
            for call in calls:
                args = call[0][0]
                if "iptables" in args and "-A" in args:
                    add_call = args
                    break

            assert add_call is not None
            assert blacklist_manager.config.iptables_chain_name in add_call
            assert ip in add_call
            assert "-j" in add_call
            assert "DROP" in add_call

    def test_iptables_remove(self, blacklist_manager):
        """Test removing rule from iptables."""
        ip = "192.168.1.109"

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0

            result = blacklist_manager._remove_from_iptables(ip)
            assert result is True

            # Find the delete command
            delete_call = None
            for call in mock_run.call_args_list:
                args = call[0][0]
                if "iptables" in args and "-D" in args:
                    delete_call = args
                    break

            assert delete_call is not None
            assert ip in delete_call

    def test_sync_with_firebase_disabled(self, blacklist_manager):
        """Test sync when firebase is disabled."""
        blacklist_manager._firebase_sync_enabled = False
        assert blacklist_manager.sync_with_firebase() is False

    def test_sync_with_firebase_success(self, blacklist_manager):
        """Test successful firebase sync."""
        blacklist_manager._firebase_sync_enabled = True

        with patch.object(blacklist_manager, "_upload_to_firebase", return_value=True) as mock_upload:
            result = blacklist_manager.sync_with_firebase()
            assert result is True
            mock_upload.assert_called_once()

            # Check sync log
            with sqlite3.connect(blacklist_manager._sqlite_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT success FROM sync_log ORDER BY id DESC LIMIT 1")
                # sqlite stores boolean as 0/1
                assert cursor.fetchone()[0] == 1
