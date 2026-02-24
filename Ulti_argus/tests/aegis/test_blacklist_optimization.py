import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from argus_v.aegis.blacklist_manager import BlacklistManager


class TestBlacklistOptimization:
    def setup_method(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.config = type('Config', (), {
            'iptables_chain_name': 'TEST-CHAIN',
            'blacklist_db_path': str(self.temp_dir / "blacklist.db"),
            'blacklist_json_path': str(self.temp_dir / "blacklist.json"),
            'emergency_stop_file': str(self.temp_dir / "emergency.stop"),
            'anonymization_salt': 'test-salt'
        })()

    def teardown_method(self):
        shutil.rmtree(self.temp_dir)

    def test_iptables_check_caching(self):
        # We mock HashAnonymizer to avoid dependency issues if any
        with patch('argus_v.aegis.blacklist_manager.HashAnonymizer'):
            manager = BlacklistManager(self.config)

            # We want to test _add_to_iptables directly.

            with patch('subprocess.run') as mock_run:
                # Configure mock to simulate iptables success
                # subprocess.run returns a CompletedProcess object
                mock_run.return_value = subprocess.CompletedProcess(args=['iptables'], returncode=0)

                # First call
                manager._add_to_iptables("1.2.3.4", "test", "low")

                # Second call
                manager._add_to_iptables("5.6.7.8", "test", "low")

                # Count how many times ['iptables', '--version'] was called
                version_calls = 0
                for call in mock_run.call_args_list:
                    args, _ = call
                    if len(args) > 0 and args[0] == ['iptables', '--version']:
                        version_calls += 1

                assert version_calls == 1, f"Expected 1 call to 'iptables --version', but got {version_calls}"

                # Verify that we tried to add rules twice (assuming check succeeded)
                rule_add_calls = 0
                for call in mock_run.call_args_list:
                    args, _ = call
                    if len(args) > 0 and len(args[0]) > 1 and args[0][0] == 'iptables' and args[0][1] == '-A':
                        rule_add_calls += 1

                assert rule_add_calls == 2, "Expected 2 attempts to add iptables rules"

    def test_iptables_check_caching_failure(self):
        """Test behavior when iptables is NOT available."""
        with patch('argus_v.aegis.blacklist_manager.HashAnonymizer'):
            manager = BlacklistManager(self.config)

            with patch('subprocess.run') as mock_run:
                # Simulate FileNotFoundError on first call
                def side_effect(*args, **kwargs):
                    if args[0] == ['iptables', '--version']:
                        raise FileNotFoundError("No iptables")
                    return subprocess.CompletedProcess(args=args[0], returncode=0)

                mock_run.side_effect = side_effect

                # First call - should fail and cache False
                result1 = manager._add_to_iptables("1.2.3.4", "test", "low")
                assert result1 is False

                # Second call - should return False immediately without checking
                mock_run.side_effect = None # Clear side effect to ensure we don't call it

                result2 = manager._add_to_iptables("5.6.7.8", "test", "low")
                assert result2 is False

                # Verify call counts
                version_calls = 0
                for call in mock_run.call_args_list:
                    args, _ = call
                    if len(args) > 0 and args[0] == ['iptables', '--version']:
                        version_calls += 1

                assert version_calls == 1, "Should check version only once"

    def test_blacklist_lookup_caching(self):
        """Test that blacklist lookups are cached."""
        with patch('argus_v.aegis.blacklist_manager.HashAnonymizer'):
            manager = BlacklistManager(self.config)
            ip = "1.2.3.4"

            # Mock the connection and cursor
            mock_conn = Mock()
            mock_cursor = Mock()
            mock_conn.cursor.return_value = mock_cursor
            mock_conn.__enter__ = Mock(return_value=mock_conn)
            mock_conn.__exit__ = Mock(return_value=None)

            # Setup return values
            # _check_db_status calls fetchone. Return None (not found).
            mock_cursor.fetchone.return_value = None

            # Inject mock connection
            manager._local.conn = mock_conn

            # First call - should hit database
            manager.is_blacklisted(ip)
            assert mock_cursor.execute.call_count == 1

            # Second call - should be cached
            manager.is_blacklisted(ip)
            assert mock_cursor.execute.call_count == 1

            # Add to blacklist - should clear cache and hit DB for insert
            manager.add_to_blacklist(ip, "test")
            calls_after_add = mock_cursor.execute.call_count
            assert calls_after_add > 1

            # Third call - should hit database again (cache cleared)
            manager.is_blacklisted(ip)
            assert mock_cursor.execute.call_count > calls_after_add
