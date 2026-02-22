import pytest
from unittest.mock import patch, MagicMock
from argus_v.aegis.blacklist_manager import BlacklistManager
from pathlib import Path
import tempfile
import shutil
import subprocess

class TestBlacklistOptimization:
    def setup_method(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.config = type('Config', (), {
            'iptables_chain_name': 'TEST-CHAIN',
            'blacklist_db_path': str(self.temp_dir / "blacklist.db"),
            'blacklist_json_path': str(self.temp_dir / "blacklist.json"),
            'emergency_stop_file': str(self.temp_dir / "emergency.stop")
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
