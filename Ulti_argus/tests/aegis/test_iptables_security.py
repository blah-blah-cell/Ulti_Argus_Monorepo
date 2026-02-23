import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Add the src directory to sys.path
sys.path.append(os.path.join(os.getcwd(), "Ulti_argus/src"))

# Mock all problematic modules conditionally
import importlib.util

def mock_if_missing(module_name):
    if not sys.modules.get(module_name):
        if importlib.util.find_spec(module_name) is None:
            sys.modules[module_name] = MagicMock()

mocks = [
    'yaml',
    'firebase_admin',
    'firebase_admin.credentials',
    'firebase_admin.storage',
    'google.cloud',
    'google.cloud.storage',
    'sklearn',
    'pandas',
    'numpy',
    'joblib',
    'skops',
    'skops.io',
    'scapy',
]

for module in mocks:
    mock_if_missing(module)

# Submodules
if isinstance(sys.modules.get('sklearn'), MagicMock):
    sys.modules['sklearn.ensemble'] = MagicMock()
    sys.modules['sklearn.preprocessing'] = MagicMock()
if isinstance(sys.modules.get('scapy'), MagicMock):
    sys.modules['scapy.all'] = MagicMock()

from argus_v.aegis.blacklist_manager import BlacklistManager
from argus_v.aegis.config import EnforcementConfig
from argus_v.oracle_core.validation import ValidationError, require_safe_name


class TestIptablesSecurity:
    """Security tests for iptables configuration validation."""

    def test_require_safe_name_valid(self):
        """Test that valid names are accepted."""
        assert require_safe_name("VALID_chain-123", path="test") == "VALID_chain-123"
        assert require_safe_name("AEGIS-DROP", path="test") == "AEGIS-DROP"

    def test_require_safe_name_invalid_chars(self):
        """Test that invalid characters are rejected."""
        invalid_names = [
            "chain; rm -rf /",
            "chain|ls",
            "chain<file",
            "chain>file",
            "chain&",
            "chain$",
            "chain( )",
            "chain' '",
            'chain" "',
            "chain` `",
            "chain\n",
            " "
        ]
        for name in invalid_names:
            with pytest.raises(ValidationError) as exc:
                require_safe_name(name, path="test")
            assert "must contain only alphanumeric characters, underscores, and hyphens" in str(exc.value)

    def test_require_safe_name_too_long(self):
        """Test that too long names are rejected."""
        name = "A" * 29
        with pytest.raises(ValidationError) as exc:
            require_safe_name(name, path="test")
        assert "must be less than 29 characters" in str(exc.value)

    def test_enforcement_config_validation(self):
        """Test that EnforcementConfig uses require_safe_name."""
        data = {
            "iptables_chain_name": "INVALID; CHAIN",
            "anonymization_salt": "test-salt"
        }
        with pytest.raises(ValidationError):
            EnforcementConfig.from_mapping(data, path="test")

    def test_blacklist_manager_initialization_validation(self):
        """Test that BlacklistManager validates config in __init__."""
        config = MagicMock(spec=EnforcementConfig)
        config.iptables_chain_name = "INVALID; CHAIN"
        config.iptables_table = "filter"
        config.blacklist_db_path = "/tmp/test.db"
        config.blacklist_json_path = "/tmp/test.json"

        # We need to mock sqlite3.connect since BlacklistManager.__init__ calls it
        with patch('sqlite3.connect'), \
             patch('pathlib.Path.mkdir'):
            with pytest.raises(ValidationError):
                BlacklistManager(config)
