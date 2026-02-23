import sys
from unittest.mock import MagicMock

import pytest

# Mock missing dependencies conditionally
import importlib.util

def mock_if_missing(module_name):
    if not sys.modules.get(module_name):
        if importlib.util.find_spec(module_name) is None:
            sys.modules[module_name] = MagicMock()

for module in ['yaml', 'firebase_admin', 'google.cloud', 'scapy', 'pandas', 'numpy', 'sklearn', 'joblib', 'skops']:
    mock_if_missing(module)

if isinstance(sys.modules.get('scapy'), MagicMock):
    sys.modules['scapy.all'] = MagicMock()
if isinstance(sys.modules.get('sklearn'), MagicMock):
    sys.modules['sklearn.ensemble'] = MagicMock()

from argus_v.aegis.blacklist_manager import BlacklistManager


@pytest.fixture
def blacklist_manager():
    config = MagicMock()
    config.blacklist_db_path = ":memory:"
    config.blacklist_json_path = "/tmp/blacklist.json"
    config.iptables_chain_name = "AEGIS-DROP"
    config.iptables_table = "filter"

    # Mocking _ensure_directories and _initialize_database to avoid side effects
    BlacklistManager._ensure_directories = MagicMock()
    BlacklistManager._initialize_database = MagicMock()

    manager = BlacklistManager(config)
    return manager

def test_validate_ip_address_valid_ipv4(blacklist_manager):
    assert blacklist_manager._validate_ip_address("127.0.0.1") is True
    assert blacklist_manager._validate_ip_address("192.168.1.1") is True
    assert blacklist_manager._validate_ip_address("8.8.8.8") is True

def test_validate_ip_address_valid_ipv6(blacklist_manager):
    assert blacklist_manager._validate_ip_address("::1") is True
    assert blacklist_manager._validate_ip_address("2001:db8::1") is True

def test_validate_ip_address_invalid_ips(blacklist_manager):
    assert blacklist_manager._validate_ip_address("not-an-ip") is False
    assert blacklist_manager._validate_ip_address("256.256.256.256") is False
    assert blacklist_manager._validate_ip_address("1.2.3") is False
    assert blacklist_manager._validate_ip_address("1.2.3.4.5") is False

def test_validate_ip_address_leading_zeros(blacklist_manager):
    # ipaddress.ip_address rejects leading zeros in IPv4
    assert blacklist_manager._validate_ip_address("012.012.012.012") is False

def test_validate_ip_address_empty_string(blacklist_manager):
    assert blacklist_manager._validate_ip_address("") is False
