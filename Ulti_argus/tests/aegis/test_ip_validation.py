import sys
from unittest.mock import MagicMock

import pytest

# Mock missing dependencies
sys.modules['yaml'] = MagicMock()
sys.modules['firebase_admin'] = MagicMock()
sys.modules['google.cloud'] = MagicMock()
sys.modules['scapy'] = MagicMock()
sys.modules['scapy.all'] = MagicMock()
sys.modules['pandas'] = MagicMock()
sys.modules['numpy'] = MagicMock()
sys.modules['sklearn'] = MagicMock()
sys.modules['sklearn.ensemble'] = MagicMock()
sys.modules['joblib'] = MagicMock()
sys.modules['skops'] = MagicMock()

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
