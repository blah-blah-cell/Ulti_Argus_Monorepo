import json
from unittest.mock import MagicMock

import pytest

from src.argus_v.aegis.feedback_manager import FeedbackManager


class HelperFeedbackManager(FeedbackManager):
    def __init__(self, config, root_path):
        # Bypass super().__init__ to avoid /var/lib creation
        self.config = config
        self.feedback_dir = root_path / "feedback"
        self.trusted_ips_file = self.feedback_dir / "trusted_ips.json"
        self.retrain_flag_file = root_path / "mnemosyne" / "trigger_retrain"
        self._trusted_ips_cache = None
        self._ensure_directories()

@pytest.fixture
def feedback_manager(tmp_path):
    config = MagicMock()
    return HelperFeedbackManager(config, tmp_path)

def test_report_false_positive(feedback_manager):
    ip = "192.168.1.10"
    success = feedback_manager.report_false_positive(ip, "test reason")

    assert success
    assert feedback_manager.is_trusted(ip)

    # Check cache
    assert any(entry['ip'] == ip for entry in feedback_manager._trusted_ips_cache)

    # Check file
    with open(feedback_manager.trusted_ips_file) as f:
        data = json.load(f)
        assert any(entry['ip'] == ip for entry in data)

def test_is_trusted(feedback_manager):
    ip = "10.0.0.1"
    feedback_manager.report_false_positive(ip)

    assert feedback_manager.is_trusted(ip)
    assert not feedback_manager.is_trusted("10.0.0.2")

def test_persistence(tmp_path):
    config = MagicMock()
    # Create one manager to write data
    mgr1 = HelperFeedbackManager(config, tmp_path)
    mgr1.report_false_positive("1.2.3.4")

    # Create second manager to read data
    mgr2 = HelperFeedbackManager(config, tmp_path)

    # Should be trusted even without cache initially populated (it loads on first check)
    assert mgr2._trusted_ips_cache is None
    assert mgr2.is_trusted("1.2.3.4")
    assert mgr2._trusted_ips_cache is not None

def test_trigger_retrain(feedback_manager):
    # Ensure file doesn't exist yet (mocked path should be clean)
    if feedback_manager.retrain_flag_file.exists():
        feedback_manager.retrain_flag_file.unlink()

    success = feedback_manager.trigger_retrain()

    assert success
    assert feedback_manager.retrain_flag_file.exists()
