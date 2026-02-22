import os
import pytest
import tempfile
from pathlib import Path
from argus_v.aegis.config import load_aegis_config

def test_config_env_var_override(monkeypatch):
    """Test that environment variables override default paths."""

    # Create a minimal valid config file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write("""
model:
  model_local_path: "/tmp/models"
polling:
  poll_interval_seconds: 5
prediction:
  anomaly_threshold: 0.5
runtime:
  log_level: "INFO"
""")
        config_path = f.name

    try:
        # Set environment variables
        env = {
            "ARGUS_BLACKLIST_DB_PATH": "/tmp/custom/blacklist.db",
            "ARGUS_BLACKLIST_JSON_PATH": "/tmp/custom/blacklist.json",
            "ARGUS_FEEDBACK_DIR": "/tmp/custom/feedback",
            "ARGUS_RETRAIN_FLAG_FILE": "/tmp/custom/trigger_retrain",
            "ARGUS_EMERGENCY_STOP_FILE": "/tmp/custom/emergency.stop"
        }

        for k, v in env.items():
            monkeypatch.setenv(k, v)

        config = load_aegis_config(config_path)

        assert config.enforcement.blacklist_db_path == "/tmp/custom/blacklist.db"
        assert config.enforcement.blacklist_json_path == "/tmp/custom/blacklist.json"
        assert config.enforcement.feedback_dir == "/tmp/custom/feedback"
        assert config.enforcement.retrain_flag_file == "/tmp/custom/trigger_retrain"
        assert config.enforcement.emergency_stop_file == "/tmp/custom/emergency.stop"

    finally:
        if os.path.exists(config_path):
            os.unlink(config_path)

def test_config_defaults(monkeypatch):
    """Test that defaults are used when env vars are not set."""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write("""
model:
  model_local_path: "/tmp/models"
polling:
  poll_interval_seconds: 5
prediction:
  anomaly_threshold: 0.5
runtime:
  log_level: "INFO"
""")
        config_path = f.name

    try:
        # Ensure env vars are NOT set
        monkeypatch.delenv("ARGUS_BLACKLIST_DB_PATH", raising=False)
        monkeypatch.delenv("ARGUS_BLACKLIST_JSON_PATH", raising=False)
        monkeypatch.delenv("ARGUS_FEEDBACK_DIR", raising=False)
        monkeypatch.delenv("ARGUS_RETRAIN_FLAG_FILE", raising=False)
        monkeypatch.delenv("ARGUS_EMERGENCY_STOP_FILE", raising=False)

        config = load_aegis_config(config_path)

        assert config.enforcement.blacklist_db_path == "/var/lib/argus/aegis/blacklist.db"
        assert config.enforcement.blacklist_json_path == "/var/lib/argus/aegis/blacklist.json"

    finally:
        if os.path.exists(config_path):
            os.unlink(config_path)
