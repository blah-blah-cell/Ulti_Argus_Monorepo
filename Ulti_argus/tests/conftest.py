from __future__ import annotations

import sys
import os
import tempfile
import pytest
from pathlib import Path


def pytest_configure() -> None:
    root = Path(__file__).resolve().parents[1]
    src = root / "src"
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))


@pytest.fixture(autouse=True)
def mock_argus_env_paths(monkeypatch):
    """Mock Argus paths to use temporary directory via environment variables."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create subdirectories to simulate structure
        models_dir = os.path.join(tmpdir, "models")
        scalers_dir = os.path.join(tmpdir, "scalers")
        foundation_dir = os.path.join(tmpdir, "foundation")
        retina_dir = os.path.join(tmpdir, "retina", "csv")
        aegis_dir = os.path.join(tmpdir, "aegis")

        os.makedirs(models_dir, exist_ok=True)
        os.makedirs(scalers_dir, exist_ok=True)
        os.makedirs(foundation_dir, exist_ok=True)
        os.makedirs(retina_dir, exist_ok=True)
        os.makedirs(aegis_dir, exist_ok=True)

        # Mock foundation files
        Path(os.path.join(foundation_dir, "model.pkl")).touch()
        Path(os.path.join(foundation_dir, "scaler.pkl")).touch()

        # Set env vars
        monkeypatch.setenv("ARGUS_BLACKLIST_DB_PATH", os.path.join(aegis_dir, "blacklist.db"))
        monkeypatch.setenv("ARGUS_BLACKLIST_JSON_PATH", os.path.join(aegis_dir, "blacklist.json"))
        monkeypatch.setenv("ARGUS_FEEDBACK_DIR", os.path.join(aegis_dir, "feedback"))
        monkeypatch.setenv("ARGUS_RETRAIN_FLAG_FILE", os.path.join(tmpdir, "mnemosyne", "trigger_retrain"))
        monkeypatch.setenv("ARGUS_EMERGENCY_STOP_FILE", os.path.join(tmpdir, "aegis.emergency"))

        monkeypatch.setenv("ARGUS_MODEL_LOCAL_PATH", models_dir)
        monkeypatch.setenv("ARGUS_SCALER_LOCAL_PATH", scalers_dir)
        monkeypatch.setenv("ARGUS_FOUNDATION_MODEL_PATH", os.path.join(foundation_dir, "model.pkl"))
        monkeypatch.setenv("ARGUS_FOUNDATION_SCALER_PATH", os.path.join(foundation_dir, "scaler.pkl"))

        monkeypatch.setenv("ARGUS_CSV_DIRECTORY", retina_dir)

        monkeypatch.setenv("ARGUS_STATE_FILE", os.path.join(aegis_dir, "state.json"))
        monkeypatch.setenv("ARGUS_PID_FILE", os.path.join(tmpdir, "aegis.pid"))
        monkeypatch.setenv("ARGUS_STATS_FILE", os.path.join(aegis_dir, "stats.json"))

        yield
