from __future__ import annotations

from pathlib import Path

import pytest

from argus_v.oracle_core.config import load_config
from argus_v.oracle_core.validation import ValidationError


def test_load_config_expands_env_vars_and_redacts(tmp_path: Path) -> None:
    cfg_text = """
interfaces:
  github:
    enabled: true
  firebase:
    enabled: false

github:
  token: ${GITHUB_TOKEN}

blacklist:
  sync_cadence_seconds: 60
  sources: []
"""
    p = tmp_path / "cfg.yaml"
    p.write_text(cfg_text, encoding="utf-8")

    cfg = load_config(p, env={"GITHUB_TOKEN": "ghp_secret_value"})
    assert cfg.github is not None
    assert cfg.github.token == "ghp_secret_value"

    safe = cfg.to_safe_dict()
    assert safe["github"]["token"] == "[REDACTED]"


def test_load_config_missing_env_var_is_an_error(tmp_path: Path) -> None:
    cfg_text = """
interfaces:
  github: true

github:
  token: ${GITHUB_TOKEN}

blacklist:
  sync_cadence_seconds: 60
  sources: []
"""
    p = tmp_path / "cfg.yaml"
    p.write_text(cfg_text, encoding="utf-8")

    with pytest.raises(ValidationError) as e:
        load_config(p, env={})

    assert "GITHUB_TOKEN" in str(e.value)
