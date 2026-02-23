from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from .validation import (
    ValidationError,
    ValidationIssue,
    as_bool,
    as_list,
    as_mapping,
    get_optional,
    get_required,
    require_non_empty_str,
    require_positive_int,
)

_ENV_VAR_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def _expand_env_str(value: str, *, env: Mapping[str, str], path: str) -> str:
    missing: set[str] = set()

    def repl(match: re.Match[str]) -> str:
        var = match.group(1)
        if var not in env:
            missing.add(var)
            return match.group(0)
        return env[var]

    out = _ENV_VAR_RE.sub(repl, value)

    if missing:
        raise ValidationError(
            [
                ValidationIssue(path, f"environment variable '{v}' is not set")
                for v in sorted(missing)
            ]
        )

    return out


@dataclass(frozen=True, slots=True)
class SamplingConfig:
    window_seconds: int = 300
    timestamp_round_seconds: int = 60

    @staticmethod
    def from_mapping(data: Mapping[str, Any], *, path: str) -> "SamplingConfig":
        window_seconds = require_positive_int(
            get_optional(data, "window_seconds", 300),
            path=f"{path}.window_seconds",
        )
        timestamp_round_seconds = require_positive_int(
            get_optional(data, "timestamp_round_seconds", 60),
            path=f"{path}.timestamp_round_seconds",
        )
        if timestamp_round_seconds > window_seconds:
            raise ValidationError(
                [
                    ValidationIssue(
                        f"{path}.timestamp_round_seconds",
                        "must be <= sampling.window_seconds",
                    )
                ]
            )
        return SamplingConfig(
            window_seconds=window_seconds,
            timestamp_round_seconds=timestamp_round_seconds,
        )


@dataclass(frozen=True, slots=True)
class InterfaceToggle:
    enabled: bool = True

    @staticmethod
    def from_any(value: Any, *, path: str) -> "InterfaceToggle":
        if isinstance(value, bool):
            return InterfaceToggle(enabled=value)
        data = as_mapping(value, path=path)
        enabled = as_bool(
            get_optional(data, "enabled", True),
            path=f"{path}.enabled",
        )
        return InterfaceToggle(enabled=enabled)


@dataclass(frozen=True, slots=True)
class FirebaseConfig:
    project_id: str
    database_url: str
    api_key: str
    request_timeout_seconds: int = 10

    @staticmethod
    def from_mapping(
        data: Mapping[str, Any],
        *,
        path: str,
        env: Mapping[str, str],
    ) -> "FirebaseConfig":
        project_id = require_non_empty_str(
            get_required(data, "project_id", path=path),
            path=f"{path}.project_id",
        )
        database_url = require_non_empty_str(
            get_required(data, "database_url", path=path),
            path=f"{path}.database_url",
        )

        api_key_raw = require_non_empty_str(
            get_required(data, "api_key", path=path),
            path=f"{path}.api_key",
        )
        api_key = _expand_env_str(api_key_raw, env=env, path=f"{path}.api_key")

        request_timeout_seconds = require_positive_int(
            get_optional(data, "request_timeout_seconds", 10),
            path=f"{path}.request_timeout_seconds",
        )

        return FirebaseConfig(
            project_id=project_id,
            database_url=database_url,
            api_key=api_key,
            request_timeout_seconds=request_timeout_seconds,
        )


@dataclass(frozen=True, slots=True)
class GitHubConfig:
    base_url: str = "https://api.github.com"
    token: str = ""
    user_agent: str = "argus-v"
    request_timeout_seconds: int = 10

    @staticmethod
    def from_mapping(
        data: Mapping[str, Any],
        *,
        path: str,
        env: Mapping[str, str],
    ) -> "GitHubConfig":
        base_url = require_non_empty_str(
            get_optional(data, "base_url", "https://api.github.com"),
            path=f"{path}.base_url",
        )

        token_raw = require_non_empty_str(
            get_required(data, "token", path=path),
            path=f"{path}.token",
        )
        token = _expand_env_str(token_raw, env=env, path=f"{path}.token")

        user_agent = require_non_empty_str(
            get_optional(data, "user_agent", "argus-v"),
            path=f"{path}.user_agent",
        )
        request_timeout_seconds = require_positive_int(
            get_optional(data, "request_timeout_seconds", 10),
            path=f"{path}.request_timeout_seconds",
        )
        return GitHubConfig(
            base_url=base_url,
            token=token,
            user_agent=user_agent,
            request_timeout_seconds=request_timeout_seconds,
        )


@dataclass(frozen=True, slots=True)
class BlacklistConfig:
    sync_cadence_seconds: int = 3600
    sources: list[str] = field(default_factory=list)

    @staticmethod
    def from_mapping(data: Mapping[str, Any], *, path: str) -> "BlacklistConfig":
        cadence = require_positive_int(
            get_optional(data, "sync_cadence_seconds", 3600),
            path=f"{path}.sync_cadence_seconds",
        )

        sources_raw = get_optional(data, "sources", [])
        sources_list_raw = as_list(sources_raw, path=f"{path}.sources")
        sources = [
            require_non_empty_str(s, path=f"{path}.sources[{i}]")
            for i, s in enumerate(sources_list_raw)
        ]

        return BlacklistConfig(sync_cadence_seconds=cadence, sources=sources)


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    dry_run: bool = False
    log_level: str = "INFO"

    @staticmethod
    def from_mapping(data: Mapping[str, Any], *, path: str) -> "RuntimeConfig":
        dry_run = as_bool(
            get_optional(data, "dry_run", False),
            path=f"{path}.dry_run",
        )
        log_level = require_non_empty_str(
            get_optional(data, "log_level", "INFO"),
            path=f"{path}.log_level",
        )
        return RuntimeConfig(dry_run=dry_run, log_level=log_level)


@dataclass(frozen=True, slots=True)
class ArgusConfig:
    sampling: SamplingConfig
    interfaces: dict[str, InterfaceToggle]
    firebase: FirebaseConfig | None
    github: GitHubConfig | None
    blacklist: BlacklistConfig
    runtime: RuntimeConfig

    def to_safe_dict(self) -> dict[str, Any]:
        interfaces = {
            k: {"enabled": v.enabled}
            for k, v in self.interfaces.items()
        }
        runtime = {
            "dry_run": self.runtime.dry_run,
            "log_level": self.runtime.log_level,
        }

        out: dict[str, Any] = {
            "sampling": {
                "window_seconds": self.sampling.window_seconds,
                "timestamp_round_seconds": self.sampling.timestamp_round_seconds,
            },
            "interfaces": interfaces,
            "blacklist": {
                "sync_cadence_seconds": self.blacklist.sync_cadence_seconds,
                "sources": list(self.blacklist.sources),
            },
            "runtime": runtime,
        }

        if self.github is not None:
            out["github"] = {
                "base_url": self.github.base_url,
                "token": "[REDACTED]" if self.github.token else "",
                "user_agent": self.github.user_agent,
                "request_timeout_seconds": self.github.request_timeout_seconds,
            }

        if self.firebase is not None:
            out["firebase"] = {
                "project_id": self.firebase.project_id,
                "database_url": self.firebase.database_url,
                "api_key": "[REDACTED]" if self.firebase.api_key else "",
                "request_timeout_seconds": self.firebase.request_timeout_seconds,
            }

        return out


def load_config(
    path: str | os.PathLike[str],
    *,
    env: Mapping[str, str] | None = None,
) -> ArgusConfig:
    """Load and validate an Argus_V YAML configuration file."""

    env_map = dict(os.environ) if env is None else dict(env)

    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    raw_map = as_mapping(raw, path="$")

    sampling = SamplingConfig.from_mapping(
        as_mapping(get_optional(raw_map, "sampling", {}), path="$.sampling"),
        path="$.sampling",
    )

    runtime = RuntimeConfig.from_mapping(
        as_mapping(get_optional(raw_map, "runtime", {}), path="$.runtime"),
        path="$.runtime",
    )

    blacklist = BlacklistConfig.from_mapping(
        as_mapping(get_optional(raw_map, "blacklist", {}), path="$.blacklist"),
        path="$.blacklist",
    )

    interfaces_raw = as_mapping(
        get_optional(raw_map, "interfaces", {}),
        path="$.interfaces",
    )
    interfaces: dict[str, InterfaceToggle] = {
        str(name): InterfaceToggle.from_any(
            value,
            path=f"$.interfaces.{name}",
        )
        for name, value in interfaces_raw.items()
    }

    firebase: FirebaseConfig | None = None
    if interfaces.get("firebase", InterfaceToggle(enabled=False)).enabled:
        firebase_map = as_mapping(
            get_required(raw_map, "firebase", path="$.firebase"),
            path="$.firebase",
        )
        firebase = FirebaseConfig.from_mapping(
            firebase_map,
            path="$.firebase",
            env=env_map,
        )

    github: GitHubConfig | None = None
    if interfaces.get("github", InterfaceToggle(enabled=False)).enabled:
        github_map = as_mapping(
            get_required(raw_map, "github", path="$.github"),
            path="$.github",
        )
        github = GitHubConfig.from_mapping(
            github_map,
            path="$.github",
            env=env_map,
        )

    return ArgusConfig(
        sampling=sampling,
        interfaces=interfaces,
        firebase=firebase,
        github=github,
        blacklist=blacklist,
        runtime=runtime,
    )
