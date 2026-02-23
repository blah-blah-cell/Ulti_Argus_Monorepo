from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Mapping

# Use python-json-logger for structured logging
from pythonjsonlogger import jsonlogger

DEFAULT_LOG_LEVEL = "INFO"

_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "auth",
        "email",
        "ip",
        "ip_address",
        "private_key",
        "client_secret",
    }
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_GITHUB_TOKEN_RE = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")
_FIREBASE_API_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{30,}\b")


def scrub_text(text: str) -> str:
    text = _EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = _IPV4_RE.sub("[REDACTED_IP]", text)
    text = _GITHUB_TOKEN_RE.sub("[REDACTED_GITHUB_TOKEN]", text)
    text = _FIREBASE_API_KEY_RE.sub("[REDACTED_FIREBASE_API_KEY]", text)
    return text


def scrub_pii(value: Any) -> Any:
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for k, v in value.items():
            key = str(k)
            if key.lower() in _SENSITIVE_KEYS:
                out[key] = "[REDACTED]"
            else:
                out[key] = scrub_pii(v)
        return out

    if isinstance(value, (list, tuple)):
        return [scrub_pii(v) for v in value]

    if isinstance(value, str):
        return scrub_text(value)

    return value


class PrivacyFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003 (filter)
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)

        record.msg = scrub_text(message)
        record.args = ()

        fields = getattr(record, "fields", None)
        if isinstance(fields, Mapping):
            record.fields = scrub_pii(fields)

        return True


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter to handle timestamp and field scrubbing compatibility."""

    def add_fields(self, log_record: dict[str, Any], record: logging.LogRecord, message_dict: dict[str, Any]) -> None:
        super().add_fields(log_record, record, message_dict)

        # Ensure timestamp is ISO 8601 with UTC
        if not log_record.get('timestamp'):
            now = datetime.fromtimestamp(record.created, tz=timezone.utc)
            log_record['timestamp'] = now.isoformat()

        # Handle 'fields' from extra if present (compatibility with log_event)
        # Note: PrivacyFilter already scrubs record.fields if it exists,
        # but python-json-logger might pull from record.__dict__ or extras.
        # log_event puts 'fields' in extra, which python-json-logger puts into log_record automatically.
        pass


def _normalize_level(level: str | int | None) -> int:
    if level is None:
        level = os.getenv("ARGUS_V_LOG_LEVEL", DEFAULT_LOG_LEVEL)
    if isinstance(level, int):
        return level
    return logging._nameToLevel.get(str(level).upper(), logging.INFO)


def configure_logging(*, level: str | int | None = None) -> logging.Logger:
    """Configure process-wide logging.

    Idempotent: calling multiple times will not add multiple handlers.
    """

    resolved_level = _normalize_level(level)

    root = logging.getLogger()
    root.setLevel(resolved_level)

    handler_name = "argus_json"
    for h in root.handlers:
        if getattr(h, "name", None) == handler_name:
            return logging.getLogger("argus_v")

    handler = logging.StreamHandler()
    handler.name = handler_name
    handler.setLevel(resolved_level)

    # Configure python-json-logger
    # We include level, name, and message in the format string (timestamp added by formatter)
    formatter = CustomJsonFormatter(
        '%(levelname)s %(name)s %(message)s',
        rename_fields={'levelname': 'level', 'name': 'logger'}
    )
    handler.setFormatter(formatter)
    handler.addFilter(PrivacyFilter())

    root.addHandler(handler)

    # Pi-friendly defaults: avoid noisy dependency logs.
    for noisy in ("urllib3", "requests"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    return logging.getLogger("argus_v")


def log_event(
    logger: logging.Logger,
    event: str,
    /,
    *,
    level: int | str = logging.INFO,
    **fields: Any,
) -> None:
    if isinstance(level, str):
        level = logging._nameToLevel.get(level.upper(), logging.INFO)

    logger.log(level, event, extra={"fields": scrub_pii(fields)})
