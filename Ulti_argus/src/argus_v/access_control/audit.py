from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from ..oracle_core.logging import scrub_pii


def _default_audit_dir() -> Path:
    configured = os.getenv("ARGUS_V_AUDIT_DIR")
    if configured:
        return Path(configured)

    return Path("/var/log/argus_v/audit")


def _fallback_audit_dir() -> Path:
    xdg_state = os.getenv("XDG_STATE_HOME")
    if xdg_state:
        return Path(xdg_state) / "argus_v" / "audit"

    return Path.home() / ".local" / "state" / "argus_v" / "audit"


@dataclass(frozen=True)
class AuditEvent:
    ts: str
    event: str
    fields: dict[str, Any]
    prev_hash: str
    hash: str


class AuditTrail:
    def __init__(self, *, file_name: str = "access-events.jsonl") -> None:
        self._dir = _default_audit_dir()
        self._file = self._dir / file_name
        self._hash_file = self._dir / f".{file_name}.sha256"

        try:
            self._dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            self._dir = _fallback_audit_dir()
            self._file = self._dir / file_name
            self._hash_file = self._dir / f".{file_name}.sha256"
            self._dir.mkdir(parents=True, exist_ok=True)

    def append(self, event: str, /, **fields: Any) -> AuditEvent:
        scrubbed = scrub_pii(fields)
        ts = datetime.now(timezone.utc).isoformat()

        prev_hash = "0" * 64
        if self._hash_file.exists():
            prev_hash = self._hash_file.read_text(encoding="utf-8").strip() or prev_hash

        payload = {
            "ts": ts,
            "event": event,
            "fields": scrubbed,
            "prev_hash": prev_hash,
        }
        payload_json = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        digest = sha256((prev_hash + payload_json).encode("utf-8")).hexdigest()

        record = {
            **payload,
            "hash": digest,
        }

        self._file.parent.mkdir(parents=True, exist_ok=True)
        with self._file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
            handle.write("\n")

        self._hash_file.write_text(digest + "\n", encoding="utf-8")

        return AuditEvent(ts=ts, event=event, fields=scrubbed, prev_hash=prev_hash, hash=digest)

    def verify_chain(self) -> tuple[bool, str]:
        if not self._file.exists():
            return True, "empty"

        prev_hash = "0" * 64
        for idx, line in enumerate(self._file.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue

            record = json.loads(line)
            expected_prev = record.get("prev_hash")
            if expected_prev != prev_hash:
                return False, f"hash chain break at line {idx}"

            payload = {
                "ts": record.get("ts"),
                "event": record.get("event"),
                "fields": record.get("fields"),
                "prev_hash": record.get("prev_hash"),
            }
            payload_json = json.dumps(
                payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
            )
            expected_hash = sha256((prev_hash + payload_json).encode("utf-8")).hexdigest()
            if record.get("hash") != expected_hash:
                return False, f"hash mismatch at line {idx}"

            prev_hash = expected_hash

        return True, "ok"


def safe_fields(fields: Mapping[str, Any] | None) -> dict[str, Any]:
    if not fields:
        return {}
    return dict(scrub_pii(dict(fields)))
