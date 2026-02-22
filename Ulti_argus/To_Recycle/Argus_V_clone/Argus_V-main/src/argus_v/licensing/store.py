from __future__ import annotations

import json
import os
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from .models import AgreementType, ContractRecord, ContractTerms, SignatureRecord


def _default_contract_dir() -> Path:
    configured = os.getenv("ARGUS_V_CONTRACT_DIR")
    if configured:
        return Path(configured)

    return Path("/var/lib/argus_v/contracts")


def _fallback_contract_dir() -> Path:
    xdg_state = os.getenv("XDG_STATE_HOME")
    if xdg_state:
        return Path(xdg_state) / "argus_v" / "contracts"

    return Path.home() / ".local" / "state" / "argus_v" / "contracts"


class ContractStore:
    def __init__(self, base_dir: Path | None = None) -> None:
        self.base_dir = base_dir or _default_contract_dir()
        try:
            self.base_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            self.base_dir = _fallback_contract_dir()
            self.base_dir.mkdir(parents=True, exist_ok=True)

    def path_for(self, ngo_id: str) -> Path:
        safe = ngo_id.replace("/", "_")
        return self.base_dir / f"{safe}.json"

    def load(self, ngo_id: str) -> ContractRecord | None:
        path = self.path_for(ngo_id)
        if not path.exists():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        return ContractRecord.from_json(payload)

    def save(self, record: ContractRecord) -> Path:
        path = self.path_for(record.terms.ngo_id)
        payload = (
            json.dumps(
                record.to_json(),
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        path.write_text(payload, encoding="utf-8")
        return path

    def upsert_terms(self, terms: ContractTerms) -> ContractRecord:
        existing = self.load(terms.ngo_id)
        if not existing:
            existing = ContractRecord(terms=terms)
        else:
            existing.terms = replace(existing.terms, **terms.__dict__)
        self.save(existing)
        return existing

    def add_signature(
        self,
        *,
        ngo_id: str,
        agreement_type: AgreementType,
        signatory_name: str,
        signatory_title: str | None = None,
        signed_at: datetime | None = None,
    ) -> ContractRecord:
        record = self.load(ngo_id)
        if not record:
            raise FileNotFoundError(f"No contract record found for {ngo_id}")

        record.signatures.append(
            SignatureRecord(
                agreement_type=agreement_type,
                signed_at=signed_at or datetime.now(timezone.utc),
                signatory_name=signatory_name,
                signatory_title=signatory_title,
            )
        )
        self.save(record)
        return record
