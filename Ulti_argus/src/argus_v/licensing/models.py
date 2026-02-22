from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from enum import StrEnum
from typing import Any


class ServiceTier(StrEnum):
    free = "free_tier"
    standard = "standard_tier"
    enterprise = "enterprise_tier"


class AgreementType(StrEnum):
    nda = "nda"
    dpa = "dpa"


@dataclass(frozen=True)
class ContractTerms:
    ngo_id: str
    organization_name: str
    organization_address: str
    jurisdiction: str
    tier: ServiceTier
    effective_date: date
    expiration_date: date
    redistribution_prohibited: bool = True


@dataclass(frozen=True)
class SignatureRecord:
    agreement_type: AgreementType
    signed_at: datetime
    signatory_name: str
    signatory_title: str | None = None


@dataclass
class ContractRecord:
    terms: ContractTerms
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    signatures: list[SignatureRecord] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "terms": {
                "ngo_id": self.terms.ngo_id,
                "organization_name": self.terms.organization_name,
                "organization_address": self.terms.organization_address,
                "jurisdiction": self.terms.jurisdiction,
                "tier": self.terms.tier.value,
                "effective_date": self.terms.effective_date.isoformat(),
                "expiration_date": self.terms.expiration_date.isoformat(),
                "redistribution_prohibited": self.terms.redistribution_prohibited,
            },
            "created_at": self.created_at.isoformat(),
            "signatures": [
                {
                    "agreement_type": s.agreement_type.value,
                    "signed_at": s.signed_at.isoformat(),
                    "signatory_name": s.signatory_name,
                    "signatory_title": s.signatory_title,
                }
                for s in self.signatures
            ],
        }

    @staticmethod
    def from_json(payload: dict[str, Any]) -> "ContractRecord":
        terms = payload.get("terms") or {}
        record = ContractRecord(
            terms=ContractTerms(
                ngo_id=str(terms["ngo_id"]),
                organization_name=str(terms["organization_name"]),
                organization_address=str(terms.get("organization_address") or ""),
                jurisdiction=str(terms.get("jurisdiction") or ""),
                tier=ServiceTier(str(terms.get("tier") or ServiceTier.free.value)),
                effective_date=date.fromisoformat(str(terms["effective_date"])),
                expiration_date=date.fromisoformat(str(terms["expiration_date"])),
                redistribution_prohibited=bool(terms.get("redistribution_prohibited", True)),
            ),
            created_at=datetime.fromisoformat(
                str(payload.get("created_at") or datetime.now(timezone.utc).isoformat())
            ),
        )

        for item in payload.get("signatures") or []:
            record.signatures.append(
                SignatureRecord(
                    agreement_type=AgreementType(str(item["agreement_type"])),
                    signed_at=datetime.fromisoformat(str(item["signed_at"])),
                    signatory_name=str(item["signatory_name"]),
                    signatory_title=(
                        str(item["signatory_title"]) if item.get("signatory_title") else None
                    ),
                )
            )

        return record
