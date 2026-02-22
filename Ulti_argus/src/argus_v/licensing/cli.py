from __future__ import annotations

import argparse
import json
from datetime import date, datetime, timezone
from pathlib import Path

from ..oracle_core.logging import configure_logging, log_event
from .documents import export_pdf, generate_license_file, render_dpa, render_nda
from .models import AgreementType, ContractTerms, ServiceTier
from .store import ContractStore
from .verify import LicenseStatus, license_path_default, verify_license_file


def _parse_date(value: str) -> date:
    return date.fromisoformat(value)


def _parse_datetime(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="argus-license", description="ARGUS_V licensing tooling")
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="Verify /opt/argus/license.txt")
    verify.add_argument("--path", default=license_path_default())
    verify.add_argument("--no-online", action="store_true", help="Skip HTTPS verification")
    verify.add_argument("--no-offline-demo", action="store_true", help="Fail instead of demo mode")
    verify.add_argument("--json", action="store_true")

    init_contract = sub.add_parser("init-contract", help="Create/update contract record")
    init_contract.add_argument("ngo_id")
    init_contract.add_argument("--org-name", required=True)
    init_contract.add_argument("--org-address", default="")
    init_contract.add_argument("--jurisdiction", default="")
    init_contract.add_argument(
        "--tier",
        default=ServiceTier.free.value,
        choices=(t.value for t in ServiceTier),
    )
    init_contract.add_argument("--effective-date", type=_parse_date, required=True)
    init_contract.add_argument("--expiration-date", type=_parse_date, required=True)
    init_contract.add_argument("--allow-redistribution", action="store_true")
    init_contract.add_argument("--json", action="store_true")

    export = sub.add_parser("export", help="Export NDA/DPA as PDF or text")
    export.add_argument("ngo_id")
    export.add_argument("agreement", choices=(a.value for a in AgreementType))
    export.add_argument("--format", default="pdf", choices=("pdf", "txt"))
    export.add_argument("--out", type=Path, required=True)

    sign = sub.add_parser("sign", help="Record signature metadata")
    sign.add_argument("ngo_id")
    sign.add_argument("agreement", choices=(a.value for a in AgreementType))
    sign.add_argument("--signatory-name", required=True)
    sign.add_argument("--signatory-title")
    sign.add_argument("--signed-at", type=_parse_datetime)
    sign.add_argument("--json", action="store_true")

    gen_license = sub.add_parser("generate-license", help="Generate a license.txt from contract")
    gen_license.add_argument("ngo_id")
    gen_license.add_argument("--license-id", required=True)
    gen_license.add_argument("--verification-url")
    gen_license.add_argument("--offline-grace-days", type=int, default=7)
    gen_license.add_argument("--out", type=Path, required=True)

    return parser


def _render_agreement(agreement: AgreementType, terms: ContractTerms) -> str:
    if agreement is AgreementType.nda:
        return render_nda(terms)
    return render_dpa(terms)


def main(argv: list[str] | None = None) -> int:
    logger = configure_logging()
    parser = _build_parser()
    args = parser.parse_args(argv)

    store = ContractStore()

    if args.command == "verify":
        result = verify_license_file(
            args.path,
            check_online=not args.no_online,
            offline_demo=not args.no_offline_demo,
        )

        log_event(
            logger,
            "licensing.verify",
            path=args.path,
            status=result.status.value,
            demo_mode=result.demo_mode,
            verified_online=result.verified_online,
        )

        if args.json:
            print(
                json.dumps(
                    {
                        "ok": result.ok,
                        "status": result.status.value,
                        "demo_mode": result.demo_mode,
                        "ngo_id": result.ngo_id,
                        "license_id": result.license_id,
                        "verified_online": result.verified_online,
                        "errors": result.errors,
                    }
                )
            )

        if result.status is LicenseStatus.valid:
            return 0
        if result.status is LicenseStatus.demo:
            return 2
        return 1

    if args.command == "init-contract":
        terms = ContractTerms(
            ngo_id=args.ngo_id,
            organization_name=args.org_name,
            organization_address=args.org_address,
            jurisdiction=args.jurisdiction,
            tier=ServiceTier(args.tier),
            effective_date=args.effective_date,
            expiration_date=args.expiration_date,
            redistribution_prohibited=not args.allow_redistribution,
        )
        record = store.upsert_terms(terms)
        log_event(logger, "licensing.contract.init", ngo_id=terms.ngo_id, tier=terms.tier.value)

        payload = {"ok": True, "ngo_id": terms.ngo_id, "path": str(store.path_for(terms.ngo_id))}
        if args.json:
            print(json.dumps(payload))
        else:
            print(f"contract saved: {payload['path']}")
        return 0

    if args.command == "export":
        record = store.load(args.ngo_id)
        if not record:
            raise SystemExit(f"No contract record found for {args.ngo_id}")

        agreement = AgreementType(args.agreement)
        text = _render_agreement(agreement, record.terms)

        args.out.parent.mkdir(parents=True, exist_ok=True)
        if args.format == "txt":
            args.out.write_text(text, encoding="utf-8")
        else:
            pdf = export_pdf(text)
            pdf.write_to(str(args.out))

        log_event(
            logger,
            "licensing.agreement.export",
            ngo_id=record.terms.ngo_id,
            agreement=agreement.value,
            out=str(args.out),
            format=args.format,
        )

        print(str(args.out))
        return 0

    if args.command == "sign":
        signed_at = args.signed_at
        record = store.add_signature(
            ngo_id=args.ngo_id,
            agreement_type=AgreementType(args.agreement),
            signatory_name=args.signatory_name,
            signatory_title=args.signatory_title,
            signed_at=signed_at,
        )
        log_event(
            logger,
            "licensing.signature.recorded",
            ngo_id=record.terms.ngo_id,
            agreement=args.agreement,
            signatory=args.signatory_name,
        )
        if args.json:
            print(json.dumps(record.to_json()))
        else:
            print(f"signature recorded for {record.terms.ngo_id}")
        return 0

    if args.command == "generate-license":
        record = store.load(args.ngo_id)
        if not record:
            raise SystemExit(f"No contract record found for {args.ngo_id}")

        content = generate_license_file(
            terms=record.terms,
            license_id=args.license_id,
            verification_url=args.verification_url,
            offline_grace_days=args.offline_grace_days,
        )
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(content, encoding="utf-8")

        log_event(
            logger,
            "licensing.license.generated",
            ngo_id=record.terms.ngo_id,
            out=str(args.out),
            license_id=args.license_id,
        )
        print(str(args.out))
        return 0

    raise SystemExit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
