from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..oracle_core.logging import configure_logging, log_event
from .audit import AuditTrail
from .manager import AccessControlError, AccessManager, load_ngo_access_config


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="argus-access",
        description="ARGUS_V access control tooling (GitHub branch + licensing operations)",
    )

    parser.add_argument("--config-dir", type=Path, help="Directory containing NGO YAML configs")
    parser.add_argument("--dry-run", action="store_true", help="Do not perform changes")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    sub = parser.add_subparsers(dest="command", required=True)

    grant = sub.add_parser("grant", help="Grant access for an NGO")
    grant.add_argument("ngo_id", help="NGO identifier (e.g. red-cross or ngo-red-cross)")

    revoke = sub.add_parser("revoke", help="Revoke access for an NGO")
    revoke.add_argument("ngo_id", help="NGO identifier (e.g. red-cross or ngo-red-cross)")
    revoke.add_argument(
        "--reason",
        default="contract_end",
        choices=("contract_end", "non_payment", "security_incident", "manual"),
        help="Revocation reason",
    )

    verify = sub.add_parser("audit-verify", help="Verify audit hash chain")
    verify.add_argument(
        "--file-name",
        default="access-events.jsonl",
        help="Audit file name (default: access-events.jsonl)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    logger = configure_logging()
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "audit-verify":
        audit = AuditTrail(file_name=args.file_name)
        ok, msg = audit.verify_chain()
        payload = {"ok": ok, "message": msg}
        if args.json:
            print(json.dumps(payload))
        else:
            print(msg)
        return 0 if ok else 1

    try:
        config = load_ngo_access_config(args.ngo_id, config_dir=args.config_dir)
        audit = AuditTrail()
        manager = AccessManager(config, audit=audit, dry_run=args.dry_run)

        if args.command == "grant":
            manager.grant_access()
            log_event(
                logger,
                "access_control.cli.grant",
                ngo_id=config.ngo_id,
                repo=f"{config.github_org}/{config.github_repo}",
                team=config.github_team,
                dry_run=args.dry_run,
            )
            payload = {"ok": True, "action": "grant", "ngo_id": config.ngo_id}

        elif args.command == "revoke":
            revoke_read_access = args.reason in {"non_payment", "security_incident"}
            manager.revoke_access(reason=args.reason, revoke_read_access=revoke_read_access)
            log_event(
                logger,
                "access_control.cli.revoke",
                ngo_id=config.ngo_id,
                repo=f"{config.github_org}/{config.github_repo}",
                team=config.github_team,
                reason=args.reason,
                revoke_read_access=revoke_read_access,
                dry_run=args.dry_run,
            )
            payload = {
                "ok": True,
                "action": "revoke",
                "ngo_id": config.ngo_id,
                "reason": args.reason,
                "revoke_read_access": revoke_read_access,
            }
        else:
            raise AccessControlError(f"Unknown command: {args.command}")

        if args.json:
            print(json.dumps(payload))
        else:
            print(f"{payload['action']} ok for {payload['ngo_id']}")

        return 0

    except AccessControlError as exc:
        log_event(logger, "access_control.cli.error", error=str(exc))
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def main_revoke(argv: list[str] | None = None) -> int:
    """Dedicated entrypoint for `argus-revoke-access`.

    Kept separate so global flags like --config-dir work as expected.
    """

    logger = configure_logging()
    parser = argparse.ArgumentParser(prog="argus-revoke-access")
    parser.add_argument("ngo_id", help="NGO identifier (e.g. red-cross or ngo-red-cross)")
    parser.add_argument(
        "--reason",
        default="contract_end",
        choices=("contract_end", "non_payment", "security_incident", "manual"),
    )
    parser.add_argument("--config-dir", type=Path, help="Directory containing NGO YAML configs")
    parser.add_argument("--dry-run", action="store_true", help="Do not perform changes")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    args = parser.parse_args(argv)

    try:
        config = load_ngo_access_config(args.ngo_id, config_dir=args.config_dir)
        manager = AccessManager(config, audit=AuditTrail(), dry_run=args.dry_run)
        revoke_read_access = args.reason in {"non_payment", "security_incident"}
        manager.revoke_access(reason=args.reason, revoke_read_access=revoke_read_access)

        log_event(
            logger,
            "access_control.cli.revoke",
            ngo_id=config.ngo_id,
            repo=f"{config.github_org}/{config.github_repo}",
            team=config.github_team,
            reason=args.reason,
            revoke_read_access=revoke_read_access,
            dry_run=args.dry_run,
        )

        payload = {
            "ok": True,
            "action": "revoke",
            "ngo_id": config.ngo_id,
            "reason": args.reason,
            "revoke_read_access": revoke_read_access,
        }
        if args.json:
            print(json.dumps(payload))
        else:
            print(f"revoke ok for {config.ngo_id}")
        return 0
    except AccessControlError as exc:
        log_event(logger, "access_control.cli.error", error=str(exc))
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def main_grant(argv: list[str] | None = None) -> int:
    """Dedicated entrypoint for `argus-grant-access`."""

    logger = configure_logging()
    parser = argparse.ArgumentParser(prog="argus-grant-access")
    parser.add_argument("ngo_id", help="NGO identifier (e.g. red-cross or ngo-red-cross)")
    parser.add_argument("--config-dir", type=Path, help="Directory containing NGO YAML configs")
    parser.add_argument("--dry-run", action="store_true", help="Do not perform changes")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    args = parser.parse_args(argv)

    try:
        config = load_ngo_access_config(args.ngo_id, config_dir=args.config_dir)
        manager = AccessManager(config, audit=AuditTrail(), dry_run=args.dry_run)
        manager.grant_access()

        log_event(
            logger,
            "access_control.cli.grant",
            ngo_id=config.ngo_id,
            repo=f"{config.github_org}/{config.github_repo}",
            team=config.github_team,
            dry_run=args.dry_run,
        )

        payload = {"ok": True, "action": "grant", "ngo_id": config.ngo_id}
        if args.json:
            print(json.dumps(payload))
        else:
            print(f"grant ok for {config.ngo_id}")
        return 0
    except AccessControlError as exc:
        log_event(logger, "access_control.cli.error", error=str(exc))
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 1
