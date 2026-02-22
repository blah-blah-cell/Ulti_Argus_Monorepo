from __future__ import annotations

import ipaddress
import json
import os
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import date, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


class LicenseStatus(StrEnum):
    valid = "valid"
    demo = "demo"
    missing = "missing"
    invalid = "invalid"
    expired = "expired"


@dataclass(frozen=True)
class LicenseVerificationResult:
    status: LicenseStatus
    demo_mode: bool
    ngo_id: str | None
    license_id: str | None
    verified_online: bool
    errors: list[str]

    @property
    def ok(self) -> bool:
        return self.status in {LicenseStatus.valid, LicenseStatus.demo}


def _parse_kv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def load_license_file(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    raw = p.read_text(encoding="utf-8")
    try:
        payload = yaml.safe_load(raw)
        if isinstance(payload, dict) and payload:
            return payload
    except Exception:
        pass
    return _parse_kv(raw)


def _canonical_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _is_safe_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False

        # Resolve hostname to IPs
        # proto=socket.IPPROTO_TCP to avoid unrelated results
        # Use getaddrinfo to handle both IPv4 and IPv6
        addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)

        for _, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            ip = ipaddress.ip_address(ip_str)

            # Check for private, loopback, multicast, reserved, etc.
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_link_local
                or ip.is_unspecified
            ):
                return False

    except (ValueError, socket.gaierror, Exception):
        # If parsing fails or DNS resolution fails, treat as unsafe
        return False

    return True


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

    http_error_301 = http_error_302
    http_error_303 = http_error_302
    http_error_307 = http_error_302


def verify_license_payload(payload: dict[str, Any]) -> tuple[bool, list[str]]:
    errors: list[str] = []
    required = ["license_id", "ngo_id", "expires_at", "signature"]
    for key in required:
        if not payload.get(key):
            errors.append(f"missing:{key}")

    if errors:
        return False, errors

    signature = str(payload.get("signature"))
    without_sig = {k: v for k, v in payload.items() if k != "signature"}
    canonical = _canonical_payload(without_sig)
    expected = sha256(canonical.encode("utf-8")).hexdigest()
    if signature != expected:
        errors.append("signature_mismatch")

    expires = str(payload.get("expires_at"))
    try:
        if "T" in expires:
            exp_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            exp_date = exp_dt.date()
        else:
            exp_date = date.fromisoformat(expires)
    except Exception:
        errors.append("invalid_expires_at")
        return False, errors

    if date.today() > exp_date:
        errors.append("expired")

    return not errors, errors


def verify_license_file(
    path: str | Path = "/opt/argus/license.txt",
    *,
    check_online: bool = True,
    timeout_s: float = 5.0,
    offline_demo: bool = True,
) -> LicenseVerificationResult:
    license_path = Path(path)
    if not license_path.exists():
        status = LicenseStatus.demo if offline_demo else LicenseStatus.missing
        return LicenseVerificationResult(
            status=status,
            demo_mode=status == LicenseStatus.demo,
            ngo_id=None,
            license_id=None,
            verified_online=False,
            errors=["license_file_missing"],
        )

    payload = load_license_file(license_path)
    ok, errors = verify_license_payload(payload)

    ngo_id = str(payload.get("ngo_id")) if payload.get("ngo_id") else None
    license_id = str(payload.get("license_id")) if payload.get("license_id") else None

    if not ok:
        status = LicenseStatus.expired if "expired" in errors else LicenseStatus.invalid
        return LicenseVerificationResult(
            status=status,
            demo_mode=False,
            ngo_id=ngo_id,
            license_id=license_id,
            verified_online=False,
            errors=errors,
        )

    if not check_online:
        return LicenseVerificationResult(
            status=LicenseStatus.valid,
            demo_mode=False,
            ngo_id=ngo_id,
            license_id=license_id,
            verified_online=False,
            errors=[],
        )

    verification_url = str(payload.get("verification_url") or "").strip()
    if not verification_url:
        # No online endpoint configured; treat local verification as sufficient.
        return LicenseVerificationResult(
            status=LicenseStatus.valid,
            demo_mode=False,
            ngo_id=ngo_id,
            license_id=license_id,
            verified_online=False,
            errors=[],
        )

    if not verification_url.startswith("https://"):
        return LicenseVerificationResult(
            status=LicenseStatus.invalid,
            demo_mode=False,
            ngo_id=ngo_id,
            license_id=license_id,
            verified_online=False,
            errors=["verification_url_not_https"],
        )

    if not _is_safe_url(verification_url):
        return LicenseVerificationResult(
            status=LicenseStatus.invalid,
            demo_mode=False,
            ngo_id=ngo_id,
            license_id=license_id,
            verified_online=False,
            errors=["verification_url_unsafe"],
        )

    request = urllib.request.Request(
        verification_url,
        headers={"User-Agent": "argus-v-license-check/1.0"},
    )

    # Use a custom opener that disables redirects to prevent SSRF via open redirects
    opener = urllib.request.build_opener(NoRedirectHandler)

    try:
        with opener.open(request, timeout=timeout_s) as resp:
            body = resp.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        if offline_demo:
            return LicenseVerificationResult(
                status=LicenseStatus.demo,
                demo_mode=True,
                ngo_id=ngo_id,
                license_id=license_id,
                verified_online=False,
                errors=[f"offline:{type(exc).__name__}"],
            )
        return LicenseVerificationResult(
            status=LicenseStatus.invalid,
            demo_mode=False,
            ngo_id=ngo_id,
            license_id=license_id,
            verified_online=False,
            errors=[f"verification_failed:{type(exc).__name__}"],
        )

    try:
        verification = json.loads(body)
    except json.JSONDecodeError:
        if offline_demo:
            return LicenseVerificationResult(
                status=LicenseStatus.demo,
                demo_mode=True,
                ngo_id=ngo_id,
                license_id=license_id,
                verified_online=False,
                errors=["verification_non_json"],
            )
        return LicenseVerificationResult(
            status=LicenseStatus.invalid,
            demo_mode=False,
            ngo_id=ngo_id,
            license_id=license_id,
            verified_online=False,
            errors=["verification_non_json"],
        )

    if bool(verification.get("valid")) is True:
        return LicenseVerificationResult(
            status=LicenseStatus.valid,
            demo_mode=False,
            ngo_id=ngo_id,
            license_id=license_id,
            verified_online=True,
            errors=[],
        )

    if offline_demo:
        return LicenseVerificationResult(
            status=LicenseStatus.demo,
            demo_mode=True,
            ngo_id=ngo_id,
            license_id=license_id,
            verified_online=False,
            errors=["verification_invalid"],
        )

    return LicenseVerificationResult(
        status=LicenseStatus.invalid,
        demo_mode=False,
        ngo_id=ngo_id,
        license_id=license_id,
        verified_online=True,
        errors=["verification_invalid"],
    )


def license_path_default() -> str:
    return os.getenv("ARGUS_V_LICENSE_PATH", "/opt/argus/license.txt")
