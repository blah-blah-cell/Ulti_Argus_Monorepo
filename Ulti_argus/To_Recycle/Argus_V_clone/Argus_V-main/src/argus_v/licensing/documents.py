from __future__ import annotations

import json
from datetime import datetime, timezone
from hashlib import sha256

from .models import AgreementType, ContractTerms
from .pdf import PdfDocument, text_to_pdf


def render_nda(terms: ContractTerms) -> str:
    """Generate a customized NDA with non-redistribution clause."""

    prohibition = "YES" if terms.redistribution_prohibited else "NO"

    return (
        "ARGUS_V NON-DISCLOSURE AGREEMENT (NDA)\n"
        "====================================\n\n"
        f"NGO ID: {terms.ngo_id}\n"
        f"Organization: {terms.organization_name}\n"
        f"Address: {terms.organization_address}\n"
        f"Jurisdiction: {terms.jurisdiction}\n"
        f"Service Tier: {terms.tier.value}\n"
        f"Effective Date: {terms.effective_date.isoformat()}\n"
        f"Expiration Date: {terms.expiration_date.isoformat()}\n\n"
        "1. Confidential Information\n"
        "   Confidential Information includes the Argus_V software, deployment methods,\n"
        "   installer scripts, configuration templates, documentation, and any\n"
        "   non-public security telemetry, models, or support materials.\n\n"
        "2. Purpose\n"
        "   Confidential Information is provided solely to enable a licensed deployment\n"
        "   of Argus_V for defensive security monitoring and incident response.\n\n"
        "3. Non-Redistribution (Material Term)\n"
        f"   Redistribution Prohibited: {prohibition}\n"
        "   Licensee must not redistribute installer bundles, configuration templates,\n"
        "   or derived deployment packages to any third party without written consent.\n\n"
        "4. Term\n"
        "   This NDA remains in effect for the contract term and for 5 years after\n"
        "   termination, except for trade secrets which remain protected indefinitely.\n\n"
        "5. Signatures\n"
        "   Licensor: Argus_V Security Solutions\n"
        "   Licensee: ____________________________\n"
    )


def render_dpa(terms: ContractTerms) -> str:
    """Generate a simplified Data Processing Agreement (DPA) for the NGO."""

    return (
        "ARGUS_V DATA PROCESSING AGREEMENT (DPA)\n"
        "======================================\n\n"
        f"NGO ID: {terms.ngo_id}\n"
        f"Organization: {terms.organization_name}\n"
        f"Jurisdiction: {terms.jurisdiction}\n"
        f"Effective Date: {terms.effective_date.isoformat()}\n"
        f"Expiration Date: {terms.expiration_date.isoformat()}\n\n"
        "1. Scope\n"
        "   Argus_V processes network flow metadata for security monitoring purposes.\n\n"
        "2. Data Minimization & Retention\n"
        "   Deployments must minimize captured data and enforce strict retention limits\n"
        "   (default: 24 hours for raw flows) per Argus_V compliance guidance.\n\n"
        "3. Security Measures\n"
        "   Deployments must enable anonymization, encryption-at-rest where applicable,\n"
        "   and access controls for operators.\n\n"
        "4. Sub-processors\n"
        "   Optional integrations (e.g., Firebase) are considered sub-processors and\n"
        "   must be disclosed in deployment documentation.\n\n"
        "5. Signatures\n"
        "   Licensor: Argus_V Security Solutions\n"
        "   Licensee: ____________________________\n"
    )


def export_pdf(text: str) -> PdfDocument:
    return text_to_pdf(text)



def generate_license_file(
    *,
    terms: ContractTerms,
    license_id: str,
    verification_url: str | None = None,
    offline_grace_days: int = 7,
) -> str:
    issued_at = datetime.now(timezone.utc).isoformat()

    payload = {
        "license_id": license_id,
        "ngo_id": terms.ngo_id,
        "tier": terms.tier.value,
        "issued_at": issued_at,
        "expires_at": terms.expiration_date.isoformat(),
        "offline_grace_days": int(offline_grace_days),
        "redistribution_prohibited": bool(terms.redistribution_prohibited),
        "verification_url": verification_url or "",
    }

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    signature = sha256(canonical.encode("utf-8")).hexdigest()
    payload["signature"] = signature

    lines = ["# Argus_V Deployment License", "# Format: key=value"]
    for k, v in payload.items():
        lines.append(f"{k}={v}")
    return "\n".join(lines) + "\n"


def default_agreement_filename(terms: ContractTerms, agreement: AgreementType) -> str:
    safe = terms.ngo_id.replace("/", "_")
    return f"{safe}-{agreement.value}.pdf"
