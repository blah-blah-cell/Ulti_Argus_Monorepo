# ARGUS_V Deployment Access Control & Licensing

This document describes the **branch-based access control** and **licensing tooling** used for NGO deployments.

## 1) Branch-based access control

### Model

- Each NGO is assigned a dedicated GitHub branch (default naming: `ngo-<ngo-id>/main`).
- The branch is auto-created on first grant if it does not exist.
- The NGO deployment branch includes the repository contents from `main`, which contains:
  - `install.sh` (installer)
  - example YAMLs (`aegis-config.example.yaml`, `example-retina-config.yaml`, `mnemosyne-config.example.yaml`)
  - documentation and configuration templates

### Grant access

Grant access using the Python CLI (requires `gh` CLI authenticated on the operator machine):

```bash
argus-grant-access <ngo-id> --config-dir ./scripts/configs
```

This will:

- create the NGO branch if missing
- apply branch protection on the NGO branch
- grant repository access to the configured GitHub team

### Read-only access to `main`

NGOs should have **read-only** access at the repository level.

- `argus-grant-access` defaults to read access unless the NGO config requests `access_level: write` or `admin`.
- `main` should remain protected (required reviews, disallow force-push, etc.) through GitHub branch protection.

## 2) Access revocation

### CLI

```bash
argus-revoke-access <ngo-id> --config-dir ./scripts/configs --reason contract_end
argus-revoke-access <ngo-id> --config-dir ./scripts/configs --reason non_payment
```

### Behavior

- `contract_end`: removes *branch access* by locking the NGO branch and downgrading permissions to read-only.
- `non_payment` / `security_incident`: revokes **read access** by removing the team from the repository.

### Audit trail

All access operations append to a tamper-evident JSONL audit chain:

- default: `/var/log/argus_v/audit/access-events.jsonl`
- fallback (no root permissions): `~/.local/state/argus_v/audit/access-events.jsonl`

Verify the hash chain:

```bash
argus-access audit-verify
```

## 3) License agreement tooling

ARGUS_V includes lightweight tooling to:

- generate NGO-specific NDA/DPA agreements
- track signature metadata
- export agreements as PDF

### Contract record

Create/update a contract record (persisted under `/var/lib/argus_v/contracts` by default):

```bash
argus-license init-contract <ngo-id> \
  --org-name "Example NGO" \
  --org-address "123 Street" \
  --jurisdiction "IN" \
  --tier free_tier \
  --effective-date 2025-01-01 \
  --expiration-date 2026-01-01
```

### Export NDA/DPA

```bash
argus-license export <ngo-id> nda --out ./out/nda.pdf
argus-license export <ngo-id> dpa --out ./out/dpa.pdf
```

### Track signatures

```bash
argus-license sign <ngo-id> nda --signatory-name "Jane Doe" --signed-at 2025-01-10T00:00:00Z
```

## 4) Installer integration

The installer checks for a deployment license at:

- `/opt/argus/license.txt`

During installation:

- the license is verified locally (signature + expiry)
- if an HTTPS verification endpoint is configured and reachable, the installer verifies online
- if the verification endpoint is **offline/unreachable**, installation continues in **DEMO mode**

The installer writes a JSON status snapshot to:

- `/etc/argus_v/license_status.json`
