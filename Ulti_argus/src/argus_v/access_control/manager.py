from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml

from .audit import AuditTrail
from .github import GitHubClient, GitHubError, RepoRef


class AccessControlError(RuntimeError):
    pass


@dataclass(frozen=True)
class NgoAccessConfig:
    ngo_id: str
    github_org: str
    github_repo: str
    github_team: str
    access_level: str = "read"
    ngo_branch: str | None = None

    @property
    def repo_ref(self) -> RepoRef:
        return RepoRef(org=self.github_org, repo=self.github_repo)


def normalize_ngo_id(ngo_id: str) -> str:
    ngo_id = ngo_id.strip()
    if ngo_id.startswith("ngo-"):
        return ngo_id
    return f"ngo-{ngo_id}"


def default_ngo_branch(ngo_id: str) -> str:
    return f"{normalize_ngo_id(ngo_id)}/main"


def _default_config_dir() -> Path:
    configured = os.getenv("ARGUS_V_NGO_CONFIG_DIR")
    if configured:
        return Path(configured)

    # Source-tree fallback.
    root = Path(__file__).resolve().parents[4]
    candidate = root / "scripts" / "configs"
    return candidate


def load_ngo_access_config(ngo_id: str, *, config_dir: Path | None = None) -> NgoAccessConfig:
    config_dir = config_dir or _default_config_dir()
    normalized = normalize_ngo_id(ngo_id)

    candidates = [
        config_dir / f"{normalized}.yaml",
        config_dir / f"{normalized}.yml",
        config_dir / f"ngo-{ngo_id}.yaml",
    ]

    path = next((p for p in candidates if p.exists()), None)
    if not path:
        raise AccessControlError(
            f"NGO config not found for '{ngo_id}' under {config_dir}. Expected one of: "
            + ", ".join(str(p.name) for p in candidates)
        )

    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    required = ("github_org", "github_repo", "github_team")
    missing = [k for k in required if not payload.get(k)]
    if missing:
        raise AccessControlError(f"Missing required NGO config fields: {', '.join(missing)}")

    return NgoAccessConfig(
        ngo_id=normalized,
        github_org=str(payload["github_org"]),
        github_repo=str(payload["github_repo"]),
        github_team=str(payload["github_team"]),
        access_level=str(payload.get("access_level") or "read"),
        ngo_branch=str(payload.get("ngo_branch") or default_ngo_branch(normalized)),
    )


class AccessManager:
    def __init__(
        self,
        config: NgoAccessConfig,
        *,
        audit: AuditTrail | None = None,
        dry_run: bool = False,
    ) -> None:
        self.config = config
        self.audit = audit or AuditTrail()
        self.dry_run = dry_run
        self.github = GitHubClient(config.repo_ref)

    def ensure_ngo_branch(self, *, from_branch: str = "main") -> str:
        branch = self.config.ngo_branch or default_ngo_branch(self.config.ngo_id)

        if self.github.branch_exists(branch):
            self.audit.append(
                "access_control.branch.exists",
                ngo_id=self.config.ngo_id,
                branch=branch,
                repo=f"{self.config.github_org}/{self.config.github_repo}",
            )
            return branch

        if self.dry_run:
            self.audit.append(
                "access_control.branch.create.dry_run",
                ngo_id=self.config.ngo_id,
                branch=branch,
                from_branch=from_branch,
            )
            return branch

        self.github.create_branch(branch=branch, from_branch=from_branch)
        self.audit.append(
            "access_control.branch.created",
            ngo_id=self.config.ngo_id,
            branch=branch,
            from_branch=from_branch,
        )
        return branch

    def grant_access(self) -> None:
        branch = self.ensure_ngo_branch()

        permission = "pull"
        if self.config.access_level == "write":
            permission = "push"
        elif self.config.access_level == "admin":
            permission = "admin"

        if self.dry_run:
            self.audit.append(
                "access_control.grant.dry_run",
                ngo_id=self.config.ngo_id,
                team=self.config.github_team,
                permission=permission,
                branch=branch,
            )
            return

        try:
            self.github.protect_branch(
                branch=branch,
                allowed_teams=[self.config.github_team],
            )
            self.github.grant_team_repo_access(
                team_slug=self.config.github_team,
                permission=permission,
            )
        except GitHubError as exc:
            self.audit.append(
                "access_control.grant.failed",
                ngo_id=self.config.ngo_id,
                branch=branch,
                team=self.config.github_team,
                error=str(exc),
            )
            raise AccessControlError(str(exc)) from exc

        self.audit.append(
            "access_control.granted",
            ngo_id=self.config.ngo_id,
            branch=branch,
            team=self.config.github_team,
            permission=permission,
        )

    def revoke_access(
        self,
        *,
        reason: str = "contract_end",
        revoke_read_access: bool = True,
    ) -> None:
        """Revoke access.

        - Contract end: remove *branch* access (push/admin) but can keep read access to main.
        - Non-payment: revoke read access by removing the team from the repo.
        """

        branch = self.config.ngo_branch or default_ngo_branch(self.config.ngo_id)

        if self.dry_run:
            self.audit.append(
                "access_control.revoke.dry_run",
                ngo_id=self.config.ngo_id,
                branch=branch,
                team=self.config.github_team,
                reason=reason,
                revoke_read_access=revoke_read_access,
            )
            return

        archived: str | None = None

        try:
            if self.github.branch_exists(branch):
                try:
                    archived = self.github.archive_branch(branch=branch)
                except GitHubError:
                    archived = None

                # Lock down the branch regardless of whether we keep read access.
                self.github.lock_branch(branch=branch)

            if revoke_read_access:
                self.github.revoke_team_repo_access(team_slug=self.config.github_team)
            else:
                # Keep read-only access.
                self.github.grant_team_repo_access(
                    team_slug=self.config.github_team,
                    permission="pull",
                )
        except GitHubError as exc:
            self.audit.append(
                "access_control.revoke.failed",
                ngo_id=self.config.ngo_id,
                branch=branch,
                team=self.config.github_team,
                reason=reason,
                error=str(exc),
            )
            raise AccessControlError(str(exc)) from exc

        self.audit.append(
            "access_control.revoked",
            ngo_id=self.config.ngo_id,
            branch=branch,
            archived_branch=archived,
            team=self.config.github_team,
            reason=reason,
            revoke_read_access=revoke_read_access,
        )

    def record_local_status(self, *, status: str, reason: str | None = None) -> None:
        self.audit.append(
            "access_control.status",
            ngo_id=self.config.ngo_id,
            status=status,
            reason=reason,
        )
