from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote


class GitHubError(RuntimeError):
    pass


@dataclass(frozen=True)
class RepoRef:
    org: str
    repo: str


class GitHubClient:
    """Thin wrapper around the GitHub API.

    Prefer using `gh` if available; fall back to raw HTTPS calls is intentionally
    out-of-scope for this repository (Pi deployments typically won't have
    credentials anyway).
    """

    def __init__(self, repo: RepoRef, *, gh_bin: str | None = None) -> None:
        self.repo = repo
        self.gh_bin = gh_bin or os.getenv("ARGUS_V_GH_BIN", "gh")

    @staticmethod
    def _encode_branch(branch: str) -> str:
        # Branch names can contain '/', which must be URL-encoded for REST endpoints.
        return quote(branch, safe="")

    def _run(self, args: list[str]) -> str:
        proc = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            stderr = proc.stderr.strip() or proc.stdout.strip()
            raise GitHubError(stderr or f"gh failed: {args}")
        return proc.stdout

    def _api(
        self,
        endpoint: str,
        *,
        method: str = "GET",
        fields: dict[str, Any] | None = None,
    ) -> str:
        args = [self.gh_bin, "api", endpoint, "--method", method]
        if fields:
            for k, v in fields.items():
                if isinstance(v, (dict, list)):
                    args.extend(["--field", f"{k}={json.dumps(v)}"])
                else:
                    args.extend(["--field", f"{k}={v}"])
        return self._run(args)

    def branch_exists(self, branch: str) -> bool:
        encoded = self._encode_branch(branch)
        endpoint = f"repos/{self.repo.org}/{self.repo.repo}/branches/{encoded}"
        try:
            self._api(endpoint)
            return True
        except GitHubError as exc:
            msg = str(exc)
            if "404" in msg or "Not Found" in msg:
                return False
            raise

    def get_branch_sha(self, branch: str) -> str:
        encoded = self._encode_branch(branch)
        endpoint = f"repos/{self.repo.org}/{self.repo.repo}/git/refs/heads/{encoded}"
        payload = json.loads(self._api(endpoint))
        return payload["object"]["sha"]

    def create_branch(self, *, branch: str, from_branch: str = "main") -> None:
        sha = self.get_branch_sha(from_branch)
        endpoint = f"repos/{self.repo.org}/{self.repo.repo}/git/refs"
        self._api(
            endpoint,
            method="POST",
            fields={
                "ref": f"refs/heads/{branch}",
                "sha": sha,
            },
        )

    def protect_branch(self, *, branch: str, allowed_teams: list[str] | None = None) -> None:
        encoded = self._encode_branch(branch)
        endpoint = f"repos/{self.repo.org}/{self.repo.repo}/branches/{encoded}/protection"
        rules = {
            "required_status_checks": {
                "strict": True,
                "contexts": ["compliance-check", "security-scan", "unit-tests"],
            },
            "enforce_admins": True,
            "required_pull_request_reviews": {
                "required_approving_review_count": 2,
                "dismiss_stale_reviews": True,
            },
            "restrictions": {
                "users": [],
                "teams": allowed_teams or [],
            },
        }
        self._api(endpoint, method="PUT", fields={"json": rules})

    def lock_branch(self, *, branch: str) -> None:
        """Protect a branch but disallow pushes from non-admin actors."""

        self.protect_branch(branch=branch, allowed_teams=[])

    def remove_branch_protection(self, *, branch: str) -> None:
        encoded = self._encode_branch(branch)
        endpoint = f"repos/{self.repo.org}/{self.repo.repo}/branches/{encoded}/protection"
        try:
            self._api(endpoint, method="DELETE")
        except GitHubError as exc:
            msg = str(exc)
            if "404" in msg or "Branch not protected" in msg:
                return
            raise

    def grant_team_repo_access(self, *, team_slug: str, permission: str) -> None:
        endpoint = (
            f"orgs/{self.repo.org}/teams/{team_slug}/repos/{self.repo.org}/{self.repo.repo}"
        )
        self._api(endpoint, method="PUT", fields={"permission": permission})

    def revoke_team_repo_access(self, *, team_slug: str) -> None:
        endpoint = (
            f"orgs/{self.repo.org}/teams/{team_slug}/repos/{self.repo.org}/{self.repo.repo}"
        )
        try:
            self._api(endpoint, method="DELETE")
        except GitHubError as exc:
            msg = str(exc)
            if "404" in msg or "does not have access" in msg:
                return
            raise

    def archive_branch(self, *, branch: str, archive_prefix: str = "archived") -> str:
        archive_branch = f"{archive_prefix}/{branch}"
        sha = self.get_branch_sha(branch)
        endpoint = f"repos/{self.repo.org}/{self.repo.repo}/git/refs"
        self._api(
            endpoint,
            method="POST",
            fields={
                "ref": f"refs/heads/{archive_branch}",
                "sha": sha,
            },
        )
        return archive_branch
