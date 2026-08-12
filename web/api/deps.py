"""Shared FastAPI dependencies for the Argus Community API.

Pulled out of ``server.py`` so router modules can import these without
importing the heavy ``server`` module (which would create circular
import problems once routes are split into ``web/api/routers/``).

This module contains:

* The shared ``slowapi`` ``Limiter`` instance (decorator: ``@limiter.limit(...)``).
* The API-key header dependency: ``Depends(get_api_key)``.
* ``sanitize_error()`` for safely returning exception messages.
* Path / input / IP / list validators.
* Shared constants (CORS origins, request size limits, etc.).

Nothing here imports ``fastapi.FastAPI`` or the ``app`` instance, so it is
safe to import from anywhere.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import List, Optional

from fastapi import HTTPException, Request, Security
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from slowapi import Limiter
from slowapi.util import get_remote_address

# Repository root: <repo>/web/api/deps.py -> parents[2] = <repo>.
ROOT_DIR = Path(__file__).parent.parent.parent


# ── Rate limiting ────────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)


# ── API key authentication ─────────────────────────────────────────────

API_KEY_NAME = "X-API-Key"

# Generate a secure default when ``ARGUS_API_KEY`` is unset. ``server.py`` is
# responsible for emitting the runtime warning when this auto-generated key
# is in use — see ``API_KEY_IS_AUTO_GENERATED`` below.
_default_key = secrets.token_hex(32)
API_KEY = os.environ.get("ARGUS_API_KEY", _default_key)
API_KEY_IS_AUTO_GENERATED = API_KEY == _default_key

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)


async def get_api_key(
    request: Request,
    api_key_header: str = Security(api_key_header),
    token: str = Security(oauth2_scheme)
) -> str:
    """FastAPI dependency: validate the X-API-Key header, OAuth2 token, or argus_session cookie.

    Raises 403 if missing or invalid.
    """
    cookie_token = request.cookies.get("argus_session")
    local_token = os.environ.get("ARGUS_LOCAL_TOKEN")
    
    if api_key_header and api_key_header == API_KEY:
        return api_key_header
        
    if local_token and (token == local_token or cookie_token == local_token or api_key_header == local_token):
        return local_token
        
    if cookie_token == API_KEY or token == API_KEY:
        return API_KEY
        
    raise HTTPException(status_code=403, detail="Not authenticated")


# ── CORS / internal auth ───────────────────────────────────────────────

ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000,http://localhost:8000,http://127.0.0.1:8000",
).split(",")

# Used by internal subsystems to authenticate to each other (separate from the
# user-facing API key).
INTERNAL_API_KEY = os.environ.get("ARGUS_INTERNAL_KEY", secrets.token_hex(32))


# ── Error sanitization ──────────────────────────────────────────────────

def sanitize_error(e: Exception) -> str:
    """Return a safe, user-facing string for an exception.

    Hides filesystem paths, stack frames, etc. The full error is logged to
    stdout for operators.
    """
    error_type = type(e).__name__
    if isinstance(e, (FileNotFoundError, PermissionError)):
        return "Resource not found or access denied"
    if isinstance(e, (ValueError, KeyError, TypeError)):
        return f"Invalid input: {error_type}"
    msg = str(e).lower()
    if "not available" in msg or "unavailable" in msg:
        return str(e)
    # Log full error internally, return generic message.
    print(f"[SECURITY] Error: {type(e).__name__}: {str(e)}")
    return "An internal error occurred"


# ── Path validation ────────────────────────────────────────────────────────

def validate_path(path: Path, allowed_dirs: Optional[List[Path]] = None) -> Path:
    """Resolve ``path`` and ensure it lives under an allowed directory.

    Raises 403 otherwise. Used to prevent path traversal in endpoints that
    accept user-supplied filesystem paths.
    """
    if allowed_dirs is None:
        allowed_dirs = [
            ROOT_DIR,
            ROOT_DIR / "models",
            ROOT_DIR / "data",
            ROOT_DIR / "datasets",
            Path("/tmp"),
        ]

    path = path.resolve()
    for allowed in allowed_dirs:
        allowed = allowed.resolve()
        try:
            path.relative_to(allowed)
            return path
        except ValueError:
            continue

    raise HTTPException(status_code=403, detail="Path not allowed")


# ── Input validation ──────────────────────────────────────────────────────

MAX_STRING_LEN = 4096
MAX_DOMAIN_LEN = 253
MAX_IP_LEN = 45
MAX_LIST_LEN = 1000

# Maximum request body size (10 MB). Enforced by the security-headers
# middleware in server.py.
MAX_REQUEST_BODY_BYTES = 10 * 1024 * 1024


def validate_input(
    value: str,
    max_len: int = MAX_STRING_LEN,
    field_name: str = "input",
) -> str:
    """Validate a string field for length and forbidden control characters."""
    if not isinstance(value, str):
        raise HTTPException(
            status_code=422, detail=f"{field_name} must be a string"
        )
    if len(value) > max_len:
        raise HTTPException(
            status_code=422,
            detail=f"{field_name} exceeds maximum length of {max_len}",
        )
    if any(c in value for c in "\x00\r\n"):
        raise HTTPException(
            status_code=422, detail=f"{field_name} contains invalid characters"
        )
    return value


def validate_ip(ip: str) -> str:
    """Validate IP address format (length + control-char check)."""
    if not ip or len(ip) > MAX_IP_LEN:
        raise HTTPException(status_code=422, detail="Invalid IP address format")
    return validate_input(ip, MAX_IP_LEN, "ip_address")


def validate_list(
    items: list,
    max_len: int = MAX_LIST_LEN,
    field_name: str = "list",
) -> list:
    """Validate that ``items`` is a list and not larger than ``max_len``."""
    if not isinstance(items, list):
        raise HTTPException(
            status_code=422, detail=f"{field_name} must be a list"
        )
    if len(items) > max_len:
        raise HTTPException(
            status_code=422,
            detail=f"{field_name} exceeds maximum length of {max_len}",
        )
    return items


__all__ = [
    "ROOT_DIR",
    "limiter",
    "API_KEY",
    "API_KEY_NAME",
    "API_KEY_IS_AUTO_GENERATED",
    "api_key_header",
    "get_api_key",
    "ALLOWED_ORIGINS",
    "INTERNAL_API_KEY",
    "sanitize_error",
    "validate_path",
    "validate_input",
    "validate_ip",
    "validate_list",
    "MAX_STRING_LEN",
    "MAX_DOMAIN_LEN",
    "MAX_IP_LEN",
    "MAX_LIST_LEN",
    "MAX_REQUEST_BODY_BYTES",
]
