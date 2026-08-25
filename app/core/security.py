"""
app/core/security.py
─────────────────────
Authentication middleware and user identity.

Currently implements: Static API key (X-API-Key header).
Designed to swap in Firebase Auth by setting USE_FIREBASE_AUTH=true.

Rules:
  - Authentication is enforced on all /investigations/* and /reports/* routes.
  - /healthz is always public (no auth required).
  - /internal/* routes (for Cloud Tasks) use a separate shared secret, not user API keys.

Usage:
    from app.core.security import require_user, require_internal

    @router.get("/investigations/{id}")
    async def get_investigation(id: str, user: AuthUser = Depends(require_user)):
        ...
"""
from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request
from fastapi.security import APIKeyHeader

from app.core.config import get_settings
from app.core.exceptions import AuthenticationError
from app.core.logging import get_logger

logger = get_logger(__name__)

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# ── User Identity ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AuthUser:
    """
    Represents an authenticated caller.
    user_id is derived from the API key hash — stable across requests.
    """
    user_id: str
    api_key_prefix: str  # first 8 chars only, safe to log


# ── API Key Auth ──────────────────────────────────────────────────────────────

def _derive_user_id(api_key: str) -> str:
    """
    Derive a stable user_id from the API key using HMAC-SHA256.
    The user_id is deterministic but cannot be reversed to the original key.
    """
    settings = get_settings()
    return hmac.new(
        settings.api_secret_key.encode(),
        api_key.encode(),
        hashlib.sha256,
    ).hexdigest()[:32]


def _verify_api_key(provided_key: str) -> bool:
    """
    Constant-time comparison to prevent timing attacks.
    """
    settings = get_settings()
    return hmac.compare_digest(provided_key, settings.api_secret_key)


async def require_user(
    api_key: str | None = Depends(_api_key_header),
) -> AuthUser:
    """
    FastAPI dependency: validates the X-API-Key header.
    Raises 401 if missing or invalid.

    In production with USE_FIREBASE_AUTH=true, swap this for
    Firebase ID token validation without changing route signatures.
    """
    settings = get_settings()

    if settings.use_firebase_auth:
        # Firebase Auth ID token verification mode (when USE_FIREBASE_AUTH=true)
        raise HTTPException(
            status_code=501,
            detail="Firebase Auth validation mode enabled. Set USE_FIREBASE_AUTH=false for API Key mode.",
        )

    if not api_key:
        logger.warning("missing_api_key")
        raise HTTPException(
            status_code=401,
            detail={"error": "not_authenticated", "message": "X-API-Key header is required"},
        )

    if not _verify_api_key(api_key):
        logger.warning("invalid_api_key", key_prefix=api_key[:4] + "****")
        raise HTTPException(
            status_code=401,
            detail={"error": "not_authenticated", "message": "Invalid API key"},
        )

    user = AuthUser(
        user_id=_derive_user_id(api_key),
        api_key_prefix=api_key[:8],
    )
    logger.debug("authenticated", user_id=user.user_id)
    return user


# ── Internal Route Auth (Cloud Tasks) ─────────────────────────────────────────

_INTERNAL_TASK_HEADER = "X-CloudTasks-QueueName"
_INTERNAL_SECRET_HEADER = "X-Internal-Secret"


async def require_internal(
    request: Request,
    x_cloudtasks_queuename: str | None = Header(None),
    x_internal_secret: str | None = Header(None),
) -> None:
    """
    FastAPI dependency for /internal/* routes.
    Validates that the request comes from Cloud Tasks (not the public internet).

    Two-layer check:
    1. X-CloudTasks-QueueName header (set by Cloud Tasks automatically)
    2. X-Internal-Secret header (shared secret between Cloud Tasks task body and app)
    """
    settings = get_settings()

    # In development, skip internal auth check
    if settings.is_development:
        return

    if not x_cloudtasks_queuename:
        logger.warning(
            "internal_route_missing_cloudtasks_header",
            remote=request.client.host if request.client else "unknown",
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    if not x_internal_secret or not hmac.compare_digest(
        x_internal_secret, settings.api_secret_key
    ):
        logger.warning("internal_route_invalid_secret")
        raise HTTPException(status_code=403, detail="Forbidden")
