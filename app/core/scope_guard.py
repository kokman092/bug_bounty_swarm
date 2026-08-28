"""
app/core/scope_guard.py
───────────────────────
Unified Scope Guard interface:
  - Verifies target is authorized for the given investigation.
  - Blocks private IP / SSRF addresses (169.254.169.254, RFC1918 in production, cloud metadata).
  - Enforces URL normalization and scheme validation.
"""
from __future__ import annotations

from app.core.exceptions import ScopeViolationError
from app.core.logging import get_logger
from app.targets.authorization import AuthorizationService
from app.targets.normalization import normalize_url
from app.targets.private_ip import validate_host_not_private

logger = get_logger(__name__)


class ScopeGuard:
    """Zero-trust scope validation gateway."""

    def __init__(self, investigation_id: str, auth_service: AuthorizationService | None = None) -> None:
        self.investigation_id = investigation_id
        self._auth_service = auth_service or AuthorizationService()

    async def validate_target_in_scope(self, target_url: str) -> None:
        """
        Validates that a URL is in authorized scope.
        Raises ScopeViolationError if out of scope or targeting private metadata.
        """
        res = await self._auth_service.check_scope(target_url, self.investigation_id)
        if not res.allowed:
            logger.warning(
                "scope_guard_rejected",
                url=target_url,
                reason=res.reason,
                investigation_id=self.investigation_id,
            )
            raise ScopeViolationError(f"Scope violation: {res.reason} for URL: {target_url}")



    def validate_url_syntax(self, target_url: str) -> str:
        """Normalizes and validates URL syntax."""
        norm = normalize_url(target_url)
        validate_host_not_private(norm.host)
        return norm.canonical
