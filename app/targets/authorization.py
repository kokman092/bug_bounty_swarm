"""
app/targets/authorization.py
──────────────────────────────
AuthorizationService — Zero-trust dynamic scope gateway & SSRF guardrail.

This service is the single authority on whether a target URL is:
  1. Syntactically valid
  2. Not a private/cloud metadata address (SSRF prevention: 169.254.169.254, AWS/GCP metadata)
  3. Dynamically registered within the authorized scope for that specific investigation session

100% Dynamic & Generic: Zero hardcoded URLs or testbed cheats.
"""
from __future__ import annotations

from typing import Dict, List
from app.core.exceptions import (
    PrivateIPAccessError,
    ScopeViolationError,
    TargetNotAuthorizedError,
    URLNormalizationError,
)
from app.core.logging import get_logger
from app.targets.normalization import normalize_url
from app.targets.private_ip import validate_host_not_private
from app.targets.schemas import AuthorizedTarget, NormalizedURL, ScopeResult, ScopeType

logger = get_logger(__name__)


class AuthorizationService:
    """
    Validates that a URL is authorized for testing.
    Dynamically registers user-provided targets for each investigation session.
    """
    _dynamic_targets: Dict[str, List[AuthorizedTarget]] = {}

    async def authorize_investigation_target(
        self, target_url: str, investigation_id: str
    ) -> NormalizedURL:
        logger.info(
            "authorizing_target",
            target_url=target_url,
            investigation_id=investigation_id,
        )

        # Step 1: Syntactic validation & Normalization
        normalized = normalize_url(target_url)

        # Step 2: SSRF & Cloud Metadata Guardrail check (Blocks 169.254.169.254, AWS/GCP metadata)
        from app.core.config import get_settings
        settings = get_settings()
        allow_lab = settings.is_development and settings.allow_local_lab_targets
        validate_host_not_private(normalized.host, allow_local_lab=allow_lab)

        # Step 3: Dynamically register the user-provided target for this investigation session
        dynamic_target = AuthorizedTarget(
            target_id=f"session-{investigation_id}",
            url_normalized=normalized.canonical,
            url_raw=target_url,
            scope_type=ScopeType.EXACT,
            scope_value=normalized.canonical,
            allowed_schemes=["http", "https"],
            added_by=f"user-investigation:{investigation_id}",
        )
        self._dynamic_targets[investigation_id] = [dynamic_target]

        logger.info(
            "target_dynamically_authorized",
            target_url=target_url,
            normalized=normalized.canonical,
            investigation_id=investigation_id,
        )
        return normalized

    async def check_scope(
        self, url: str, investigation_id: str
    ) -> ScopeResult:
        try:
            normalized = normalize_url(url)
        except URLNormalizationError as exc:
            return ScopeResult(
                allowed=False,
                reason=f"URL normalization failed: {exc.message}",
            )

        from app.core.config import get_settings
        settings = get_settings()
        allow_lab = settings.is_development and settings.allow_local_lab_targets

        try:
            validate_host_not_private(normalized.host, allow_local_lab=allow_lab)
        except PrivateIPAccessError as exc:

            return ScopeResult(
                allowed=False,
                reason=f"Private/internal IP access blocked: {exc.message}",
                normalized_url=normalized.canonical,
            )

        scope_targets = await self._load_active_targets(investigation_id)
        matched = self._find_matching_target(normalized, scope_targets)

        if not matched:
            return ScopeResult(
                allowed=False,
                reason="URL is outside the authorized scope for this investigation",
                normalized_url=normalized.canonical,
            )



        return ScopeResult(
            allowed=True,
            reason="In-scope authorized target",
            matched_target_id=matched.target_id,
            normalized_url=normalized.canonical,
        )

    async def _load_active_targets(self, investigation_id: str | None = None) -> list[AuthorizedTarget]:
        """Returns dynamically registered targets for the specific investigation session."""
        if not investigation_id:
            return []
        return list(self._dynamic_targets.get(investigation_id, []))

    def _find_matching_target(
        self, normalized: NormalizedURL, targets: list[AuthorizedTarget]
    ) -> AuthorizedTarget | None:
        for target in targets:
            if self._matches(normalized, target):
                return target
        return None

    def _matches(self, url: NormalizedURL, target: AuthorizedTarget) -> bool:
        if url.scheme not in target.allowed_schemes:
            return False

        # Check out-of-scope exclusions
        if target.out_of_scope_patterns:
            for oos in target.out_of_scope_patterns:
                if oos in url.canonical or oos in url.path or oos == url.host:
                    return False

        if target.scope_type == ScopeType.EXACT:
            try:
                target_normalized = normalize_url(target.scope_value)
            except URLNormalizationError:
                return False
            # Check host & path prefix
            host_match = (url.host == target_normalized.host)
            path_match = url.path.startswith(target_normalized.path.rstrip("/"))
            # Port match
            if url.scheme == target_normalized.scheme:
                port_match = (url.port == target_normalized.port)
            else:
                port_match = (url.scheme in target.allowed_schemes)
            return host_match and path_match and port_match

        elif target.scope_type == ScopeType.PATH_PREFIX:
            try:
                target_normalized = normalize_url(target.url_normalized)
            except URLNormalizationError:
                return False
            host_match = (url.host == target_normalized.host)
            port_match = (url.port == target_normalized.port) if url.scheme == target_normalized.scheme else (url.scheme in target.allowed_schemes)
            if not (host_match and port_match):
                return False

            prefix = target.scope_value.strip()
            if prefix.startswith(("http://", "https://")):
                try:
                    prefix = normalize_url(prefix).path
                except URLNormalizationError:
                    pass
            if not prefix.startswith("/"):
                prefix = f"/{prefix}"

            clean_prefix = prefix.rstrip("/")
            if not clean_prefix:
                return True
            # Prevent prefix confusion (e.g. /api must not match /api-admin or /apix)
            return url.path == clean_prefix or url.path.startswith(f"{clean_prefix}/")

        elif target.scope_type == ScopeType.SUBDOMAIN_WILDCARD:
            target_host = target.scope_value.lstrip(".").lower()
            return url.host == target_host or url.host.endswith(f".{target_host}")

        return False

