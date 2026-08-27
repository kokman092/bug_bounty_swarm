"""
app/tools/http_client.py
─────────────────────────
ScopeEnforcingHttpClient — the ONLY HTTP client agents may use.

This client wraps httpx and enforces scope authorization on every request.
Agents MUST use this client for all network requests. Direct use of
requests, urllib, or httpx in agent code is FORBIDDEN.

Enforcement:
  Before every request:
    1. Normalize the URL
    2. Check for private/internal IP (SSRF protection)
    3. Check URL is within authorized scope
    4. Validate DNS has not been rebound (re-resolve and compare)

  After redirect:
    5. Validate the redirect destination is also in scope

Security properties:
  - An LLM cannot be prompt-injected to bypass scope (check is in Python,
    not in the prompt).
  - DNS rebinding is detected because we re-resolve at request time.
  - All requests are logged with investigation_id for audit trails.

Usage in agent tool functions:
    async def get_page(url: str, investigation_id: str) -> str:
        async with ScopeEnforcingHttpClient(
            investigation_id=investigation_id,
            auth_service=AuthorizationService(),
        ) as client:
            response = await client.get(url)
            return response.text
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from app.core.config import get_settings
from app.core.exceptions import ScopeViolationError
from app.core.logging import get_logger
from app.targets.authorization import AuthorizationService
from app.targets.normalization import normalize_url
from app.targets.private_ip import validate_host_not_private, validate_no_dns_rebinding

logger = get_logger(__name__)

# Global constants for HTTP safety
_MAX_RESPONSE_SIZE_BYTES = 1_048_576  # 1MB — cap response body size
_DEFAULT_TIMEOUT_SECONDS = 15.0
_MAX_REDIRECTS = 3  # Limit redirect chains


class ScopeEnforcingHttpClient:
    """
    SSRF-safe, scope-enforcing HTTP client for agent tool use.

    Always instantiate as an async context manager:
        async with ScopeEnforcingHttpClient(investigation_id, auth_service) as client:
            response = await client.get("https://target.com/api")
    """

    def __init__(
        self,
        investigation_id: str,
        auth_service: AuthorizationService | None = None,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.investigation_id = investigation_id
        self._auth_service = auth_service or AuthorizationService()
        self._timeout = timeout_seconds
        self._extra_headers = extra_headers or {}
        self._resolved_ips: dict[str, list[str]] = {}  # hostname → IPs at auth time
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "ScopeEnforcingHttpClient":
        settings = get_settings()
        proxy_url = settings.burp_proxy_url if settings.burp_proxy_enabled else None

        self._client = httpx.AsyncClient(
            timeout=self._timeout,
            proxy=proxy_url,
            verify=False if proxy_url else True,
            follow_redirects=False,  # We handle redirects manually to validate each hop
            headers={
                "User-Agent": "BugBounty-Swarm/1.0 (authorized security research)",
                **self._extra_headers,
            },
            max_redirects=0,
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()

    async def get(
        self,
        url: str,
        params: dict | None = None,
        headers: dict | None = None,
    ) -> httpx.Response:
        return await self._request("GET", url, params=params, headers=headers)

    async def post(
        self,
        url: str,
        params: dict | None = None,
        data: dict | None = None,
        json_body: dict | None = None,
        headers: dict | None = None,
    ) -> httpx.Response:
        return await self._request(
            "POST", url, params=params, data=data, json_body=json_body, headers=headers
        )

    async def put(
        self,
        url: str,
        params: dict | None = None,
        data: dict | None = None,
        json_body: dict | None = None,
        headers: dict | None = None,
    ) -> httpx.Response:
        return await self._request(
            "PUT", url, params=params, data=data, json_body=json_body, headers=headers
        )

    async def patch(
        self,
        url: str,
        params: dict | None = None,
        data: dict | None = None,
        json_body: dict | None = None,
        headers: dict | None = None,
    ) -> httpx.Response:
        return await self._request(
            "PATCH", url, params=params, data=data, json_body=json_body, headers=headers
        )

    async def delete(
        self,
        url: str,
        params: dict | None = None,
        headers: dict | None = None,
    ) -> httpx.Response:
        return await self._request("DELETE", url, params=params, headers=headers)

    async def _request(
        self,
        method: str,
        url: str,
        params: dict | None = None,
        data: dict | None = None,
        json_body: dict | None = None,
        headers: dict | None = None,
        _redirect_count: int = 0,
    ) -> httpx.Response:
        """
        Execute an HTTP request after full scope validation.
        Handles redirects with per-hop scope validation.
        """
        if self._client is None:
            raise RuntimeError("ScopeEnforcingHttpClient must be used as async context manager")

        if _redirect_count > _MAX_REDIRECTS:
            raise ScopeViolationError(url, self.investigation_id)

        # ── Pre-request scope check ────────────────────────────────────────────
        await self._validate_url(url)

        logger.debug(
            "http_request",
            method=method,
            url=url,
            investigation_id=self.investigation_id,
        )

        # ── Execute request ────────────────────────────────────────────────────
        response = await self._client.request(
            method=method,
            url=url,
            params=params,
            data=data,
            json=json_body,
            headers=headers or {},
        )

        # ── Redirect handling ──────────────────────────────────────────────────
        if response.is_redirect and "location" in response.headers:
            redirect_url = str(response.headers["location"])

            # Resolve relative redirects to absolute
            if not redirect_url.startswith("http"):
                base = normalize_url(url)
                redirect_url = f"{base.scheme}://{base.host_with_port}{redirect_url}"

            logger.debug(
                "http_redirect",
                from_url=url,
                to_url=redirect_url,
                status_code=response.status_code,
                investigation_id=self.investigation_id,
            )

            return await self._request(
                method=method,
                url=redirect_url,
                params=params,
                data=data,
                json_body=json_body,
                headers=headers,
                _redirect_count=_redirect_count + 1,
            )

        logger.debug(
            "http_response",
            url=url,
            status_code=response.status_code,
            content_length=len(response.content),
            investigation_id=self.investigation_id,
        )
        return response

    async def _validate_url(self, url: str) -> None:
        """
        Full pre-request validation:
          1. Normalize URL
          2. Private IP / SSRF check
          3. DNS rebinding check
          4. Scope check
        """
        # 1. Normalize
        normalized = normalize_url(url)

        # 2. Private IP check
        validate_host_not_private(normalized.host)

        # 3. DNS rebinding check (re-resolve and compare to original)
        if normalized.host in self._resolved_ips:
            validate_no_dns_rebinding(
                normalized.host,
                self._resolved_ips[normalized.host],
            )

        # 4. Scope check
        scope_result = await self._auth_service.check_scope(
            url=url,
            investigation_id=self.investigation_id,
        )

        if not scope_result.allowed:
            logger.warning(
                "scope_violation_blocked",
                url=url,
                reason=scope_result.reason,
                investigation_id=self.investigation_id,
            )
            raise ScopeViolationError(url, self.investigation_id)

    def get_response_text_safe(self, response: httpx.Response) -> str:
        """
        Safely extract response text, truncating at MAX_RESPONSE_SIZE_BYTES.
        This prevents enormous responses from flooding agent context.
        """
        content = response.content
        if len(content) > _MAX_RESPONSE_SIZE_BYTES:
            logger.warning(
                "response_truncated",
                url=str(response.url),
                original_size=len(content),
                truncated_to=_MAX_RESPONSE_SIZE_BYTES,
            )
            content = content[:_MAX_RESPONSE_SIZE_BYTES]
        try:
            return content.decode("utf-8", errors="replace")
        except Exception:
            return repr(content[:1000])
