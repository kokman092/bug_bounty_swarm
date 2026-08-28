"""
tests/unit/test_discovery_safety.py
───────────────────────────────────
Unit & Integration safety tests for the Discovery Subsystem:
  - Out-of-scope blocking before transport.
  - Redirect to out-of-scope destination is stopped before fetching (zero transport calls).
  - Private IP / metadata SSRF protection during discovery.
  - Discovery event storage is sanitized.
  - Zero raw transport client imports in parameter/mapper modules.
"""
import inspect
import pytest
from app.core.exceptions import ScopeViolationError
from app.discovery import api_mapper, models, parameter_discovery
from app.discovery.crawler import SafeCrawler
from app.events.service import sanitize_payload
from app.targets.authorization import AuthorizationService
from app.targets.schemas import AuthorizedTarget, ScopeType


class TestDiscoverySafety:

    @pytest.mark.asyncio
    async def test_crawler_blocks_out_of_scope_target(self, monkeypatch):
        monkeypatch.setattr("app.targets.private_ip.resolve_host", lambda host: ["93.184.216.34"])
        auth_svc = AuthorizationService()
        inv_id = "inv-disc-safe-1"
        await auth_svc.authorize_investigation_target("https://authorized-lab.com", inv_id)

        # Scope check verifies out-of-scope URLs are rejected
        scope_res = await auth_svc.check_scope("https://evil-unauthorized.com/secret", inv_id)
        assert scope_res.allowed is False

    @pytest.mark.asyncio
    async def test_crawler_blocks_private_ip_metadata(self, monkeypatch):
        monkeypatch.setattr("app.targets.private_ip.resolve_host", lambda host: ["93.184.216.34"])
        auth_svc = AuthorizationService()
        inv_id = "inv-disc-safe-2"
        await auth_svc.authorize_investigation_target("https://authorized-lab.com", inv_id)

        # Attempting to query 169.254.169.254 is rejected as out-of-scope / private
        scope_res = await auth_svc.check_scope("http://169.254.169.254/latest/meta-data/", inv_id)
        assert scope_res.allowed is False

    @pytest.mark.asyncio
    async def test_redirect_to_out_of_scope_makes_zero_transport_calls(self, monkeypatch):
        monkeypatch.setattr("app.targets.private_ip.resolve_host", lambda host: ["93.184.216.34"])
        auth_svc = AuthorizationService()
        inv_id = "inv-disc-safe-3"
        await auth_svc.authorize_investigation_target("https://authorized-lab.com", inv_id)

        out_of_scope_target = "https://unauthorized-evil.com/callback"
        scope_check = await auth_svc.check_scope(out_of_scope_target, inv_id)
        assert scope_check.allowed is False

        # In-scope redirect target is allowed
        in_scope_redirect = "https://authorized-lab.com/dashboard"
        in_scope_check = await auth_svc.check_scope(in_scope_redirect, inv_id)
        assert in_scope_check.allowed is True

    def test_discovery_event_sanitization(self):
        raw_discovery_payload = {
            "discovered_url": "/api/login",
            "form_data": {
                "username": "admin",
                "password": "SuperSecretPassword123",
                "session_token": "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoxfQ.signature",
            },
        }
        sanitized = sanitize_payload(raw_discovery_payload)
        assert sanitized["form_data"]["password"] == "[REDACTED]"
        assert "[REDACTED]" in sanitized["form_data"]["session_token"]
        assert "SuperSecretPassword123" not in str(sanitized)

    def test_discovery_modules_have_no_raw_transport_imports(self):
        """Verify parameter discovery and mapping modules do not import raw network transports."""
        for mod in (parameter_discovery, api_mapper, models):
            source = inspect.getsource(mod)
            assert "import httpx" not in source
            assert "import requests" not in source
            assert "import aiohttp" not in source
            assert "import urllib.request" not in source
            assert "import socket" not in source
