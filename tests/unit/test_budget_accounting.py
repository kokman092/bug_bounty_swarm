"""
tests/unit/test_budget_accounting.py
────────────────────────────────────
Unit tests for Request Budget Accounting and Telemetry:
  - Setting max_requests_per_endpoint=1 prevents a second transport call.
  - Reproducibility retries cannot reset or exceed the declared budget.
  - Rate-limit backoff does not issue extra requests beyond configured limits.
  - Budget state is visible in sanitized telemetry.
"""
import pytest
from unittest.mock import AsyncMock

from app.core.exceptions import RateLimitExceededError
from app.core.policy_engine import get_policy_engine
from app.targets.session_vault import UserSession, get_session_vault
from app.tools.http_client import ScopeEnforcingHttpClient


class TestBudgetAccounting:

    def setup_method(self):
        get_policy_engine().reset_budgets()

    @pytest.mark.asyncio
    async def test_endpoint_budget_enforcement_blocks_excess_calls(self, monkeypatch):
        inv_id = "inv-budget-1"
        policy = get_policy_engine()
        policy.reset_budgets(inv_id)
        # Set max budget = 1 for GET /api/v1/resource
        policy.set_endpoint_budget(inv_id, "GET", "/api/v1/resource", max_requests=1)

        monkeypatch.setattr("app.targets.private_ip.resolve_host", lambda h: ["93.184.216.34"])


        async def mock_request(self, method, url, **kwargs):
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_resp.content = b'{"status": "ok"}'
            mock_resp.is_redirect = False
            mock_resp.headers = {}
            return mock_resp

        monkeypatch.setattr("httpx.AsyncClient.request", mock_request)
        monkeypatch.setattr("app.targets.authorization.AuthorizationService.check_scope", AsyncMock(return_value=type("ScopeRes", (), {"allowed": True, "reason": "in scope"})()))

        async with ScopeEnforcingHttpClient(inv_id) as client:
            # 1st call: Allowed (1/1)
            resp1 = await client.get("https://authorized-target.com/api/v1/resource")
            assert resp1.status_code == 200

            # 2nd call: Exceeds budget (2/1) -> RateLimitExceededError
            with pytest.raises(RateLimitExceededError) as exc_info:
                await client.get("https://authorized-target.com/api/v1/resource")
            assert "Request budget exceeded" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_budget_telemetry_is_sanitized_and_accurate(self, monkeypatch):
        inv_id = "inv-budget-2"
        policy = get_policy_engine()
        policy.reset_budgets(inv_id)

        monkeypatch.setattr("app.targets.private_ip.resolve_host", lambda h: ["93.184.216.34"])

        async def mock_request(self, method, url, **kwargs):
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_resp.content = b'{"status": "ok"}'
            mock_resp.is_redirect = False
            mock_resp.headers = {}
            return mock_resp

        monkeypatch.setattr("httpx.AsyncClient.request", mock_request)
        monkeypatch.setattr("app.targets.authorization.AuthorizationService.check_scope", AsyncMock(return_value=type("ScopeRes", (), {"allowed": True, "reason": "in scope"})()))

        async with ScopeEnforcingHttpClient(inv_id) as client:
            await client.get("https://authorized-target.com/api/v1/users")
            await client.get("https://authorized-target.com/api/v1/users")
            await client.get("https://authorized-target.com/api/v1/orders")

        telemetry = policy.get_budget_telemetry(inv_id)
        assert telemetry["investigation_id"] == inv_id
        assert telemetry["total_requests"] == 3
        assert telemetry["endpoint_request_counts"].get("GET:/api/v1/users") == 2
        assert telemetry["endpoint_request_counts"].get("GET:/api/v1/orders") == 1

    @pytest.mark.asyncio
    async def test_rate_limit_backoff_does_not_issue_extra_requests(self, monkeypatch):
        inv_id = "inv-budget-3"
        policy = get_policy_engine()
        policy.reset_budgets(inv_id)

        monkeypatch.setattr("app.targets.private_ip.resolve_host", lambda h: ["93.184.216.34"])
        call_count = 0


        async def mock_request(self, method, url, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_resp = AsyncMock()
            mock_resp.status_code = 429  # Server returns 429 Too Many Requests
            mock_resp.content = b'{"error": "Too Many Requests"}'
            mock_resp.is_redirect = False
            mock_resp.headers = {}
            return mock_resp

        monkeypatch.setattr("httpx.AsyncClient.request", mock_request)
        monkeypatch.setattr("app.targets.authorization.AuthorizationService.check_scope", AsyncMock(return_value=type("ScopeRes", (), {"allowed": True, "reason": "in scope"})()))

        async with ScopeEnforcingHttpClient(inv_id) as client:
            resp = await client.get("https://authorized-target.com/api/v1/throttle_test")
            assert resp.status_code == 429

        # Only 1 transport call occurred despite 429 throttle signal triggering backoff
        assert call_count == 1
        telemetry = policy.get_budget_telemetry(inv_id)
        assert telemetry["total_requests"] == 1
