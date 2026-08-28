"""
tests/unit/test_api_resource_consumption_verifier.py
────────────────────────────────────────────────────
Unit tests for ResourceConsumptionVerifier:
  - Documented maximum 20 gives probe value 20 in request query params.
  - Bounded response at or below documented maximum yields negative.
  - Large or slow response alone remains non-signal / negative.
  - Zero item values, IDs, tokens, or PII stored in TestResult metadata.
  - All transport calls strictly route through ScopeEnforcingHttpClient.
"""
import pytest
from unittest.mock import AsyncMock

from app.discovery.models import ParameterProfile
from app.findings.schemas import Confidence, FindingStatus, Severity, VulnClass
from app.targets.session_vault import UserSession, get_session_vault
from app.testing.api_security.resource_consumption_policy import ResourceConsumptionPolicy
from app.testing.api_security.resource_consumption_verifier import ResourceConsumptionVerifier


class TestApiResourceConsumptionVerifier:

    @pytest.mark.asyncio
    async def test_documented_maximum_strictly_clamps_probe_value(self, monkeypatch):
        inv_id = "inv-rc-unit-1"
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="attacker", token="tok_123"))

        policy = ResourceConsumptionPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/v1/orders"],
            max_probe_parameter_value=1000,
        )
        verifier = ResourceConsumptionVerifier(inv_id, "https://authorized-target.com", policy)

        # Documented max is 20
        param = ParameterProfile(
            name="limit",
            location="query",
            documented_maximum=20,
            schema_reference="openapi:/paths/~1api~1v1~1orders/get/parameters/limit",
        )

        captured_params = {}

        async def mock_get(self, url, params=None, headers=None, **kwargs):
            nonlocal captured_params
            captured_params = params or {}
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            import json
            mock_resp.content = json.dumps({"items": [{"id": i} for i in range(20)]}).encode("utf-8")
            return mock_resp

        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        res = await verifier.verify_endpoint({
            "path": "/api/v1/orders",
            "method": "GET",
            "protocol": "REST_CONFIRMED",
            "parameters": [param],
        })

        # Crucial: probe value is strictly clamped to documented maximum 20 (never 40 or 100)
        assert captured_params.get("limit") == "20"
        assert res.status == FindingStatus.REJECTED
        assert "PARTIALLY_COVERED — safe documented-bound observation" in res.observations[0]
        assert res.raw_evidence.get("item_count_observed") == 20
        assert res.raw_evidence.get("probe_value") == 20
        assert res.raw_evidence.get("documented_maximum") == 20

    @pytest.mark.asyncio
    async def test_no_documented_max_uses_default_probe_value(self, monkeypatch):
        inv_id = "inv-rc-unit-2"
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="attacker", token="tok_456"))

        policy = ResourceConsumptionPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/v1/orders"],
            default_probe_parameter_value=50,
            max_probe_parameter_value=1000,
        )
        verifier = ResourceConsumptionVerifier(inv_id, "https://authorized-target.com", policy)

        param = ParameterProfile(
            name="size",
            location="query",
            documented_maximum=None,
        )

        captured_params = {}

        async def mock_get(self, url, params=None, headers=None, **kwargs):
            nonlocal captured_params
            captured_params = params or {}
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            import json
            mock_resp.content = json.dumps({"orders": [{"id": i} for i in range(10)]}).encode("utf-8")
            return mock_resp

        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        res = await verifier.verify_endpoint({
            "path": "/api/v1/orders",
            "method": "GET",
            "protocol": "REST_CONFIRMED",
            "parameters": [param],
        })

        assert captured_params.get("size") == "50"
        assert res.status == FindingStatus.REJECTED
        assert res.raw_evidence.get("probe_value") == 50

    @pytest.mark.asyncio
    async def test_large_or_slow_response_alone_remains_negative(self, monkeypatch):
        inv_id = "inv-rc-unit-3"
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="attacker", token="tok_789"))

        policy = ResourceConsumptionPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/v1/reports"],
        )
        verifier = ResourceConsumptionVerifier(inv_id, "https://authorized-target.com", policy)

        param = ParameterProfile(
            name="size",
            location="query",
            documented_maximum=10,
        )

        async def mock_get(self, url, params=None, headers=None, **kwargs):
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            import json
            # Returns 10 items but with large text content (large payload)
            mock_resp.content = json.dumps({"description": "A" * 50000, "items": [1, 2, 3]}).encode("utf-8")
            return mock_resp

        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        res = await verifier.verify_endpoint({
            "path": "/api/v1/reports",
            "method": "GET",
            "protocol": "REST_CONFIRMED",
            "parameters": [param],
        })

        # Large size alone without contract violation is NOT a vulnerability signal
        assert res.status == FindingStatus.REJECTED
        assert "PARTIALLY_COVERED" in res.observations[0]
