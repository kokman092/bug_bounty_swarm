"""
tests/integration/test_resource_consumption_pipeline.py
────────────────────────────────────────────────────────
Integration tests for ResourceConsumptionVerifier:
  - Verifier uses safe clamped probe value at or below documented maximum.
  - Bounded response yields negative with safe documented-bound observation status.
  - Existing JWT, BFLA, and API3 tests remain fully intact.
"""
import json
import pytest
from unittest.mock import AsyncMock

from app.discovery.models import ParameterProfile
from app.findings.schemas import FindingStatus
from app.targets.session_vault import UserSession, get_session_vault
from app.testing.api_security.resource_consumption_policy import ResourceConsumptionPolicy
from app.testing.api_security.resource_consumption_verifier import ResourceConsumptionVerifier


class TestResourceConsumptionPipelineIntegration:

    @pytest.mark.asyncio
    async def test_safe_endpoint_observation_produces_negative_result(self, monkeypatch):
        inv_id = "inv-rc-int-1"
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="attacker", token="tok_int_1"))

        policy = ResourceConsumptionPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/v1/products"],
        )
        verifier = ResourceConsumptionVerifier(inv_id, "https://authorized-target.com", policy)

        param = ParameterProfile(
            name="limit",
            location="query",
            documented_maximum=20,
            schema_reference="openapi:/paths/~1api~1v1~1products/get/parameters/limit",
        )

        captured_params = {}

        async def mock_get(self, url, params=None, headers=None, **kwargs):
            nonlocal captured_params
            captured_params = params or {}
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_resp.content = json.dumps({"products": [{"id": i} for i in range(20)]}).encode("utf-8")
            return mock_resp

        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        test_res = await verifier.verify_endpoint({
            "path": "/api/v1/products",
            "method": "GET",
            "protocol": "REST_CONFIRMED",
            "parameters": [param],
        })

        assert test_res.status == FindingStatus.REJECTED
        assert captured_params.get("limit") == "20"
        assert "PARTIALLY_COVERED" in test_res.observations[0]
