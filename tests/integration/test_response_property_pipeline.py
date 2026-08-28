"""
tests/integration/test_response_property_pipeline.py
────────────────────────────────────────────────────
Integration tests for ResponsePropertyVerifier connected to ValidationPipeline:
  - Secure server returns compliant properties; no candidate signal is routed.
  - Vulnerable server leaks protected property; candidate signal is processed by ValidationPipeline.
  - Fully validated signal reaches CONFIRMED finding status only through pipeline thresholds.
  - Undocumented ordinary fields are handled without false positives.
"""
import pytest
from unittest.mock import AsyncMock

from app.findings.schemas import FindingStatus, VulnClass
from app.targets.session_vault import UserSession, get_session_vault
from app.testing.api_security.response_property_policy import (
    ResponseFieldContract,
    ResponsePropertyPolicy,
)
from app.testing.api_security.response_property_verifier import ResponsePropertyVerifier
from app.validation.models import FindingClassification
from app.validation.pipeline import ValidationPipeline


class TestResponsePropertyPipelineIntegration:

    @pytest.mark.asyncio
    async def test_secure_endpoint_produces_no_signal_in_pipeline(self, monkeypatch):
        inv_id = "inv-rp-int-1"
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="owner", token="owner_int_tok_1"))

        contract = ResponseFieldContract(
            allowed_fields_by_role={"owner": {"id", "email", "name"}},
            protected_fields={"stripe_customer_id", "internal_hash"},
            source="openapi:/paths/~1api~1me",
        )
        policy = ResponsePropertyPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/me"],
            response_contracts={"GET /api/me": contract},
        )
        verifier = ResponsePropertyVerifier(inv_id, "https://authorized-target.com", policy)

        async def mock_get(self, url, headers=None, **kwargs):
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_resp.content = b'{"id": 101, "email": "alice@test.com", "name": "Alice"}'
            return mock_resp

        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        test_res = await verifier.verify_endpoint({"path": "/api/me", "method": "GET"}, role="owner")
        assert test_res.status == FindingStatus.REJECTED

    @pytest.mark.asyncio
    async def test_vulnerable_endpoint_signal_processed_by_validation_pipeline(self, monkeypatch):
        inv_id = "inv-rp-int-2"
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="owner", token="owner_int_tok_2"))

        contract = ResponseFieldContract(
            allowed_fields_by_role={"owner": {"id", "email", "name"}},
            protected_fields={"internal_hash", "stripe_customer_id"},
            source="openapi:/paths/~1api~1me",
        )
        policy = ResponsePropertyPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/me"],
            response_contracts={"GET /api/me": contract},
        )
        verifier = ResponsePropertyVerifier(inv_id, "https://authorized-target.com", policy)

        # Server leaks internal_hash
        async def mock_get(self, url, headers=None, **kwargs):
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_resp.content = b'{"id": 101, "email": "alice@test.com", "name": "Alice", "internal_hash": "sec_hash_val_999"}'
            return mock_resp

        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        test_res = await verifier.verify_endpoint({"path": "/api/me", "method": "GET"}, role="owner")
        assert test_res.status == FindingStatus.VALIDATED
        assert test_res.vuln_class == VulnClass.MASS_ASSIGNMENT

        # Route candidate signal through ValidationPipeline
        pipeline = ValidationPipeline(inv_id, "https://authorized-target.com")
        val_res = await pipeline.validate_signal(test_res)

        assert val_res.confidence_score >= 80
        assert val_res.status in (FindingClassification.CONFIRMED, FindingClassification.HIGH_CONFIDENCE)
        assert val_res.baseline_difference_confirmed is True

    @pytest.mark.asyncio
    async def test_undocumented_ordinary_field_does_not_create_false_positive(self, monkeypatch):
        inv_id = "inv-rp-int-3"
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="owner", token="owner_int_tok_3"))

        contract = ResponseFieldContract(
            allowed_fields_by_role={"owner": {"id", "email"}},
            protected_fields={"password_hash"},
            source="openapi:/paths/~1api~1me",
        )
        policy = ResponsePropertyPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/me"],
            response_contracts={"GET /api/me": contract},
        )
        verifier = ResponsePropertyVerifier(inv_id, "https://authorized-target.com", policy)

        # Response has an ordinary unmodeled UI field 'avatar_url'
        async def mock_get(self, url, headers=None, **kwargs):
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_resp.content = b'{"id": 101, "email": "alice@test.com", "avatar_url": "https://img.target.com/a.png"}'
            return mock_resp

        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        test_res = await verifier.verify_endpoint({"path": "/api/me", "method": "GET"}, role="owner")
        assert test_res.status == FindingStatus.REJECTED
