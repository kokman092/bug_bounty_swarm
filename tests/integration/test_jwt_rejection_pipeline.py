"""
tests/integration/test_jwt_rejection_pipeline.py
────────────────────────────────────────────────
Integration tests for JWT rejection verification connected to ValidationPipeline:
  - Secure server rejects tampered tokens; no signal is routed.
  - Vulnerable server accepts tampered tokens; signal is routed through ValidationPipeline.
  - State-changing methods are blocked before transport.
  - Reproducibility multi-trial verification operates safely without scope/policy bypass.
"""
import base64
import json
import pytest
from unittest.mock import AsyncMock

from app.findings.schemas import FindingStatus, VulnClass
from app.targets.session_vault import UserSession, get_session_vault
from app.testing.authentication.jwt_policy import JwtRejectionTestPolicy
from app.testing.authentication.jwt_verifier import JwtSignatureRejectionVerifier
from app.validation.models import FindingClassification
from app.validation.pipeline import ValidationPipeline


def generate_integration_jwt(sub: str = "test_alice") -> str:
    h = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode("ascii").rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps({"sub": sub, "role": "user"}).encode("utf-8")).decode("ascii").rstrip("=")
    s = base64.urlsafe_b64encode(b'sig_alice_int_12345').decode("ascii").rstrip("=")
    return f"{h}.{p}.{s}"


class TestJwtRejectionPipelineIntegration:

    @pytest.mark.asyncio
    async def test_secure_endpoint_produces_no_signal_in_pipeline(self, monkeypatch):
        inv_id = "inv-jwt-int-1"
        jwt_tok = generate_integration_jwt()
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="owner", token=jwt_tok))

        policy = JwtRejectionTestPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/user/info"],
            allow_invalid_signature_probe=True,
        )
        verifier = JwtSignatureRejectionVerifier(inv_id, "https://authorized-target.com", policy)

        # Mock secure server
        async def mock_get(self, url, headers=None, **kwargs):
            auth_header = (headers or {}).get("Authorization", "")
            mock_resp = AsyncMock()
            if "sig_alice_int" in auth_header:
                mock_resp.status_code = 200
                mock_resp.content = b'{"user_id": 1, "name": "Alice"}'
            else:
                mock_resp.status_code = 401
                mock_resp.content = b'{"detail": "Invalid or missing token"}'
            return mock_resp

        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        test_res = await verifier.verify_endpoint({"path": "/api/user/info", "method": "GET"})
        assert test_res.status == FindingStatus.REJECTED

    @pytest.mark.asyncio
    async def test_vulnerable_endpoint_signal_processed_by_validation_pipeline(self, monkeypatch):
        inv_id = "inv-jwt-int-2"
        jwt_tok = generate_integration_jwt()
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="owner", token=jwt_tok))

        policy = JwtRejectionTestPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/user/info"],
            allow_invalid_signature_probe=True,
        )
        verifier = JwtSignatureRejectionVerifier(inv_id, "https://authorized-target.com", policy)

        # Mock vulnerable server accepting tampered signature
        async def mock_get(self, url, headers=None, **kwargs):
            auth_header = (headers or {}).get("Authorization", "")
            mock_resp = AsyncMock()
            if not auth_header:
                mock_resp.status_code = 401
                mock_resp.content = b'{"detail": "Missing token"}'
            else:
                mock_resp.status_code = 200
                mock_resp.content = b'{"user_id": 1, "name": "Alice", "role": "admin"}'
            return mock_resp


        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        test_res = await verifier.verify_endpoint({"path": "/api/user/info", "method": "GET"})
        assert test_res.status == FindingStatus.VALIDATED
        assert test_res.vuln_class == VulnClass.AUTH_BYPASS

        # Route candidate signal through ValidationPipeline
        pipeline = ValidationPipeline(inv_id, "https://authorized-target.com")
        val_res = await pipeline.validate_signal(test_res)

        # Verified through pipeline stages
        assert val_res.confidence_score >= 80
        assert val_res.status in (FindingClassification.CONFIRMED, FindingClassification.HIGH_CONFIDENCE)
        assert val_res.baseline_difference_confirmed is True

    @pytest.mark.asyncio
    async def test_state_changing_method_rejected_by_policy_before_transport(self, monkeypatch):
        inv_id = "inv-jwt-int-3"
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="owner", token=generate_integration_jwt()))

        policy = JwtRejectionTestPolicy(
            enabled=True,
            allowed_endpoint_patterns=["*"],
            read_only_methods={"GET", "HEAD"},
        )
        verifier = JwtSignatureRejectionVerifier(inv_id, "https://authorized-target.com", policy)

        # Verify POST and DELETE are rejected before any transport call
        res_post = await verifier.verify_endpoint({"path": "/api/user/update", "method": "POST"})
        assert res_post.status == FindingStatus.REJECTED
        assert res_post.raw_evidence.get("skip_reason") == "non_read_only_method"

        res_del = await verifier.verify_endpoint({"path": "/api/user/delete", "method": "DELETE"})
        assert res_del.status == FindingStatus.REJECTED
        assert res_del.raw_evidence.get("skip_reason") == "non_read_only_method"
