"""
tests/integration/test_role_matrix_pipeline.py
───────────────────────────────────────────────
Integration tests for RoleMatrixAuthorizationVerifier connected to ValidationPipeline:
  - Secure server enforces role access; no signal is routed.
  - Vulnerable server leaks role access; signal is processed through ValidationPipeline.
  - Public contract routes are handled as non-vulnerable.
  - Reproducibility multi-trial verification operates safely without scope/policy bypass.
"""
import pytest
from unittest.mock import AsyncMock

from app.findings.schemas import FindingStatus, VulnClass
from app.targets.session_vault import UserSession, get_session_vault
from app.testing.authorization.role_matrix_policy import RoleMatrixPolicy
from app.testing.authorization.role_matrix_verifier import RoleMatrixAuthorizationVerifier
from app.validation.models import FindingClassification
from app.validation.pipeline import ValidationPipeline


class TestRoleMatrixPipelineIntegration:

    @pytest.mark.asyncio
    async def test_secure_endpoint_produces_no_signal_in_pipeline(self, monkeypatch):
        inv_id = "inv-rm-int-1"
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="admin", token="admin_tok_int_1"))
        vault.add_session(UserSession(role="attacker", token="attacker_tok_int_1"))

        policy = RoleMatrixPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/v1/system/settings"],
            expected_access_rules={"GET /api/v1/system/settings": {"admin"}},
        )
        verifier = RoleMatrixAuthorizationVerifier(inv_id, "https://authorized-target.com", policy)

        # Mock secure server
        async def mock_get(self, url, headers=None, **kwargs):
            auth_header = (headers or {}).get("Authorization", "")
            mock_resp = AsyncMock()
            if "admin_tok_int" in auth_header:
                mock_resp.status_code = 200
                mock_resp.content = b'{"setting_debug": false, "env": "production"}'
            else:
                mock_resp.status_code = 403
                mock_resp.content = b'{"detail": "Access forbidden: admin privileges required."}'
            return mock_resp

        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        test_res = await verifier.verify_endpoint({"path": "/api/v1/system/settings", "method": "GET"})
        assert test_res.status == FindingStatus.REJECTED

    @pytest.mark.asyncio
    async def test_vulnerable_endpoint_candidate_signal_processed_by_validation_pipeline(self, monkeypatch):
        """Candidate signal from tester reaches ValidationPipeline for multi-stage verification."""
        inv_id = "inv-rm-int-2"
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="admin", token="admin_tok_int_2"))
        vault.add_session(UserSession(role="attacker", token="attacker_tok_int_2"))

        policy = RoleMatrixPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/v1/system/settings"],
            expected_access_rules={"GET /api/v1/system/settings": {"admin"}},
        )
        verifier = RoleMatrixAuthorizationVerifier(inv_id, "https://authorized-target.com", policy)

        # Mock vulnerable server: unauthorized attacker receives admin data
        async def mock_get(self, url, headers=None, **kwargs):
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_resp.content = b'{"setting_debug": false, "env": "production", "db_pool": 10}'
            return mock_resp

        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        test_res = await verifier.verify_endpoint({"path": "/api/v1/system/settings", "method": "GET"})
        # Tester output is candidate signal (requires validation, NOT automatically confirmed finding)
        assert test_res.status == FindingStatus.VALIDATED
        assert test_res.vuln_class == VulnClass.AUTH_BYPASS

        # Route candidate signal through ValidationPipeline
        pipeline = ValidationPipeline(inv_id, "https://authorized-target.com")
        val_res = await pipeline.validate_signal(test_res)

        assert val_res.confidence_score >= 80
        assert val_res.status in (FindingClassification.CONFIRMED, FindingClassification.HIGH_CONFIDENCE)
        assert val_res.baseline_difference_confirmed is True

    @pytest.mark.asyncio
    async def test_role_matrix_signal_with_incomplete_reproducibility_does_not_persist(self, monkeypatch):
        """Candidate signal failing reproducibility repeat is rejected and NOT persisted."""
        inv_id = "inv-rm-int-2b"
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="admin", token="admin_tok_int_2b"))
        vault.add_session(UserSession(role="attacker", token="attacker_tok_int_2b"))

        policy = RoleMatrixPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/v1/system/settings"],
            expected_access_rules={"GET /api/v1/system/settings": {"admin"}},
        )
        verifier = RoleMatrixAuthorizationVerifier(inv_id, "https://authorized-target.com", policy)

        # Candidate signal produced initially
        test_res = await verifier.verify_endpoint({"path": "/api/v1/system/settings", "method": "GET"})
        # Overwrite reproducibility to False to simulate failing repeat trials
        test_res.reproducible = False

        pipeline = ValidationPipeline(inv_id, "https://authorized-target.com")
        val_res = await pipeline.validate_signal(test_res)

        # Incomplete reproducibility must be rejected or not confirmed
        assert val_res.status != FindingClassification.CONFIRMED
        assert val_res.is_confirmed is False

    @pytest.mark.asyncio
    async def test_public_contract_route_skips_cleanly(self, monkeypatch):

        inv_id = "inv-rm-int-3"
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="admin", token="admin_tok_int_3"))
        vault.add_session(UserSession(role="attacker", token="attacker_tok_int_3"))

        # Explicitly marked as public/all
        policy = RoleMatrixPolicy(
            enabled=True,
            allowed_endpoint_patterns=["*"],
            expected_access_rules={"GET /api/health": {"admin", "owner", "attacker", "anonymous", "alice", "bob"}},
        )
        verifier = RoleMatrixAuthorizationVerifier(inv_id, "https://authorized-target.com", policy)

        res = await verifier.verify_endpoint({"path": "/api/health", "method": "GET"})
        assert res.status == FindingStatus.REJECTED
        assert res.raw_evidence.get("skip_reason") == "insufficient_personas_configured"
