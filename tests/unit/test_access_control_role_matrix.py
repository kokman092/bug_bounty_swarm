"""
tests/unit/test_access_control_role_matrix.py
─────────────────────────────────────────────
Unit tests for RoleMatrixAuthorizationVerifier execution & BFLA candidate signal detection:
  - Authorized persona succeeds and unauthorized persona is denied -> Negative (Secure / Rejected).
  - Unauthorized persona receives matching protected content -> Signal (Validated / Vulnerable).
  - 200 OK without protected fingerprint match -> Inconclusive / Rejected.
  - Zero token or secret leakage into TestResult metadata or raw evidence.
  - All transport calls strictly route through ScopeEnforcingHttpClient.
"""
import pytest
from unittest.mock import AsyncMock

from app.findings.schemas import Confidence, FindingStatus, Severity, VulnClass
from app.targets.session_vault import UserSession, get_session_vault
from app.testing.authorization.role_matrix_policy import RoleMatrixPolicy
from app.testing.authorization.role_matrix_verifier import RoleMatrixAuthorizationVerifier


class TestAccessControlRoleMatrix:

    @pytest.mark.asyncio
    async def test_secure_server_denies_unauthorized_persona_yields_negative(self, monkeypatch):
        inv_id = "inv-rm-unit-1"
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="admin", token="admin_token_sec_123"))
        vault.add_session(UserSession(role="attacker", token="attacker_token_sec_456"))

        policy = RoleMatrixPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/admin/metrics"],
            expected_access_rules={"GET /api/admin/metrics": {"admin"}},
        )
        verifier = RoleMatrixAuthorizationVerifier(inv_id, "https://authorized-target.com", policy)

        # Mock ScopeEnforcingHttpClient calls:
        # 1. Authorized baseline (admin): 200 OK with admin metric data
        # 2. Unauthorized control (attacker): 403 Forbidden (Secure denial)
        async def mock_get(self, url, headers=None, **kwargs):
            auth_header = (headers or {}).get("Authorization", "")
            mock_resp = AsyncMock()
            if "admin_token_sec" in auth_header:
                mock_resp.status_code = 200
                mock_resp.content = b'{"system_status": "optimal", "active_nodes": 12, "memory_usage": "42%"}'
            else:
                mock_resp.status_code = 403
                mock_resp.content = b'{"detail": "Forbidden: Requires administrator role."}'
            return mock_resp

        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        res = await verifier.verify_endpoint({"path": "/api/admin/metrics", "method": "GET"})
        assert res.status == FindingStatus.REJECTED
        assert "securely enforced role boundary" in res.observations[0]
        assert res.raw_evidence.get("authorized_status") == 200
        assert res.raw_evidence.get("unauthorized_status") == 403

        # Verify no token strings leaked
        assert "admin_token_sec" not in str(res.observations)
        assert "attacker_token_sec" not in str(res.observations)
        assert "admin_token_sec" not in str(res.raw_evidence)

    @pytest.mark.asyncio
    async def test_vulnerable_server_permits_unauthorized_persona_yields_signal(self, monkeypatch):
        inv_id = "inv-rm-unit-2"
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="admin", token="admin_token_vuln_123"))
        vault.add_session(UserSession(role="attacker", token="attacker_token_vuln_456"))

        policy = RoleMatrixPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/admin/metrics"],
            expected_access_rules={"GET /api/admin/metrics": {"admin"}},
        )
        verifier = RoleMatrixAuthorizationVerifier(inv_id, "https://authorized-target.com", policy)

        # Mock ScopeEnforcingHttpClient calls:
        # Both admin and attacker receive HTTP 200 with identical admin metric data
        async def mock_get(self, url, headers=None, **kwargs):
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_resp.content = b'{"system_status": "optimal", "active_nodes": 12, "memory_usage": "42%"}'
            return mock_resp

        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        res = await verifier.verify_endpoint({"path": "/api/admin/metrics", "method": "GET"})
        assert res.status == FindingStatus.VALIDATED
        assert res.confidence == Confidence.HIGH
        assert res.severity == Severity.HIGH
        assert res.vuln_class == VulnClass.AUTH_BYPASS
        assert "Role boundary violation" in res.observations[0]
        assert res.raw_evidence.get("authorized_status") == 200
        assert res.raw_evidence.get("unauthorized_status") == 200

        # Verify zero token leakage
        assert "admin_token_vuln" not in str(res.observations)
        assert "attacker_token_vuln" not in str(res.raw_evidence)

    @pytest.mark.asyncio
    async def test_unauthorized_200_with_mismatched_generic_content_does_not_yield_signal(self, monkeypatch):
        inv_id = "inv-rm-unit-3"
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="admin", token="admin_token_mis_123"))
        vault.add_session(UserSession(role="attacker", token="attacker_token_mis_456"))

        policy = RoleMatrixPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/admin/metrics"],
            expected_access_rules={"GET /api/admin/metrics": {"admin"}},
        )
        verifier = RoleMatrixAuthorizationVerifier(inv_id, "https://authorized-target.com", policy)

        # Admin receives metric JSON, attacker receives generic public fallback page
        async def mock_get(self, url, headers=None, **kwargs):
            auth_header = (headers or {}).get("Authorization", "")
            mock_resp = AsyncMock()
            if "admin_token_mis" in auth_header:
                mock_resp.status_code = 200
                mock_resp.content = b'{"system_status": "optimal", "active_nodes": 12}'
            else:
                mock_resp.status_code = 200
                mock_resp.content = b'{"public_notice": "welcome guest", "docs": "https://api.target.com"}' + b"X" * 2000
            return mock_resp

        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        res = await verifier.verify_endpoint({"path": "/api/admin/metrics", "method": "GET"})
        assert res.status == FindingStatus.REJECTED
        assert "fingerprint mismatch" in res.observations[0]
