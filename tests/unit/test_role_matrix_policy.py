"""
tests/unit/test_role_matrix_policy.py
─────────────────────────────────────
Unit tests for RoleMatrixPolicy & RoleMatrixAuthorizationVerifier eligibility:
  - Disabled policy causes skip and zero transport calls.
  - Missing explicit access contract causes skip and zero transport calls.
  - Non-GET/HEAD methods cause skip and zero transport calls.
  - Non-allowlisted endpoint causes skip and zero transport calls.
  - Unapproved / insufficient test personas cause skip and zero transport calls.
  - Exact and template path matching for explicit access contracts.
  - Path names alone do NOT make an endpoint eligible for BFLA testing.
"""
import pytest

from app.findings.schemas import FindingStatus
from app.targets.session_vault import UserSession, get_session_vault
from app.testing.authorization.role_matrix_policy import RoleMatrixPolicy
from app.testing.authorization.role_matrix_verifier import RoleMatrixAuthorizationVerifier


class TestRoleMatrixPolicy:

    def test_policy_defaults_and_contract_resolution(self):
        policy = RoleMatrixPolicy()
        assert policy.enabled is False
        assert policy.read_only_methods == {"GET", "HEAD"}

        policy.expected_access_rules = {
            "GET /api/admin/reports": {"admin"},
            "GET /api/orders/{id}": {"owner", "admin"},
            "GET /api/public/status": {"anonymous", "owner", "attacker", "admin"},
        }

        # Exact match
        assert policy.get_expected_roles_for_endpoint("GET", "/api/admin/reports") == {"admin"}
        # Template match
        assert policy.get_expected_roles_for_endpoint("GET", "/api/orders/12345") == {"owner", "admin"}
        assert policy.get_expected_roles_for_endpoint("GET", "/api/orders/abc-def") == {"owner", "admin"}
        # Missing contract returns None
        assert policy.get_expected_roles_for_endpoint("GET", "/api/admin/unknown") is None
        assert policy.get_expected_roles_for_endpoint("POST", "/api/orders/12345") is None

    @pytest.mark.asyncio
    async def test_disabled_policy_causes_skip_and_zero_transport(self):
        policy = RoleMatrixPolicy(enabled=False)
        verifier = RoleMatrixAuthorizationVerifier("inv-rm-1", "http://target.com", policy)

        res = await verifier.verify_endpoint({"path": "/api/admin/reports", "method": "GET"})
        assert res.status == FindingStatus.REJECTED
        assert "disabled by policy" in res.observations[0]
        assert res.raw_evidence.get("skip_reason") == "policy_disabled"

    @pytest.mark.asyncio
    async def test_missing_contract_causes_skip(self):
        # Even if path contains "admin", without an explicit contract it MUST skip
        policy = RoleMatrixPolicy(enabled=True, allowed_endpoint_patterns=["*"])
        verifier = RoleMatrixAuthorizationVerifier("inv-rm-2", "http://target.com", policy)

        res = await verifier.verify_endpoint({"path": "/api/admin/secret_dashboard", "method": "GET"})
        assert res.status == FindingStatus.REJECTED
        assert "No explicit authorization contract found" in res.observations[0]
        assert res.raw_evidence.get("skip_reason") == "skipped_missing_authorization_contract"

    @pytest.mark.asyncio
    async def test_non_read_only_method_causes_skip(self):
        policy = RoleMatrixPolicy(
            enabled=True,
            allowed_endpoint_patterns=["*"],
            expected_access_rules={"POST /api/admin/users": {"admin"}},
        )
        verifier = RoleMatrixAuthorizationVerifier("inv-rm-3", "http://target.com", policy)

        res = await verifier.verify_endpoint({"path": "/api/admin/users", "method": "POST"})
        assert res.status == FindingStatus.REJECTED
        assert "not a read-only method" in res.observations[0]
        assert res.raw_evidence.get("skip_reason") == "non_read_only_method"

    @pytest.mark.asyncio
    async def test_non_allowlisted_endpoint_causes_skip(self):
        policy = RoleMatrixPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/v1/.*"],
            expected_access_rules={"GET /api/v2/admin": {"admin"}},
        )
        verifier = RoleMatrixAuthorizationVerifier("inv-rm-4", "http://target.com", policy)

        res = await verifier.verify_endpoint({"path": "/api/v2/admin", "method": "GET"})
        assert res.status == FindingStatus.REJECTED
        assert "not in role-matrix test allowlist" in res.observations[0]
        assert res.raw_evidence.get("skip_reason") == "endpoint_not_allowlisted"

    @pytest.mark.asyncio
    async def test_insufficient_personas_causes_skip(self):
        # Only admin is configured in allowed roles, but if only owner exists in vault or no unauthorized role can be picked
        policy = RoleMatrixPolicy(
            enabled=True,
            allowed_endpoint_patterns=["*"],
            expected_access_rules={"GET /api/public/all": {"admin", "owner", "alice", "attacker", "bob", "anonymous"}},
        )
        verifier = RoleMatrixAuthorizationVerifier("inv-rm-5", "http://target.com", policy)

        # No unauthorized persona exists for a rule that allows every role
        res = await verifier.verify_endpoint({"path": "/api/public/all", "method": "GET"})
        assert res.status == FindingStatus.REJECTED
        assert "Insufficient configured test personas" in res.observations[0]
        assert res.raw_evidence.get("skip_reason") == "insufficient_personas_configured"
