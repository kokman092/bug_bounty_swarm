"""
tests/unit/test_api_response_property_verifier.py
─────────────────────────────────────────────────
Unit tests for ResponsePropertyVerifier candidate signal detection:
  - Matching response fields yield negative (Passed / Compliant).
  - Explicit protected field returned yields candidate signal (Validated / Potential Finding).
  - Explicitly forbidden field for role yields candidate signal (Validated / Potential Finding).
  - Undocumented ordinary field does NOT yield signal (False-positive prevention).
  - Sensitive-sounding field name without explicit contract treatment does NOT yield signal.
  - Zero raw values, passwords, hashes, tokens, or PII in TestResult metadata.
"""
import pytest
from unittest.mock import AsyncMock

from app.findings.schemas import Confidence, FindingStatus, Severity, VulnClass
from app.targets.session_vault import UserSession, get_session_vault
from app.testing.api_security.response_property_policy import (
    ResponseFieldContract,
    ResponsePropertyPolicy,
)
from app.testing.api_security.response_property_verifier import ResponsePropertyVerifier


class TestApiResponsePropertyVerifier:

    @pytest.mark.asyncio
    async def test_compliant_response_yields_negative(self, monkeypatch):
        inv_id = "inv-rp-unit-1"
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="owner", token="owner_tok_123"))

        contract = ResponseFieldContract(
            allowed_fields_by_role={"owner": {"id", "username", "email", "profile", "profile.display_name"}},
            protected_fields={"password_hash", "mfa_token"},
            source="openapi:/paths/~1api~1users~1me",
        )
        policy = ResponsePropertyPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/users/me"],
            response_contracts={"GET /api/users/me": contract},
        )
        verifier = ResponsePropertyVerifier(inv_id, "https://authorized-target.com", policy)

        async def mock_get(self, url, headers=None, **kwargs):
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_resp.content = b'{"id": 1, "username": "alice", "email": "alice@target.com", "profile": {"display_name": "Alice"}}'
            return mock_resp

        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        res = await verifier.verify_endpoint({"path": "/api/users/me", "method": "GET"}, role="owner")
        assert res.status == FindingStatus.REJECTED
        assert "validation passed" in res.observations[0]

    @pytest.mark.asyncio
    async def test_explicit_protected_field_leak_yields_signal(self, monkeypatch):
        inv_id = "inv-rp-unit-2"
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="owner", token="owner_tok_456"))

        contract = ResponseFieldContract(
            allowed_fields_by_role={"owner": {"id", "username", "email"}},
            protected_fields={"password_hash", "mfa_secret", "private_signing_key"},
            source="openapi+role_policy",
        )
        policy = ResponsePropertyPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/users/me"],
            response_contracts={"GET /api/users/me": contract},
        )
        verifier = ResponsePropertyVerifier(inv_id, "https://authorized-target.com", policy)

        # Response leaks password_hash
        async def mock_get(self, url, headers=None, **kwargs):
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_resp.content = b'{"id": 1, "username": "alice", "email": "alice@target.com", "password_hash": "$2a$12$e8s7df6a5sd7f6a5sd"}'
            return mock_resp

        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        res = await verifier.verify_endpoint({"path": "/api/users/me", "method": "GET"}, role="owner")
        assert res.status == FindingStatus.VALIDATED
        assert res.confidence == Confidence.HIGH
        assert res.severity == Severity.HIGH
        assert res.vuln_class == VulnClass.MASS_ASSIGNMENT
        assert "password_hash" in res.raw_evidence["violating_fields"]

        # Crucial privacy assertion: Zero raw password hash values stored in evidence
        assert "$2a$12$" not in str(res.observations)
        assert "$2a$12$" not in str(res.raw_evidence)

    @pytest.mark.asyncio
    async def test_explicitly_forbidden_role_field_yields_signal(self, monkeypatch):
        inv_id = "inv-rp-unit-3"
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="owner", token="owner_tok_789"))

        # account_tier and internal_notes are permitted for admin only, forbidden for owner
        contract = ResponseFieldContract(
            allowed_fields_by_role={
                "owner": {"id", "username"},
                "admin": {"id", "username", "account_tier", "internal_notes"},
            },
            protected_fields=set(),
            source="openapi_rbac",
        )
        policy = ResponsePropertyPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/users/profile"],
            response_contracts={"GET /api/users/profile": contract},
        )
        verifier = ResponsePropertyVerifier(inv_id, "https://authorized-target.com", policy)

        async def mock_get(self, url, headers=None, **kwargs):
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_resp.content = b'{"id": 1, "username": "alice", "account_tier": "VIP_INTERNAL"}'
            return mock_resp

        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        res = await verifier.verify_endpoint({"path": "/api/users/profile", "method": "GET"}, role="owner")
        assert res.status == FindingStatus.VALIDATED
        assert "account_tier" in res.raw_evidence["violating_fields"]

        # Ensure value "VIP_INTERNAL" is not stored
        assert "VIP_INTERNAL" not in str(res.observations)
        assert "VIP_INTERNAL" not in str(res.raw_evidence)

    @pytest.mark.asyncio
    async def test_undocumented_ordinary_field_does_not_yield_signal(self, monkeypatch):
        inv_id = "inv-rp-unit-4"
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="owner", token="owner_tok_000"))

        # Incomplete contract: unlisted field is ignored as harmless schema drift
        contract = ResponseFieldContract(
            allowed_fields_by_role={"owner": {"id", "username"}},
            protected_fields={"secret_key"},
            source="openapi_base",
            role_allowlists_complete=False,
        )
        policy = ResponsePropertyPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/users/profile"],
            response_contracts={"GET /api/users/profile": contract},
        )
        verifier = ResponsePropertyVerifier(inv_id, "https://authorized-target.com", policy)

        # Server returns an ordinary extra field 'created_at' or 'theme_color' not in contract
        async def mock_get(self, url, headers=None, **kwargs):
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_resp.content = b'{"id": 1, "username": "alice", "theme_color": "blue", "created_at": "2026-01-01"}'
            return mock_resp

        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        res = await verifier.verify_endpoint({"path": "/api/users/profile", "method": "GET"}, role="owner")
        # Must NOT yield signal for undocumented harmless fields when contract is incomplete
        assert res.status == FindingStatus.REJECTED
        assert "validation passed" in res.observations[0]

    @pytest.mark.asyncio
    async def test_complete_contract_treats_unlisted_omitted_field_as_signal(self, monkeypatch):
        inv_id = "inv-rp-unit-5"
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="owner", token="owner_tok_111"))

        # Complete contract: role_allowlists_complete=True means strict closed-world schema
        contract = ResponseFieldContract(
            allowed_fields_by_role={"owner": {"id", "username"}},
            protected_fields=set(),
            source="openapi_strict_closed_world",
            role_allowlists_complete=True,
        )
        policy = ResponsePropertyPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/users/profile"],
            response_contracts={"GET /api/users/profile": contract},
        )
        verifier = ResponsePropertyVerifier(inv_id, "https://authorized-target.com", policy)

        async def mock_get(self, url, headers=None, **kwargs):
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_resp.content = b'{"id": 1, "username": "alice", "unauthorized_extra_prop": "leak"}'
            return mock_resp

        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        res = await verifier.verify_endpoint({"path": "/api/users/profile", "method": "GET"}, role="owner")
        assert res.status == FindingStatus.VALIDATED
        assert "unauthorized_extra_prop" in res.raw_evidence["violating_fields"]

