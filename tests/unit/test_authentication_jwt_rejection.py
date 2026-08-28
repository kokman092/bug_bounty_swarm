"""
tests/unit/test_authentication_jwt_rejection.py
───────────────────────────────────────────────
Unit tests for JwtSignatureRejectionVerifier differential execution & signal detection:
  - Valid baseline + denied control + denied probe -> Negative (Rejected / Secure).
  - Valid baseline + denied control + accepted probe -> Signal (Validated / Vulnerable).
  - 200 OK without protected fingerprint match does not yield signal.
  - Zero token or claim leakage into TestResult metadata or raw evidence.
"""
import base64
import json
import pytest
from unittest.mock import AsyncMock, patch

from app.findings.schemas import Confidence, FindingStatus, Severity, VulnClass
from app.targets.session_vault import UserSession, get_session_vault
from app.testing.authentication.jwt_policy import JwtRejectionTestPolicy
from app.testing.authentication.jwt_verifier import JwtSignatureRejectionVerifier


def generate_test_jwt(sub: str = "user123") -> str:
    h = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode("ascii").rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps({"sub": sub, "role": "user"}).encode("utf-8")).decode("ascii").rstrip("=")
    s = base64.urlsafe_b64encode(b'valid_signature_bytes_123').decode("ascii").rstrip("=")
    return f"{h}.{p}.{s}"


class TestAuthenticationJwtRejection:

    @pytest.mark.asyncio
    async def test_secure_server_rejects_tampered_token_yields_negative(self, monkeypatch):
        inv_id = "inv-jwt-unit-1"
        test_jwt = generate_test_jwt()
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="owner", token=test_jwt))

        policy = JwtRejectionTestPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/user/profile"],
            allow_invalid_signature_probe=True,
        )
        verifier = JwtSignatureRejectionVerifier(inv_id, "https://authorized-target.com", policy)

        # Mock ScopeEnforcingHttpClient calls:
        # 1. Baseline: 200 OK with authenticated user profile
        # 2. Control: 401 Unauthorized
        # 3. Tampered probe: 401 Unauthorized (Secure rejection)
        async def mock_get(self, url, headers=None, **kwargs):
            auth_header = (headers or {}).get("Authorization", "")
            mock_resp = AsyncMock()
            if auth_header == f"Bearer {test_jwt}":
                mock_resp.status_code = 200
                mock_resp.content = b'{"user_id": 123, "email": "alice@target.com", "balance": 500}'
            elif not auth_header:
                mock_resp.status_code = 401
                mock_resp.content = b'{"detail": "Authentication credentials were not provided."}'
            else:
                # Tampered signature
                mock_resp.status_code = 401
                mock_resp.content = b'{"detail": "Signature verification failed."}'
            return mock_resp

        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        res = await verifier.verify_endpoint({"path": "/api/user/profile", "method": "GET"})
        assert res.status == FindingStatus.REJECTED
        assert "securely rejected tampered token" in res.observations[0]
        assert res.raw_evidence.get("probe_status") == 401

        # Verify no token strings leaked into observations or raw evidence
        assert test_jwt not in str(res.observations)
        assert test_jwt not in str(res.raw_evidence)

    @pytest.mark.asyncio
    async def test_vulnerable_server_accepts_tampered_token_yields_signal(self, monkeypatch):
        inv_id = "inv-jwt-unit-2"
        test_jwt = generate_test_jwt()
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="owner", token=test_jwt))

        policy = JwtRejectionTestPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/user/profile"],
            allow_invalid_signature_probe=True,
        )
        verifier = JwtSignatureRejectionVerifier(inv_id, "https://authorized-target.com", policy)

        # Mock ScopeEnforcingHttpClient calls:
        # 1. Baseline: 200 OK
        # 2. Control: 401 Unauthorized
        # 3. Tampered probe: 200 OK (Vulnerable signature bypass)
        async def mock_get(self, url, headers=None, **kwargs):
            auth_header = (headers or {}).get("Authorization", "")
            mock_resp = AsyncMock()
            if not auth_header:
                mock_resp.status_code = 401
                mock_resp.content = b'{"detail": "Unauthorized"}'
            else:
                # Insecure validation accepts tampered signature
                mock_resp.status_code = 200
                mock_resp.content = b'{"user_id": 123, "email": "alice@target.com", "balance": 500}'
            return mock_resp

        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        res = await verifier.verify_endpoint({"path": "/api/user/profile", "method": "GET"})
        assert res.status == FindingStatus.VALIDATED
        assert res.confidence == Confidence.HIGH
        assert res.severity == Severity.CRITICAL
        assert res.vuln_class == VulnClass.AUTH_BYPASS
        assert "Server accepted tampered JWT probe" in res.observations[0]
        assert res.raw_evidence.get("token_state_label") == "invalid_signature_probe"

        # Verify no token strings leaked into observations or raw evidence
        assert test_jwt not in str(res.observations)
        assert test_jwt not in str(res.raw_evidence)

    @pytest.mark.asyncio
    async def test_probe_200_with_mismatched_generic_body_does_not_yield_signal(self, monkeypatch):
        inv_id = "inv-jwt-unit-3"
        test_jwt = generate_test_jwt()
        vault = get_session_vault(inv_id)
        vault.add_session(UserSession(role="owner", token=test_jwt))

        policy = JwtRejectionTestPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/user/profile"],
            allow_invalid_signature_probe=True,
        )
        verifier = JwtSignatureRejectionVerifier(inv_id, "https://authorized-target.com", policy)

        # Baseline is small user JSON; Tampered probe returns a huge generic public HTML/error page
        async def mock_get(self, url, headers=None, **kwargs):
            auth_header = (headers or {}).get("Authorization", "")
            mock_resp = AsyncMock()
            if auth_header == f"Bearer {test_jwt}":
                mock_resp.status_code = 200
                mock_resp.content = b'{"user_id": 123, "email": "alice@target.com"}'
            elif not auth_header:
                mock_resp.status_code = 401
                mock_resp.content = b'{"detail": "Unauthorized"}'
            else:
                # Returns 200 with totally different/generic public content (e.g. static fallback)
                mock_resp.status_code = 200
                mock_resp.content = b'{"public_status": "ok", "message": "welcome to generic public api"}' + b"A" * 5000
            return mock_resp




        monkeypatch.setattr("app.tools.http_client.ScopeEnforcingHttpClient.get", mock_get)

        res = await verifier.verify_endpoint({"path": "/api/user/profile", "method": "GET"})
        assert res.status == FindingStatus.REJECTED
        assert "fingerprint mismatch" in res.observations[0]
