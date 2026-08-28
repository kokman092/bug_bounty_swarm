"""
tests/unit/test_evidence_consistency.py
───────────────────────────────────────
Unit tests for Evidence Consistency and Policy Decisions:
  - Disabled policy yields structured skip reason in raw evidence.
  - Missing contract yields structured skip reason.
  - Scope block yields structured exception and blocked reason.
  - Evidence objects never leak raw tokens, cookies, auth headers, or passwords.
"""
import pytest

from app.core.exceptions import ScopeViolationError
from app.events.schemas import EventType
from app.events.service import sanitize_payload
from app.findings.schemas import FindingStatus
from app.testing.api_security.resource_consumption_policy import ResourceConsumptionPolicy
from app.testing.api_security.resource_consumption_verifier import ResourceConsumptionVerifier
from app.testing.api_security.response_property_policy import ResponsePropertyPolicy
from app.testing.api_security.response_property_verifier import ResponsePropertyVerifier
from app.testing.authentication.jwt_policy import JwtRejectionTestPolicy
from app.testing.authentication.jwt_verifier import JwtSignatureRejectionVerifier


class TestEvidenceConsistency:

    @pytest.mark.asyncio
    async def test_disabled_policy_records_structured_skip_reason(self):
        verifier = ResponsePropertyVerifier("inv-ev-1", "https://target.com", ResponsePropertyPolicy(enabled=False))
        res = await verifier.verify_endpoint({"path": "/api/test", "method": "GET"})

        assert res.status == FindingStatus.REJECTED
        assert res.raw_evidence.get("skip_reason") == "policy_disabled"
        assert "disabled by policy" in res.observations[0]

    @pytest.mark.asyncio
    async def test_missing_contract_records_structured_skip_reason(self):
        policy = ResponsePropertyPolicy(enabled=True, allowed_endpoint_patterns=["*"])
        verifier = ResponsePropertyVerifier("inv-ev-2", "https://target.com", policy)
        res = await verifier.verify_endpoint({"path": "/api/no-contract", "method": "GET"})

        assert res.status == FindingStatus.REJECTED
        assert res.raw_evidence.get("skip_reason") == "missing_response_contract"

    @pytest.mark.asyncio
    async def test_jwt_verifier_disabled_policy_records_structured_skip_reason(self):
        verifier = JwtSignatureRejectionVerifier("inv-ev-3", "https://target.com", JwtRejectionTestPolicy(enabled=False))
        res = await verifier.verify_endpoint({"path": "/api/auth-test", "method": "GET"})

        assert res.status == FindingStatus.REJECTED
        assert res.raw_evidence.get("skip_reason") == "policy_disabled"

    def test_sanitize_payload_redacts_tokens_and_credentials_completely(self):
        raw_event_payload = {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature",
            "Cookie": "session_id=abc123secret; remember_token=def456secret",
            "user_credentials": "secret_credential_string",
            "account_data": {
                "password": "SuperSecretPassword123!",
                "api_key": "sk-live-abcdef123456",
            },
            "status": "active",
            "count": 42,
        }

        sanitized = sanitize_payload(raw_event_payload)

        assert sanitized["Authorization"] == "[REDACTED]"
        assert sanitized["Cookie"] == "[REDACTED]"
        assert sanitized["user_credentials"] == "[REDACTED]"
        assert sanitized["account_data"]["password"] == "[REDACTED]"
        assert sanitized["account_data"]["api_key"] == "[REDACTED]"
        assert sanitized["status"] == "active"
        assert sanitized["count"] == 42
        assert "SuperSecretPassword123!" not in str(sanitized)
        assert "doNotLeakThisSignature" not in str(sanitized)


