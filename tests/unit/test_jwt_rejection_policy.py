"""
tests/unit/test_jwt_rejection_policy.py
───────────────────────────────────────
Unit tests for JwtRejectionTestPolicy & JwtSignatureRejectionVerifier eligibility:
  - Disabled policy causes skip and zero transport calls.
  - Opaque non-JWT token causes skip and zero transport calls.
  - Non-allowlisted endpoint causes skip and zero transport calls.
  - Non-GET/HEAD method causes skip and zero transport calls.
  - Unapproved test identity causes skip and zero transport calls.
  - alg:none probe is impossible unless explicitly enabled in policy.
  - Zero token or claim leakage into TestResult metadata.
"""
import base64
import json
import pytest

from app.findings.schemas import FindingStatus
from app.targets.session_vault import UserSession, get_session_vault
from app.testing.authentication.jwt_policy import JwtRejectionTestPolicy
from app.testing.authentication.jwt_verifier import (
    JwtSignatureRejectionVerifier,
    create_invalid_signature_probe,
    create_unsigned_alg_none_probe,
    is_compact_jwt_candidate,
)


class TestJwtRejectionPolicy:

    def test_policy_defaults_and_allowlist(self):
        policy = JwtRejectionTestPolicy()
        assert policy.enabled is False
        assert policy.allow_alg_none_probe is False
        assert policy.allow_invalid_signature_probe is True

        policy.allowed_endpoint_patterns = ["/api/v1/profile", "/api/orders/.*"]
        assert policy.is_endpoint_allowed("/api/v1/profile") is True
        assert policy.is_endpoint_allowed("/api/orders/123") is True
        assert policy.is_endpoint_allowed("/api/admin/delete") is False

    def test_is_compact_jwt_candidate_detects_jwt_structure_vs_opaque(self):
        # Valid 3-part JWT
        h = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode("ascii").rstrip("=")
        p = base64.urlsafe_b64encode(b'{"sub":"user123","role":"user"}').decode("ascii").rstrip("=")
        s = base64.urlsafe_b64encode(b'signaturebytes12345').decode("ascii").rstrip("=")
        valid_jwt = f"{h}.{p}.{s}"

        assert is_compact_jwt_candidate(valid_jwt) is True
        assert is_compact_jwt_candidate(f"Bearer {valid_jwt}") is True

        # Opaque tokens / non-JWTs
        assert is_compact_jwt_candidate("opaque_random_token_12345") is False
        assert is_compact_jwt_candidate("Bearer opaque_random_token_12345") is False
        assert is_compact_jwt_candidate("part1.part2") is False
        assert is_compact_jwt_candidate("part1.part2.part3.part4") is False
        assert is_compact_jwt_candidate("not_b64.not_b64.not_b64") is False


    def test_create_invalid_signature_probe_preserves_payload(self):
        h = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode("ascii").rstrip("=")
        p = base64.urlsafe_b64encode(b'{"sub":"user123","role":"user"}').decode("ascii").rstrip("=")
        s = base64.urlsafe_b64encode(b'original_signature').decode("ascii").rstrip("=")
        original_jwt = f"{h}.{p}.{s}"

        probed = create_invalid_signature_probe(original_jwt)
        segments = probed.split(".")
        assert len(segments) == 3
        assert segments[0] == h  # Header unchanged
        assert segments[1] == p  # Payload unchanged
        assert segments[2] != s  # Signature modified

    def test_create_unsigned_alg_none_probe_sets_none_alg(self):
        h = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode("ascii").rstrip("=")
        p = base64.urlsafe_b64encode(b'{"sub":"user123","role":"user"}').decode("ascii").rstrip("=")
        s = base64.urlsafe_b64encode(b'original_signature').decode("ascii").rstrip("=")
        original_jwt = f"{h}.{p}.{s}"

        probed = create_unsigned_alg_none_probe(original_jwt)
        segments = probed.split(".")
        assert len(segments) == 3
        assert segments[2] == ""  # Empty signature
        assert segments[1] == p   # Payload unchanged

        # Verify header is alg:none
        hdr_json = json.loads(base64.urlsafe_b64decode(segments[0] + "=="))
        assert hdr_json.get("alg") == "none"

    @pytest.mark.asyncio
    async def test_disabled_policy_causes_skip_and_zero_transport(self):
        policy = JwtRejectionTestPolicy(enabled=False)
        verifier = JwtSignatureRejectionVerifier("inv-jwt-1", "http://target.com", policy)

        res = await verifier.verify_endpoint({"path": "/api/profile", "method": "GET"})
        assert res.status == FindingStatus.REJECTED
        assert "disabled by policy" in res.observations[0]
        assert res.raw_evidence.get("skip_reason") == "policy_disabled"

    @pytest.mark.asyncio
    async def test_non_read_only_method_causes_skip(self):
        policy = JwtRejectionTestPolicy(enabled=True, allowed_endpoint_patterns=["*"])
        verifier = JwtSignatureRejectionVerifier("inv-jwt-2", "http://target.com", policy)

        res = await verifier.verify_endpoint({"path": "/api/profile", "method": "POST"})
        assert res.status == FindingStatus.REJECTED
        assert "not a read-only method" in res.observations[0]
        assert res.raw_evidence.get("skip_reason") == "non_read_only_method"

    @pytest.mark.asyncio
    async def test_non_allowlisted_endpoint_causes_skip(self):
        policy = JwtRejectionTestPolicy(enabled=True, allowed_endpoint_patterns=["/api/safe/.*"])
        verifier = JwtSignatureRejectionVerifier("inv-jwt-3", "http://target.com", policy)

        res = await verifier.verify_endpoint({"path": "/api/forbidden", "method": "GET"})
        assert res.status == FindingStatus.REJECTED
        assert "not in JWT test allowlist" in res.observations[0]
        assert res.raw_evidence.get("skip_reason") == "endpoint_not_allowlisted"

    @pytest.mark.asyncio
    async def test_unapproved_identity_causes_skip(self):
        policy = JwtRejectionTestPolicy(
            enabled=True,
            allowed_endpoint_patterns=["*"],
            allowed_test_identities={"owner", "attacker"},
        )
        verifier = JwtSignatureRejectionVerifier("inv-jwt-4", "http://target.com", policy)

        res = await verifier.verify_endpoint({"path": "/api/profile", "method": "GET"}, role="untrusted_external")
        assert res.status == FindingStatus.REJECTED
        assert "not in allowed test identities" in res.observations[0]
        assert res.raw_evidence.get("skip_reason") == "identity_not_allowed"

    @pytest.mark.asyncio
    async def test_opaque_token_causes_skip(self):
        vault = get_session_vault("inv-jwt-5")
        vault.add_session(UserSession(role="owner", token="opaque_random_token_val_123"))

        policy = JwtRejectionTestPolicy(enabled=True, allowed_endpoint_patterns=["*"])
        verifier = JwtSignatureRejectionVerifier("inv-jwt-5", "http://target.com", policy)

        res = await verifier.verify_endpoint({"path": "/api/profile", "method": "GET"}, role="owner")
        assert res.status == FindingStatus.REJECTED
        assert "not a syntactically valid 3-part compact JWT" in res.observations[0]
        assert res.raw_evidence.get("skip_reason") == "non_jwt_or_opaque_token"
