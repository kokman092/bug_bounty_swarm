"""
app/testing/authentication/jwt_verifier.py
──────────────────────────────────────────
Negative-only, read-only JWT signature-rejection verifier.

Safety & Token Handling Rules:
  1. Complete JWTs and decoded claims are treated as secrets.
  2. Tokens are never logged, persisted, or included in TestResult/event metadata.
  3. No claim modification, elevation, or tampering with sub/roles.
  4. Negative control test: Expected secure result is server rejection (401/403).
  5. Maximum 3 requests: Valid baseline -> Negative control -> 1 Tampered probe.
"""
from __future__ import annotations

import base64
import json
from typing import Any

from app.core.logging import get_logger
from app.findings.schemas import Confidence, FindingStatus, Severity, VulnClass
from app.targets.session_vault import get_session_vault
from app.testing.authentication.jwt_policy import JwtRejectionTestPolicy
from app.testing.base_tester import TestResult
from app.tools.http_client import ScopeEnforcingHttpClient

logger = get_logger(__name__)


def is_compact_jwt_candidate(token_str: str) -> bool:
    """
    Format classification only: Verifies that token string has a 3-segment compact JWT structure.
    NOTE: This is NOT cryptographic signature validation.
    """
    if not isinstance(token_str, str):
        return False
    clean = token_str.strip()
    if clean.lower().startswith("bearer "):
        clean = clean[7:].strip()
    segments = clean.split(".")
    if len(segments) != 3:
        return False
    # Validate that header segment decodes to valid JSON containing 'alg'
    try:
        header_b64 = segments[0]
        padding = "=" * ((4 - len(header_b64) % 4) % 4)
        header_json = json.loads(base64.urlsafe_b64decode(header_b64 + padding))
        return isinstance(header_json, dict) and "alg" in header_json
    except Exception:
        return False



def create_invalid_signature_probe(jwt_token: str) -> str:
    """Preserves header and payload, but replaces the signature with an invalid placeholder."""
    clean = jwt_token.strip()
    prefix = "Bearer " if clean.lower().startswith("bearer ") else ""
    raw = clean[len(prefix):].strip()
    segments = raw.split(".")
    if len(segments) != 3:
        return jwt_token
    # Replace signature with fixed invalid base64url bytes
    invalid_sig = base64.urlsafe_b64encode(b"invalidsignatureprobe").decode("ascii").rstrip("=")
    tampered = f"{segments[0]}.{segments[1]}.{invalid_sig}"
    return f"{prefix}{tampered}" if prefix else tampered


def create_unsigned_alg_none_probe(jwt_token: str) -> str:
    """Constructs an alg:none unsigned JWT keeping payload unchanged and omitting signature."""
    clean = jwt_token.strip()
    prefix = "Bearer " if clean.lower().startswith("bearer ") else ""
    raw = clean[len(prefix):].strip()
    segments = raw.split(".")
    if len(segments) < 2:
        return jwt_token
    none_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8")).decode("ascii").rstrip("=")
    tampered = f"{none_header}.{segments[1]}."
    return f"{prefix}{tampered}" if prefix else tampered


def compute_fingerprint_match(valid_body: str, probe_body: str) -> bool:
    """Verifies that probe response structurally and content-wise matches the authenticated baseline."""
    if not valid_body or not probe_body:
        return False
    # If probe body has significant length delta relative to baseline
    len_delta = abs(len(probe_body) - len(valid_body))
    max_allowed_delta = max(30, int(len(valid_body) * 0.15))
    if len_delta > max_allowed_delta:
        return False

    # Check JSON key similarity if both are JSON
    try:
        valid_json = json.loads(valid_body)
        probe_json = json.loads(probe_body)
        if isinstance(valid_json, dict) and isinstance(probe_json, dict):
            common_keys = set(valid_json.keys()) & set(probe_json.keys())
            return len(common_keys) >= max(1, int(len(valid_json.keys()) * 0.7))
    except Exception:
        pass
    return len_delta <= max_allowed_delta


class JwtSignatureRejectionVerifier:

    """Executes safe differential negative-control JWT rejection verification."""

    def __init__(
        self,
        investigation_id: str,
        target_base_url: str,
        policy: JwtRejectionTestPolicy | None = None,
    ) -> None:
        self.investigation_id = investigation_id
        self.target_base_url = target_base_url.rstrip("/")
        self.policy = policy or JwtRejectionTestPolicy()
        self._vault = get_session_vault(investigation_id)

    async def verify_endpoint(
        self,
        endpoint_info: dict[str, Any],
        role: str = "owner",
    ) -> TestResult:
        path = str(endpoint_info.get("path", "/"))
        method = str(endpoint_info.get("method", "GET")).upper()
        target_url = f"{self.target_base_url}{path}"

        # ── 1. Eligibility Check ──────────────────────────────────────────────
        if not self.policy.enabled:
            return TestResult(
                test_name="JWT Signature Rejection Verification",
                target_url=target_url,
                endpoint=path,
                method=method,
                vuln_class=VulnClass.AUTH_BYPASS,
                status=FindingStatus.REJECTED,
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                observations=["Skipped: JWT signature rejection testing is disabled by policy."],
                raw_evidence={"skip_reason": "policy_disabled"},
            )

        if method not in self.policy.read_only_methods:
            return TestResult(
                test_name="JWT Signature Rejection Verification",
                target_url=target_url,
                endpoint=path,
                method=method,
                vuln_class=VulnClass.AUTH_BYPASS,
                status=FindingStatus.REJECTED,
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                observations=[f"Skipped: Method '{method}' is not a read-only method in policy."],
                raw_evidence={"skip_reason": "non_read_only_method"},
            )

        if not self.policy.is_endpoint_allowed(path):
            return TestResult(
                test_name="JWT Signature Rejection Verification",
                target_url=target_url,
                endpoint=path,
                method=method,
                vuln_class=VulnClass.AUTH_BYPASS,
                status=FindingStatus.REJECTED,
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                observations=[f"Skipped: Endpoint '{path}' is not in JWT test allowlist."],
                raw_evidence={"skip_reason": "endpoint_not_allowlisted"},
            )

        if not self.policy.is_identity_allowed(role):
            return TestResult(
                test_name="JWT Signature Rejection Verification",
                target_url=target_url,
                endpoint=path,
                method=method,
                vuln_class=VulnClass.AUTH_BYPASS,
                status=FindingStatus.REJECTED,
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                observations=[f"Skipped: Role '{role}' is not in allowed test identities."],
                raw_evidence={"skip_reason": "identity_not_allowed"},
            )

        # Resolve auth headers from vault
        headers = self._vault.resolve_headers_for_role(role)
        auth_hdr = headers.get("Authorization") or headers.get("authorization", "")
        token_val = auth_hdr[7:].strip() if auth_hdr.lower().startswith("bearer ") else auth_hdr

        if not is_compact_jwt_candidate(token_val):
            return TestResult(
                test_name="JWT Signature Rejection Verification",
                target_url=target_url,
                endpoint=path,
                method=method,
                vuln_class=VulnClass.AUTH_BYPASS,
                status=FindingStatus.REJECTED,
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                observations=["Skipped: Resolved token is not a syntactically valid 3-part compact JWT."],
                raw_evidence={"skip_reason": "non_jwt_or_opaque_token"},
            )


        # ── 2. Three-Step Test Flow ───────────────────────────────────────────
        async with ScopeEnforcingHttpClient(self.investigation_id) as client:
            try:
                # Step 1: Valid baseline
                valid_resp = await client.get(target_url, headers={"Authorization": f"Bearer {token_val}", "Accept": "application/json"})
                valid_body = client.get_response_text_safe(valid_resp)
                valid_status = valid_resp.status_code

                if valid_status != 200 or "<!doctype html>" in valid_body.lower():
                    return TestResult(
                        test_name="JWT Signature Rejection Verification",
                        target_url=target_url,
                        endpoint=path,
                        method=method,
                        vuln_class=VulnClass.AUTH_BYPASS,
                        status=FindingStatus.REJECTED,
                        confidence=Confidence.LOW,
                        severity=Severity.LOW,
                        observations=["Skipped: Valid baseline did not return authenticated HTTP 200 response."],
                        raw_evidence={"skip_reason": "skipped_not_confirmed_protected", "baseline_status": valid_status},
                    )

                # Step 2: Negative control (Zero auth / invalid non-secret token)
                control_resp = await client.get(target_url, headers={"Accept": "application/json"})
                control_status = control_resp.status_code

                if control_status == 200:
                    return TestResult(
                        test_name="JWT Signature Rejection Verification",
                        target_url=target_url,
                        endpoint=path,
                        method=method,
                        vuln_class=VulnClass.AUTH_BYPASS,
                        status=FindingStatus.REJECTED,
                        confidence=Confidence.LOW,
                        severity=Severity.LOW,
                        observations=["Skipped: Unauthenticated negative control returned 200 OK (endpoint is public/unprotected)."],
                        raw_evidence={"skip_reason": "skipped_not_confirmed_protected", "control_status": control_status},
                    )

                # Step 3: Approved Tampered Probe
                if self.policy.allow_invalid_signature_probe:
                    probe_type = "invalid_signature_probe"
                    tampered_token = create_invalid_signature_probe(token_val)
                elif self.policy.allow_alg_none_probe:
                    probe_type = "unsigned_alg_none_probe"
                    tampered_token = create_unsigned_alg_none_probe(token_val)
                else:
                    return TestResult(
                        test_name="JWT Signature Rejection Verification",
                        target_url=target_url,
                        endpoint=path,
                        method=method,
                        vuln_class=VulnClass.AUTH_BYPASS,
                        status=FindingStatus.REJECTED,
                        confidence=Confidence.LOW,
                        severity=Severity.LOW,
                        observations=["Skipped: No tampered probe family is allowed by policy."],
                        raw_evidence={"skip_reason": "no_probe_allowed"},
                    )

                probe_resp = await client.get(target_url, headers={"Authorization": f"Bearer {tampered_token}", "Accept": "application/json"})
                probe_body = client.get_response_text_safe(probe_resp)
                probe_status = probe_resp.status_code

                # Verification of Rejection (Expected Secure Result)
                if probe_status in (401, 403, 400, 422):
                    return TestResult(
                        test_name="JWT Signature Rejection Verification",
                        target_url=target_url,
                        endpoint=path,
                        method=method,
                        vuln_class=VulnClass.AUTH_BYPASS,
                        status=FindingStatus.REJECTED,
                        confidence=Confidence.HIGH,
                        severity=Severity.LOW,
                        reproducible=True,
                        observations=[
                            f"Server securely rejected tampered token ({probe_type}) with HTTP {probe_status}.",
                        ],
                        raw_evidence={
                            "probe_type": probe_type,
                            "baseline_status": valid_status,
                            "control_status": control_status,
                            "probe_status": probe_status,
                            "token_state_label": probe_type,
                        },
                    )

                # Potential Signal: Server accepted tampered token (HTTP 200 with fingerprint match)
                if probe_status == 200 and compute_fingerprint_match(valid_body, probe_body):
                    return TestResult(

                        test_name=f"Authentication Bypass: Server Accepts Tampered JWT ({probe_type})",
                        target_url=target_url,
                        endpoint=path,
                        method=method,
                        vuln_class=VulnClass.AUTH_BYPASS,
                        status=FindingStatus.VALIDATED,
                        confidence=Confidence.HIGH,
                        severity=Severity.CRITICAL,
                        reproducible=True,
                        evidence_score=10,
                        observations=[
                            f"Server accepted tampered JWT probe ({probe_type}) without valid signature verification.",
                            f"Baseline status: HTTP {valid_status}; Negative control: HTTP {control_status}; Probe status: HTTP {probe_status}.",
                            "Private resource payload successfully rendered using tampered token state.",
                        ],
                        raw_evidence={
                            "probe_type": probe_type,
                            "baseline_status": valid_status,
                            "control_status": control_status,
                            "probe_status": probe_status,
                            "token_state_label": probe_type,
                            "status_code": 200,
                            "body_length_delta": abs(len(probe_body) - len(valid_body)),
                        },
                        remediation="Enforce mandatory cryptographic signature verification on all incoming JWTs. Explicitly reject unsigned tokens and tokens with invalid signatures.",
                    )

                # Fallback: Inconclusive status
                return TestResult(
                    test_name="JWT Signature Rejection Verification",
                    target_url=target_url,
                    endpoint=path,
                    method=method,
                    vuln_class=VulnClass.AUTH_BYPASS,
                    status=FindingStatus.REJECTED,
                    confidence=Confidence.LOW,
                    severity=Severity.LOW,
                    observations=[f"Server returned HTTP {probe_status} (fingerprint mismatch / unconfirmed signal)."],
                    raw_evidence={
                        "probe_type": probe_type,
                        "probe_status": probe_status,
                        "token_state_label": probe_type,
                    },
                )

            except Exception as exc:
                logger.warning("jwt_verifier_execution_error", error=str(exc))
                return TestResult(
                    test_name="JWT Signature Rejection Verification",
                    target_url=target_url,
                    endpoint=path,
                    method=method,
                    vuln_class=VulnClass.AUTH_BYPASS,
                    status=FindingStatus.REJECTED,
                    confidence=Confidence.LOW,
                    severity=Severity.LOW,
                    observations=[f"Error during execution: {str(exc)}"],
                    raw_evidence={"error": str(exc)},
                )
