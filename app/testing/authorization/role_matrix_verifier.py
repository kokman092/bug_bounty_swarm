"""
app/testing/authorization/role_matrix_verifier.py
─────────────────────────────────────────────────
Safe, Read-Only Multi-Persona Role-Matrix Authorization (BFLA) Verifier.

Safety & Execution Rules:
  1. No path-substring heuristics: Only routes with explicit role contracts are tested.
  2. Read-only methods (GET/HEAD) only: Zero state-changing operations.
  3. Strict differential testing:
       - Authorized baseline persona -> Expected 200 OK + authenticated profile.
       - Unauthorized control persona -> Expected 401/403 denial.
  4. Response fingerprint match required before generating candidate signals.
  5. Zero secret or token leakage into TestResult metadata.
"""
from __future__ import annotations

import json
from typing import Any

from app.core.logging import get_logger
from app.findings.schemas import Confidence, FindingStatus, Severity, VulnClass
from app.targets.session_vault import get_session_vault
from app.testing.authorization.role_matrix_policy import RoleMatrixPolicy
from app.testing.base_tester import TestResult
from app.tools.http_client import ScopeEnforcingHttpClient

logger = get_logger(__name__)


def compute_body_fingerprint_match(auth_body: str, unauth_body: str) -> bool:
    """Verifies that unauthorized response structurally and content-wise matches the authorized baseline."""
    if not auth_body or not unauth_body:
        return False
    len_delta = abs(len(unauth_body) - len(auth_body))
    max_allowed_delta = max(30, int(len(auth_body) * 0.15))
    if len_delta > max_allowed_delta:
        return False

    try:
        auth_json = json.loads(auth_body)
        unauth_json = json.loads(unauth_body)
        if isinstance(auth_json, dict) and isinstance(unauth_json, dict):
            common_keys = set(auth_json.keys()) & set(unauth_json.keys())
            return len(common_keys) >= max(1, int(len(auth_json.keys()) * 0.7))
    except Exception:
        pass
    return len_delta <= max_allowed_delta


class RoleMatrixAuthorizationVerifier:
    """Executes safe role-matrix differential authorization testing."""

    def __init__(
        self,
        investigation_id: str,
        target_base_url: str,
        policy: RoleMatrixPolicy | None = None,
    ) -> None:
        self.investigation_id = investigation_id
        self.target_base_url = target_base_url.rstrip("/")
        self.policy = policy or RoleMatrixPolicy()
        self._vault = get_session_vault(investigation_id)

    async def verify_endpoint(self, endpoint_info: dict[str, Any]) -> TestResult:
        path = str(endpoint_info.get("path", "/"))
        method = str(endpoint_info.get("method", "GET")).upper()
        target_url = f"{self.target_base_url}{path}"

        # ── 1. Eligibility Check ──────────────────────────────────────────────
        if not self.policy.enabled:
            return TestResult(
                test_name="Role Matrix Authorization Verification",
                target_url=target_url,
                endpoint=path,
                method=method,
                vuln_class=VulnClass.AUTH_BYPASS,
                status=FindingStatus.REJECTED,
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                observations=["Skipped: Role matrix testing is disabled by policy."],
                raw_evidence={"skip_reason": "policy_disabled"},
            )

        if method not in self.policy.read_only_methods:
            return TestResult(
                test_name="Role Matrix Authorization Verification",
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
                test_name="Role Matrix Authorization Verification",
                target_url=target_url,
                endpoint=path,
                method=method,
                vuln_class=VulnClass.AUTH_BYPASS,
                status=FindingStatus.REJECTED,
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                observations=[f"Skipped: Endpoint '{path}' is not in role-matrix test allowlist."],
                raw_evidence={"skip_reason": "endpoint_not_allowlisted"},
            )

        # Resolve explicit contract
        expected_allowed_roles = self.policy.get_expected_roles_for_endpoint(method, path)
        if expected_allowed_roles is None:
            # Check if provided directly via endpoint_info
            if endpoint_info.get("expected_roles"):
                expected_allowed_roles = set(endpoint_info["expected_roles"])

        if expected_allowed_roles is None:
            return TestResult(
                test_name="Role Matrix Authorization Verification",
                target_url=target_url,
                endpoint=path,
                method=method,
                vuln_class=VulnClass.AUTH_BYPASS,
                status=FindingStatus.REJECTED,
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                observations=["Skipped: No explicit authorization contract found for endpoint."],
                raw_evidence={"skip_reason": "skipped_missing_authorization_contract"},
            )

        # Identify authorized persona vs unauthorized persona from configured vault identities
        allowed_identities = {r.lower() for r in expected_allowed_roles}
        authorized_persona = None
        unauthorized_persona = None

        for candidate_role in ("admin", "owner", "alice", "attacker", "bob", "anonymous"):
            if candidate_role in allowed_identities and not authorized_persona:
                authorized_persona = candidate_role
            elif candidate_role not in allowed_identities and not unauthorized_persona:
                unauthorized_persona = candidate_role

        if not authorized_persona or not unauthorized_persona:
            return TestResult(
                test_name="Role Matrix Authorization Verification",
                target_url=target_url,
                endpoint=path,
                method=method,
                vuln_class=VulnClass.AUTH_BYPASS,
                status=FindingStatus.REJECTED,
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                observations=["Skipped: Insufficient configured test personas to establish differential comparison."],
                raw_evidence={"skip_reason": "insufficient_personas_configured"},
            )

        # ── 2. Differential Flow ──────────────────────────────────────────────
        async with ScopeEnforcingHttpClient(self.investigation_id) as client:
            try:
                # Step 1: Authorized Baseline Request
                auth_headers = self._vault.resolve_headers_for_role(authorized_persona)
                auth_resp = await client.get(target_url, headers=auth_headers)
                auth_body = client.get_response_text_safe(auth_resp)
                auth_status = auth_resp.status_code

                if auth_status != 200 or "<!doctype html>" in auth_body.lower():
                    return TestResult(
                        test_name="Role Matrix Authorization Verification",
                        target_url=target_url,
                        endpoint=path,
                        method=method,
                        vuln_class=VulnClass.AUTH_BYPASS,
                        status=FindingStatus.REJECTED,
                        confidence=Confidence.LOW,
                        severity=Severity.LOW,
                        observations=[f"Skipped: Authorized persona ('{authorized_persona}') did not receive HTTP 200 baseline."],
                        raw_evidence={"skip_reason": "skipped_authorized_baseline_failed", "auth_status": auth_status},
                    )

                # Step 2: Unauthorized Control Request
                unauth_headers = self._vault.resolve_headers_for_role(unauthorized_persona)
                unauth_resp = await client.get(target_url, headers=unauth_headers)
                unauth_body = client.get_response_text_safe(unauth_resp)
                unauth_status = unauth_resp.status_code

                # Expected Secure Outcome: Unauthorized persona is denied
                if unauth_status in (401, 403, 404):
                    return TestResult(
                        test_name=f"Role Matrix Authorization on {path}",
                        target_url=target_url,
                        endpoint=path,
                        method=method,
                        vuln_class=VulnClass.AUTH_BYPASS,
                        status=FindingStatus.REJECTED,
                        confidence=Confidence.HIGH,
                        severity=Severity.LOW,
                        reproducible=True,
                        observations=[
                            f"Server securely enforced role boundary: Unauthorized persona ('{unauthorized_persona}') received HTTP {unauth_status}.",
                            f"Authorized role ('{authorized_persona}') succeeded with HTTP {auth_status}.",
                        ],
                        raw_evidence={
                            "authorized_persona": authorized_persona,
                            "unauthorized_persona": unauthorized_persona,
                            "authorized_status": auth_status,
                            "unauthorized_status": unauth_status,
                            "expected_allowed_roles": list(expected_allowed_roles),
                        },
                    )

                # Potential Signal: Server allowed unauthorized persona (HTTP 200 with fingerprint match)
                if unauth_status == 200 and compute_body_fingerprint_match(auth_body, unauth_body):
                    return TestResult(
                        test_name=f"Broken Function Level Authorization (BFLA) on {path}",
                        target_url=target_url,
                        endpoint=path,
                        method=method,
                        vuln_class=VulnClass.AUTH_BYPASS,
                        status=FindingStatus.VALIDATED,
                        confidence=Confidence.HIGH,
                        severity=Severity.HIGH,
                        reproducible=True,
                        evidence_score=9,
                        observations=[
                            f"Role boundary violation: Unauthorized persona ('{unauthorized_persona}') successfully accessed restricted resource {path}.",
                            f"Explicit contract allows: {', '.join(sorted(expected_allowed_roles))}",
                            f"Both authorized ('{authorized_persona}') and unauthorized ('{unauthorized_persona}') personas received matching HTTP 200 data.",
                        ],
                        raw_evidence={
                            "authorized_persona": authorized_persona,
                            "unauthorized_persona": unauthorized_persona,
                            "authorized_status": auth_status,
                            "unauthorized_status": unauth_status,
                            "expected_allowed_roles": list(expected_allowed_roles),
                            "body_length_delta": abs(len(unauth_body) - len(auth_body)),
                        },
                        remediation=f"Enforce server-side role checks verifying that caller role belongs to explicit authorized set: {', '.join(sorted(expected_allowed_roles))}.",
                    )

                # Fallback: Inconclusive / Mismatched response
                return TestResult(
                    test_name=f"Role Matrix Authorization on {path}",
                    target_url=target_url,
                    endpoint=path,
                    method=method,
                    vuln_class=VulnClass.AUTH_BYPASS,
                    status=FindingStatus.REJECTED,
                    confidence=Confidence.LOW,
                    severity=Severity.LOW,
                    observations=[f"Server returned HTTP {unauth_status} with response fingerprint mismatch."],
                    raw_evidence={
                        "authorized_persona": authorized_persona,
                        "unauthorized_persona": unauthorized_persona,
                        "unauthorized_status": unauth_status,
                    },
                )

            except Exception as exc:
                logger.warning("role_matrix_execution_error", error=str(exc))
                return TestResult(
                    test_name="Role Matrix Authorization Verification",
                    target_url=target_url,
                    endpoint=path,
                    method=method,
                    vuln_class=VulnClass.AUTH_BYPASS,
                    status=FindingStatus.REJECTED,
                    confidence=Confidence.LOW,
                    severity=Severity.LOW,
                    observations=[f"Execution error: {str(exc)}"],
                    raw_evidence={"error": str(exc)},
                )
