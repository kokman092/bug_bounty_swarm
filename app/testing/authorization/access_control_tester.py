"""
app/testing/authorization/access_control_tester.py
─────────────────────────────────────────────────
OWASP A01:2021 / API1:2023 & API5:2023 Authorization Testing Engine:
  1. Broken Object Level Authorization (BOLA / IDOR):
     - Multi-Persona Differential: Control (Account A) vs Test (Account B) on candidate resource IDs.
  2. Broken Function Level Authorization (BFLA):
     - Administrative endpoints called with low-privileged user tokens.
  3. Semantic Evidence Graph Verification.
"""
from __future__ import annotations

from typing import Any

from app.agents.validator import SemanticEvidenceEngine
from app.core.logging import get_logger
from app.findings.schemas import Confidence, FindingStatus, Severity, VulnClass
from app.targets.session_vault import get_session_vault
from app.testing.authorization.role_matrix_policy import RoleMatrixPolicy
from app.testing.authorization.role_matrix_verifier import RoleMatrixAuthorizationVerifier
from app.testing.base_tester import BaseTester, TestResult
from app.tools.http_client import ScopeEnforcingHttpClient
from app.tools.param_normalizer import normalize_test_path

logger = get_logger(__name__)


class AccessControlTester(BaseTester):
    """Automated BOLA, IDOR, and BFLA authorization testing engine."""

    def __init__(
        self,
        investigation_id: str,
        target_base_url: str,
        role_matrix_policy: RoleMatrixPolicy | None = None,
    ) -> None:
        super().__init__(investigation_id, target_base_url)
        self._vault = get_session_vault(investigation_id)
        self._validator = SemanticEvidenceEngine()
        self.role_matrix_policy = role_matrix_policy
        self._role_matrix_verifier = RoleMatrixAuthorizationVerifier(
            investigation_id=investigation_id,
            target_base_url=target_base_url,
            policy=role_matrix_policy or RoleMatrixPolicy(),
        )

    async def execute_test(self, endpoint_info: dict[str, Any]) -> list[TestResult]:
        path = endpoint_info.get("path", "/")
        method = endpoint_info.get("method", "GET").upper()
        results: list[TestResult] = []

        # ── 0. Optional Role-Matrix BFLA Verification (Step 5B) ──────────────
        if self.role_matrix_policy and self.role_matrix_policy.enabled:
            rm_res = await self._role_matrix_verifier.verify_endpoint(endpoint_info)
            if rm_res.status == FindingStatus.VALIDATED:
                results.append(rm_res)


        # Replace template placeholders like /api/orders/{{order_id}} -> /api/orders/1
        clean_path = normalize_test_path(path)
        target_url = f"{self.target_base_url}{clean_path}"

        # Resolve credentials for Owner (Alice) vs Attacker (Bob)
        owner_headers = self._vault.resolve_headers_for_role("owner")
        attacker_headers = self._vault.resolve_headers_for_role("attacker")

        async with ScopeEnforcingHttpClient(self.investigation_id) as client:
            try:
                # ── 1. Control Request (Legitimate Owner) ──────────────────────
                control_resp = await client._request(method, target_url, headers=owner_headers)
                control_body = client.get_response_text_safe(control_resp)
                control_status = control_resp.status_code

                # ── 2. Test Request (Unauthorized Attacker) ────────────────────
                test_resp = await client._request(method, target_url, headers=attacker_headers)
                test_body = client.get_response_text_safe(test_resp)
                test_status = test_resp.status_code

                # ── 3. Validate with Semantic Evidence Engine ─────────────────
                verdict, val_block, conf, eg = self._validator.evaluate_finding(
                    vuln_type="BOLA",
                    method=method,
                    endpoint=clean_path,
                    http_status=test_status,
                    response_body=test_body,
                    request_body=None,
                    caller_user_id=2,
                )

                if verdict == "CONFIRMED":
                    results.append(
                        TestResult(
                            test_name=f"Broken Object Level Authorization (BOLA) on {clean_path}",
                            target_url=target_url,
                            endpoint=clean_path,
                            method=method,
                            vuln_class=VulnClass.BOLA,
                            status=FindingStatus.VALIDATED,
                            confidence=Confidence.HIGH if conf >= 0.90 else Confidence.MEDIUM,
                            severity=Severity.HIGH,
                            reproducible=True,
                            evidence_score=10,
                            observations=[
                                f"Unauthorized user successfully accessed private resource on {clean_path}.",
                                f"Evidence Level: {eg.evidence_level.name} ({eg.evidence_level.value})",
                                f"Semantic Summary: {eg.semantic_summary}",
                            ],
                            raw_evidence={
                                "control_status": control_status,
                                "test_status": test_status,
                                "evidence_tree": eg.render_ascii_tree(),
                            },
                            remediation="Enforce server-side authorization checks verifying that the authenticated user owns or is explicitly authorized to access the requested object ID.",
                        )
                    )

            except Exception as exc:
                logger.debug("access_control_test_error", path=clean_path, error=str(exc))

        return results
