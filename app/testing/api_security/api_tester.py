"""
app/testing/api_security/api_tester.py
──────────────────────────────────────
OWASP API3:2023 / API4:2023 API Security Testing Engine:
  1. Broken Object Property Level Authorization (Mass Assignment):
     - Injects privileged fields (`role: admin`, `tier: enterprise`, `is_admin: true`) on mutation endpoints.
     - Detects state transition in response payloads.
  2. Unrestricted Resource Consumption:
     - Tests excessive pagination / limit parameter bounds safely.
"""
from __future__ import annotations

from typing import Any

from app.agents.validator import SemanticEvidenceEngine
from app.core.logging import get_logger
from app.findings.schemas import Confidence, FindingStatus, Severity, VulnClass
from app.targets.session_vault import get_session_vault
from app.testing.api_security.resource_consumption_policy import ResourceConsumptionPolicy
from app.testing.api_security.resource_consumption_verifier import ResourceConsumptionVerifier
from app.testing.api_security.response_property_policy import ResponsePropertyPolicy
from app.testing.api_security.response_property_verifier import ResponsePropertyVerifier
from app.testing.base_tester import BaseTester, TestResult
from app.tools.http_client import ScopeEnforcingHttpClient

logger = get_logger(__name__)


class ApiSecurityTester(BaseTester):
    """Automated API Security Top 10 testing engine."""

    def __init__(
        self,
        investigation_id: str,
        target_base_url: str,
        response_property_policy: ResponsePropertyPolicy | None = None,
        resource_consumption_policy: ResourceConsumptionPolicy | None = None,
    ) -> None:
        super().__init__(investigation_id, target_base_url)
        self._vault = get_session_vault(investigation_id)
        self._validator = SemanticEvidenceEngine()
        self.response_property_policy = response_property_policy
        self._response_property_verifier = ResponsePropertyVerifier(
            investigation_id=investigation_id,
            target_base_url=target_base_url,
            policy=response_property_policy or ResponsePropertyPolicy(),
        )
        self.resource_consumption_policy = resource_consumption_policy
        self._resource_verifier = ResourceConsumptionVerifier(
            investigation_id=investigation_id,
            target_base_url=target_base_url,
            policy=resource_consumption_policy or ResourceConsumptionPolicy(),
        )

    async def execute_test(self, endpoint_info: dict[str, Any]) -> list[TestResult]:
        path = endpoint_info.get("path", "/")
        method = endpoint_info.get("method", "GET").upper()
        results: list[TestResult] = []
        target_url = f"{self.target_base_url}{path}"
        headers = self._vault.resolve_headers_for_role("attacker")

        # ── 0a. Optional Response Property Authorization Verification (Step 5C)
        if self.response_property_policy and self.response_property_policy.enabled:
            rp_res = await self._response_property_verifier.verify_endpoint(endpoint_info)
            if rp_res.status == FindingStatus.VALIDATED:
                results.append(rp_res)

        # ── 0b. Optional Bounded Resource Consumption Verification (Step 5D) ──
        if self.resource_consumption_policy and self.resource_consumption_policy.enabled:
            rc_res = await self._resource_verifier.verify_endpoint(endpoint_info)
            if rc_res.status == FindingStatus.VALIDATED:
                results.append(rc_res)



        async with ScopeEnforcingHttpClient(self.investigation_id) as client:
            # ── 1. Mass Assignment (State Mutation) ───────────────────────────
            if method in ("PUT", "PATCH", "POST") or any(k in path.lower() for k in ["/profile", "/user", "/account", "/settings"]):
                mutation_payloads = [
                    {"role": "admin", "is_admin": True},
                    {"tier": "enterprise", "plan": "unlimited"},
                    {"verified": True, "status": "active"},
                ]
                for payload in mutation_payloads:
                    try:
                        mut_resp = await client.put(
                            target_url,
                            json_body=payload,
                            headers=headers,
                        )
                        mut_body = client.get_response_text_safe(mut_resp)

                        verdict, val_block, conf, eg = self._validator.evaluate_finding(
                            vuln_type="MassAssignment",
                            method="PUT",
                            endpoint=path,
                            http_status=mut_resp.status_code,
                            response_body=mut_body,
                            request_body=payload,
                            caller_user_id=2,
                        )

                        if verdict == "CONFIRMED":
                            results.append(
                                TestResult(
                                    test_name=f"Mass Assignment / Broken Property Authorization on {path}",
                                    target_url=target_url,
                                    endpoint=path,
                                    method="PUT",
                                    vuln_class=VulnClass.MASS_ASSIGNMENT,
                                    status=FindingStatus.VALIDATED,
                                    confidence=Confidence.HIGH,
                                    severity=Severity.HIGH,
                                    reproducible=True,
                                    evidence_score=9,
                                    observations=[
                                        f"Server allowed unauthorized privilege field mutation with payload: {payload}",
                                        f"Semantic State: {eg.semantic_summary}",
                                    ],
                                    raw_evidence={
                                        "status_code": mut_resp.status_code,
                                        "payload_sent": payload,
                                        "evidence_tree": eg.render_ascii_tree(),
                                    },
                                    remediation="Use explicit Data Transfer Objects (DTOs) or input allowlists to filter permitted request fields. Never bind incoming JSON payloads directly to database models.",
                                )
                            )
                            break
                    except Exception as exc:
                        logger.debug("mass_assignment_test_error", path=path, error=str(exc))

            # ── 2. Safe Pagination / Resource Limit Testing ───────────────────
            if method == "GET":
                try:
                    limit_resp = await client.get(
                        target_url,
                        params={"limit": "10000", "size": "10000"},
                        headers=headers,
                    )
                    # Check if response payload returned an un-capped massive list (>100 items)
                    body = client.get_response_text_safe(limit_resp)
                    if limit_resp.status_code == 200 and len(body) > 200_000:
                        results.append(
                            TestResult(
                                test_name=f"Unrestricted Resource Consumption on {path}",
                                target_url=target_url,
                                endpoint=path,
                                method="GET",
                                vuln_class=VulnClass.MISCONFIG,
                                status=FindingStatus.VALIDATED,
                                confidence=Confidence.MEDIUM,
                                severity=Severity.MEDIUM,
                                reproducible=True,
                                evidence_score=8,
                                observations=[
                                    f"Endpoint served uncapped dataset ({len(body)} bytes) without enforcing server-side pagination ceilings.",
                                ],
                                raw_evidence={
                                    "status_code": 200,
                                    "response_size_bytes": len(body),
                                },
                                remediation="Enforce strict maximum limits on query pagination parameters (e.g. max limit=100) on the server side.",
                            )
                        )
                except Exception as exc:
                    logger.debug("resource_limit_test_error", path=path, error=str(exc))

        return results
