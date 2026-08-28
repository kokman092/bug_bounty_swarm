"""
app/testing/authentication/auth_tester.py
─────────────────────────────────────────
OWASP A07:2021 / API2:2023 Broken Authentication Testing Engine:
  1. Unauthenticated Access on Protected Resources (Auth stripping).
  2. Token Tampering & None Algorithm Simulation (`Bearer none`, `Bearer null`).
  3. Sensitive Endpoint Exposure without Authentication Boundary.
"""
from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.findings.schemas import Confidence, FindingStatus, Severity, VulnClass
from app.testing.authentication.jwt_policy import JwtRejectionTestPolicy
from app.testing.authentication.jwt_verifier import JwtSignatureRejectionVerifier
from app.testing.base_tester import BaseTester, TestResult
from app.tools.http_client import ScopeEnforcingHttpClient

logger = get_logger(__name__)


class AuthenticationTester(BaseTester):
    """Automated Broken Authentication test suite."""

    def __init__(
        self,
        investigation_id: str,
        target_base_url: str,
        jwt_policy: JwtRejectionTestPolicy | None = None,
    ) -> None:
        super().__init__(investigation_id, target_base_url)
        self.jwt_policy = jwt_policy
        self._jwt_verifier = JwtSignatureRejectionVerifier(
            investigation_id=investigation_id,
            target_base_url=target_base_url,
            policy=jwt_policy or JwtRejectionTestPolicy(),
        )

    async def execute_test(self, endpoint_info: dict[str, Any]) -> list[TestResult]:
        path = endpoint_info.get("path", "/")
        requires_auth = endpoint_info.get("requires_auth", False)
        results: list[TestResult] = []
        target_url = f"{self.target_base_url}{path}"

        # ── 0. Optional JWT Signature Rejection Verifier (Step 5A) ───────────
        if self.jwt_policy and self.jwt_policy.enabled:
            jwt_res = await self._jwt_verifier.verify_endpoint(endpoint_info)
            if jwt_res.status == FindingStatus.VALIDATED:
                results.append(jwt_res)


        async with ScopeEnforcingHttpClient(self.investigation_id) as client:
            # ── 1. Unauthenticated Request on Protected Resource ───────────────
            if requires_auth or any(k in path.lower() for k in ["/user", "/profile", "/order", "/wallet", "/admin", "/account", "/cart", "/basket"]):
                try:
                    anon_resp = await client.get(
                        target_url,
                        headers={"Accept": "application/json"},  # Zero auth headers
                    )
                    body_text = client.get_response_text_safe(anon_resp).lower()
                    
                    # Ensure it is not an SPA HTML fallback
                    is_spa = "<!doctype html>" in body_text or "<html" in body_text

                    # If status is 200 OK on a user data route without auth headers
                    if anon_resp.status_code == 200 and not is_spa:
                        sensitive_markers = ["user_id", "email", "balance", "wallet", "orders", "profile", "phone", "address", "secret"]
                        found_markers = [m for m in sensitive_markers if m in body_text]

                        if found_markers:
                            results.append(
                                TestResult(
                                    test_name="Broken Authentication: Unprotected Private Data Route",
                                    target_url=target_url,
                                    endpoint=path,
                                    method="GET",
                                    vuln_class=VulnClass.AUTH_BYPASS,
                                    status=FindingStatus.VALIDATED,
                                    confidence=Confidence.HIGH,
                                    severity=Severity.HIGH,
                                    reproducible=True,
                                    evidence_score=9,
                                    observations=[
                                        f"Server returned HTTP 200 OK without any authentication header.",
                                        f"Private data fields disclosed anonymously: {', '.join(found_markers[:4])}",
                                    ],
                                    raw_evidence={
                                        "status_code": 200,
                                        "disclosed_fields": found_markers,
                                        "body_preview": body_text[:300],
                                    },
                                    remediation="Enforce mandatory authentication middleware before resolving user-specific or sensitive API routes.",
                                )
                            )
                except Exception as exc:
                    logger.debug("unauth_test_error", path=path, error=str(exc))

            # ── 2. Malformed / None Token Header Tampering ─────────────────────
            for fake_token in ["Bearer none", "Bearer null", "Bearer undefined", "Bearer"]:
                try:
                    fake_resp = await client.get(
                        target_url,
                        headers={"Authorization": fake_token, "Accept": "application/json"},
                    )
                    body_text = client.get_response_text_safe(fake_resp).lower()
                    is_spa = "<!doctype html>" in body_text or "<html" in body_text

                    if fake_resp.status_code == 200 and not is_spa and ("email" in body_text or "balance" in body_text or "wallet" in body_text):
                        results.append(
                            TestResult(
                                test_name=f"Authentication Bypass via Malformed Token ('{fake_token}')",
                                target_url=target_url,
                                endpoint=path,
                                method="GET",
                                vuln_class=VulnClass.AUTH_BYPASS,
                                status=FindingStatus.VALIDATED,
                                confidence=Confidence.HIGH,
                                severity=Severity.CRITICAL,
                                reproducible=True,
                                evidence_score=10,
                                observations=[
                                    f"Server accepted forged/placeholder Authorization header: '{fake_token}'",
                                    "Private resource rendered without valid cryptographic signature verification.",
                                ],
                                raw_evidence={
                                    "tested_token": fake_token,
                                    "status_code": 200,
                                    "body_preview": body_text[:300],
                                },
                                remediation="Reject all invalid or placeholder JWT signatures. Validate cryptographic signatures strictly against public key / HMAC secret.",
                            )
                        )
                        break
                except Exception as exc:
                    logger.debug("token_tamper_test_error", token=fake_token, error=str(exc))

        return results
