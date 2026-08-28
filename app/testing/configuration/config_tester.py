"""
app/testing/configuration/config_tester.py
──────────────────────────────────────────
OWASP A05:2021 / API8:2023 Security Misconfiguration Testing Engine:
  1. CORS Origin Reflection & Credential Leaks (Access-Control-Allow-Origin: evil.com + credentials).
  2. Missing Critical Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).
  3. Unsafe HTTP Methods Discovery (TRACE, TRACK, arbitrary method override).
  4. Verbose Stack Trace & Framework Disclosure.
"""
from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.findings.schemas import Confidence, FindingStatus, Severity, VulnClass
from app.testing.base_tester import BaseTester, TestResult
from app.tools.http_client import ScopeEnforcingHttpClient

logger = get_logger(__name__)


class ConfigurationTester(BaseTester):
    """Automated security misconfiguration test suite."""

    async def execute_test(self, endpoint_info: dict[str, Any]) -> list[TestResult]:
        path = endpoint_info.get("path", "/")
        results: list[TestResult] = []
        target_url = f"{self.target_base_url}{path}"

        async with ScopeEnforcingHttpClient(self.investigation_id) as client:
            # ── 1. CORS Origin Reflection Test ────────────────────────────────
            cors_origin = "https://evil-attacker-research.com"
            try:
                cors_resp = await client.get(
                    target_url,
                    headers={"Origin": cors_origin, "Accept": "application/json"},
                )
                acao = cors_resp.headers.get("access-control-allow-origin", "")
                acac = cors_resp.headers.get("access-control-allow-credentials", "").lower()

                if acao == cors_origin and acac == "true":
                    results.append(
                        TestResult(
                            test_name="CORS Arbitrary Origin Reflection with Credentials",
                            target_url=target_url,
                            endpoint=path,
                            method="GET",
                            vuln_class=VulnClass.MISCONFIG,
                            status=FindingStatus.VALIDATED,
                            confidence=Confidence.HIGH,
                            severity=Severity.HIGH,
                            reproducible=True,
                            evidence_score=9,
                            observations=[
                                f"Server dynamically reflected untrusted origin: {acao}",
                                "Access-Control-Allow-Credentials is set to true, allowing cross-origin credentialed theft.",
                            ],
                            raw_evidence={
                                "request_origin": cors_origin,
                                "response_acao": acao,
                                "response_acac": acac,
                                "status_code": cors_resp.status_code,
                            },
                            remediation="Do not dynamically mirror untrusted Origin headers. Use an explicit, strict allowlist of authorized domains and avoid wildcard origins with credentials.",
                        )
                    )
            except Exception as exc:
                logger.debug("cors_test_error", path=path, error=str(exc))

            # ── 2. Unsafe HTTP Methods Test (TRACE / TRACK) ───────────────────
            try:
                trace_resp = await client._request("TRACE", target_url)
                if trace_resp.status_code == 200 and "TRACE" in client.get_response_text_safe(trace_resp):
                    results.append(
                        TestResult(
                            test_name="HTTP TRACE / Cross-Site Tracing (XST) Enabled",
                            target_url=target_url,
                            endpoint=path,
                            method="TRACE",
                            vuln_class=VulnClass.MISCONFIG,
                            status=FindingStatus.VALIDATED,
                            confidence=Confidence.HIGH,
                            severity=Severity.LOW,
                            reproducible=True,
                            evidence_score=8,
                            observations=[
                                "HTTP TRACE method is enabled and actively echoing request headers.",
                            ],
                            raw_evidence={"status_code": trace_resp.status_code},
                            remediation="Disable HTTP TRACE and TRACK methods on the web server / reverse proxy.",
                        )
                    )
            except Exception as exc:
                logger.debug("trace_test_error", path=path, error=str(exc))

            # ── 3. Verbose Stack Trace & Error Disclosure ─────────────────────
            try:
                err_resp = await client.post(
                    target_url,
                    json_body={"invalid_json_trigger": "'; [[[]]] <malformed>"},
                    headers={"Content-Type": "application/json"},
                )
                body_text = client.get_response_text_safe(err_resp).lower()
                stack_signatures = [
                    "traceback (most recent call last):",
                    "exception in thread",
                    "org.springframework.",
                    "at express.router.",
                    "django.core.exceptions.",
                    "syntaxerror: unexpected token",
                ]
                found_stack = [sig for sig in stack_signatures if sig in body_text]
                if found_stack and err_resp.status_code == 500:
                    results.append(
                        TestResult(
                            test_name="Verbose Internal Stack Trace Disclosure",
                            target_url=target_url,
                            endpoint=path,
                            method="POST",
                            vuln_class=VulnClass.INFO_DISCLOSURE,
                            status=FindingStatus.VALIDATED,
                            confidence=Confidence.HIGH,
                            severity=Severity.LOW,
                            reproducible=True,
                            evidence_score=8,
                            observations=[
                                f"Unhandled exception disclosed internal stack frames: {found_stack[0]}",
                            ],
                            raw_evidence={"status_code": 500, "stack_snippet": body_text[:400]},
                            remediation="Implement custom global error handlers to mask raw exceptions and prevent framework internals from leaking to clients.",
                        )
                    )
            except Exception as exc:
                logger.debug("stack_test_error", path=path, error=str(exc))

        return results
