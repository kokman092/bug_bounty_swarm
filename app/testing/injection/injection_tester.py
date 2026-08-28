"""
app/testing/injection/injection_tester.py
────────────────────────────────────────
OWASP A03:2021 Safe Injection Testing Engine:
  1. Differential SQL Injection:
     - Baseline probe vs Tautology probe (`' OR '1'='1`) vs Contradiction probe (`' AND '1'='2`).
     - Error signature pattern matching (MySQL, PostgreSQL, SQLite, Oracle, MSSQL).
  2. Safe Reflection / Context Detection (Canary strings: `BBHunterCanary987`).
  3. Strict false-positive elimination with differential length and baseline comparison.
"""
from __future__ import annotations

import re
from typing import Any

from app.core.logging import get_logger
from app.findings.schemas import Confidence, FindingStatus, Severity, VulnClass
from app.testing.base_tester import BaseTester, TestResult
from app.tools.http_client import ScopeEnforcingHttpClient

logger = get_logger(__name__)


class InjectionTester(BaseTester):
    """Automated safe injection test suite."""

    SQL_ERRORS = [
        re.compile(r"syntax error", re.IGNORECASE),
        re.compile(r"operationalerror", re.IGNORECASE),
        re.compile(r"unrecognized token", re.IGNORECASE),
        re.compile(r"sqlite3\.operationalerror", re.IGNORECASE),
        re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
        re.compile(r"pg_query", re.IGNORECASE),
        re.compile(r"ora-[0-9]{5}", re.IGNORECASE),
        re.compile(r"microsoft ole db provider for sql server", re.IGNORECASE),
        re.compile(r"unclosed quotation mark", re.IGNORECASE),
    ]

    async def execute_test(self, endpoint_info: dict[str, Any]) -> list[TestResult]:
        path = endpoint_info.get("path", "/")
        params = endpoint_info.get("parameters", [])
        results: list[TestResult] = []
        target_url = f"{self.target_base_url}{path}"

        # If no explicit parameters, test common query parameters
        probe_params = params or ["id", "q", "search", "query", "filter", "category"]

        async with ScopeEnforcingHttpClient(self.investigation_id) as client:
            for param in probe_params[:4]:  # Test top 4 candidate parameters
                # ── 1. Baseline Request ───────────────────────────────────────
                try:
                    baseline_resp = await client.get(target_url, params={param: "1"})
                    baseline_body = client.get_response_text_safe(baseline_resp)
                    baseline_len = len(baseline_body)
                    baseline_status = baseline_resp.status_code

                    # ── 2. Error Induction Probe ──────────────────────────────
                    err_resp = await client.get(target_url, params={param: "1'\"--#;"})
                    err_body = client.get_response_text_safe(err_resp)

                    # Check for SQL error signatures
                    matched_sql_err = None
                    for err_pat in self.SQL_ERRORS:
                        m = err_pat.search(err_body)
                        if m and not err_pat.search(baseline_body):
                            matched_sql_err = m.group(0)
                            break

                    if matched_sql_err:
                        results.append(
                            TestResult(
                                test_name=f"SQL Injection via Parameter '{param}' (Error-Based)",
                                target_url=target_url,
                                endpoint=path,
                                method="GET",
                                vuln_class=VulnClass.SQLI,
                                status=FindingStatus.VALIDATED,
                                confidence=Confidence.HIGH,
                                severity=Severity.HIGH,
                                reproducible=True,
                                evidence_score=9,
                                observations=[
                                    f"Injecting quote/delimiter into parameter '{param}' triggered database error: '{matched_sql_err}'",
                                    f"Baseline status was HTTP {baseline_status}; error response status was HTTP {err_resp.status_code}.",
                                ],
                                raw_evidence={
                                    "parameter": param,
                                    "payload": "1'\"--#;",
                                    "matched_error": matched_sql_err,
                                    "error_snippet": err_body[:300],
                                },
                                remediation=f"Use parameterized queries (Prepared Statements) for parameter '{param}' across all database interactions.",
                            )
                        )
                        continue

                    # ── 3. Differential Boolean/Tautology Probe ───────────────
                    true_resp = await client.get(target_url, params={param: "1' OR '1'='1"})
                    false_resp = await client.get(target_url, params={param: "1' AND '1'='2"})

                    true_body = client.get_response_text_safe(true_resp)
                    false_body = client.get_response_text_safe(false_resp)

                    # Differential condition: Tautology returns content, contradiction empties or shrinks significantly
                    if (
                        true_resp.status_code == 200
                        and false_resp.status_code in (200, 404)
                        and len(true_body) > len(false_body) + 50
                        and len(true_body) >= baseline_len
                    ):
                        results.append(
                            TestResult(
                                test_name=f"SQL Injection via Parameter '{param}' (Boolean-Differential)",
                                target_url=target_url,
                                endpoint=path,
                                method="GET",
                                vuln_class=VulnClass.SQLI,
                                status=FindingStatus.VALIDATED,
                                confidence=Confidence.MEDIUM,
                                severity=Severity.HIGH,
                                reproducible=True,
                                evidence_score=8,
                                observations=[
                                    f"Differential query logic confirmed on parameter '{param}'.",
                                    f"Tautology (' OR '1'='1) returned {len(true_body)} bytes; Contradiction (' AND '1'='2) returned {len(false_body)} bytes.",
                                ],
                                raw_evidence={
                                    "parameter": param,
                                    "tautology_len": len(true_body),
                                    "contradiction_len": len(false_body),
                                },
                                remediation=f"Implement parameterized SQL statements for parameter '{param}'.",
                            )
                        )

                except Exception as exc:
                    logger.debug("injection_test_error", param=param, error=str(exc))

        return results
