"""
app/agents/reporter.py
──────────────────────
ReportAgent — Compiles ONLY validated security findings into HackerOne/Bugcrowd
ready reports with concrete curl PoC reproduction steps and remediation guidance using Gemini LLMs.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.agents.llm_client import agenerate_structured_content
from app.core.logging import get_logger
from app.findings.schemas import Finding, FindingStatus
from app.findings.service import FindingService
from app.reports.schemas import InvestigationReport, ReportFindingItem

logger = get_logger(__name__)

SYSTEM_INSTRUCTION = """
You are an expert Security Assessment Technical Writer and Bug Bounty Triage Specialist.
Generate a clean, structured HackerOne/Bugcrowd ready Markdown security assessment report summarizing the validated findings.

Format each finding with:
- Severity & Title
- Vulnerability Type & Affected Endpoint
- Root Cause & Description
- Step-by-Step Proof of Concept (PoC) with executable curl commands
- Impact Assessment
- Actionable Developer Remediation Guidance
"""


def _build_poc_and_steps(
    vuln_class_val: str,
    endpoint: str,
    title: str,
    base_url: str,
    attacker_token: str,
) -> tuple[str, list[str], str, str]:
    """
    Returns (poc_curl, reproduction_steps, impact, remediation) tailored to the specific vulnerability type.
    """
    base = base_url.rstrip("/")
    ep = endpoint if endpoint.startswith("/") else f"/{endpoint}"
    full_url = f"{base}{ep}"
    ep_lower = ep.lower()
    title_lower = title.lower()

    if "jwt" in ep_lower or "jwt" in title_lower or "algorithm none" in title_lower:
        token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJib2IiLCJyb2xlIjoiYWRtaW4ifQ."
        poc_curl = f'curl -X GET "{full_url}" \\\n     -H "Authorization: Bearer {token}" \\\n     -H "Accept: application/json"'
        steps = [
            '1. Construct an unsigned JWT token with header `{"alg": "none", "typ": "JWT"}` and administrative payload `{"sub": "bob", "role": "admin"}`.',
            f'2. Send a GET request to `{ep}` supplying the forged token in the Authorization header.',
            '3. Observe HTTP 200 response with administrative privileges, confirming signature verification bypass.',
        ]
        impact = "Complete authentication bypass allowing unauthenticated remote actors to forge arbitrary administrative sessions."
        remediation = "Enforce strict cryptographic signature verification on all received JWT tokens. Explicitly reject tokens with algorithm 'none' and restrict allowed algorithms to secure asymmetric algorithms (e.g. RS256/ES256)."
        return poc_curl, steps, impact, remediation

    if "debug" in ep_lower or "metric" in ep_lower or vuln_class_val == "InfoDisclosure":
        poc_curl = f'curl -X GET "{full_url}" \\\n     -H "Accept: application/json"'
        steps = [
            f'1. Send an unauthenticated GET request to `{ep}`.',
            '2. Inspect the HTTP response headers and body.',
            '3. Observe sensitive internal infrastructure details, backend endpoints, or cloud metadata URLs exposed without authentication.',
        ]
        impact = "Exposes internal system configuration, network topology, and sensitive microservice endpoints to unauthenticated remote attackers."
        remediation = "Restrict debug and metrics endpoints to internal management networks or require authenticated administrative credentials."
        return poc_curl, steps, impact, remediation

    if "webhook" in ep_lower or vuln_class_val == "SSRF":
        poc_curl = f'curl -X POST "{full_url}" \\\n     -H "Authorization: Bearer {attacker_token}" \\\n     -H "Content-Type: application/json" \\\n     -d \'{{"webhook_url": "http://169.254.169.254/latest/meta-data/"}}\''
        steps = [
            '1. Authenticate with standard user credentials.',
            f'2. Send a POST request to `{ep}` supplying a cloud metadata target (`http://169.254.169.254/latest/meta-data/`) in the `webhook_url` parameter.',
            '3. Observe the server attempting outbound connection to the protected internal metadata IP address.',
        ]
        impact = "Server-Side Request Forgery enables unauthorized probing of internal cloud metadata, IAM credentials, and intranet microservices."
        remediation = "Implement strict URL domain whitelisting and block all loopback, link-local (169.254.169.254), and private IP ranges (RFC 1918) on server-side requests."
        return poc_curl, steps, impact, remediation

    if "profile" in ep_lower or vuln_class_val == "MassAssignment":
        poc_curl = f'curl -X PUT "{full_url}" \\\n     -H "Authorization: Bearer {attacker_token}" \\\n     -H "Content-Type: application/json" \\\n     -d \'{{"role": "admin", "email": "attacker@pwned.io"}}\''
        steps = [
            '1. Authenticate as a standard unprivileged user.',
            f'2. Send a PUT request to `{ep}` injecting the privileged property `role: "admin"`.',
            '3. Observe the application accepting and persisting the elevated role without authorization validation.',
        ]
        impact = "Unprivileged users can unilaterally escalate their account privileges to full system administrator."
        remediation = "Use explicit Data Transfer Objects (DTOs) with strict field whitelisting to prevent mass assignment of sensitive security attributes."
        return poc_curl, steps, impact, remediation

    if vuln_class_val == "SQLi" or "sqli" in ep_lower:
        poc_curl = f'curl -X GET "{full_url}?q=\' UNION SELECT 1,2,3,4-- -"'
        steps = [
            f'1. Send a request to `{ep}` appending a SQL injection payload in the query parameter.',
            '2. Observe query execution artifacts or unescaped database outputs returned in the response body.',
        ]
        impact = "Arbitrary SQL execution allowing unauthorized read, modification, or extraction of persistent database records."
        remediation = "Use parameterized queries, prepared statements, and Object-Relational Mappers (ORM) for all database operations."
        return poc_curl, steps, impact, remediation

    # Standard BOLA / IDOR / Authorization Differential
    poc_curl = f'curl -X GET "{full_url}" \\\n     -H "Authorization: Bearer {attacker_token}" \\\n     -H "Accept: application/json"'
    steps = [
        "1. Authenticate as User A (legitimate resource owner) and observe legitimate access.",
        f"2. Authenticate as User B (unauthorized attacker) and send request to: `{ep}`.",
        "3. Observe HTTP 200 response returning User A's private data to User B.",
    ]
    impact = "Cross-user unauthorized data access violating tenant and object boundary isolation."
    remediation = "Enforce server-side authorization checks verifying user ownership on the queried object ID."
    return poc_curl, steps, impact, remediation


class ReportAgent:
    """Compiles validated security findings into executive reports."""

    def __init__(
        self,
        investigation_id: str,
        target_url: str,
        finding_service: FindingService | None = None,
    ) -> None:
        self.investigation_id = investigation_id
        self.target_url = target_url
        self._finding_service = finding_service or FindingService()

    async def run(self) -> InvestigationReport:
        logger.info("report_agent_started", investigation_id=self.investigation_id)

        # 1. Read ONLY validated findings from Firestore
        validated_findings = await self._finding_service.list_findings(
            self.investigation_id,
            status_filter=FindingStatus.VALIDATED,
        )

        finding_items: list[ReportFindingItem] = []
        attacker_tokens: dict[str, str] = {}

        for f in validated_findings:
            token = "bob_token_456"
            if f.raw_evidence_inline:
                steps = f.raw_evidence_inline.get("steps_executed", [])
                for step in steps:
                    hdrs = step.get("request_headers") or {}
                    auth = hdrs.get("Authorization", "")
                    if step.get("step_number", 0) == 2 and auth:
                        token = auth.replace("Bearer ", "").strip()
                        break
            attacker_tokens[f.finding_id] = token

            poc_curl, repro_steps, impact, remediation = _build_poc_and_steps(
                vuln_class_val=f.vuln_class.value,
                endpoint=f.endpoint,
                title=f.title,
                base_url=self.target_url,
                attacker_token=token,
            )

            finding_items.append(
                ReportFindingItem(
                    finding_id=f.finding_id,
                    title=f.title,
                    severity=f.severity.value,
                    vuln_class=f.vuln_class.value,
                    affected_endpoint=f.endpoint,
                    description=f.evidence_summary or f"Vulnerability detected on {f.endpoint}",
                    impact=impact,
                    reproduction_steps=repro_steps,
                    poc_curl=poc_curl,
                    remediation=f.remediation_guidance or remediation,
                    confidence=f.confidence.value if f.confidence else "High",
                )
            )

        # 2. Compile Markdown report via Gemini
        prompt = f"""
Target URL: {self.target_url}
Investigation ID: {self.investigation_id}
Validated Findings Count: {len(finding_items)}

Findings JSON:
{json.dumps([fi.model_dump(mode="json") for fi in finding_items], indent=2)}

Generate a professional HackerOne-ready Markdown security assessment report with Proof of Concept reproduction commands.
"""

        try:
            markdown_content = await agenerate_structured_content(
                contents=prompt,
                system_instruction=SYSTEM_INSTRUCTION,
                response_mime_type="text/plain",
                temperature=0.2,
            )
        except Exception as exc:
            logger.error("gemini_reporter_error", error=str(exc))
            md_lines = [
                f"# Security Assessment Report: {self.target_url}",
                f"\n**Investigation ID:** `{self.investigation_id}`",
                f"**Report Format:** HackerOne / Bugcrowd Triage Standards",
                f"**Total Validated Findings:** {len(finding_items)}\n",
                "## 1. Executive Summary",
                "An automated multi-agent security assessment was executed against the authorized target. All findings below have been deterministically verified with HTTP response differential proof.\n",
                "## 2. Validated Vulnerabilities\n",
            ]
            if not finding_items:
                md_lines.append("No critical vulnerabilities were discovered during this assessment.")
            for i, fi in enumerate(finding_items, 1):
                attacker_token = attacker_tokens.get(fi.finding_id, "bob_token_456")
                endpoint_clean = f"{self.target_url.rstrip('/')}{fi.affected_endpoint}"
                poc_curl = f'curl -X GET "{endpoint_clean}" \\\n     -H "Authorization: Bearer {attacker_token}" \\\n     -H "Accept: application/json"'

                md_lines.extend([
                    f"### {i}. [{fi.severity.upper()}] {fi.title}",
                    f"- **Vulnerability Type:** {fi.vuln_class}",
                    f"- **Affected Endpoint:** `{fi.affected_endpoint}`",
                    f"- **Confidence:** {fi.confidence}",
                    f"\n#### Vulnerability Description",
                    f"{fi.description}\n",
                    f"#### Step-by-Step Proof of Concept (PoC)",
                    "\n".join(fi.reproduction_steps),
                    f"\n```bash",
                    f"# PoC Verification Command",
                    f"{poc_curl}",
                    f"```\n",
                    f"#### Security Impact",
                    f"{fi.impact}\n",
                    f"#### Recommended Remediation",
                    f"{fi.remediation}\n",
                    "---",
                ])
            markdown_content = "\n".join(md_lines)

        report = InvestigationReport(
            investigation_id=self.investigation_id,
            target_url=self.target_url,
            finding_count=len(finding_items),
            findings=finding_items,
            markdown_report=markdown_content,
        )

        logger.info("report_agent_completed", finding_count=len(finding_items))
        return report
