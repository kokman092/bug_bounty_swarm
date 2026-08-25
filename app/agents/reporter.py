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

            finding_items.append(
                ReportFindingItem(
                    finding_id=f.finding_id,
                    title=f.title,
                    severity=f.severity.value,
                    vuln_class=f.vuln_class.value,
                    affected_endpoint=f.endpoint,
                    description=f.evidence_summary or f"Authorization vulnerability detected on {f.endpoint}",
                    impact="Cross-user unauthorized data access violating tenant and object boundary isolation.",
                    reproduction_steps=[
                        f"1. Authenticate as User A (legitimate resource owner) and observe legitimate access.",
                        f"2. Authenticate as User B (unauthorized attacker) and send request to: `{f.endpoint}`.",
                        f"3. Observe HTTP 200 response returning User A's private data to User B.",
                    ],
                    remediation=f.remediation_guidance or "Enforce server-side authorization checks verifying user ownership on the queried object ID.",
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
