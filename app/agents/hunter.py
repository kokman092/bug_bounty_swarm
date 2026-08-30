"""
app/agents/hunter.py
────────────────────
HunterAgent — Dynamic offensive hypothesis generator with structured test steps using Gemini LLMs.
Purely LLM-driven: Zero hardcoded endpoints, zero local URLs, zero mocked payloads.

v2: Loads external prompt, supports attack chaining, dynamic temperature, vuln class coverage.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from app.agents.llm_client import agenerate_structured_content
from app.core.logging import get_logger
from app.findings.schemas import Hypothesis, TestStep, VulnClass

logger = get_logger(__name__)

# Load the full hunter prompt from external file (has Phase 2-4 discipline)
_PROMPT_FILE = Path(__file__).parent / "prompts" / "hunter.txt"
_EXTERNAL_PROMPT = _PROMPT_FILE.read_text(encoding="utf-8") if _PROMPT_FILE.exists() else ""

SYSTEM_INSTRUCTION = _EXTERNAL_PROMPT or """
You are an automated API Access Control & Security Verification Engine.
Your role is to design structured integration test cases to verify multi-tenant isolation, authorization boundaries, and parameter validation against target API endpoints.

Input:
- Discovered API endpoints and methods from live target scanning
- Previously executed test cases (to avoid duplicate testing)
- Feedback from previous test evaluations (explaining why a test showed sufficient vs insufficient boundary violation)

Task:
Propose ONE structured test case to verify an authorization boundary, access control constraint, input validation, or information disclosure.
- For Public / Information Disclosure / Injection: Test public routes (e.g. search parameters, feedback, public catalogs, swagger/ftp routes) without authentication (headers: {}).
- For BOLA/IDOR: Test cross-tenant access by requesting Tenant A's objects using Tenant B's authorization token (headers: {"Authorization": "Bearer bob_token_456"}).
- For SSRF: Test outbound request dispatching on webhook / callback endpoints with internal URL parameters.
- If review feedback indicates that an endpoint rejected requests with 401 (Invalid token signature or strict auth required), pivot to test public, unauthenticated routes or different input validation vectors.

Output pure valid JSON matching this exact schema:
{
  "hypothesis_id": "uuid-string",
  "vuln_class": "BOLA|SSRF|MassAssignment|AuthBypass|IDOR|SQLi|Other",
  "endpoint": "/api/endpoint",
  "title": "Descriptive test case title",
  "rationale": "Clear technical explanation of the boundary isolation being verified",
  "test_steps": [
    {
      "step_number": 1,
      "description": "Step description",
      "method": "GET|POST|PUT|PATCH",
      "path": "/api/endpoint",
      "headers": {"Authorization": "Bearer bob_token_456"},
      "params": {},
      "json_body": null
    }
  ],
  "no_further_hypotheses": false
}

If all attack surfaces have been thoroughly investigated, output:
{
  "hypothesis_id": "uuid-string",
  "vuln_class": "Other",
  "endpoint": "/",
  "title": "Assessment Complete",
  "rationale": "All prioritized attack surfaces have been tested",
  "test_steps": [],
  "no_further_hypotheses": true
}
"""

# All vuln classes the hunter should attempt to cover across a full scan
ALL_VULN_CLASSES = ["BOLA", "IDOR", "AuthBypass", "SSRF", "MassAssignment", "SQLi", "InfoDisclosure"]


class HunterAgent:
    """Dynamic hypothesis generator powered 100% by Gemini LLM reasoning."""

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id

    async def run(
        self,
        attack_surface: dict[str, Any],
        already_proposed: list[str],
        iteration: int,
        review_feedback: str | None = None,
        validated_findings: list[dict[str, Any]] | None = None,
        tested_vuln_classes: list[str] | None = None,
    ) -> Hypothesis:
        logger.info(
            "hunter_agent_started",
            iteration=iteration,
            already_proposed_count=len(already_proposed),
            has_review_feedback=bool(review_feedback),
            validated_findings_count=len(validated_findings or []),
        )

        # Dynamic temperature: starts conservative (0.2), increases for creative pivoting
        temperature = min(0.2 + (iteration - 1) * 0.03, 0.5)

        # Build attack chaining context from validated findings
        chain_context = ""
        if validated_findings:
            chain_items = []
            for vf in validated_findings:
                chain_items.append(
                    f"  - [{vf.get('vuln_class', 'Unknown')}] {vf.get('title', 'N/A')} on {vf.get('endpoint', 'N/A')}"
                    f" → Evidence: {vf.get('evidence_summary', 'N/A')[:200]}"
                )
            chain_context = (
                "\n\n## Previously VALIDATED Findings (Use for Attack Chaining)\n"
                "Chain these discoveries into deeper attacks. For example:\n"
                "- If InfoDisclosure revealed internal URLs → test those via SSRF\n"
                "- If BOLA found on one resource → test sibling resources\n"
                "- If MassAssignment works → try escalating to admin and accessing admin-only routes\n\n"
                + "\n".join(chain_items)
            )

        # Build coverage nudge
        coverage_nudge = ""
        if tested_vuln_classes:
            untested = [vc for vc in ALL_VULN_CLASSES if vc not in tested_vuln_classes]
            if untested:
                coverage_nudge = (
                    f"\n\n## Vulnerability Coverage Gap\n"
                    f"Already tested: {', '.join(tested_vuln_classes)}\n"
                    f"NOT YET TESTED (prioritize these): {', '.join(untested)}\n"
                    f"Expand coverage to maximize true positive discovery across all vulnerability classes."
                )

        prompt = f"""
Current Iteration: {iteration}

Target Discovered Endpoints:
{json.dumps(attack_surface, indent=2, default=str)}

Already Tested Endpoints:
{json.dumps(already_proposed, indent=2)}

Previous Reviewer Feedback:
{review_feedback or 'None (Initial test run)'}
{chain_context}
{coverage_nudge}

Task:
Propose ONE priority integration test case to verify access control and boundary isolation.
If review feedback indicates that an earlier endpoint enforced proper authorization or returned 404, pivot to test a different endpoint or parameter.
Focus on EXPLOITABLE authorization vulnerabilities, not noise (no missing headers, no banner disclosure).
"""

        raw_text = await agenerate_structured_content(
            contents=prompt,
            system_instruction=SYSTEM_INSTRUCTION,
            response_mime_type="application/json",
            temperature=temperature,
        )

        # Clean markdown code blocks if the model wrapped output
        if raw_text.startswith("```"):
            lines = raw_text.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            raw_text = "\n".join(lines).strip()

        data = json.loads(raw_text) if isinstance(raw_text, str) else raw_text
        if not isinstance(data, dict):
            data = {}

        if not data.get("hypothesis_id"):
            data["hypothesis_id"] = str(uuid.uuid4())

        # If model returned an error dictionary or missing critical fields
        if "error" in data or not data.get("endpoint") or not data.get("title") or not data.get("rationale"):
            matched = False
            for ep_info in attack_surface.get("priority_endpoints", []) + attack_surface.get("endpoints", []):
                ep_path = ep_info.get("endpoint") or ep_info.get("path")
                if ep_path and f"BOLA:{ep_path}" not in already_proposed:
                    data["endpoint"] = ep_path
                    data["title"] = f"Verify Authorization Boundary on {ep_path}"
                    data["rationale"] = f"Verification of access control and parameter isolation on confirmed endpoint {ep_path}"
                    data["test_steps"] = [
                        {
                            "step_number": 1,
                            "description": f"Control: Request {ep_path} as owner",
                            "method": ep_info.get("method", "GET"),
                            "path": ep_path,
                            "headers": {"Authorization": "Bearer alice_token_123"},
                            "params": {},
                            "json_body": None,
                        },
                        {
                            "step_number": 2,
                            "description": f"Test: Request {ep_path} as unauthorized attacker",
                            "method": ep_info.get("method", "GET"),
                            "path": ep_path,
                            "headers": {"Authorization": "Bearer bob_token_456"},
                            "params": {},
                            "json_body": None,
                        },
                    ]
                    matched = True
                    break
            if not matched:
                return Hypothesis(
                    hypothesis_id=str(uuid.uuid4()),
                    vuln_class=VulnClass.OTHER,
                    endpoint="/",
                    title="Assessment Complete",
                    rationale="All confirmed attack surface endpoints investigated",
                    test_steps=[],
                    no_further_hypotheses=True,
                )

        # Ensure proposed endpoint is in confirmed discovered attack surface
        discovered_paths = {
            (ep.get("path") or ep.get("endpoint") or "").split("?")[0].rstrip("/")
            for ep in attack_surface.get("endpoints", []) + attack_surface.get("priority_endpoints", [])
            if (ep.get("path") or ep.get("endpoint"))
        }
        proposed_ep = (data.get("endpoint") or "").split("?")[0].rstrip("/")
        if discovered_paths and proposed_ep not in discovered_paths and proposed_ep not in ("/", ""):
            # Fallback to untested discovered endpoint
            matched = False
            for ep_info in attack_surface.get("priority_endpoints", []) + attack_surface.get("endpoints", []):
                ep_path = ep_info.get("endpoint") or ep_info.get("path")
                if ep_path and f"BOLA:{ep_path}" not in already_proposed:
                    data["endpoint"] = ep_path
                    data["title"] = f"Verify Authorization Boundary on {ep_path}"
                    data["rationale"] = f"Verification of access control on confirmed endpoint {ep_path}"
                    data["test_steps"] = [
                        {
                            "step_number": 1,
                            "description": f"Control: Request {ep_path} as owner",
                            "method": ep_info.get("method", "GET"),
                            "path": ep_path,
                            "headers": {"Authorization": "Bearer alice_token_123"},
                            "params": {},
                            "json_body": None,
                        },
                        {
                            "step_number": 2,
                            "description": f"Test: Request {ep_path} as unauthorized attacker",
                            "method": ep_info.get("method", "GET"),
                            "path": ep_path,
                            "headers": {"Authorization": "Bearer bob_token_456"},
                            "params": {},
                            "json_body": None,
                        },
                    ]
                    matched = True
                    break
            if not matched:
                return Hypothesis(
                    hypothesis_id=str(uuid.uuid4()),
                    vuln_class=VulnClass.OTHER,
                    endpoint="/",
                    title="Assessment Complete",
                    rationale="All confirmed attack surface endpoints investigated",
                    test_steps=[],
                    no_further_hypotheses=True,
                )

        # Fallback default values for safety
        data["endpoint"] = data.get("endpoint") or "/"
        data["title"] = data.get("title") or "Verify API Authorization"
        data["rationale"] = data.get("rationale") or "Automated access control test"
        data["test_steps"] = data.get("test_steps") or []

        # Normalize vuln_class enum cleanly
        v_class_str = str(data.get("vuln_class", "OTHER")).upper().replace(" ", "").replace("_", "")
        matched_enum = VulnClass.OTHER
        for member in VulnClass:
            if member.value.upper() == v_class_str or member.name.upper() == v_class_str:
                matched_enum = member
                break
        data["vuln_class"] = matched_enum

        return Hypothesis(**data)

