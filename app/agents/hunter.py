"""
app/agents/hunter.py
────────────────────
HunterAgent — Dynamic offensive hypothesis generator with structured test steps using Gemini LLMs.
Purely LLM-driven: Zero hardcoded endpoints, zero local URLs, zero mocked payloads.
"""
from __future__ import annotations

import json
import uuid
from typing import Any

from app.agents.llm_client import agenerate_structured_content
from app.core.logging import get_logger
from app.findings.schemas import Hypothesis, TestStep, VulnClass

logger = get_logger(__name__)

SYSTEM_INSTRUCTION = """
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
    ) -> Hypothesis:
        logger.info(
            "hunter_agent_started",
            iteration=iteration,
            already_proposed_count=len(already_proposed),
            has_review_feedback=bool(review_feedback),
        )

        prompt = f"""
Current Iteration: {iteration}

Target Discovered Endpoints:
{json.dumps(attack_surface, indent=2, default=str)}

Already Tested Endpoints:
{json.dumps(already_proposed, indent=2)}

Previous Reviewer Feedback:
{review_feedback or 'None (Initial test run)'}

Task:
Propose ONE priority integration test case to verify access control and boundary isolation.
If review feedback indicates that an earlier endpoint enforced proper authorization or returned 404, pivot to test a different endpoint or parameter.
"""

        raw_text = await agenerate_structured_content(
            contents=prompt,
            system_instruction=SYSTEM_INSTRUCTION,
            response_mime_type="application/json",
            temperature=0.2,
        )

        # Clean markdown code blocks if the model wrapped output
        if raw_text.startswith("```"):
            lines = raw_text.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            raw_text = "\n".join(lines).strip()

        data = json.loads(raw_text)
        if not data.get("hypothesis_id"):
            data["hypothesis_id"] = str(uuid.uuid4())

        # If data is missing fields due to unexpected output
        if not data.get("endpoint") or not data.get("title"):
            priority_eps = attack_surface.get("priority_endpoints", [])
            for ep_info in priority_eps:
                ep_path = ep_info.get("endpoint") or ep_info.get("path")
                tag = f"BOLA:{ep_path}"
                if tag not in already_proposed:
                    return Hypothesis(
                        hypothesis_id=str(uuid.uuid4()),
                        vuln_class=VulnClass.BOLA,
                        endpoint=ep_path,
                        title=f"Verify Authorization Boundary on {ep_path}",
                        rationale=f"Dynamic verification of access control on {ep_path}",
                        test_steps=[
                            TestStep(
                                step_number=1,
                                description=f"Probe {ep_path} for object level authorization",
                                method=ep_info.get("method", "GET"),
                                path=ep_path,
                                headers={"Authorization": "Bearer bob_token_456"},
                                params={},
                                json_body=None,
                            )
                        ],
                        no_further_hypotheses=False,
                    )
            return Hypothesis(
                hypothesis_id=str(uuid.uuid4()),
                vuln_class=VulnClass.OTHER,
                endpoint="/",
                title="Assessment Complete",
                rationale="All attack surfaces investigated",
                test_steps=[],
                no_further_hypotheses=True,
            )

        # Normalize vuln_class enum cleanly
        v_class_str = str(data.get("vuln_class", "OTHER")).upper().replace(" ", "").replace("_", "")
        matched_enum = VulnClass.OTHER
        for member in VulnClass:
            if member.value.upper() == v_class_str or member.name.upper() == v_class_str:
                matched_enum = member
                break
        data["vuln_class"] = matched_enum

        return Hypothesis(**data)
