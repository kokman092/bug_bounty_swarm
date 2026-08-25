"""
app/agents/reviewer.py
──────────────────────
ReviewAgent — Rigorous triage and evidence validator.
Implements the full 6-phase Vulnerability Verification Protocol:
  Phase 5: Evidence Chain Validation (Observed / Inferred / Unknown)
  Phase 6: False-Positive Defense (12-question checklist)
  Evidence Scoring: 0-10 scale across 5 dimensions.
  Minimum score for VALIDATED: 8/10.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from google import genai

from app.agents.llm_client import agenerate_structured_content
from app.agents.validator import SemanticEvidenceEngine
from app.core.config import get_settings
from app.core.logging import get_logger
from app.findings.schemas import Confidence, FindingStatus, Hypothesis, Severity

logger = get_logger(__name__)

# Load the full verification protocol from the prompt file
_PROMPT_FILE = Path(__file__).parent / "prompts" / "reviewer.txt"
_REVIEWER_PROMPT = _PROMPT_FILE.read_text(encoding="utf-8") if _PROMPT_FILE.exists() else ""

SYSTEM_INSTRUCTION = _REVIEWER_PROMPT or """
You are ReviewAgent, a rigorous senior application security triager operating under strict HackerOne triage standards.
Think like a bug bounty triager actively trying to REJECT the report.

Phase 5: Separate OBSERVED (direct evidence), INFERRED (reasonable conclusions), UNKNOWN (not demonstrated).
Phase 6: Actively try to disprove the finding using the 12-point false-positive checklist.
Evidence Scoring: Score each dimension 0-2; minimum 8/10 for VALIDATED verdict.

Output strictly valid JSON matching:
{
  "verdict": "VALIDATED" | "REJECTED" | "INCONCLUSIVE",
  "confidence": "High" | "Medium" | "Low",
  "observed_facts": ["<exact fact from HTTP evidence>"],
  "inferred_conclusions": ["<reasonable inference>"],
  "unknown_elements": ["<what was not demonstrated>"],
  "false_positive_analysis": "<strongest alternative explanations and why each was eliminated>",
  "evidence_score": {
    "reproducibility": 0,
    "authorization_bypass": 0,
    "security_impact": 0,
    "differential_evidence": 0,
    "root_cause": 0,
    "total": 0
  },
  "reason": "<full triage rationale referencing specific HTTP evidence>",
  "technical_severity": "Critical" | "High" | "Medium" | "Low" | "Informational",
  "remediation_guidance": "<concise engineering fix including specific code layer>"
}
"""


class ReviewAgent:
    """Evaluates collected evidence against vulnerability hypothesis using the full
    6-phase Vulnerability Verification Protocol."""

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        self.engine = SemanticEvidenceEngine()

    async def run(
        self,
        hypothesis: Hypothesis,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        logger.info("review_agent_started", hypothesis_id=hypothesis.hypothesis_id)

        # ── Phase 5: Deterministic Semantic Evidence Engine ─────────────────────
        steps = evidence.get("steps_executed", [])
        step0 = steps[0] if steps else {}
        step1 = steps[1] if len(steps) > 1 else {}

        # step0 = CONTROL (owner request), step1 = TEST (attacker request)
        primary_step = step1 if len(steps) > 1 else step0
        control_step = step0

        status_code = primary_step.get("status_code", 0)
        body = primary_step.get("body") or primary_step.get("response_body") or {}
        req_body = primary_step.get("request_params") or primary_step.get("request_body")

        verdict_val, val_block, conf, eg = self.engine.evaluate_finding(
            vuln_type=hypothesis.vuln_class.value,
            method=primary_step.get("method", "GET"),
            endpoint=hypothesis.endpoint,
            http_status=status_code,
            response_body=body,
            request_body=req_body,
            caller_user_id=2,
        )

        status_map = {
            "CONFIRMED": FindingStatus.VALIDATED.value,
            "FALSE_POSITIVE": FindingStatus.REJECTED.value,
            "NEEDS_HUMAN_VALIDATION": FindingStatus.REJECTED.value,
        }
        deterministic_verdict = status_map.get(verdict_val, FindingStatus.REJECTED.value)

        # ── Phase 6: LLM Full Verification Protocol ──────────────────────────────
        settings = get_settings()

        prompt = f"""
Apply the full 6-phase Vulnerability Verification Protocol.

## Hypothesis Under Review
{hypothesis.model_dump_json(indent=2)}

## Observed HTTP Evidence (All Steps)
Control Step (Authorized User / Owner):
{json.dumps(control_step, indent=2, default=str)}

Test Step (Unauthorized Attacker):
{json.dumps(primary_step, indent=2, default=str)}

## Full Evidence Payload
{json.dumps(evidence, indent=2, default=str)}

## Deterministic Evidence Engine Pre-Evaluation
Deterministic Verdict: {verdict_val} (Evidence Level {eg.evidence_level.value} — {eg.evidence_level.name})
Evidence Summary: {val_block.get('proof_summary') or eg.semantic_summary}
Evidence Tree:
{eg.render_ascii_tree()}

## Instructions
Phase 5: Populate observed_facts, inferred_conclusions, unknown_elements.
  - OBSERVED = facts directly from HTTP evidence (status codes, exact response body fields).
  - INFERRED = reasonable conclusions derived from observed facts.
  - UNKNOWN = information not demonstrated by the evidence.
Phase 6: Populate false_positive_analysis (address all 12 false-positive questions).
Evidence Scoring: Score each dimension 0-2. Minimum 8/10 required for VALIDATED.
Final Verdict: If evidence_score.total < 8, verdict MUST be REJECTED or INCONCLUSIVE.
"""

        try:
            raw_text = await agenerate_structured_content(
                contents=prompt,
                system_instruction=SYSTEM_INSTRUCTION,
                response_mime_type="application/json",
                temperature=0.1,
            )
            llm_result = json.loads(raw_text)

            observed_facts = llm_result.get("observed_facts", [])
            inferred_conclusions = llm_result.get("inferred_conclusions", [])
            unknown_elements = llm_result.get("unknown_elements", [])
            fp_analysis = llm_result.get("false_positive_analysis", "")
            evidence_score = llm_result.get("evidence_score", {
                "reproducibility": 0, "authorization_bypass": 0,
                "security_impact": 0, "differential_evidence": 0,
                "root_cause": 0, "total": 0,
            })
            reason = llm_result.get("reason") or val_block.get("proof_summary") or eg.semantic_summary
            remediation = llm_result.get("remediation_guidance") or "Enforce strict server-side authorization checks."
            llm_verdict = llm_result.get("verdict", "REJECTED")
            llm_severity = llm_result.get("technical_severity", "Low")

            # Enforce evidence score threshold
            score_total = evidence_score.get("total", 0)
            if score_total < 8 and llm_verdict == "VALIDATED":
                llm_verdict = "REJECTED"
                reason = f"[Evidence Score {score_total}/10 below 8/10 threshold for VALIDATED] " + reason

            verdict_out = FindingStatus.VALIDATED.value if llm_verdict == "VALIDATED" else FindingStatus.REJECTED.value

        except Exception as exc:
            logger.warning("review_agent_llm_warning", error=str(exc))
            observed_facts = [f"HTTP {status_code} returned from {hypothesis.endpoint}"]
            inferred_conclusions = [val_block.get("proof_summary") or eg.semantic_summary]
            unknown_elements = ["Full differential comparison not available"]
            fp_analysis = "LLM phase 6 analysis unavailable; falling back to deterministic engine verdict."
            evidence_score = {
                "reproducibility": 1, "authorization_bypass": 1,
                "security_impact": 1, "differential_evidence": 1,
                "root_cause": 0, "total": 4,
            }
            reason = val_block.get("proof_summary") or eg.semantic_summary
            remediation = "Enforce strict tenant/object authorization boundaries and verify requesting user matches resource ownership."
            verdict_out = deterministic_verdict
            llm_severity = Severity.HIGH.value if verdict_val == "CONFIRMED" else Severity.LOW.value

        logger.info(
            "review_agent_completed",
            verdict=verdict_out,
            evidence_score=evidence_score.get("total", 0),
            hypothesis_id=hypothesis.hypothesis_id,
        )

        return {
            "verdict": verdict_out,
            "confidence": Confidence.HIGH.value if conf >= 0.90 else Confidence.MEDIUM.value,
            "observed_facts": observed_facts,
            "inferred_conclusions": inferred_conclusions,
            "unknown_elements": unknown_elements,
            "false_positive_analysis": fp_analysis,
            "evidence_score": evidence_score,
            "reason": reason,
            "technical_severity": llm_severity,
            "evidence_level": eg.evidence_level.value,
            "evidence_graph_tree": eg.render_ascii_tree(),
            "remediation_guidance": remediation,
        }
