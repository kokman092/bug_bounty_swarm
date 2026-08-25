"""
app/agents/attack_surface.py
────────────────────────────
AttackSurfaceAgent — Dynamically prioritizes attack surface vectors using Gemini LLMs.
Purely LLM-driven: Zero hardcoded endpoints.
"""
from __future__ import annotations

import json
from typing import Any

from app.agents.llm_client import agenerate_structured_content
from app.core.logging import get_logger

logger = get_logger(__name__)

SYSTEM_INSTRUCTION = """
You are an expert Attack Surface Analyzer operating on authorized target reconnaissance data.
Identify high-value API endpoints, evaluate auth boundaries, and prioritize attack vectors (BOLA, IDOR, Auth Bypass, SSRF, Mass Assignment).

Output pure valid JSON matching this schema:
{
  "target_url": "http://...",
  "priority_endpoints": [
    {
      "path": "/api/...",
      "method": "GET|POST|PUT|DELETE|PATCH",
      "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
      "likely_vulnerabilities": ["BOLA", "IDOR", ...],
      "rationale": "Why this endpoint is a high-priority target"
    }
  ],
  "threat_model_summary": "High-level summary of the prioritized threat model"
}
"""


class AttackSurfaceAgent:
    """Attack surface analysis agent prioritizing target routes for hunter."""

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id

    async def run(self, recon_result: dict[str, Any]) -> dict[str, Any]:
        logger.info("attack_surface_agent_started")

        prompt = f"""
Reconnaissance Output from Live Target:
{json.dumps(recon_result, indent=2, default=str)}

Analyze and prioritize the highest risk attack surfaces for active security testing.
"""

        raw_json = await agenerate_structured_content(
            contents=prompt,
            system_instruction=SYSTEM_INSTRUCTION,
            response_mime_type="application/json",
            temperature=0.2,
        )

        if raw_json.startswith("```"):
            lines = raw_json.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            raw_json = "\n".join(lines).strip()

        result = json.loads(raw_json)
        logger.info("attack_surface_agent_succeeded", priority_count=len(result.get("priority_endpoints", [])))
        return result
