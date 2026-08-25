"""
app/agents/recon.py
───────────────────
ReconAgent — Executes active web reconnaissance and dynamically synthesizes results using live Gemini LLMs.
Purely scan-driven and LLM-synthesized: Zero hardcoded endpoints.
"""
from __future__ import annotations

import json
from typing import Any

from app.agents.llm_client import agenerate_structured_content
from app.core.logging import get_logger
from app.tools.recon_tools import fetch_robots_txt, fetch_sitemap, scrape_links_and_forms

logger = get_logger(__name__)

SYSTEM_INSTRUCTION = """
You are an expert Web Security Reconnaissance Agent operating on an authorized target.
Analyze the raw network scan data (robots.txt, sitemaps, scraped routes, HTML forms, parameters) and synthesize a comprehensive attack surface map.

Output pure valid JSON matching this schema:
{
  "target_url": "http://...",
  "technologies": ["Python", "Flask", "SQLite", ...],
  "endpoints": [
    {
      "path": "/api/...",
      "method": "GET|POST|PUT|DELETE|PATCH",
      "parameters": ["id", "filter", ...],
      "requires_auth": true,
      "description": "Endpoint purpose"
    }
  ],
  "potential_auth_endpoints": ["/api/login", ...],
  "recon_summary": "High-level summary of the discovered application attack surface"
}
"""


class ReconAgent:
    """Reconnaissance agent performing tool calls and structured synthesis."""

    def __init__(self, investigation_id: str, target_url: str) -> None:
        self.investigation_id = investigation_id
        self.target_url = target_url

    async def run(self) -> dict[str, Any]:
        logger.info("recon_agent_started", target=self.target_url)

        # 1. Execute deterministic recon tools against live target
        robots_res = await fetch_robots_txt(self.target_url, self.investigation_id)
        sitemap_res = await fetch_sitemap(self.target_url, self.investigation_id)
        scrape_res = await scrape_links_and_forms(self.target_url, self.investigation_id)

        tool_findings = {
            "target_url": self.target_url,
            "robots_txt": robots_res,
            "sitemap": sitemap_res,
            "scraped_structure": scrape_res,
        }

        # 2. Invoke Gemini dynamically
        prompt = f"""
Target URL: {self.target_url}

Observed Tool Recon Data from Live Network Scan:
{json.dumps(tool_findings, indent=2, default=str)}

Synthesize all discovered routes, endpoints, methods, and parameters into a structured attack surface JSON.
"""

        raw_json = await agenerate_structured_content(
            contents=prompt,
            system_instruction=SYSTEM_INSTRUCTION,
            response_mime_type="application/json",
            temperature=0.1,
        )

        if raw_json.startswith("```"):
            lines = raw_json.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            raw_json = "\n".join(lines).strip()

        result = json.loads(raw_json)
        logger.info("recon_agent_succeeded", endpoint_count=len(result.get("endpoints", [])))
        return result
