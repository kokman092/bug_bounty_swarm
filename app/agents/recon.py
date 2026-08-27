"""
app/agents/recon.py
───────────────────
ReconAgent — Comprehensive multi-tool reconnaissance orchestrator powered by:
  - Subfinder (Passive subdomain enumeration + crt.sh fallback)
  - Katana (High-speed web & JS bundle crawler)
  - Nuclei (Misconfiguration & exposure scan)
  - OpenAPI / Swagger spec ingestion engine
  - Deep REST API prober
  - Robots.txt & sitemap analyzer
  - Live Gemini 2.5 LLM synthesis
"""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from app.agents.llm_client import agenerate_structured_content
from app.core.logging import get_logger
from app.tools import (
    fetch_and_parse_openapi_specs,
    fetch_robots_txt,
    fetch_sitemap,
    probe_common_api_paths,
    run_httpx_probe,
    run_katana,
    run_nuclei_scan,
    run_subfinder,
    scrape_links_and_forms,
)

logger = get_logger(__name__)

SYSTEM_INSTRUCTION = """
You are an expert Web Security Reconnaissance Agent operating on an authorized target.
Analyze the raw network scan data from all integrated recon tools (Subfinder, Katana crawler, OpenAPI specs, Nuclei exposures, robots.txt, sitemaps, and deep API probe results) and synthesize a comprehensive attack surface map.

Important: Include ALL discovered endpoints, parameters, and technologies from every data source. Do NOT discard discovered paths.

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
    """Reconnaissance agent orchestrating the full open-source + native tool suite."""

    def __init__(self, investigation_id: str, target_url: str) -> None:
        self.investigation_id = investigation_id
        self.target_url = target_url

    async def run(self) -> dict[str, Any]:
        logger.info("recon_agent_started", target=self.target_url)
        parsed_domain = urlparse(self.target_url).netloc or self.target_url

        # 1. Execute deterministic & external recon tools in parallel
        robots_res = await fetch_robots_txt(self.target_url, self.investigation_id)
        sitemap_res = await fetch_sitemap(self.target_url, self.investigation_id)
        openapi_res = await fetch_and_parse_openapi_specs(self.target_url, self.investigation_id)
        katana_res = await run_katana(self.target_url, self.investigation_id)
        subfinder_res = await run_subfinder(parsed_domain, self.investigation_id)
        nuclei_res = await run_nuclei_scan(self.target_url, self.investigation_id)
        deep_probe_res = await probe_common_api_paths(self.target_url, self.investigation_id)
        robots_spider_res = await self._spider_robots_paths(robots_res)

        tool_findings = {
            "target_url": self.target_url,
            "subfinder_subdomains": subfinder_res,
            "katana_crawled_routes": katana_res,
            "openapi_specs": openapi_res,
            "nuclei_exposures": nuclei_res,
            "robots_txt": robots_res,
            "sitemap": sitemap_res,
            "deep_api_probes": deep_probe_res,
            "robots_disallow_spider": robots_spider_res,
        }

        # 2. Invoke Gemini dynamically to synthesize attack surface
        prompt = f"""
Target URL: {self.target_url}

Observed Tool Recon Data from Live Recon Suite:
{json.dumps(tool_findings, indent=2, default=str)}

Synthesize ALL discovered routes, endpoints, methods, and parameters into a structured attack surface JSON.
Include every endpoint found across all data sources. Do NOT omit any discovered paths.
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

    async def _spider_robots_paths(self, robots_res: dict) -> dict[str, Any]:
        """Actively probe paths discovered in robots.txt disallow directives."""
        if robots_res.get("status") != "found":
            return {"status": "skipped", "reason": "No robots.txt found"}

        disallowed = robots_res.get("disallowed_paths", [])
        if not disallowed:
            return {"status": "skipped", "reason": "No disallowed paths"}

        from app.targets.normalization import normalize_url
        from app.tools.http_client import ScopeEnforcingHttpClient

        base = normalize_url(self.target_url)
        discovered_endpoints = []

        async with ScopeEnforcingHttpClient(self.investigation_id) as client:
            for path in disallowed[:8]:
                clean_path = path.strip().rstrip("/")
                if not clean_path:
                    continue
                probe_url = f"{base.scheme}://{base.host_with_port}{clean_path}"
                try:
                    resp = await client.get(probe_url)
                    if resp.status_code in (200, 201, 301, 302):
                        discovered_endpoints.append({
                            "path": clean_path,
                            "status_code": resp.status_code,
                            "content_type": resp.headers.get("content-type", ""),
                            "body_preview": client.get_response_text_safe(resp)[:500],
                        })
                except Exception as exc:
                    logger.debug("robots_spider_skip", path=clean_path, error=str(exc))

        return {
            "status": "completed",
            "probed_count": len(disallowed[:8]),
            "discovered": discovered_endpoints,
        }
