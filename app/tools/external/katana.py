"""
app/tools/external/katana.py
────────────────────────────
Katana High-Speed Web & JavaScript Crawler Tool Wrapper.

1. Binary Mode: Executes `katana -u <target> -silent -json -jc -d 3` if available.
2. Fallback Mode: Native BeautifulSoup + Regex JavaScript AST endpoint scraper.
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
from typing import Any
from urllib.parse import urljoin, urlparse

from app.core.logging import get_logger
from app.targets.normalization import normalize_url
from app.tools.external.scope_filter import filter_discovered_targets
from app.tools.http_client import ScopeEnforcingHttpClient

logger = get_logger(__name__)


async def run_katana(
    target_url: str,
    investigation_id: str,
    depth: int = 3,
) -> dict[str, Any]:
    """
    Crawls target web application and JavaScript bundles using Katana CLI
    or native pure-Python crawler fallback.
    """
    katana_bin = shutil.which("katana")

    if katana_bin:
        # Binary execution mode
        try:
            proc = await asyncio.create_subprocess_exec(
                katana_bin,
                "-u", target_url,
                "-silent",
                "-json",
                "-jc",  # JavaScript crawling
                "-d", str(depth),
                "-ct", "5s",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=45.0)

            endpoints = []
            for line in stdout.decode("utf-8", errors="ignore").splitlines():
                if line.strip():
                    try:
                        data = json.loads(line)
                        req = data.get("request", {})
                        ep_url = req.get("endpoint") or data.get("endpoint") or req.get("url")
                        if ep_url:
                            endpoints.append(ep_url)
                    except ValueError:
                        endpoints.append(line.strip())

            filtered = await filter_discovered_targets(endpoints, investigation_id)
            return {
                "engine": "katana",
                "mode": "cli_binary",
                "target_url": target_url,
                "discovered_count": len(filtered),
                "endpoints": sorted(list(set(filtered)))[:100],
            }
        except Exception as exc:
            logger.warning("katana_cli_failed_falling_back", error=str(exc))

    # Native Python Crawler Fallback
    base = normalize_url(target_url)
    root = f"{base.scheme}://{base.host_with_port}"
    discovered_paths: set[str] = set()

    async with ScopeEnforcingHttpClient(investigation_id) as client:
        try:
            resp = await client.get(target_url)
            html = client.get_response_text_safe(resp)

            # 1. Scrape links and forms
            for m in re.finditer(r'(?:href|action|src)=["\'](/[^"\'#\s?]+)', html, re.IGNORECASE):
                discovered_paths.add(m.group(1))

            # 2. Extract script tags and download JS bundles to extract hidden API routes
            script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
            for src in script_srcs[:5]:
                js_url = urljoin(root, src)
                try:
                    js_resp = await client.get(js_url)
                    if js_resp.status_code == 200:
                        js_code = client.get_response_text_safe(js_resp)
                        # Find API route patterns like "/api/v1/..." or "fetch('/api/...')"
                        for api_m in re.finditer(r'["\'](/(?:api|v1|v2|v3|admin|auth|debug|user|order|webhook)/[a-zA-Z0-9_\-/{}]*)["\']', js_code):
                            discovered_paths.add(api_m.group(1))
                except Exception:
                    continue

        except Exception as exc:
            logger.debug("katana_fallback_crawler_error", error=str(exc))

    return {
        "engine": "katana",
        "mode": "native_spider_fallback",
        "target_url": target_url,
        "discovered_count": len(discovered_paths),
        "endpoints": sorted(list(discovered_paths))[:50],
    }
