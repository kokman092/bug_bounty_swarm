"""
app/tools/external/httpx_probe.py
─────────────────────────────────
ProjectDiscovery HTTPX Prober Tool Wrapper.

1. Binary Mode: Executes `httpx -u <targets> -silent -json -title -status-code -tech-detect`.
2. Fallback Mode: Concurrent async probing via `ScopeEnforcingHttpClient`.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from typing import Any

from app.core.logging import get_logger
from app.tools.http_client import ScopeEnforcingHttpClient

logger = get_logger(__name__)


async def run_httpx_probe(
    target_urls: list[str],
    investigation_id: str,
) -> dict[str, Any]:
    """
    Probes URLs for HTTP status codes, server headers, and tech stacks using
    ProjectDiscovery HTTPX CLI or ScopeEnforcingHttpClient async fallback.
    """
    if not target_urls:
        return {"engine": "httpx_probe", "results": []}

    httpx_bin = shutil.which("httpx")

    if httpx_bin:
        # Binary execution mode
        try:
            urls_input = "\n".join(target_urls)
            proc = await asyncio.create_subprocess_exec(
                httpx_bin,
                "-silent",
                "-json",
                "-title",
                "-status-code",
                "-tech-detect",
                "-content-length",
                "-timeout", "5",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(input=urls_input.encode()), timeout=30.0)

            probe_results = []
            for line in stdout.decode("utf-8", errors="ignore").splitlines():
                if line.strip():
                    try:
                        data = json.loads(line)
                        probe_results.append({
                            "url": data.get("url"),
                            "status_code": data.get("status_code"),
                            "title": data.get("title", ""),
                            "tech": data.get("tech", []),
                            "content_length": data.get("content_length", 0),
                        })
                    except ValueError:
                        continue

            return {
                "engine": "httpx_probe",
                "mode": "cli_binary",
                "probed_count": len(probe_results),
                "results": probe_results,
            }
        except Exception as exc:
            logger.warning("httpx_cli_failed_falling_back", error=str(exc))

    # Fallback Mode: Concurrent Python async probe
    probe_results = []
    async with ScopeEnforcingHttpClient(investigation_id) as client:
        for url in target_urls[:20]:
            try:
                resp = await client.get(url)
                body = client.get_response_text_safe(resp)
                title = ""
                if "<title>" in body.lower():
                    try:
                        title = body.lower().split("<title>")[1].split("</title>")[0].strip()
                    except Exception:
                        pass

                probe_results.append({
                    "url": url,
                    "status_code": resp.status_code,
                    "title": title,
                    "server": resp.headers.get("server", ""),
                    "content_type": resp.headers.get("content-type", ""),
                    "content_length": len(resp.content),
                })
            except Exception:
                continue

    return {
        "engine": "httpx_probe",
        "mode": "async_python_fallback",
        "probed_count": len(probe_results),
        "results": probe_results,
    }
