"""
app/tools/burp/burp_api_tool.py
───────────────────────────────
Burp Suite REST API Client & Automation Tool.

Interacts with Burp Suite REST API (default http://127.0.0.1:1337) to:
  - Ingest Burp's Site Map for target endpoints
  - Trigger Burp Active & Passive Scans
  - Fetch Burp Scanner issue reports
"""
from __future__ import annotations

from typing import Any
import httpx

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


async def fetch_burp_sitemap(target_url: str) -> dict[str, Any]:
    """
    Fetches the sitemap recorded by Burp Suite for the given target.
    """
    settings = get_settings()
    api_url = settings.burp_api_url
    api_key = settings.burp_api_key

    headers = {}
    if api_key:
        headers["X-API-Key"] = api_key

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{api_url.rstrip('/')}/v0.1/sitemap", headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "status": "success",
                    "source": "burp_rest_api",
                    "endpoints": data.get("endpoints", []),
                }
    except Exception as exc:
        logger.debug("burp_api_sitemap_unavailable", error=str(exc))

    return {
        "status": "unavailable",
        "reason": "Burp Suite REST API is not running or unreachable on configured port.",
        "endpoints": [],
    }


async def trigger_burp_scan(target_url: str) -> dict[str, Any]:
    """
    Triggers an active vulnerability scan via Burp Suite REST API.
    """
    settings = get_settings()
    api_url = settings.burp_api_url
    api_key = settings.burp_api_key

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{api_url.rstrip('/')}/v0.1/scan",
                headers=headers,
                json={"urls": [target_url]},
            )
            if resp.status_code in (200, 201, 202):
                task_id = resp.headers.get("Location", resp.text)
                return {
                    "status": "scan_initiated",
                    "target": target_url,
                    "task_id": task_id,
                }
    except Exception as exc:
        logger.debug("burp_api_scan_unavailable", error=str(exc))

    return {
        "status": "unavailable",
        "reason": "Burp Suite REST API not responding to scan requests.",
    }
