"""
app/tools/burp/burp_proxy_tool.py
─────────────────────────────────
Burp Suite Proxy Health & Status Checker.

Detects if Burp Suite Proxy (e.g. 127.0.0.1:8080) is reachable and active.
"""
from __future__ import annotations

from typing import Any
import httpx

from app.core.config import get_settings


async def check_burp_proxy_status() -> dict[str, Any]:
    """
    Checks if Burp Suite Proxy listener is currently active and reachable on localhost.
    """
    settings = get_settings()
    proxy_url = settings.burp_proxy_url

    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"{proxy_url.rstrip('/')}/", headers={"Host": "burp"})
            is_burp = ("burp" in resp.text.lower() or "portswigger" in resp.text.lower() or resp.status_code in (200, 500, 502, 504))
            return {
                "status": "connected" if is_burp else "online",
                "proxy_url": proxy_url,
                "proxy_enabled": settings.burp_proxy_enabled,
                "detail": "Burp Suite Proxy is running and accepting traffic.",
            }
    except Exception as exc:
        return {
            "status": "disconnected",
            "proxy_url": proxy_url,
            "proxy_enabled": settings.burp_proxy_enabled,
            "detail": f"Burp Suite Proxy not detected on {proxy_url} ({exc}). Running in direct HTTP mode.",
        }
