"""
app/tools/recon_tools.py
────────────────────────
Safe reconnaissance tools that route all HTTP traffic through ScopeEnforcingHttpClient.
Supports static HTML scraping and dynamic SPA JavaScript bundle API endpoint extraction.
"""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin

from app.core.logging import get_logger
from app.targets.authorization import AuthorizationService
from app.targets.normalization import normalize_url
from app.tools.http_client import ScopeEnforcingHttpClient

logger = get_logger(__name__)


async def fetch_robots_txt(target_url: str, investigation_id: str) -> dict[str, str | list[str]]:
    """Fetch and parse robots.txt for disallowed or hidden paths."""
    base = normalize_url(target_url)
    robots_url = f"{base.scheme}://{base.host_with_port}/robots.txt"

    async with ScopeEnforcingHttpClient(investigation_id) as client:
        try:
            resp = await client.get(robots_url)
            if resp.status_code == 200:
                text = client.get_response_text_safe(resp)
                disallowed = re.findall(r"Disallow:\s*([^\r\n#]+)", text, re.IGNORECASE)
                sitemaps = re.findall(r"Sitemap:\s*([^\r\n#]+)", text, re.IGNORECASE)
                return {
                    "status": "found",
                    "disallowed_paths": [p.strip() for p in disallowed],
                    "sitemaps": [s.strip() for s in sitemaps],
                    "raw": text[:2000],
                }
            return {"status": "not_found", "status_code": resp.status_code}
        except Exception as exc:
            logger.info("robots_fetch_skipped", error=str(exc))
            return {"status": "error", "error": str(exc)}


async def fetch_sitemap(target_url: str, investigation_id: str) -> dict[str, Any]:
    """Fetch and extract URLs from sitemap.xml."""
    base = normalize_url(target_url)
    sitemap_url = f"{base.scheme}://{base.host_with_port}/sitemap.xml"

    async with ScopeEnforcingHttpClient(investigation_id) as client:
        try:
            resp = await client.get(sitemap_url)
            if resp.status_code == 200:
                text = client.get_response_text_safe(resp)
                urls = re.findall(r"<loc>([^<]+)</loc>", text, re.IGNORECASE)
                return {
                    "status": "found",
                    "discovered_urls": urls[:50],
                }
            return {"status": "not_found", "status_code": resp.status_code}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}


def extract_paths_recursively(data: Any) -> set[str]:
    """Recursively search any depth of JSON/nested structures for valid URI paths."""
    paths: set[str] = set()
    if isinstance(data, dict):
        for v in data.values():
            paths.update(extract_paths_recursively(v))
    elif isinstance(data, list):
        for item in data:
            paths.update(extract_paths_recursively(item))
    elif isinstance(data, str) and data.startswith("/"):
        # Filter out scheme-relative URLs (//), comment fragments (/*), and HTML tag fragments (/<)
        if len(data) > 1 and not data.startswith(("//", "/*", "/<")):
            clean_p = data.split("?")[0].split("#")[0].rstrip("/")
            if not re.search(r'\.(css|png|jpg|jpeg|gif|svg|woff2?|ico|map)$', clean_p, re.IGNORECASE):
                paths.add(clean_p)
    return paths


async def scrape_links_and_forms(target_url: str, investigation_id: str) -> dict[str, Any]:
    """
    Scrape links, script paths, form actions, and analyze SPA JavaScript bundles
    to extract exposed REST API endpoints.
    """
    base = normalize_url(target_url)
    root_url = f"{base.scheme}://{base.host_with_port}/"

    async with ScopeEnforcingHttpClient(investigation_id) as client:
        try:
            resp = await client.get(root_url)
            if resp.status_code != 200:
                return {"status": "failed", "status_code": resp.status_code}

            html = client.get_response_text_safe(resp)
            discovered_paths: set[str] = set()

            # 1. Recursive JSON extraction (OpenAPI specs, Postman configs, REST API directory roots)
            try:
                data = json.loads(html)
                discovered_paths.update(extract_paths_recursively(data))
            except (ValueError, TypeError):
                pass

            # 2. Extract HTML links
            raw_hrefs = re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)
            for href in raw_hrefs:
                if href.startswith(("/", "http")):
                    abs_url = urljoin(root_url, href)
                    try:
                        norm = normalize_url(abs_url)
                        if norm.host == base.host:
                            clean = norm.path.rstrip("/")
                            if not re.search(r'\.(css|png|jpg|jpeg|gif|svg|woff2?|ico|map)$', clean, re.IGNORECASE):
                                discovered_paths.add(clean)
                    except Exception:
                        pass

            # 3. Extract HTML forms
            forms = []
            for form_match in re.finditer(r'<form\b([^>]*)>(.*?)</form>', html, re.IGNORECASE | re.DOTALL):
                attrs = form_match.group(1)
                action_m = re.search(r'action=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
                method_m = re.search(r'method=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
                inputs = re.findall(r'name=["\']([^"\']+)["\']', form_match.group(2), re.IGNORECASE)
                forms.append({
                    "action": action_m.group(1) if action_m else "/",
                    "method": (method_m.group(1) if method_m else "GET").upper(),
                    "input_names": inputs,
                })

            # 4. Extract script sources
            scripts = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE)

            # 5. Generalized relative path extraction from HTML body (agnostic to keyword prefixes)
            path_pattern = re.compile(r"""(?:["'`=\s])(/[a-zA-Z0-9_.~%!$&'()*+,;=:@/-]+)""")
            for match in path_pattern.finditer(html):
                path = match.group(1).rstrip("/")
                if len(path) > 1 and not path.startswith(("//", "/*", "/<")):
                    if not re.search(r'\.(css|png|jpg|jpeg|gif|svg|woff2?|ico|map|js|html)$', path, re.IGNORECASE):
                        discovered_paths.add(path)

            # 6. SPA JavaScript Bundle Analysis (e.g. Angular, React, Vue bundles)
            for script_src in scripts[:4]:
                script_url = urljoin(root_url, script_src)
                try:
                    js_resp = await client.get(script_url)
                    if js_resp.status_code == 200:
                        js_content = client.get_response_text_safe(js_resp)
                        for match in path_pattern.finditer(js_content):
                            endpoint_path = match.group(1).rstrip("/")
                            if len(endpoint_path) > 1 and not endpoint_path.startswith(("//", "/*", "/<")):
                                if not re.search(r'\.(css|png|jpg|jpeg|gif|svg|woff2?|ico|map|js|html)$', endpoint_path, re.IGNORECASE):
                                    discovered_paths.add(endpoint_path)
                except Exception as exc:
                    logger.debug("script_fetch_skipped", script=script_src, error=str(exc))

            return {
                "status": "success",
                "paths": sorted(list(discovered_paths))[:50],
                "forms": forms[:10],
                "scripts": scripts[:10],
            }
        except Exception as exc:
            return {"status": "error", "error": str(exc)}


async def probe_common_api_paths(target_url: str, investigation_id: str) -> dict[str, Any]:
    """
    Actively probe common REST API path prefixes to discover deep endpoints
    not linked from the root page (e.g., /api/v2/, /api/admin/, /api/debug/).
    """
    base = normalize_url(target_url)
    root = f"{base.scheme}://{base.host_with_port}"

    # Common API paths to probe — covers versioned APIs, admin panels, debug endpoints
    PROBE_PATHS = [
        "/api",
        "/api/v1",
        "/api/v2",
        "/api/v3",
        "/api/admin",
        "/api/debug",
        "/api/debug/config",
        "/api/users",
        "/api/orders",
        "/api/products",
        "/api/products/search",
        "/api/invoices",
        "/api/integrations",
        "/api/integrations/webhook/test",
        "/api/users/profile",
        "/api/v2/organizations",
        "/api/v2/tenants",
        "/api/v2/subscriptions",
        "/api/documents",
        "/api/support/tickets",
        "/api/cloud/instances",
        "/api/audit-logs",
        "/api/test/reset-db",
        "/swagger",
        "/docs",
        "/openapi.json",
        "/.env",
        "/health",
        "/status",
    ]

    discovered = []
    async with ScopeEnforcingHttpClient(investigation_id) as client:
        for path in PROBE_PATHS:
            probe_url = f"{root}{path}"
            try:
                resp = await client.get(probe_url)
                if resp.status_code in (200, 201, 301, 302, 400, 405):
                    body_preview = client.get_response_text_safe(resp)[:500]
                    discovered.append({
                        "path": path,
                        "status_code": resp.status_code,
                        "content_type": resp.headers.get("content-type", ""),
                        "body_preview": body_preview,
                    })
                    logger.info("deep_probe_hit", path=path, status=resp.status_code)
            except Exception as exc:
                logger.debug("deep_probe_skip", path=path, error=str(exc))

    return {
        "status": "completed",
        "probed_count": len(PROBE_PATHS),
        "discovered_count": len(discovered),
        "endpoints": discovered,
    }

