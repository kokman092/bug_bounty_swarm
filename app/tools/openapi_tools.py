"""
app/tools/openapi_tools.py
──────────────────────────
OpenAPI / Swagger / Postman Spec Parser & Schema Ingestion Engine.

Automatically fetches, parses, and extracts structured attack surface metadata from:
  - `/openapi.json`
  - `/swagger.json`
  - `/api-docs`
  - `/v2/api-docs`
  - `/v3/api-docs`
"""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import urljoin

from app.targets.normalization import normalize_url
from app.tools.http_client import ScopeEnforcingHttpClient

SPEC_CANDIDATE_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/api/openapi.json",
    "/api/swagger.json",
    "/swagger/v1/swagger.json",
]


async def fetch_and_parse_openapi_specs(
    target_base_url: str,
    investigation_id: str,
) -> dict[str, Any]:
    """
    Attempts to discover and parse OpenAPI / Swagger documentation from common endpoints.
    Extracts route paths, HTTP methods, parameter names, and schemas.
    """
    base = normalize_url(target_base_url)
    root = f"{base.scheme}://{base.host_with_port}"

    discovered_endpoints: list[dict[str, Any]] = []
    found_spec_url: str | None = None

    async with ScopeEnforcingHttpClient(investigation_id) as client:
        for path in SPEC_CANDIDATE_PATHS:
            spec_url = urljoin(root, path)
            try:
                resp = await client.get(spec_url)
                if resp.status_code == 200:
                    text = client.get_response_text_safe(resp)
                    try:
                        spec = json.loads(text)
                    except ValueError:
                        continue

                    # Validate it looks like OpenAPI or Swagger
                    paths_obj = spec.get("paths", {})
                    if paths_obj and isinstance(paths_obj, dict):
                        found_spec_url = spec_url
                        for route_path, methods_data in paths_obj.items():
                            if isinstance(methods_data, dict):
                                for method, details in methods_data.items():
                                    if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                                        params_list = []
                                        for p in details.get("parameters", []):
                                            if isinstance(p, dict):
                                                schema_obj = p.get("schema", {}) if isinstance(p.get("schema"), dict) else {}
                                                min_val = p.get("minimum") if p.get("minimum") is not None else schema_obj.get("minimum")
                                                max_val = p.get("maximum") if p.get("maximum") is not None else schema_obj.get("maximum")
                                                def_val = p.get("default") if p.get("default") is not None else schema_obj.get("default")
                                                params_list.append({
                                                    "name": p.get("name"),
                                                    "in": p.get("in"),
                                                    "required": p.get("required", False),
                                                    "type": p.get("type") or schema_obj.get("type", "string"),
                                                    "documented_minimum": int(min_val) if isinstance(min_val, (int, float)) else None,
                                                    "documented_maximum": int(max_val) if isinstance(max_val, (int, float)) else None,
                                                    "documented_default": int(def_val) if isinstance(def_val, (int, float)) else None,
                                                    "schema_reference": f"openapi:/paths/{route_path}/{method}/parameters/{p.get('name')}",
                                                })


                                        discovered_endpoints.append({
                                            "path": route_path,
                                            "method": method.upper(),
                                            "summary": details.get("summary", ""),
                                            "description": details.get("description", ""),
                                            "parameters": params_list,
                                            "tags": details.get("tags", []),
                                            "requires_auth": bool(details.get("security", spec.get("security", []))),
                                        })
                        break
            except Exception:
                continue

    return {
        "status": "found" if found_spec_url else "not_found",
        "spec_url": found_spec_url,
        "endpoint_count": len(discovered_endpoints),
        "endpoints": discovered_endpoints,
    }
