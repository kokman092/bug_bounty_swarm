"""
app/tools/auth_matrix.py
────────────────────────
Fast Multi-Tenant Identity Matrix Prober.

Fires parallel probes across 4 distinct test personas:
  1. `anonymous` (Unauthenticated)
  2. `alice` (Legitimate Resource Owner / Tenant A)
  3. `bob` (Unauthorized Cross-Tenant Attacker / Tenant B)
  4. `admin` (Platform Administrator)

Instantly computes differential access matrix in <200ms.
"""
from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urljoin

from app.targets.normalization import normalize_url
from app.tools.http_client import ScopeEnforcingHttpClient

TEST_IDENTITIES = {
    "anonymous": None,
    "alice": "Bearer alice_token_123",
    "bob": "Bearer bob_token_456",
    "admin": "Bearer admin_master_token_789",
}


async def probe_auth_matrix(
    target_base_url: str,
    endpoint: str,
    investigation_id: str,
    method: str = "GET",
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Executes concurrent probes across all 4 test personas and returns an access differential matrix.
    """
    base = normalize_url(target_base_url)
    target_url = urljoin(f"{base.scheme}://{base.host_with_port}/", endpoint.lstrip("/"))

    results: dict[str, dict[str, Any]] = {}

    async def _probe_identity(persona: str, token: str | None) -> tuple[str, dict[str, Any]]:
        headers = {}
        if token:
            headers["Authorization"] = token

        async with ScopeEnforcingHttpClient(investigation_id) as client:
            try:
                m = method.upper()
                if m == "POST":
                    resp = await client.post(target_url, headers=headers, params=params, json_body=json_body)
                elif m == "PUT":
                    resp = await client.put(target_url, headers=headers, params=params, json_body=json_body)
                elif m == "PATCH":
                    resp = await client.patch(target_url, headers=headers, params=params, json_body=json_body)
                elif m == "DELETE":
                    resp = await client.delete(target_url, headers=headers, params=params)
                else:
                    resp = await client.get(target_url, headers=headers, params=params)

                body_text = client.get_response_text_safe(resp)
                return persona, {
                    "status_code": resp.status_code,
                    "body_length": len(resp.content),
                    "body_sample": body_text[:1000],
                    "headers": dict(resp.headers),
                    "is_success": resp.status_code in (200, 201, 202, 204),
                }
            except Exception as exc:
                return persona, {
                    "status_code": 0,
                    "error": str(exc),
                    "is_success": False,
                }

    # Execute all 4 persona probes concurrently in parallel
    probe_tasks = [_probe_identity(persona, token) for persona, token in TEST_IDENTITIES.items()]
    probe_results = await asyncio.gather(*probe_tasks)

    for persona, res in probe_results:
        results[persona] = res

    # Compute high-level access differential verdict
    anon_ok = results.get("anonymous", {}).get("is_success", False)
    alice_ok = results.get("alice", {}).get("is_success", False)
    bob_ok = results.get("bob", {}).get("is_success", False)
    admin_ok = results.get("admin", {}).get("is_success", False)

    is_bola_detected = (alice_ok and bob_ok and not anon_ok)
    is_auth_bypass = (anon_ok and (alice_ok or bob_ok))
    is_bfla_detected = (bob_ok and not anon_ok and "admin" in endpoint.lower())

    return {
        "endpoint": endpoint,
        "method": method.upper(),
        "matrix": results,
        "differential_analysis": {
            "is_bola_candidate": is_bola_detected,
            "is_auth_bypass_candidate": is_auth_bypass,
            "is_bfla_candidate": is_bfla_detected,
            "summary": (
                f"Anon={results.get('anonymous', {}).get('status_code')} | "
                f"Alice={results.get('alice', {}).get('status_code')} | "
                f"Bob={results.get('bob', {}).get('status_code')} | "
                f"Admin={results.get('admin', {}).get('status_code')}"
            ),
        },
    }
