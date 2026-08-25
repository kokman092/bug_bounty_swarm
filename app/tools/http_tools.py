"""
app/tools/http_tools.py
───────────────────────
Live HTTP Execution & Evidence Validation Tools for ADK Multi-Agent System.

Components:
  - `execute_authorized_probe`: Hunter Agent tool executing live HTTP probes with scope guardrails and seeded test identities.
  - `run_evidence_validation`: Evidence Agent tool evaluating raw probe observations with the Semantic Evidence Engine.
"""
from __future__ import annotations

import httpx
from typing import Any

from app.tools.guardrail import is_authorized_target
from app.agents.validator import SemanticEvidenceEngine

# Seeded test tokens mapping to test personas (Alice, Bob, Admin)
IDENTITY_TOKEN_MAP = {
    "alice": "Bearer alice_token_123",       # User ID 1 (Tenant Alice / Victim Org)
    "bob": "Bearer bob_token_456",           # User ID 2 (Test Researcher / Caller)
    "admin": "Bearer admin_master_token_789", # User ID 3 (Platform Admin)
    "anonymous": None,
}

_validator_engine = SemanticEvidenceEngine()


def _resolve_identity_headers(caller_identity: str) -> dict[str, str]:
    """Resolves identity token to appropriate Authorization header."""
    token = IDENTITY_TOKEN_MAP.get(caller_identity.lower().strip())
    if token:
        return {"Authorization": token}
    return {}


async def execute_authorized_probe(
    target_base_url: str,
    endpoint: str,
    method: str = "GET",
    caller_identity: str = "bob",
    request_body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    ADK tool for Hunter Agent. Sends ONE live HTTP request to an
    explicitly authorized target and returns structured observation
    data for Evidence Agent to validate. Refuses any target not on
    the authorized_targets allow-list.
    """
    if not is_authorized_target(target_base_url):
        return {
            "error": "TARGET_NOT_AUTHORIZED",
            "detail": f"{target_base_url} is not on the authorized_targets allow-list.",
        }

    auth_headers = _resolve_identity_headers(caller_identity)
    merged_headers = {**auth_headers, **(headers or {})}
    url = f"{target_base_url.rstrip('/')}{endpoint}"

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            method_upper = method.upper()
            if method_upper in ("POST", "PUT", "PATCH"):
                resp = await client.request(method_upper, url, headers=merged_headers, json=request_body)
            else:
                resp = await client.request(method_upper, url, headers=merged_headers)

            try:
                body = resp.json()
            except ValueError:
                body = resp.text

            return {
                "endpoint": endpoint,
                "method": method_upper,
                "caller_identity": caller_identity,
                "status_code": resp.status_code,
                "response_body": body,
                "request_body": request_body,
                "response_headers": dict(resp.headers),
                "latency_ms": int(resp.elapsed.total_seconds() * 1000),
            }
        except httpx.RequestError as exc:
            return {
                "error": "REQUEST_FAILED",
                "endpoint": endpoint,
                "method": method.upper(),
                "detail": str(exc),
            }


def run_evidence_validation(
    vuln_type: str,
    method: str,
    endpoint: str,
    status_code: int,
    response_body: Any,
    request_body: dict[str, Any] | None = None,
    response_headers: dict[str, str] | None = None,
    caller_id: int | str = 2,
    target_scope_in: bool = True,
) -> dict[str, Any]:
    """
    ADK tool for Evidence Agent. Passes observation facts into the
    Semantic Evidence Engine to construct a 5-branch Evidence Graph and
    determine the deterministic verdict (CONFIRMED, FALSE_POSITIVE, NEEDS_HUMAN_VALIDATION).
    """
    verdict, val_block, confidence, evidence_graph = _validator_engine.evaluate_finding(
        vuln_type=vuln_type,
        method=method,
        endpoint=endpoint,
        http_status=status_code,
        response_body=response_body,
        request_body=request_body,
        response_headers=response_headers,
        caller_user_id=caller_id,
        target_scope_in=target_scope_in,
    )

    return {
        "verdict": verdict,
        "confidence": confidence,
        "evidence_level": evidence_graph.evidence_level.value,
        "evidence_level_name": evidence_graph.evidence_level.name,
        "evidence_graph_tree": evidence_graph.render_ascii_tree(),
        "validation_block": val_block,
        "semantic_summary": evidence_graph.semantic_summary,
    }
