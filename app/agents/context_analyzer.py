"""
app/agents/context_analyzer.py
──────────────────────────────
Context Verification Engine for Vulnerability Triage.

Analyzes execution context before evidence evaluation:
  1. Synthetic / Public / Demo Data Detection (e.g. "Public Anon Sample", "demo_", "example.com")
  2. Data Ownership & Identity Verification (Caller ID vs Resource Owner ID)
  3. Semantic State Transition Tracking (Before-state vs After-state mutation)
  4. HTTP Protocol & Status Code Semantic Context (e.g. 206 Partial Stream, 202 Async Job)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ContextAnalysisResult:
    is_synthetic_or_demo: bool
    is_cross_account_leak: bool
    is_state_mutation_verified: bool
    caller_is_resource_owner: bool
    data_confidentiality_level: str  # "PUBLIC_DEMO", "TELEMETRY", "CONFIDENTIAL", "UNKNOWN"
    semantic_summary: str


class ContextAnalyzer:
    """Evaluates contextual metadata, data semantics, and identity relationships."""

    DEMO_MARKERS = [
        "public anon sample",
        "demo_",
        "test_sample",
        "sample anonymized",
        "public catalog",
        "example.com",
        "placeholder",
    ]

    def analyze_context(
        self,
        endpoint: str,
        method: str,
        http_status: int,
        request_body: dict[str, Any] | None,
        response_body: dict[str, Any] | str,
        caller_id: int | str = 2,
    ) -> ContextAnalysisResult:
        body_dict = response_body if isinstance(response_body, dict) else {}
        body_str = str(response_body).lower()

        # 1. Synthetic / Public / Demo Data Check
        is_synthetic = any(marker in body_str for marker in self.DEMO_MARKERS) or http_status == 206 and "anon" in body_str

        # 2. Ownership & Identity Analysis
        returned_user_id = body_dict.get("returned_user_id") or body_dict.get("account_owner_id") or body_dict.get("owner_id") or body_dict.get("user_id")
        caller_is_owner = False
        is_cross_account = False

        if returned_user_id is not None:
            if str(returned_user_id) == str(caller_id):
                caller_is_owner = True
            else:
                is_cross_account = True
        elif "workspace_id" in body_dict and body_dict.get("owner_id") != caller_id:
            is_cross_account = True

        # 3. Semantic State Transition Check (for Mass Assignment / Privilege Escalation)
        is_state_mutated = False
        if method in ("PUT", "PATCH", "POST") and http_status in (200, 201, 202):
            if request_body:
                # Check if requested field (e.g. tier, role, status) was successfully reflected in response
                for field in ("role", "tier", "permission", "is_admin", "status"):
                    if field in request_body:
                        req_val = request_body[field]
                        resp_val = body_dict.get(field)
                        if resp_val == req_val or body_dict.get("status") in ("role_updated", "tier_updated", "profile_updated"):
                            is_state_mutated = True
                            break

        # 4. Confidentiality Classification
        if is_synthetic:
            confidentiality = "PUBLIC_DEMO"
            summary = "Data contains explicit public/demo/anonymized sample markers; no victim identity breached."
        elif is_cross_account and not caller_is_owner:
            confidentiality = "CONFIDENTIAL"
            summary = f"Response contains private object belonging to User {returned_user_id}, different from Caller {caller_id}."
        elif is_state_mutated:
            confidentiality = "CONFIDENTIAL"
            summary = f"State transition confirmed: caller modified restricted field to '{request_body.get('tier') or request_body.get('role')}'."
        elif http_status in (401, 403, 404):
            confidentiality = "PROTECTED"
            summary = f"Resource is protected by access controls (HTTP {http_status})."
        else:
            confidentiality = "TELEMETRY"
            summary = "Response contains generic operational telemetry or public metadata."

        return ContextAnalysisResult(
            is_synthetic_or_demo=is_synthetic,
            is_cross_account_leak=is_cross_account and not caller_is_owner and not is_synthetic,
            is_state_mutation_verified=is_state_mutated,
            caller_is_resource_owner=caller_is_owner,
            data_confidentiality_level=confidentiality,
            semantic_summary=summary,
        )
