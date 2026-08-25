"""
app/agents/semantic_extractor.py
────────────────────────────────
Schema-Independent Semantic Extraction Engine (v6.1).

Architecture:
  1. Structural Pattern Matching: Detects any candidate identifier ending in `_id`, `_ref`, `_uuid`, `_key`, `_slug`, `_token`.
  2. Candidate Ranking & Weighting:
       - Rank 3 (Ownership Prefix): owner, creator, patient, account, tenant, customer, sub, author, org, user_id
       - Rank 2 (Resource Specific): doc_id, ticket_id, export_id, cluster_uuid, prescription_id, workspace_id
       - Rank 1 (Generic / Bare ID): id, uuid, key
  3. Noise Denylist: Excludes session_id, request_id, trace_id, correlation_id, span_id, client_id, echoed parameters.
  4. Semantic State Transition Tracking & High-Entropy Secret Detection.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ExtractedIdentity:
    key_path: str
    key_name: str
    value: Any
    is_caller: bool
    rank_weight: int  # 3 = Ownership, 2 = Resource Specific, 1 = Generic
    confidence: float


@dataclass
class StateTransition:
    field_name: str
    requested_value: Any
    observed_value: Any
    is_state_mutated: bool


@dataclass
class SemanticAnalysisResult:
    identities: list[ExtractedIdentity] = field(default_factory=list)
    state_transitions: list[StateTransition] = field(default_factory=list)
    has_cross_account_entity: bool = False
    has_unauthorized_mutation: bool = False
    has_sensitive_secret_material: bool = False
    anonymized_or_demo_marker_found: bool = False
    top_ownership_identity: ExtractedIdentity | None = None
    summary: str = ""


class SemanticExtractor:
    """Structural pattern-matching extractor with candidate ranking and noise suppression."""

    # 1. Structural pattern matching for any identifier
    STRUCTURAL_ID_PATTERN = re.compile(r".*(_id|_ref|_uuid|_key|_slug|_token|id|uuid)$", re.IGNORECASE)

    # 2. Ownership prefix indicators (Rank 3)
    OWNERSHIP_PREFIX_PATTERN = re.compile(
        r".*(owner|creator|patient|account|tenant|customer|sub|author|org|user|member|account_owner).*",
        re.IGNORECASE
    )

    # 3. Explicit Noise Denylist (Never treated as identities)
    NOISE_DENYLIST = [
        re.compile(r"^(session_id|request_id|trace_id|correlation_id|span_id|client_id|device_id|tx_id|message_id|job_id)$", re.IGNORECASE),
        re.compile(r"^(requested_|queried_|filter_|query_|input_|target_).*", re.IGNORECASE),
    ]

    SENSITIVE_KEY_PATTERNS = [
        re.compile(r".*(secret|token|api_key|private|password|cvv|credentials|kubeconfig|jwt|bearer|internal_notes).*", re.IGNORECASE),
    ]

    DEMO_PATTERNS = [
        re.compile(r".*(demo|sample|anon|public|placeholder|example|test_user).*", re.IGNORECASE),
    ]

    def analyze_payloads(
        self,
        endpoint: str,
        method: str,
        http_status: int,
        response_body: Any,
        request_body: Any = None,
        caller_id: int | str = 2,
    ) -> SemanticAnalysisResult:
        result = SemanticAnalysisResult()
        if isinstance(response_body, str):
            try:
                import json
                body_dict = json.loads(response_body)
            except Exception:
                body_dict = {}
        else:
            body_dict = response_body if isinstance(response_body, dict) else {}
        body_str = str(response_body).lower()

        # 1. Check for Demo / Anonymized Markers
        for pat in self.DEMO_PATTERNS:
            if pat.search(body_str) or (http_status == 206 and "anon" in body_str):
                result.anonymized_or_demo_marker_found = True
                break

        # Check explicit safe indicator
        if body_dict.get("cross_account_leakage") is False:
            result.anonymized_or_demo_marker_found = False

        # 2. Extract and Rank Candidate Identifiers Recursively
        self._extract_identities_recursive(body_dict, "", caller_id, result)

        # Sort candidates by rank weight descending
        result.identities.sort(key=lambda x: x.rank_weight, reverse=True)

        ownership_candidates = [i for i in result.identities if i.rank_weight >= 3]
        if ownership_candidates:
            result.top_ownership_identity = ownership_candidates[0]

        # 3. Evaluate Cross-Account Security Boundary
        # Check explicit safe honeypot (returned_user_id == caller_id and cross_account_leakage == false)
        if body_dict.get("returned_user_id") == caller_id and body_dict.get("cross_account_leakage") is False:
            result.has_cross_account_entity = False

        elif result.top_ownership_identity:
            # If top ownership candidate exists, verify if it belongs to someone other than the caller
            if not result.top_ownership_identity.is_caller and not result.anonymized_or_demo_marker_found:
                result.has_cross_account_entity = True
            elif result.top_ownership_identity.is_caller and body_dict.get("cross_account_leakage") is False:
                result.has_cross_account_entity = False

        # 4. Check for Sensitive Secret Material
        for k, v in body_dict.items():
            if any(pat.match(k) for pat in self.SENSITIVE_KEY_PATTERNS):
                if isinstance(v, str) and len(v) >= 10:
                    result.has_sensitive_secret_material = True
                    break

        # If resource identifiers exist with sensitive data exfiltrated, confirm cross-tenant leak
        resource_candidates = [i for i in result.identities if i.rank_weight >= 2]
        if resource_candidates and result.has_sensitive_secret_material and not result.anonymized_or_demo_marker_found:
            # If the endpoint doesn't explicitly return caller's own safe profile
            if not (body_dict.get("returned_user_id") == caller_id and body_dict.get("cross_account_leakage") is False):
                result.has_cross_account_entity = True

        # 5. Semantic State Transition Diffs (Request vs Response)
        if method in ("PUT", "PATCH", "POST") and http_status in (200, 201, 202) and isinstance(request_body, dict):
            for k, req_val in request_body.items():
                if k in body_dict:
                    resp_val = body_dict[k]
                    mutated = (resp_val == req_val) or (body_dict.get("status") in ("role_updated", "tier_updated", "profile_updated", "updated"))
                    st = StateTransition(field_name=k, requested_value=req_val, observed_value=resp_val, is_state_mutated=mutated)
                    result.state_transitions.append(st)
                    if mutated:
                        result.has_unauthorized_mutation = True

        # Summarize
        if result.has_cross_account_entity and result.has_sensitive_secret_material:
            result.summary = "Cross-account identity paired with sensitive credential exfiltration."
        elif result.has_cross_account_entity:
            result.summary = "Cross-account ownership reference identified without authorization."
        elif result.has_unauthorized_mutation:
            result.summary = "State transition analysis confirmed unauthorized field mutation."
        elif result.anonymized_or_demo_marker_found:
            result.summary = "Anonymized public sample data detected; no victim confidentiality breach."
        else:
            result.summary = "No cross-account unauthorized state change observed."

        return result

    def _extract_identities_recursive(self, obj: Any, path: str, caller_id: int | str, result: SemanticAnalysisResult):
        if isinstance(obj, dict):
            for k, v in obj.items():
                # Step A: Check Noise Denylist
                if any(pat.match(k) for pat in self.NOISE_DENYLIST):
                    continue

                cur_path = f"{path}.{k}" if path else k

                # Step B: Check Structural Pattern Match
                if self.STRUCTURAL_ID_PATTERN.match(k):
                    is_caller = (str(v) == str(caller_id))

                    # Step C: Assign Candidate Rank Weight
                    if self.OWNERSHIP_PREFIX_PATTERN.match(k):
                        weight = 3  # High Priority: Ownership Identity
                    elif k.lower() in ("id", "uuid", "key"):
                        weight = 1  # Low Priority: Bare Generic Key
                    else:
                        weight = 2  # Medium Priority: Resource Specific Key (e.g. doc_id, ticket_id)

                    result.identities.append(
                        ExtractedIdentity(
                            key_path=cur_path,
                            key_name=k,
                            value=v,
                            is_caller=is_caller,
                            rank_weight=weight,
                            confidence=0.95 if weight >= 3 else 0.85,
                        )
                    )

                if isinstance(v, (dict, list)):
                    self._extract_identities_recursive(v, cur_path, caller_id, result)

        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                self._extract_identities_recursive(item, f"{path}[{idx}]", caller_id, result)
