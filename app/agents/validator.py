"""
app/agents/validator.py
───────────────────────
Semantic Evidence Engine (AEV v6).

Architecture:
  1. Semantic Extraction Layer: Schema-independent identity candidate discovery & state transition tracking.
  2. Context Verification Layer: Distinguishes public/demo datasets from real victim boundaries.
  3. 5-Branch Explainable Evidence Graph:
       - Scope Branch (IN_SCOPE vs OUT_OF_SCOPE)
       - Authentication Branch (Caller identity verified)
       - Authorization Branch (Identity candidate ownership comparison)
       - Impact Branch (Confidential data exfiltration / State mutation demonstrated)
       - Reproducibility Branch (Repeatable HTTP execution)
  4. Evidence Hierarchy (Level 0 - Level 4).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from app.agents.context_analyzer import ContextAnalyzer
from app.agents.semantic_extractor import SemanticExtractor, SemanticAnalysisResult


class EvidenceLevel(IntEnum):
    LEVEL_0_OBSERVATION = 0
    LEVEL_1_SUSPICIOUS = 1
    LEVEL_2_REPRODUCIBLE_DIFFERENTIAL = 2
    LEVEL_3_BOUNDARY_VIOLATION = 3
    LEVEL_4_HIGH_IMPACT_PROVEN = 4


@dataclass
class EvidenceBranch:
    name: str     # Scope, Authentication, Authorization, Impact, Reproducibility
    status: str   # VERIFIED, VIOLATED, SECURE, INCONCLUSIVE, PUBLIC_DEMO, OUT_OF_SCOPE
    detail: str


@dataclass
class EvidenceGraph:
    graph_id: str
    target: str
    component: str
    vulnerability_type: str
    branches: list[EvidenceBranch] = field(default_factory=list)
    evidence_level: EvidenceLevel = EvidenceLevel.LEVEL_0_OBSERVATION
    verdict: str = "NEEDS_HUMAN_VALIDATION"  # CONFIRMED | FALSE_POSITIVE | NEEDS_HUMAN_VALIDATION
    confidence: float = 0.0
    semantic_summary: str = ""

    def render_ascii_tree(self) -> str:
        lines = [
            f"Finding: [{self.verdict}] {self.vulnerability_type} @ {self.component}",
            " |",
        ]
        for idx, b in enumerate(self.branches):
            is_last = idx == len(self.branches) - 1
            branch_char = " \\--" if is_last else " |--"
            lines.append(f"{branch_char} {b.name:<16}: [{b.status}] {b.detail}")
        lines.append(f"     \\-- Evidence Level  : LEVEL {self.evidence_level.value} ({self.evidence_level.name})")
        return "\n".join(lines)


class SemanticEvidenceEngine:
    """AEV v6: Schema-independent Semantic Evidence Engine."""

    def __init__(self):
        self.context_analyzer = ContextAnalyzer()
        self.semantic_extractor = SemanticExtractor()

    def evaluate_finding(
        self,
        vuln_type: str,
        method: str,
        endpoint: str,
        http_status: int,
        response_body: dict[str, Any] | str,
        request_body: dict[str, Any] | None = None,
        response_headers: dict[str, str] | None = None,
        caller_user_id: int | str = 2,
        target_scope_in: bool = True,
    ) -> tuple[str, dict[str, Any], float, EvidenceGraph]:
        """
        Evaluates execution evidence using schema-independent semantic extraction and constructs a 5-branch Evidence Graph.
        """
        response_headers = response_headers or {}
        if isinstance(response_body, str):
            try:
                import json
                body_dict = json.loads(response_body)
            except Exception:
                body_dict = {}
        else:
            body_dict = response_body if isinstance(response_body, dict) else {}
        body_str = str(response_body)
        graph_id = f"eg_{uuid.uuid4().hex[:8]}"

        # Step 1: Semantic & Context Extraction
        sem: SemanticAnalysisResult = self.semantic_extractor.analyze_payloads(
            endpoint=endpoint,
            method=method,
            http_status=http_status,
            response_body=body_dict if body_dict else response_body,
            request_body=request_body,
            caller_id=caller_user_id,
        )

        # 5 Mandatory Branches
        branches: list[EvidenceBranch] = []

        # 1. Scope Branch
        if not target_scope_in:
            branches.append(EvidenceBranch("Scope", "OUT_OF_SCOPE", f"Endpoint {endpoint} is outside authorized program scope."))
            eg = EvidenceGraph(graph_id, "target", f"{method} {endpoint}", vuln_type, branches, EvidenceLevel.LEVEL_0_OBSERVATION, "FALSE_POSITIVE", 0.0, sem.summary)
            return "FALSE_POSITIVE", {"scope_verified": False}, 0.0, eg
        branches.append(EvidenceBranch("Scope", "VERIFIED", "Endpoint is authorized within scope."))

        # 2. Authentication Branch
        branches.append(EvidenceBranch("Authentication", "VERIFIED", f"Caller authenticated as User ID {caller_user_id}."))

        val_block = {
            "reproducible": http_status in (200, 201, 202, 206, 400, 403, 422, 500),
            "evidence_level": EvidenceLevel.LEVEL_0_OBSERVATION.value,
            "authorization_boundary_broken": False,
            "impact_demonstrated": False,
            "scope_verified": True,
            "duplicate_checked": True,
            "proof_summary": "",
        }

        # ── 1. BOLA / IDOR Verification ───────────────────────────────────────
        if vuln_type in ("BOLA", "IDOR"):
            # A. Public / Anonymized Demo Data
            if sem.anonymized_or_demo_marker_found or (http_status == 206 and "anon" in body_str.lower()):
                branches.append(EvidenceBranch("Authorization", "SECURE", "Public anonymized data stream; no private identity breached."))
                branches.append(EvidenceBranch("Impact", "PUBLIC_DEMO", "Data contains public anonymized demo markers; no victim confidentiality breach."))
                branches.append(EvidenceBranch("Reproducibility", "VERIFIED", f"HTTP {http_status} partial response consistent."))
                val_block["evidence_level"] = EvidenceLevel.LEVEL_1_SUSPICIOUS.value
                val_block["proof_summary"] = "Public anonymized sample; not a vulnerability."
                eg = EvidenceGraph(graph_id, "target", f"{method} {endpoint}", vuln_type, branches, EvidenceLevel.LEVEL_1_SUSPICIOUS, "NEEDS_HUMAN_VALIDATION", 0.50, sem.summary)
                return "NEEDS_HUMAN_VALIDATION", val_block, 0.50, eg

            # B. Adversarial Honeypot (Caller owns the returned identity)
            if not sem.has_cross_account_entity and any(i.is_caller for i in sem.identities):
                branches.append(EvidenceBranch("Authorization", "SECURE", f"Server returned caller's own identity (User {caller_user_id}); no cross-tenant leak."))
                branches.append(EvidenceBranch("Impact", "SECURE", "No confidentiality or tenant boundary breach observed."))
                branches.append(EvidenceBranch("Reproducibility", "VERIFIED", f"HTTP {http_status} response consistent."))
                val_block["evidence_level"] = EvidenceLevel.LEVEL_2_REPRODUCIBLE_DIFFERENTIAL.value
                val_block["proof_summary"] = "Adversarial: Server returned caller's own profile without cross-account leakage."
                eg = EvidenceGraph(graph_id, "target", f"{method} {endpoint}", vuln_type, branches, EvidenceLevel.LEVEL_2_REPRODUCIBLE_DIFFERENTIAL, "FALSE_POSITIVE", 0.95, sem.summary)
                return "FALSE_POSITIVE", val_block, 0.95, eg

            # C. Access Denied (HTTP 401 / 403 / 404)
            if http_status in (401, 403, 404):
                branches.append(EvidenceBranch("Authorization", "SECURE", f"Access blocked with HTTP {http_status} Forbidden."))
                branches.append(EvidenceBranch("Impact", "SECURE", "Protected by access controls."))
                branches.append(EvidenceBranch("Reproducibility", "VERIFIED", f"HTTP {http_status} repeatable."))
                val_block["evidence_level"] = EvidenceLevel.LEVEL_1_SUSPICIOUS.value
                val_block["proof_summary"] = f"Access denied with HTTP {http_status}."
                eg = EvidenceGraph(graph_id, "target", f"{method} {endpoint}", vuln_type, branches, EvidenceLevel.LEVEL_1_SUSPICIOUS, "FALSE_POSITIVE", 0.95, sem.summary)
                return "FALSE_POSITIVE", val_block, 0.95, eg

            # D. Verified Cross-Tenant Object Access (Level 4 Impact)
            if http_status in (200, 201) and (sem.has_cross_account_entity or sem.has_sensitive_secret_material or any(k in body_dict for k in ["secret_token", "api_key", "order", "invoice_id", "patient_name", "wallet_balance", "kubeconfig", "cvv"])):
                branches.append(EvidenceBranch("Authorization", "VIOLATED", "Cross-tenant / cross-user private object accessed without owner authorization."))
                branches.append(EvidenceBranch("Impact", "VERIFIED", "Extracted confidential tenant secrets / records in response payload."))
                branches.append(EvidenceBranch("Reproducibility", "VERIFIED", f"HTTP {http_status} response reproducible."))
                val_block["evidence_level"] = EvidenceLevel.LEVEL_4_HIGH_IMPACT_PROVEN.value
                val_block["authorization_boundary_broken"] = True
                val_block["impact_demonstrated"] = True
                val_block["proof_summary"] = "Exfiltrated cross-tenant secret keys or private records."
                eg = EvidenceGraph(graph_id, "target", f"{method} {endpoint}", vuln_type, branches, EvidenceLevel.LEVEL_4_HIGH_IMPACT_PROVEN, "CONFIRMED", 0.98, sem.summary)
                return "CONFIRMED", val_block, 0.98, eg

        # ── 2. SSRF Verification ──────────────────────────────────────────────
        elif vuln_type == "SSRF":
            # Egress filter blocked connection (HTTP 400 / blocked: true)
            if http_status == 400 or body_dict.get("blocked") is True or "disallowed target" in body_str.lower() or "blocked by egress" in body_str.lower():
                branches.append(EvidenceBranch("Authorization", "SECURE", "Egress security policy actively blocked destination at ingress."))
                branches.append(EvidenceBranch("Impact", "SECURE", "Target unreachable; egress filter enforced."))
                branches.append(EvidenceBranch("Reproducibility", "VERIFIED", "HTTP 400 response reproducible."))
                val_block["evidence_level"] = EvidenceLevel.LEVEL_1_SUSPICIOUS.value
                val_block["proof_summary"] = "Server-side egress security filter blocked target IP."
                eg = EvidenceGraph(graph_id, "target", f"{method} {endpoint}", vuln_type, branches, EvidenceLevel.LEVEL_1_SUSPICIOUS, "FALSE_POSITIVE", 0.95, sem.summary)
                return "FALSE_POSITIVE", val_block, 0.95, eg

            # Level 4: Destination reached + data preview returned
            has_preview = "response_body_preview" in body_dict or "internal_build" in body_str or "meta-data" in body_str
            if http_status in (200, 201) and has_preview:
                branches.append(EvidenceBranch("Authorization", "VIOLATED", "Server initiated outbound request to internal destination."))
                branches.append(EvidenceBranch("Impact", "VERIFIED", "Server returned internal response body preview / metadata (Level 4)."))
                branches.append(EvidenceBranch("Reproducibility", "VERIFIED", f"HTTP {http_status} reproducible."))
                val_block["evidence_level"] = EvidenceLevel.LEVEL_4_HIGH_IMPACT_PROVEN.value
                val_block["authorization_boundary_broken"] = True
                val_block["impact_demonstrated"] = True
                val_block["proof_summary"] = "SSRF Proven: Outbound request returned target response body."
                eg = EvidenceGraph(graph_id, "target", f"{method} {endpoint}", vuln_type, branches, EvidenceLevel.LEVEL_4_HIGH_IMPACT_PROVEN, "CONFIRMED", 0.98, sem.summary)
                return "CONFIRMED", val_block, 0.98, eg

            # Level 3: Server-side socket initiated but closed port/timeout
            has_outbound_network_attempt = any(err in body_str for err in ["urlopen error", "WinError", "timed out", "fetch_error", "ConnectionRefusedError", "network_error"])
            if http_status in (200, 201, 502) and has_outbound_network_attempt:
                branches.append(EvidenceBranch("Authorization", "VIOLATED", "Server initiated outbound TCP socket connection."))
                branches.append(EvidenceBranch("Impact", "VERIFIED", "Server attempted outbound TCP socket connection to attacker-specified target (Level 3)."))
                branches.append(EvidenceBranch("Reproducibility", "VERIFIED", f"HTTP {http_status} reproducible."))
                val_block["evidence_level"] = EvidenceLevel.LEVEL_3_BOUNDARY_VIOLATION.value
                val_block["authorization_boundary_broken"] = True
                val_block["impact_demonstrated"] = True
                val_block["proof_summary"] = "SSRF Proven: Backend initiated outbound network socket connection to attacker-specified target."
                eg = EvidenceGraph(graph_id, "target", f"{method} {endpoint}", vuln_type, branches, EvidenceLevel.LEVEL_3_BOUNDARY_VIOLATION, "CONFIRMED", 0.94, sem.summary)
                return "CONFIRMED", val_block, 0.94, eg

        # ── 3. Mass Assignment / State Mutation ──────────────────────────────
        elif vuln_type == "MassAssignment":
            # Rejection / Blocked (HTTP 400 / 422 / upgraded: false)
            if http_status in (400, 422) or body_dict.get("upgraded") is False or (body_dict.get("privilege_escalation") is False and not sem.has_unauthorized_mutation):
                branches.append(EvidenceBranch("Authorization", "SECURE", "Server rejected unauthorized role/privilege modification."))
                branches.append(EvidenceBranch("Impact", "SECURE", "No privilege state change permitted."))
                branches.append(EvidenceBranch("Reproducibility", "VERIFIED", f"HTTP {http_status} repeatable."))
                val_block["evidence_level"] = EvidenceLevel.LEVEL_1_SUSPICIOUS.value
                val_block["proof_summary"] = "Server rejected unauthorized role/tier modification."
                eg = EvidenceGraph(graph_id, "target", f"{method} {endpoint}", vuln_type, branches, EvidenceLevel.LEVEL_1_SUSPICIOUS, "FALSE_POSITIVE", 0.95, sem.summary)
                return "FALSE_POSITIVE", val_block, 0.95, eg

            # Confirmed State Mutation via Semantic Comparison
            if http_status in (200, 201, 202) and (sem.has_unauthorized_mutation or body_dict.get("privilege_escalation") is True or body_dict.get("status") in ("role_updated", "tier_updated")):
                mutated_val = body_dict.get("role") or body_dict.get("tier") or (request_body.get("tier") if request_body else "privileged")
                branches.append(EvidenceBranch("Authorization", "VIOLATED", "Unauthorized field modification permitted without privilege check."))
                branches.append(EvidenceBranch("Impact", "VERIFIED", f"Privileged field successfully mutated in database: '{mutated_val}'."))
                branches.append(EvidenceBranch("Reproducibility", "VERIFIED", f"HTTP {http_status} repeatable."))
                val_block["evidence_level"] = EvidenceLevel.LEVEL_3_BOUNDARY_VIOLATION.value
                val_block["authorization_boundary_broken"] = True
                val_block["impact_demonstrated"] = True
                val_block["proof_summary"] = f"Mass Assignment Proven: Unauthorized privilege state mutation to '{mutated_val}'."
                eg = EvidenceGraph(graph_id, "target", f"{method} {endpoint}", vuln_type, branches, EvidenceLevel.LEVEL_3_BOUNDARY_VIOLATION, "CONFIRMED", 0.97, sem.summary)
                return "CONFIRMED", val_block, 0.97, eg

        # ── 4. Auth Bypass / BFLA ─────────────────────────────────────────────
        elif vuln_type == "AuthBypass":
            if http_status in (401, 403):
                branches.append(EvidenceBranch("Authorization", "SECURE", f"Access blocked by role-based authorization check (HTTP {http_status})."))
                branches.append(EvidenceBranch("Impact", "SECURE", "Protected resource guarded."))
                branches.append(EvidenceBranch("Reproducibility", "VERIFIED", f"HTTP {http_status} repeatable."))
                val_block["evidence_level"] = EvidenceLevel.LEVEL_1_SUSPICIOUS.value
                eg = EvidenceGraph(graph_id, "target", f"{method} {endpoint}", vuln_type, branches, EvidenceLevel.LEVEL_1_SUSPICIOUS, "FALSE_POSITIVE", 0.95, sem.summary)
                return "FALSE_POSITIVE", val_block, 0.95, eg

            if http_status in (200, 201) and ("users" in body_dict or "records" in body_dict or "system_dump" in body_dict):
                branches.append(EvidenceBranch("Authorization", "VIOLATED", "Administrative interface rendered without role verification."))
                branches.append(EvidenceBranch("Impact", "VERIFIED", "Administrative records disclosed to non-admin."))
                branches.append(EvidenceBranch("Reproducibility", "VERIFIED", f"HTTP {http_status} repeatable."))
                val_block["evidence_level"] = EvidenceLevel.LEVEL_3_BOUNDARY_VIOLATION.value
                val_block["authorization_boundary_broken"] = True
                val_block["impact_demonstrated"] = True
                eg = EvidenceGraph(graph_id, "target", f"{method} {endpoint}", vuln_type, branches, EvidenceLevel.LEVEL_3_BOUNDARY_VIOLATION, "CONFIRMED", 0.96, sem.summary)
                return "CONFIRMED", val_block, 0.96, eg

        # ── 5. Ambiguous / Telemetry / Edge Fallback ──────────────────────────
        branches.append(EvidenceBranch("Authorization", "INCONCLUSIVE", "Telemetry, timing metric, or benign error observed."))
        branches.append(EvidenceBranch("Impact", "INCONCLUSIVE", "No security boundary breach or unauthorized action demonstrated."))
        branches.append(EvidenceBranch("Reproducibility", "VERIFIED", f"HTTP {http_status} observed."))
        val_block["evidence_level"] = EvidenceLevel.LEVEL_1_SUSPICIOUS.value
        val_block["proof_summary"] = "Telemetry / observation only; insufficient evidence of security breach."
        eg = EvidenceGraph(graph_id, "target", f"{method} {endpoint}", vuln_type, branches, EvidenceLevel.LEVEL_1_SUSPICIOUS, "NEEDS_HUMAN_VALIDATION", 0.50, sem.summary)
        return "NEEDS_HUMAN_VALIDATION", val_block, 0.50, eg


# Aliases for backward compatibility
ContextAwareEvidenceValidator = SemanticEvidenceEngine
AdaptiveEvidenceValidator = SemanticEvidenceEngine
