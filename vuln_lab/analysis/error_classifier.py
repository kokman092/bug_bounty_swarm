"""
vuln_lab/analysis/error_classifier.py
─────────────────────────────────────
Automated Error Classification & Root Cause Engine.

Analyzes every False Positive (FP) and False Negative (FN) to diagnose:
  - Failed Evidence Graph Branch (Scope, Authentication, Authorization, Impact, Reproducibility)
  - Failure Category (Identity Extraction, Schema Mismatch, Telemetry Conflation, State Tracking)
  - Root Cause Explanation
  - Architectural Recommendation (without hardcoded keyword rules)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class FailureDiagnostic:
    case_id: str
    failure_type: str  # "FALSE_POSITIVE" | "FALSE_NEGATIVE"
    vuln_type: str
    endpoint: str
    expected_verdict: str
    actual_verdict: str
    failed_branch: str  # Scope, Authentication, Authorization, Impact, Reproducibility
    evidence_level: int
    observed_facts: dict[str, Any]
    root_cause: str
    recommendation: str

    def format_diagnostic_card(self) -> str:
        return f"""
--------------------------------------------------------------------------------
Case ID:            {self.case_id}
Failure Type:       {self.failure_type}
Vulnerability Type: {self.vuln_type}
Endpoint:           {self.endpoint}
Expected Verdict:   {self.expected_verdict}
Actual Verdict:     {self.actual_verdict} (Evidence Level {self.evidence_level})

Failed Branch:      {self.failed_branch}
Observed Facts:     {self.observed_facts}

Root Cause:
  {self.root_cause}

Architectural Recommendation:
  {self.recommendation}
--------------------------------------------------------------------------------"""


class ErrorClassifier:
    """Classifies verification discrepancies and pinpoints Evidence Graph branch failures."""

    def diagnose_failure(
        self,
        case_id: str,
        vuln_type: str,
        endpoint: str,
        expected: str,
        actual: str,
        evidence_level: int,
        evidence_graph: Any,
        http_status: int,
        response_body: Any,
        request_body: Any = None,
        caller_id: int | str = 2,
    ) -> FailureDiagnostic:
        body_dict = response_body if isinstance(response_body, dict) else {}
        body_str = str(response_body)

        # 1. Diagnose False Positive (Secure/Ambiguous wrongly called CONFIRMED)
        if actual == "CONFIRMED" and expected in ("FALSE_POSITIVE", "NEEDS_HUMAN_VALIDATION"):
            failed_branch = "Impact / Telemetry"
            root_cause = "Telemetry or public sample data was conflated with confidential tenant exfiltration."
            recommendation = "Enhance context analysis to verify whether data points carry victim identity value."

            if "public" in body_str.lower() or "anon" in body_str.lower() or http_status == 206:
                failed_branch = "Impact"
                root_cause = "Public sample / anonymized chunk contained sensitive-looking field names."
                recommendation = "Enforce semantic dataset classification before assessing confidentiality impact."

            elif body_dict.get("returned_user_id") == caller_id:
                failed_branch = "Authorization"
                root_cause = "Server returned caller's own profile; identity match was not verified against caller ID."
                recommendation = "Enforce identity candidate extraction comparing returned identity with authenticated caller."

            return FailureDiagnostic(
                case_id=case_id,
                failure_type="FALSE_POSITIVE",
                vuln_type=vuln_type,
                endpoint=endpoint,
                expected_verdict=expected,
                actual_verdict=actual,
                failed_branch=failed_branch,
                evidence_level=evidence_level,
                observed_facts={"http_status": http_status, "body_snippet": body_str[:120]},
                root_cause=root_cause,
                recommendation=recommendation,
            )

        # 2. Diagnose False Negative (Real vuln missed / flagged FP/NHV)
        else:
            failed_branch = "Authorization / State Transition"
            root_cause = "Evidence validator failed to recognize security boundary violation."
            recommendation = "Implement schema-independent semantic entity extraction."

            if vuln_type in ("BOLA", "IDOR"):
                failed_branch = "Authorization"
                root_cause = "Identity extraction failed because the response schema used non-standard identity keys."
                recommendation = "Extract identity candidates across nested objects and compare ownership."

            elif vuln_type == "SSRF":
                failed_branch = "Reproducibility / Network Interaction"
                root_cause = "Outbound socket error was classified as connection failure rather than server-side request behavior."
                recommendation = "Recognize server-initiated socket operations as Level 3 network activity."

            elif vuln_type == "MassAssignment":
                failed_branch = "State Transition"
                root_cause = "State mutation occurred on a non-standard field not present in static keyword lists."
                recommendation = "Perform generic state differential analysis between request and response."

            return FailureDiagnostic(
                case_id=case_id,
                failure_type="FALSE_NEGATIVE",
                vuln_type=vuln_type,
                endpoint=endpoint,
                expected_verdict=expected,
                actual_verdict=actual,
                failed_branch=failed_branch,
                evidence_level=evidence_level,
                observed_facts={"http_status": http_status, "body_snippet": body_str[:120]},
                root_cause=root_cause,
                recommendation=recommendation,
            )
