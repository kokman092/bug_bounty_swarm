"""
vuln_lab/analysis/failure_report.py
───────────────────────────────────
Failure Report Generator.

Compiles structured failure diagnostics and architectural recommendations.
"""
from __future__ import annotations

from typing import Any
from vuln_lab.analysis.error_classifier import FailureDiagnostic


class FailureReportGenerator:
    """Generates detailed failure reports from diagnostic cards."""

    def generate_report(self, diagnostics: list[FailureDiagnostic]) -> str:
        if not diagnostics:
            return "No failures observed in benchmark run. 100% precision and recall."

        lines = [
            "=" * 80,
            f"AUTOMATED FAILURE & ROOT CAUSE REPORT ({len(diagnostics)} Issues Diagnosed)",
            "=" * 80,
        ]

        fp_list = [d for d in diagnostics if d.failure_type == "FALSE_POSITIVE"]
        fn_list = [d for d in diagnostics if d.failure_type == "FALSE_NEGATIVE"]

        lines.append(f"\nSummary: {len(fp_list)} False Positives, {len(fn_list)} False Negatives\n")

        if fp_list:
            lines.append("-- FALSE POSITIVES (Security Defenses Flagged as Vulnerabilities) ---------")
            for d in fp_list:
                lines.append(d.format_diagnostic_card())

        if fn_list:
            lines.append("\n-- FALSE NEGATIVES (Real Vulnerabilities Missed / Blocked) ---------------")
            for d in fn_list:
                lines.append(d.format_diagnostic_card())

        lines.append("=" * 80 + "\n")
        return "\n".join(lines)

