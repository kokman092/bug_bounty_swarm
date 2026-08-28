"""
app/validation/models.py
────────────────────────
Unified validation data models, scoring schemas, and rejection reasons.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class FindingClassification(str, Enum):
    CONFIRMED = "CONFIRMED"                # Score 90-100: Automatically enters verified finding stream
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"    # Score 70-89: Stored as high confidence candidate
    MANUAL_REVIEW = "MANUAL_REVIEW"        # Score 40-69: Requires researcher triage
    REJECTED = "REJECTED"                  # Score 0-39: Disproven or false positive
    VALIDATION_ERROR = "VALIDATION_ERROR"  # Error during verification (e.g. timeout / network fault)
    INCONCLUSIVE = "INCONCLUSIVE"          # Ambiguous differential


@dataclass
class RejectionReason:
    """Structured rationale explaining why a potential signal was rejected."""
    code: str
    message: str
    evidence_reference: str | None = None


@dataclass
class ValidationResult:
    """Unified result model representing the outcome of multi-stage validation."""
    __test__ = False
    test_id: str
    endpoint: str
    method: str
    vuln_class: str
    status: FindingClassification = FindingClassification.MANUAL_REVIEW
    reproducible: bool = False
    baseline_difference_confirmed: bool = False
    independent_validation: bool = False
    security_impact_confirmed: bool = False
    sanitized_evidence_complete: bool = False
    confidence_score: int = 0
    scoring_reasons: list[str] = field(default_factory=list)
    rejection_reasons: list[RejectionReason] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    evidence_level: int = 0
    evidence_graph_tree: str = ""
    remediation_guidance: str = ""
    validation_errors: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def is_confirmed(self) -> bool:
        return self.status == FindingClassification.CONFIRMED
