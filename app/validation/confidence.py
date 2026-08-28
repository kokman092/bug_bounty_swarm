"""
app/validation/confidence.py
────────────────────────────
Deterministic Confidence Scoring & Status Classification.

Scoring Rubric (0-100 max):
  - Reproducibility (+25)
  - Baseline Difference Confirmed (+20)
  - Independent Validation (+20)
  - Security Impact Confirmed (+20)
  - Sanitized Evidence Complete (+15)

Classification:
  - 90-100: CONFIRMED
  - 70-89:  HIGH_CONFIDENCE
  - 40-69:  MANUAL_REVIEW
  - 0-39:   REJECTED
"""
from __future__ import annotations

from app.validation.models import FindingClassification, ValidationResult


def calculate_confidence(validation: ValidationResult) -> tuple[int, list[str]]:
    """
    Computes a deterministic, explainable confidence score (0-100) and rationale.
    Zero LLM dependency.
    """
    score = 0
    reasons: list[str] = []

    if validation.reproducible:
        score += 25
        reasons.append("+25 Reproducible: Consistent differential proof across multiple execution trials")

    if validation.baseline_difference_confirmed:
        score += 20
        reasons.append("+20 Baseline Difference: Confirmed distinct state vs control baseline")

    if validation.independent_validation:
        score += 20
        reasons.append("+20 Independent Validation: Verified via semantic evidence engine / cross-role check")

    if validation.security_impact_confirmed:
        score += 20
        reasons.append("+20 Security Impact: Confirmed confidential data access, auth bypass, or state mutation")

    if validation.sanitized_evidence_complete:
        score += 15
        reasons.append("+15 Sanitized Evidence: Complete, clean request/response evidence with redacted credentials")

    clamped_score = max(0, min(100, score))
    return clamped_score, reasons


def classify_score(score: int) -> FindingClassification:
    """Classifies a numeric confidence score into standard finding tiers."""
    if score >= 90:
        return FindingClassification.CONFIRMED
    elif score >= 70:
        return FindingClassification.HIGH_CONFIDENCE
    elif score >= 40:
        return FindingClassification.MANUAL_REVIEW
    else:
        return FindingClassification.REJECTED
