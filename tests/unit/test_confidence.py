"""
tests/unit/test_confidence.py
─────────────────────────────
Unit tests for deterministic confidence scoring and classification.
"""
import pytest
from app.validation.confidence import calculate_confidence, classify_score
from app.validation.models import FindingClassification, ValidationResult


class TestConfidenceScoring:

    def test_score_zero(self):
        val = ValidationResult(test_id="t0", endpoint="/api", method="GET", vuln_class="BOLA")
        score, reasons = calculate_confidence(val)
        assert score == 0
        assert len(reasons) == 0
        assert classify_score(score) == FindingClassification.REJECTED

    def test_score_25_reproducible_only(self):
        val = ValidationResult(
            test_id="t25", endpoint="/api", method="GET", vuln_class="BOLA",
            reproducible=True
        )
        score, reasons = calculate_confidence(val)
        assert score == 25
        assert len(reasons) == 1
        assert classify_score(score) == FindingClassification.REJECTED

    def test_score_40_manual_review_threshold(self):
        val = ValidationResult(
            test_id="t40", endpoint="/api", method="GET", vuln_class="BOLA",
            baseline_difference_confirmed=True,
            security_impact_confirmed=True,
        )
        score, reasons = calculate_confidence(val)
        assert score == 40
        assert len(reasons) == 2
        assert classify_score(score) == FindingClassification.MANUAL_REVIEW

    def test_score_70_high_confidence(self):
        val = ValidationResult(
            test_id="t70", endpoint="/api", method="GET", vuln_class="BOLA",
            reproducible=True,                      # +25
            baseline_difference_confirmed=True,     # +20
            independent_validation=True,            # +20
            sanitized_evidence_complete=False,      # 0
        )
        score, reasons = calculate_confidence(val)
        assert score == 65
        # Add sanitized evidence
        val.sanitized_evidence_complete = True      # +15
        score2, reasons2 = calculate_confidence(val)
        assert score2 == 80
        assert classify_score(score2) == FindingClassification.HIGH_CONFIDENCE

    def test_score_100_confirmed_finding(self):
        val = ValidationResult(
            test_id="t100", endpoint="/api/orders/1", method="GET", vuln_class="BOLA",
            reproducible=True,                      # +25
            baseline_difference_confirmed=True,     # +20
            independent_validation=True,            # +20
            security_impact_confirmed=True,         # +20
            sanitized_evidence_complete=True,       # +15
        )
        score, reasons = calculate_confidence(val)
        assert score == 100
        assert len(reasons) == 5
        assert classify_score(score) == FindingClassification.CONFIRMED
        assert val.is_confirmed is False # Until updated
        val.status = classify_score(score)
        assert val.is_confirmed is True

    def test_score_cannot_exceed_100(self):
        val = ValidationResult(
            test_id="t-max", endpoint="/api", method="GET", vuln_class="BOLA",
            reproducible=True,
            baseline_difference_confirmed=True,
            independent_validation=True,
            security_impact_confirmed=True,
            sanitized_evidence_complete=True,
        )
        score, _ = calculate_confidence(val)
        assert score <= 100
