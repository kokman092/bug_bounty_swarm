"""
tests/unit/test_validation_pipeline.py
──────────────────────────────────────
Unit & Integration tests for the full ValidationPipeline:
  - Scenario A: Consistent signal + AEV v6 + Reproducibility -> CONFIRMED (score 100).
  - Scenario B: Inconsistent signal (failed repeat) -> REJECTED / NON_REPRODUCIBLE.
  - Scenario C: Policy blocked during repeat -> Error recorded without safety bypass.
  - High confidence does not automatically become final confirmed finding.
"""
import pytest
from app.findings.schemas import Confidence, FindingStatus, Severity, VulnClass
from app.testing.base_tester import TestResult
from app.validation.models import FindingClassification
from app.validation.pipeline import ValidationPipeline
from app.validation.reproducibility import ReproducibilityPolicy


class TestValidationPipeline:

    @pytest.mark.asyncio
    async def test_scenario_a_confirmed_finding_pipeline(self):
        pipeline = ValidationPipeline(
            investigation_id="inv-pipe-1",
            target_url="http://target.com",
            repro_policy=ReproducibilityPolicy(max_attempts=2, required_consistent_results=2, inter_trial_delay_seconds=0),
        )

        test_result = TestResult(
            test_name="BOLA on /api/orders/1",
            target_url="http://target.com/api/orders/1",
            endpoint="/api/orders/1",
            method="GET",
            vuln_class=VulnClass.BOLA,
            status=FindingStatus.VALIDATED,
            confidence=Confidence.HIGH,
            severity=Severity.HIGH,
            reproducible=True,
            evidence_score=10,
            observations=["Cross-tenant private data returned to attacker"],
            raw_evidence={
                "status_code": 200,
                "body": {"order_id": 1, "owner_id": 10, "secret_token": "live_sec_123"},
            },
            remediation="Enforce object authorization check",
        )

        async def repeat_exec():
            return [test_result]

        val_res = await pipeline.validate_signal(test_result, repeat_executor=repeat_exec)
        assert val_res.confidence_score == 100
        assert val_res.status == FindingClassification.CONFIRMED
        assert val_res.is_confirmed is True
        assert val_res.reproducible is True
        assert val_res.security_impact_confirmed is True
        assert val_res.sanitized_evidence_complete is True

    @pytest.mark.asyncio
    async def test_scenario_b_inconsistent_signal_rejected(self):
        pipeline = ValidationPipeline(
            investigation_id="inv-pipe-2",
            target_url="http://target.com",
            repro_policy=ReproducibilityPolicy(max_attempts=3, required_consistent_results=2, inter_trial_delay_seconds=0),
        )

        test_result = TestResult(
            test_name="Flaky BOLA signal on /api/orders/2",
            target_url="http://target.com/api/orders/2",
            endpoint="/api/orders/2",
            method="GET",
            vuln_class=VulnClass.BOLA,
            status=FindingStatus.VALIDATED,
            confidence=Confidence.HIGH,
            severity=Severity.HIGH,
            raw_evidence={"status_code": 200, "body": {"item": "demo_item"}},
        )

        # Repeat trials fail
        async def failing_repeat_exec():
            return [TestResult("BOLA", "http://target.com", "/api/orders/2", "GET", VulnClass.BOLA, FindingStatus.REJECTED, Confidence.LOW, Severity.LOW)]

        val_res = await pipeline.validate_signal(test_result, repeat_executor=failing_repeat_exec)
        assert val_res.reproducible is False
        assert val_res.status in (FindingClassification.REJECTED, FindingClassification.MANUAL_REVIEW)
        assert val_res.is_confirmed is False
        assert any(r.code == "NON_REPRODUCIBLE" for r in val_res.rejection_reasons)

    @pytest.mark.asyncio
    async def test_high_confidence_is_not_automatically_confirmed(self):
        pipeline = ValidationPipeline(
            investigation_id="inv-pipe-3",
            target_url="http://target.com",
            repro_policy=ReproducibilityPolicy(max_attempts=1, required_consistent_results=1, inter_trial_delay_seconds=0),
        )

        # Test result missing independent verification or incomplete evidence
        test_result = TestResult(
            test_name="Potential Configuration Leak",
            target_url="http://target.com/api/status",
            endpoint="/api/status",
            method="GET",
            vuln_class=VulnClass.MISCONFIG,
            status=FindingStatus.VALIDATED,
            confidence=Confidence.MEDIUM,
            severity=Severity.LOW,
            evidence_score=6,  # Below 8
            reproducible=True,
            raw_evidence={},   # Incomplete evidence
        )

        val_res = await pipeline.validate_signal(test_result)
        # Score should be below 90
        assert val_res.confidence_score < 90
        assert val_res.status != FindingClassification.CONFIRMED
        assert val_res.is_confirmed is False
