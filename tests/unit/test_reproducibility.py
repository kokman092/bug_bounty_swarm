"""
tests/unit/test_reproducibility.py
──────────────────────────────────
Unit tests for ReproducibilityChecker:
  - Multi-trial consistency verification (2/3 consistent, 1/3 fail, 3/3 pass).
  - Strict safety enforcement (PolicyEngine and ScopeGuard cannot be bypassed).
"""
import pytest
from app.core.exceptions import DestructiveActionError, ScopeViolationError
from app.findings.schemas import Confidence, FindingStatus, Severity, VulnClass
from app.testing.base_tester import TestResult
from app.validation.reproducibility import ReproducibilityChecker, ReproducibilityPolicy


class TestReproducibilityChecker:

    @pytest.mark.asyncio
    async def test_two_out_of_three_signals_is_reproducible(self):
        checker = ReproducibilityChecker(
            "inv-rep-1", "http://target.com",
            policy=ReproducibilityPolicy(max_attempts=3, required_consistent_results=2, inter_trial_delay_seconds=0)
        )

        call_count = 0
        async def mock_executor():
            nonlocal call_count
            call_count += 1
            # Attempt 1 & 2 succeed, Attempt 3 fails
            if call_count in (1, 2):
                return [TestResult("Test", "http://target.com", "/api", "GET", VulnClass.BOLA, FindingStatus.VALIDATED, Confidence.HIGH, Severity.HIGH)]
            return [TestResult("Test", "http://target.com", "/api", "GET", VulnClass.BOLA, FindingStatus.REJECTED, Confidence.LOW, Severity.LOW)]

        res = await checker.verify_trial(mock_executor)
        assert res.is_reproducible is True
        assert res.positive_count == 2
        assert res.total_attempts == 3
        assert pytest.approx(res.consistency_ratio, 0.01) == 2 / 3

    @pytest.mark.asyncio
    async def test_one_out_of_three_signals_is_not_reproducible(self):
        checker = ReproducibilityChecker(
            "inv-rep-2", "http://target.com",
            policy=ReproducibilityPolicy(max_attempts=3, required_consistent_results=2, inter_trial_delay_seconds=0)
        )

        call_count = 0
        async def mock_executor():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [TestResult("Test", "http://target.com", "/api", "GET", VulnClass.BOLA, FindingStatus.VALIDATED, Confidence.HIGH, Severity.HIGH)]
            return [TestResult("Test", "http://target.com", "/api", "GET", VulnClass.BOLA, FindingStatus.REJECTED, Confidence.LOW, Severity.LOW)]

        res = await checker.verify_trial(mock_executor)
        assert res.is_reproducible is False
        assert res.positive_count == 1
        assert res.total_attempts == 3

    @pytest.mark.asyncio
    async def test_all_signals_is_reproducible(self):
        checker = ReproducibilityChecker(
            "inv-rep-3", "http://target.com",
            policy=ReproducibilityPolicy(max_attempts=3, required_consistent_results=2, inter_trial_delay_seconds=0)
        )

        async def mock_executor():
            return [TestResult("Test", "http://target.com", "/api", "GET", VulnClass.BOLA, FindingStatus.VALIDATED, Confidence.HIGH, Severity.HIGH)]

        res = await checker.verify_trial(mock_executor)
        assert res.is_reproducible is True
        assert res.positive_count == 3
        assert res.consistency_ratio == 1.0

    @pytest.mark.asyncio
    async def test_scope_blocked_during_repeat_does_not_bypass(self):
        checker = ReproducibilityChecker(
            "inv-rep-4", "http://target.com",
            policy=ReproducibilityPolicy(max_attempts=3, required_consistent_results=2, inter_trial_delay_seconds=0)
        )

        transport_called = False
        async def mock_executor_with_scope_guard():
            nonlocal transport_called
            # Simulate ScopeGuard evaluating before transport
            from app.core.exceptions import ScopeViolationError
            raise ScopeViolationError("http://evil-out-of-scope.com", "inv-rep-4")
            transport_called = True  # Must never be reached

        res = await checker.verify_trial(mock_executor_with_scope_guard)
        assert res.is_reproducible is False
        assert transport_called is False  # Assert transport was NEVER called
        assert "Safety guardrail blocked repeat trial" in (res.error_message or "")

    @pytest.mark.asyncio
    async def test_policy_blocked_during_repeat_does_not_bypass(self):
        checker = ReproducibilityChecker(
            "inv-rep-5", "http://target.com",
            policy=ReproducibilityPolicy(max_attempts=3, required_consistent_results=2, inter_trial_delay_seconds=0)
        )

        transport_called = False
        async def mock_executor_with_policy_engine():
            nonlocal transport_called
            # Simulate PolicyEngine evaluating before transport
            from app.core.policy_engine import get_policy_engine
            policy = get_policy_engine()
            policy.validate_action_safety("POST", "/api/system/shutdown", payload="DROP TABLE users;")
            transport_called = True  # Must never be reached

        res = await checker.verify_trial(mock_executor_with_policy_engine)
        assert res.is_reproducible is False
        assert transport_called is False  # Assert transport was NEVER called
        assert "Safety guardrail blocked" in (res.error_message or "")

    @pytest.mark.asyncio
    async def test_private_ip_ssrf_blocked_during_repeat(self):
        checker = ReproducibilityChecker(
            "inv-rep-6", "http://169.254.169.254",
            policy=ReproducibilityPolicy(max_attempts=3, required_consistent_results=2, inter_trial_delay_seconds=0)
        )

        transport_called = False
        async def mock_executor_with_ssrf_check():
            nonlocal transport_called
            from app.targets.private_ip import validate_host_not_private
            validate_host_not_private("169.254.169.254", allow_local_lab=False)
            transport_called = True

        res = await checker.verify_trial(mock_executor_with_ssrf_check)
        assert res.is_reproducible is False
        assert transport_called is False  # Assert transport was NEVER called

    def test_reproducibility_checker_has_no_raw_transport_imports(self):
        """Verify ReproducibilityChecker has zero imports of httpx, requests, urllib, or aiohttp."""
        import inspect
        from app.validation import reproducibility
        source = inspect.getsource(reproducibility)
        assert "import httpx" not in source
        assert "import requests" not in source
        assert "import aiohttp" not in source
        assert "import urllib" not in source

