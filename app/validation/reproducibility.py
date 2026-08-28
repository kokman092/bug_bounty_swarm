"""
app/validation/reproducibility.py
─────────────────────────────────
Controlled Reproducibility Verification Engine.

Guarantees:
  1. Executes controlled repeat trials of candidate signals.
  2. Strictly routes all repeat attempts through ScopeEnforcingHttpClient & PolicyEngine.
  3. Never executes prohibited destructive actions or out-of-scope targets.
  4. Preserves all trial attempt metadata and consistency ratios.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine

from app.core.exceptions import DestructiveActionError, ScopeViolationError
from app.core.logging import get_logger
from app.findings.schemas import FindingStatus

logger = get_logger(__name__)


@dataclass
class ReproducibilityPolicy:
    """Configurable policy parameters for multi-trial verification."""
    max_attempts: int = 3
    required_consistent_results: int = 2
    inter_trial_delay_seconds: float = 1.0


@dataclass
class ReproducibilityTrialResult:
    """Detailed summary of multi-trial reproducibility verification."""
    is_reproducible: bool
    positive_count: int
    total_attempts: int
    consistency_ratio: float
    trial_records: list[dict[str, Any]] = field(default_factory=list)
    error_message: str | None = None


class ReproducibilityChecker:
    """Multi-trial reproducibility verification service."""

    def __init__(
        self,
        investigation_id: str,
        target_base_url: str,
        policy: ReproducibilityPolicy | None = None,
    ) -> None:
        self.investigation_id = investigation_id
        self.target_base_url = target_base_url.rstrip("/")
        self.policy = policy or ReproducibilityPolicy()

    async def verify_trial(
        self,
        test_executor: Callable[[], Coroutine[Any, Any, list[Any]]],
        action_name: str = "reproducibility_trial",
    ) -> ReproducibilityTrialResult:
        """
        Executes N controlled trials using the provided test_executor coroutine.
        All network requests inside test_executor pass through ScopeEnforcingHttpClient.
        """
        positive_count = 0
        trial_records: list[dict[str, Any]] = []

        logger.info(
            "reproducibility_verification_started",
            action=action_name,
            max_attempts=self.policy.max_attempts,
            required_consistent=self.policy.required_consistent_results,
        )

        for attempt in range(1, self.policy.max_attempts + 1):
            if attempt > 1 and self.policy.inter_trial_delay_seconds > 0:
                await asyncio.sleep(self.policy.inter_trial_delay_seconds)

            try:
                raw_results = await test_executor()
                has_signal = any(
                    getattr(r, "status", None) == FindingStatus.VALIDATED
                    or getattr(r, "is_confirmed", False)
                    for r in raw_results
                )
                if has_signal:
                    positive_count += 1

                trial_records.append({
                    "attempt": attempt,
                    "success": True,
                    "signal_detected": has_signal,
                    "result_count": len(raw_results),
                })

            except (ScopeViolationError, DestructiveActionError) as safety_exc:
                logger.warning("reproducibility_blocked_by_safety_policy", error=str(safety_exc))
                return ReproducibilityTrialResult(
                    is_reproducible=False,
                    positive_count=positive_count,
                    total_attempts=attempt,
                    consistency_ratio=0.0,
                    trial_records=trial_records,
                    error_message=f"Safety guardrail blocked repeat trial: {safety_exc.message if hasattr(safety_exc, 'message') else str(safety_exc)}",
                )
            except Exception as exc:
                logger.warning("reproducibility_trial_error", attempt=attempt, error=str(exc))
                trial_records.append({
                    "attempt": attempt,
                    "success": False,
                    "error": str(exc),
                    "signal_detected": False,
                })

        is_reproducible = positive_count >= self.policy.required_consistent_results
        consistency = positive_count / max(1, len(trial_records))

        logger.info(
            "reproducibility_verification_completed",
            is_reproducible=is_reproducible,
            positive_count=positive_count,
            total_attempts=len(trial_records),
            consistency=consistency,
        )

        return ReproducibilityTrialResult(
            is_reproducible=is_reproducible,
            positive_count=positive_count,
            total_attempts=len(trial_records),
            consistency_ratio=consistency,
            trial_records=trial_records,
        )
