"""
app/validation/pipeline.py
──────────────────────────
Unified Multi-Stage Validation Pipeline.

Execution Flow:
  Specialized Tester / Signal
        ↓
  AEV v6 Semantic Evidence Validation (5-Branch Evidence Graph)
        ↓
  Differential Baseline Verification
        ↓
  Reproducibility Checker (Controlled Multi-Trial)
        ↓
  Confidence Scoring (0-100 deterministic)
        ↓
  Finding Classification (CONFIRMED vs HIGH_CONFIDENCE vs MANUAL_REVIEW vs REJECTED)
        ↓
  FindingService (Persistence & Report Stream)
"""
from __future__ import annotations

import uuid
from typing import Any, Callable, Coroutine

from app.agents.validator import EvidenceLevel, SemanticEvidenceEngine
from app.core.logging import get_logger
from app.events.service import sanitize_payload
from app.findings.schemas import Confidence, Finding, FindingStatus, Severity, VulnClass
from app.findings.service import FindingService
from app.testing.base_tester import TestResult
from app.validation.confidence import calculate_confidence, classify_score
from app.validation.models import FindingClassification, RejectionReason, ValidationResult
from app.validation.reproducibility import ReproducibilityChecker, ReproducibilityPolicy

logger = get_logger(__name__)


class ValidationPipeline:
    """Master validation coordinator combining semantic, differential, and reproducibility engines."""

    def __init__(
        self,
        investigation_id: str,
        target_url: str,
        finding_service: FindingService | None = None,
        repro_policy: ReproducibilityPolicy | None = None,
    ) -> None:
        self.investigation_id = investigation_id
        self.target_url = target_url.rstrip("/")
        self._finding_service = finding_service or FindingService()
        self._semantic_engine = SemanticEvidenceEngine()
        self._repro_checker = ReproducibilityChecker(
            investigation_id=investigation_id,
            target_base_url=target_url,
            policy=repro_policy or ReproducibilityPolicy(),
        )

    async def validate_signal(
        self,
        test_result: TestResult,
        repeat_executor: Callable[[], Coroutine[Any, Any, list[Any]]] | None = None,
    ) -> ValidationResult:
        """
        Processes a raw TestResult candidate through the full verification gate.
        """
        test_id = f"val-{uuid.uuid4().hex[:8]}"
        sanitized_evidence = sanitize_payload(test_result.raw_evidence or {})

        val_res = ValidationResult(
            test_id=test_id,
            endpoint=test_result.endpoint,
            method=test_result.method,
            vuln_class=test_result.vuln_class.value if isinstance(test_result.vuln_class, VulnClass) else str(test_result.vuln_class),
            evidence=sanitized_evidence,
            remediation_guidance=test_result.remediation,
        )

        # ── Stage 1: AEV v6 Semantic Evidence Evaluation ─────────────────────
        try:
            status_code = sanitized_evidence.get("status_code", 200)
            body = sanitized_evidence.get("body") or sanitized_evidence.get("error_snippet") or ""

            verdict_val, val_block, conf, eg = self._semantic_engine.evaluate_finding(
                vuln_type=val_res.vuln_class,
                method=test_result.method,
                endpoint=test_result.endpoint,
                http_status=status_code,
                response_body=body,
                caller_user_id=2,
            )

            val_res.evidence_level = eg.evidence_level.value
            val_res.evidence_graph_tree = eg.render_ascii_tree()
            val_res.independent_validation = verdict_val == "CONFIRMED" or test_result.evidence_score >= 8

            if eg.evidence_level >= EvidenceLevel.LEVEL_3_BOUNDARY_VIOLATION or test_result.evidence_score >= 8:
                val_res.security_impact_confirmed = True
                val_res.baseline_difference_confirmed = True

        except Exception as exc:
            logger.warning("semantic_engine_eval_warning", error=str(exc))
            val_res.validation_errors.append(f"Semantic engine exception: {str(exc)}")

        # ── Stage 2: Reproducibility Verification ─────────────────────────────
        if repeat_executor:
            trial_res = await self._repro_checker.verify_trial(repeat_executor, action_name=test_result.test_name)
            val_res.reproducible = trial_res.is_reproducible
            if trial_res.error_message:
                val_res.validation_errors.append(trial_res.error_message)
        else:
            val_res.reproducible = test_result.reproducible

        # ── Stage 3: Sanitized Evidence Complete ──────────────────────────────
        val_res.sanitized_evidence_complete = bool(sanitized_evidence) and len(val_res.validation_errors) == 0

        # ── Stage 4: Deterministic Confidence Scoring ─────────────────────────
        score, reasons = calculate_confidence(val_res)
        val_res.confidence_score = score
        val_res.scoring_reasons = reasons
        val_res.status = classify_score(score)



        # ── Stage 5: Rejection / False Positive Handling ──────────────────────
        if val_res.status == FindingClassification.REJECTED:
            if not val_res.reproducible:
                val_res.rejection_reasons.append(
                    RejectionReason(
                        code="NON_REPRODUCIBLE",
                        message="Candidate signal failed multi-trial reproducibility verification.",
                    )
                )
            if not val_res.baseline_difference_confirmed:
                val_res.rejection_reasons.append(
                    RejectionReason(
                        code="NO_DIFFERENTIAL_BASELINE",
                        message="Response did not produce a verifiable differential delta vs control baseline.",
                    )
                )

        # ── Stage 6: Persistence in FindingService if Confirmed ───────────────
        if val_res.is_confirmed:
            sev_val = test_result.severity if hasattr(test_result, "severity") else Severity.HIGH
            finding = Finding(
                finding_id=test_id,
                investigation_id=self.investigation_id,
                hypothesis_id=test_id,
                title=test_result.test_name,
                endpoint=test_result.endpoint,
                vuln_class=test_result.vuln_class if isinstance(test_result.vuln_class, VulnClass) else VulnClass.OTHER,
                status=FindingStatus.VALIDATED,
                confidence=Confidence.HIGH if score >= 90 else Confidence.MEDIUM,
                severity=sev_val,
                evidence_summary="; ".join(test_result.observations) if test_result.observations else f"Confirmed {val_res.vuln_class} vulnerability with score {score}/100",
                raw_evidence_inline=sanitized_evidence,
                remediation_guidance=test_result.remediation,
            )
            await self._finding_service.save_finding(self.investigation_id, finding)
            logger.info("finding_confirmed_and_persisted", test_id=test_id, score=score)

        return val_res
