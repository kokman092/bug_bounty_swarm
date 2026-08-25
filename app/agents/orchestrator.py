"""
app/agents/orchestrator.py
──────────────────────────
AgentOrchestrator — Coordinates the full multi-agent pipeline with:
- Strict context trimming between phases (preventing token explosion)
- Deterministic EvidenceCollector execution (no LLM hallucination in HTTP probing)
- Deduplication tracking in the hypothesis loop
- Monitored iteration limits (max 4)
- Live event emission via EventService
"""
from __future__ import annotations

from typing import Any

from app.agents.attack_surface import AttackSurfaceAgent
from app.agents.evidence_collector import EvidenceCollector
from app.agents.hunter import HunterAgent
from app.agents.recon import ReconAgent
from app.agents.reporter import ReportAgent
from app.agents.reviewer import ReviewAgent
from app.core.config import get_settings
from app.core.logging import get_logger
from app.events.schemas import EventType
from app.events.service import EventService
from app.findings.schemas import Confidence, Finding, FindingStatus, Severity
from app.findings.service import FindingService
from app.investigations.domain import InvestigationPhase
from app.reports.service import ReportService

logger = get_logger(__name__)


class AgentOrchestrator:
    """Master workflow orchestrator for the BugBounty Swarm."""

    def __init__(
        self,
        investigation_id: str,
        target_url: str,
        event_service: EventService | None = None,
        finding_service: FindingService | None = None,
        report_service: ReportService | None = None,
    ) -> None:
        self.investigation_id = investigation_id
        self.target_url = target_url
        self._event_service = event_service or EventService()
        self._finding_service = finding_service or FindingService()
        self._report_service = report_service or ReportService()

    async def run(self) -> None:
        logger.info("orchestrator_pipeline_started", investigation_id=self.investigation_id)
        settings = get_settings()

        # ── Phase 1: Reconnaissance ───────────────────────────────────────────
        await self._event_service.emit_event(
            investigation_id=self.investigation_id,
            phase=InvestigationPhase.RECON.value,
            event_type=EventType.PHASE_STARTED,
            agent_name="ReconAgent",
            input_summary=f"Initiating reconnaissance on {self.target_url}",
        )

        recon_agent = ReconAgent(self.investigation_id, self.target_url)
        recon_result = await recon_agent.run()

        await self._event_service.emit_event(
            investigation_id=self.investigation_id,
            phase=InvestigationPhase.RECON.value,
            event_type=EventType.AGENT_COMPLETED,
            agent_name="ReconAgent",
            input_summary="Reconnaissance completed",
            payload={"endpoints_discovered": len(recon_result.get("endpoints", [])), "summary": recon_result.get("recon_summary")},
        )

        # ── Context Trim 1: Summarize recon for Attack Surface ─────────────────
        trimmed_recon = {
            "target_url": self.target_url,
            "technologies": recon_result.get("technologies", []),
            "endpoints": recon_result.get("endpoints", [])[:10],
            "auth_endpoints": recon_result.get("potential_auth_endpoints", []),
            "summary": recon_result.get("recon_summary", ""),
        }

        # ── Phase 2: Attack Surface Analysis ──────────────────────────────────
        await self._event_service.emit_event(
            investigation_id=self.investigation_id,
            phase=InvestigationPhase.ATTACK_SURFACE.value,
            event_type=EventType.PHASE_STARTED,
            agent_name="AttackSurfaceAgent",
            input_summary="Analyzing attack surface and prioritizing targets",
        )

        surface_agent = AttackSurfaceAgent(self.investigation_id)
        attack_surface = await surface_agent.run(trimmed_recon)

        await self._event_service.emit_event(
            investigation_id=self.investigation_id,
            phase=InvestigationPhase.ATTACK_SURFACE.value,
            event_type=EventType.AGENT_COMPLETED,
            agent_name="AttackSurfaceAgent",
            input_summary="Attack surface analyzed",
            payload={"priority_vectors": attack_surface.get("priority_endpoints", [])},
        )

        # ── Phase 3: Finding Loop (Hunter -> Evidence -> Reviewer) ────────────
        await self._event_service.emit_event(
            investigation_id=self.investigation_id,
            phase=InvestigationPhase.LOOP.value,
            event_type=EventType.PHASE_STARTED,
            agent_name="HunterAgent",
            input_summary="Starting iterative vulnerability hypothesis & validation loop",
        )

        hunter_agent = HunterAgent(self.investigation_id)
        evidence_collector = EvidenceCollector(self.investigation_id, self.target_url)
        review_agent = ReviewAgent(self.investigation_id)

        already_proposed: list[str] = []
        review_feedback: str | None = None
        max_iters = settings.max_loop_iterations

        for iteration in range(1, max_iters + 1):
            logger.info("finding_loop_iteration_started", iteration=iteration, has_review_feedback=bool(review_feedback))

            # 1. Hunter proposes hypothesis (incorporating feedback from previous rejections)
            hypothesis = await hunter_agent.run(
                attack_surface=attack_surface,
                already_proposed=already_proposed,
                iteration=iteration,
                review_feedback=review_feedback,
            )

            if hypothesis.no_further_hypotheses:
                logger.info("hunter_signaled_no_further_hypotheses", iteration=iteration)
                break

            already_proposed.append(f"{hypothesis.vuln_class.value}:{hypothesis.endpoint}")

            await self._event_service.emit_event(
                investigation_id=self.investigation_id,
                phase=InvestigationPhase.LOOP.value,
                iteration=iteration,
                event_type=EventType.HYPOTHESIS_PROPOSED,
                agent_name="HunterAgent",
                input_summary=f"Iteration {iteration}: Proposing {hypothesis.vuln_class.value} on {hypothesis.endpoint}" + (f" (Pivoted based on feedback: '{review_feedback[:60]}...')" if review_feedback else ""),
                payload=hypothesis.model_dump(mode="json"),
                correlation_id=hypothesis.hypothesis_id,
            )

            # 2. Deterministic Evidence Collection (NO LLM)
            evidence = await evidence_collector.collect_evidence(hypothesis)

            await self._event_service.emit_event(
                investigation_id=self.investigation_id,
                phase=InvestigationPhase.LOOP.value,
                iteration=iteration,
                event_type=EventType.EVIDENCE_COLLECTED,
                agent_name="EvidenceCollector",
                input_summary=f"Executed {len(hypothesis.test_steps)} test steps",
                payload={"all_succeeded": evidence.get("all_steps_succeeded"), "steps": evidence.get("steps_executed")},
                correlation_id=hypothesis.hypothesis_id,
            )

            # 3. ReviewAgent evaluates evidence
            review = await review_agent.run(hypothesis, evidence)
            verdict_str = review.get("verdict", FindingStatus.REJECTED.value)
            verdict = FindingStatus(verdict_str) if verdict_str in FindingStatus.__members__.values() else FindingStatus.REJECTED

            # Capture feedback if rejected to guide Hunter's next pivot
            if verdict == FindingStatus.REJECTED:
                review_feedback = review.get("reason", "Observation did not produce differential proof of vulnerability.")
            else:
                review_feedback = None

            # 4. Record Finding with robust enum normalization
            raw_sev = str(review.get("technical_severity", Severity.MEDIUM.value)).upper()
            if "CRIT" in raw_sev:
                sev_val = Severity.CRITICAL
            elif "HIGH" in raw_sev:
                sev_val = Severity.HIGH
            elif "MED" in raw_sev:
                sev_val = Severity.MEDIUM
            elif "INFO" in raw_sev:
                sev_val = Severity.INFO
            else:
                sev_val = Severity.LOW

            raw_conf = str(review.get("confidence", "Medium")).upper()
            if "HIGH" in raw_conf:
                conf_val = Confidence.HIGH
            elif "LOW" in raw_conf:
                conf_val = Confidence.LOW
            else:
                conf_val = Confidence.MEDIUM

            finding = Finding(
                finding_id=hypothesis.hypothesis_id,
                investigation_id=self.investigation_id,
                hypothesis_id=hypothesis.hypothesis_id,
                title=hypothesis.title,
                endpoint=hypothesis.endpoint,
                vuln_class=hypothesis.vuln_class,
                status=verdict,
                confidence=conf_val,
                severity=sev_val,
                iterations_used=iteration,
                evidence_summary=review.get("reason", ""),
                raw_evidence_inline=evidence,
                review_feedback=review.get("reason"),
                remediation_guidance=review.get("remediation_guidance"),
            )

            await self._finding_service.save_finding(self.investigation_id, finding)

            # 5. Emit Verdict Event
            event_type = EventType.FINDING_VALIDATED if verdict == FindingStatus.VALIDATED else EventType.FINDING_REJECTED
            await self._event_service.emit_event(
                investigation_id=self.investigation_id,
                phase=InvestigationPhase.LOOP.value,
                iteration=iteration,
                event_type=event_type,
                agent_name="ReviewAgent",
                input_summary=f"Verdict: {verdict.value} for {hypothesis.endpoint} ({finding.confidence.value if finding.confidence else 'N/A'} confidence)",
                payload=review,
                correlation_id=hypothesis.hypothesis_id,
            )

        # ── Phase 4: Final Report Generation ──────────────────────────────────
        await self._event_service.emit_event(
            investigation_id=self.investigation_id,
            phase=InvestigationPhase.REPORT.value,
            event_type=EventType.PHASE_STARTED,
            agent_name="ReportAgent",
            input_summary="Compiling finalized security assessment report",
        )

        reporter = ReportAgent(
            self.investigation_id,
            self.target_url,
            finding_service=self._finding_service,
        )
        report = await reporter.run()
        await self._report_service.save_report(report)

        await self._event_service.emit_event(
            investigation_id=self.investigation_id,
            phase=InvestigationPhase.REPORT.value,
            event_type=EventType.REPORT_GENERATED,
            agent_name="ReportAgent",
            input_summary=f"Report generated with {report.finding_count} validated findings",
            payload={"finding_count": report.finding_count},
        )

        logger.info("orchestrator_pipeline_finished", investigation_id=self.investigation_id)
        return report
