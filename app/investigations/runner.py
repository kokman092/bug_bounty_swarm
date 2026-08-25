"""
app/investigations/runner.py
────────────────────────────
InvestigationRunner — Durable background execution engine.
Invoked either via Cloud Tasks POST /internal/investigations/{id}/run or
local asyncio background tasks.
"""
from __future__ import annotations

import asyncio
from datetime import datetime

from app.core.config import get_settings
from app.core.exceptions import AgentTimeoutError, ModelAPIError, ScopeViolationError
from app.core.logging import get_logger
from app.db.firestore import investigations_ref
from app.events.schemas import EventType
from app.events.service import EventService
from app.investigations.domain import (
    InvestigationPhase,
    InvestigationStateMachine,
    InvestigationStatus,
)

logger = get_logger(__name__)


class InvestigationRunner:
    """Orchestrates the durable end-to-end execution of an investigation."""

    def __init__(self, event_service: EventService | None = None) -> None:
        self._event_service = event_service or EventService()

    async def run_investigation(self, investigation_id: str) -> None:
        """
        Main execution loop:
        1. Checks current state (ensures idempotency / not already running or cancelled).
        2. Transitions AUTHORIZED -> QUEUED -> RUNNING.
        3. Invokes AgentOrchestrator.
        4. Transitions to FINALIZING -> COMPLETED (or RETRYING / FAILED on error).
        """
        logger.info("investigation_runner_started", investigation_id=investigation_id)
        doc_ref = investigations_ref().document(investigation_id)
        snapshot = await doc_ref.get()

        if not snapshot.exists:
            logger.error("runner_investigation_not_found", investigation_id=investigation_id)
            return

        data = snapshot.to_dict() or {}
        current_status = InvestigationStatus(data["status"])

        if current_status in {InvestigationStatus.RUNNING, InvestigationStatus.COMPLETED, InvestigationStatus.CANCELLED}:
            logger.info("runner_skipping_already_active_or_terminal", status=current_status.value)
            return

        target_url = data["target_url_normalized"]
        settings = get_settings()
        is_retry = current_status == InvestigationStatus.RETRYING

        try:
            if is_retry:
                # RETRYING → RUNNING directly (skip QUEUED)
                await self._update_status(investigation_id, InvestigationStatus.RUNNING, phase=InvestigationPhase.RECON)
            else:
                # AUTHORIZED → QUEUED → RUNNING
                await self._update_status(investigation_id, InvestigationStatus.QUEUED)
                await self._update_status(investigation_id, InvestigationStatus.RUNNING, phase=InvestigationPhase.RECON)

            await self._event_service.emit_event(
                investigation_id=investigation_id,
                phase=InvestigationPhase.RECON.value,
                event_type=EventType.INVESTIGATION_STARTED,
                agent_name="Runner",
                input_summary=f"Starting multi-agent security investigation against {target_url}",
            )

            # Lazy import to avoid circular dependencies
            from app.agents.orchestrator import AgentOrchestrator
            orchestrator = AgentOrchestrator(
                investigation_id=investigation_id,
                target_url=target_url,
                event_service=self._event_service,
            )

            # Run with timeout guard (asyncio.wait_for works on Python 3.10+)
            await asyncio.wait_for(
                orchestrator.run(),
                timeout=settings.agent_timeout_seconds,
            )

            # Check if cancelled mid-flight
            latest_snap = await doc_ref.get()
            latest_status = InvestigationStatus((latest_snap.to_dict() or {}).get("status", ""))
            if latest_status == InvestigationStatus.CANCELLING:
                await self._update_status(investigation_id, InvestigationStatus.CANCELLED)
                logger.info("runner_investigation_cancelled", investigation_id=investigation_id)
                return

            # Transition: -> FINALIZING -> COMPLETED
            await self._update_status(investigation_id, InvestigationStatus.FINALIZING, phase=InvestigationPhase.REPORT)
            await self._update_status(investigation_id, InvestigationStatus.COMPLETED, phase=InvestigationPhase.DONE)

            await self._event_service.emit_event(
                investigation_id=investigation_id,
                phase=InvestigationPhase.DONE.value,
                event_type=EventType.INVESTIGATION_COMPLETED,
                agent_name="Runner",
                input_summary="Investigation completed successfully.",
            )
            logger.info("investigation_completed_successfully", investigation_id=investigation_id)

        except asyncio.TimeoutError:
            err_msg = f"Investigation timed out after {settings.agent_timeout_seconds}s"
            logger.error("investigation_timeout", investigation_id=investigation_id)
            await self._handle_failure(investigation_id, err_msg)

        except ScopeViolationError as exc:
            err_msg = f"Scope violation: {exc.message}"
            logger.error("investigation_scope_violation", investigation_id=investigation_id, error=err_msg)
            await self._handle_failure(investigation_id, err_msg)

        except Exception as exc:
            err_msg = f"Unexpected runner error: {str(exc)}"
            logger.exception("investigation_execution_failed", investigation_id=investigation_id)
            await self._handle_failure(investigation_id, err_msg)

    async def _update_status(
        self,
        investigation_id: str,
        target_status: InvestigationStatus,
        phase: InvestigationPhase | None = None,
    ) -> None:
        doc_ref = investigations_ref().document(investigation_id)
        snapshot = await doc_ref.get()
        data = snapshot.to_dict() or {}
        sm = InvestigationStateMachine(InvestigationStatus(data["status"]))
        new_status = sm.transition(target_status)

        updates = {
            "status": new_status.value,
            "updated_at": datetime.utcnow(),
        }
        if phase:
            updates["current_phase"] = phase.value
        if new_status == InvestigationStatus.COMPLETED:
            updates["completed_at"] = datetime.utcnow()

        await doc_ref.update(updates)

    async def _handle_failure(self, investigation_id: str, error_message: str) -> None:
        doc_ref = investigations_ref().document(investigation_id)
        snapshot = await doc_ref.get()
        if not snapshot.exists:
            return

        data = snapshot.to_dict() or {}
        current_status = InvestigationStatus(data["status"])
        retries = data.get("retry_count", 0)
        max_retries = data.get("max_retries", 2)

        if retries < max_retries and current_status == InvestigationStatus.RUNNING:
            sm = InvestigationStateMachine(current_status)
            try:
                sm.transition(InvestigationStatus.RETRYING)
                await doc_ref.update({
                    "status": InvestigationStatus.RETRYING.value,
                    "retry_count": retries + 1,
                    "error": error_message,
                    "updated_at": datetime.utcnow(),
                })
                logger.info("retrying_investigation", attempt=retries + 1, investigation_id=investigation_id)
                # Re-run after brief backoff
                await asyncio.sleep(2 ** retries)
                await self.run_investigation(investigation_id)
                return
            except Exception:
                pass

        # Final failure
        try:
            sm = InvestigationStateMachine(current_status)
            if sm.can_transition_to(InvestigationStatus.FAILED):
                await doc_ref.update({
                    "status": InvestigationStatus.FAILED.value,
                    "error": error_message,
                    "completed_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow(),
                })
        except Exception:
            await doc_ref.update({
                "status": InvestigationStatus.FAILED.value,
                "error": error_message,
                "completed_at": datetime.utcnow(),
            })

        await self._event_service.emit_event(
            investigation_id=investigation_id,
            phase="FAILURE",
            event_type=EventType.INVESTIGATION_FAILED,
            agent_name="Runner",
            input_summary=f"Investigation failed: {error_message}",
            payload={"error": error_message},
        )
