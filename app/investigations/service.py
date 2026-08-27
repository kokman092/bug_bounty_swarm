"""
app/investigations/service.py
──────────────────────────────
InvestigationService — Business logic for creating, retrieving, cancelling,
and transitioning investigation state.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from app.core.config import get_settings
from app.core.exceptions import (
    InvestigationAlreadyTerminalError,
    InvestigationNotFoundError,
    InvalidStateTransitionError,
    TargetNotAuthorizedError,
)
from app.core.logging import get_logger
from app.core.security import AuthUser
from app.db.firestore import get_firestore_client, investigations_ref
from app.events.schemas import EventType
from app.events.service import EventService
from app.investigations.domain import (
    InvestigationPhase,
    InvestigationStateMachine,
    InvestigationStatus,
    TERMINAL_STATES,
)
from app.investigations.schemas import (
    CreateInvestigationRequest,
    CreateInvestigationResponse,
    InvestigationResponse,
)
from app.targets.authorization import AuthorizationService

logger = get_logger(__name__)

try:
    from google.cloud import firestore
    _async_transactional = firestore.async_transactional
except Exception:
    firestore = None
    _async_transactional = lambda f: f


class InvestigationService:
    """Service layer managing investigation lifecycle and interactions with DB & Cloud Tasks."""

    def __init__(
        self,
        auth_service: AuthorizationService | None = None,
        event_service: EventService | None = None,
    ) -> None:
        self._auth_service = auth_service or AuthorizationService()
        self._event_service = event_service or EventService()

    async def create_investigation(
        self,
        request: CreateInvestigationRequest,
        user: AuthUser,
    ) -> CreateInvestigationResponse:
        """
        1. Authorize target URL (fails fast if out of scope / SSRF).
        2. Check for duplicate idempotency key (if supplied).
        3. Persist investigation document in Firestore (status = AUTHORIZED).
        4. Emit initial event.
        5. Dispatch execution task (Cloud Tasks or local background execution).
        """
        investigation_id = str(uuid.uuid4())
        settings = get_settings()

        # Step 1: Authorize target
        normalized_target = await self._auth_service.authorize_investigation_target(
            target_url=request.target_url,
            investigation_id=investigation_id,
        )

        # Step 2: Idempotency check if key provided
        if request.idempotency_key:
            existing = await self._find_by_idempotency_key(request.idempotency_key, user.user_id)
            if existing:
                logger.info("idempotent_investigation_returned", inv_id=existing.investigation_id)
                return CreateInvestigationResponse(
                    investigation_id=existing.investigation_id,
                    status=existing.status,
                    created_at=existing.created_at,
                    message="Investigation already exists for idempotency key.",
                )

        now = datetime.utcnow()
        doc_data = {
            "id": investigation_id,
            "target_url": request.target_url,
            "target_url_normalized": normalized_target.canonical,
            "requested_by": user.user_id,
            "status": InvestigationStatus.AUTHORIZED.value,
            "current_phase": None,
            "created_at": now,
            "updated_at": now,
            "completed_at": None,
            "authorized": True,
            "error": None,
            "retry_count": 0,
            "max_retries": settings.max_retries,
            "event_sequence_counter": 0,
            "idempotency_key": request.idempotency_key,
        }

        doc_ref = investigations_ref().document(investigation_id)
        await doc_ref.set(doc_data)

        # Step 3: Populate SessionVault if human researcher provided authenticated sessions
        from app.targets.session_vault import UserSession, get_session_vault
        vault = get_session_vault(investigation_id)
        for s in (request.sessions or []):
            vault.add_session(UserSession(role=s.role, token=s.token, headers=s.headers, cookies=s.cookies))

        # Step 4: Parse pre-recorded Burp history if supplied
        parsed_history = None
        if request.burp_history_xml:
            from app.tools.burp.history_parser import parse_burp_xml_history
            parsed_history = parse_burp_xml_history(request.burp_history_xml)
        elif request.burp_history_har:
            from app.tools.burp.history_parser import parse_har_history
            parsed_history = parse_har_history(request.burp_history_har)

        doc_data["burp_history"] = parsed_history

        # Step 5: Emit creation event
        await self._event_service.emit_event(
            investigation_id=investigation_id,
            phase="INITIALIZATION",
            event_type=EventType.INVESTIGATION_CREATED,
            agent_name="System",
            input_summary=f"Investigation created for {normalized_target.canonical}" + (f" with {len(request.sessions)} authenticated sessions" if request.sessions else "") + (f" and {parsed_history.get('total_requests', 0)} recorded Burp requests" if parsed_history else ""),
            payload={
                "target_url": request.target_url,
                "canonical": normalized_target.canonical,
                "sessions_configured": len(request.sessions or []),
                "burp_requests_ingested": parsed_history.get("total_requests", 0) if parsed_history else 0,
            },
        )

        # Step 4: Dispatch task to queue
        await self._dispatch_investigation_task(investigation_id)

        return CreateInvestigationResponse(
            investigation_id=investigation_id,
            status=InvestigationStatus.AUTHORIZED,
            created_at=now,
        )

    async def get_investigation(
        self,
        investigation_id: str,
        user: AuthUser,
    ) -> InvestigationResponse:
        """Fetch investigation state, ensuring ownership."""
        doc_ref = investigations_ref().document(investigation_id)
        snapshot = await doc_ref.get()

        if not snapshot.exists:
            raise InvestigationNotFoundError(investigation_id)

        data = snapshot.to_dict() or {}
        if data.get("requested_by") != user.user_id:
            # 404 to avoid enumeration
            raise InvestigationNotFoundError(investigation_id)

        return InvestigationResponse(
            investigation_id=data["id"],
            target_url=data["target_url"],
            status=InvestigationStatus(data["status"]),
            current_phase=InvestigationPhase(data["current_phase"]) if data.get("current_phase") else None,
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            completed_at=data.get("completed_at"),
            error=data.get("error"),
            retry_count=data.get("retry_count", 0),
        )

    async def cancel_investigation(
        self,
        investigation_id: str,
        user: AuthUser,
    ) -> InvestigationStatus:
        """Request cancellation of an active investigation."""
        doc_ref = investigations_ref().document(investigation_id)
        snapshot = await doc_ref.get()

        if not snapshot.exists:
            raise InvestigationNotFoundError(investigation_id)

        data = snapshot.to_dict() or {}
        if data.get("requested_by") != user.user_id:
            raise InvestigationNotFoundError(investigation_id)

        current_status = InvestigationStatus(data["status"])
        sm = InvestigationStateMachine(current_status)
        new_status = sm.transition(InvestigationStatus.CANCELLING)

        await doc_ref.update({
            "status": new_status.value,
            "updated_at": firestore.SERVER_TIMESTAMP if firestore else datetime.utcnow(),
        })

        await self._event_service.emit_event(
            investigation_id=investigation_id,
            phase="LIFECYCLE",
            event_type=EventType.INVESTIGATION_CANCELLED,
            agent_name="System",
            input_summary="Cancellation requested by user",
        )

        return new_status

    async def transition_status(
        self,
        investigation_id: str,
        target_status: InvestigationStatus,
        phase: InvestigationPhase | None = None,
        error: str | None = None,
    ) -> InvestigationStatus:
        """Atomic state machine transition."""
        client = get_firestore_client()
        doc_ref = investigations_ref().document(investigation_id)
        transaction = client.transaction()

        @_async_transactional
        async def _transition_txn(txn: Any) -> InvestigationStatus:
            snapshot = await doc_ref.get(transaction=txn)
            if not snapshot.exists:
                raise InvestigationNotFoundError(investigation_id)
            data = snapshot.to_dict() or {}
            current_status = InvestigationStatus(data["status"])

            sm = InvestigationStateMachine(current_status)
            new_status = sm.transition(target_status)

            updates: dict[str, Any] = {
                "status": new_status.value,
                "updated_at": firestore.SERVER_TIMESTAMP if firestore else datetime.utcnow(),
            }
            if phase is not None:
                updates["current_phase"] = phase.value
            if error is not None:
                updates["error"] = error
            if new_status in TERMINAL_STATES:
                updates["completed_at"] = firestore.SERVER_TIMESTAMP if firestore else datetime.utcnow()

            if hasattr(txn, "update"):
                txn.update(doc_ref, updates)
            return new_status

        try:
            return await _transition_txn(transaction)
        except Exception:
            return target_status

    async def _find_by_idempotency_key(self, key: str, user_id: str) -> InvestigationResponse | None:
        query = (
            investigations_ref()
            .where("idempotency_key", "==", key)
            .where("requested_by", "==", user_id)
            .limit(1)
        )
        docs = await query.get()
        if docs:
            data = docs[0].to_dict() or {}
            return InvestigationResponse(
                investigation_id=data["id"],
                target_url=data["target_url"],
                status=InvestigationStatus(data["status"]),
                current_phase=InvestigationPhase(data["current_phase"]) if data.get("current_phase") else None,
                created_at=data["created_at"],
                updated_at=data["updated_at"],
                completed_at=data.get("completed_at"),
                error=data.get("error"),
                retry_count=data.get("retry_count", 0),
            )
        return None

    async def _dispatch_investigation_task(self, investigation_id: str) -> None:
        """Dispatches execution task."""
        settings = get_settings()
        if settings.is_development:
            import asyncio
            from app.investigations.runner import InvestigationRunner
            runner = InvestigationRunner()
            asyncio.create_task(runner.run_investigation(investigation_id))
            logger.info("local_async_runner_dispatched", investigation_id=investigation_id)
        else:
            try:
                from google.cloud import tasks_v2
                client = tasks_v2.CloudTasksAsyncClient()
                parent = client.queue_path(
                    settings.gcp_project_id,
                    settings.cloud_tasks_location,
                    settings.cloud_tasks_queue,
                )
                url = f"{settings.runner_base_url}/internal/investigations/{investigation_id}/run"
                task = {
                    "http_request": {
                        "http_method": tasks_v2.HttpMethod.POST,
                        "url": url,
                        "headers": {
                            "Content-Type": "application/json",
                            "X-Internal-Secret": settings.api_secret_key,
                        },
                    }
                }
                await client.create_task(request={"parent": parent, "task": task})
                logger.info("cloud_task_enqueued", investigation_id=investigation_id, queue=settings.cloud_tasks_queue)
            except Exception as exc:
                logger.error("cloud_task_enqueue_failed", error=str(exc), investigation_id=investigation_id)
                import asyncio
                from app.investigations.runner import InvestigationRunner
                runner = InvestigationRunner()
                asyncio.create_task(runner.run_investigation(investigation_id))
