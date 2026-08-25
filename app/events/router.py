"""
app/events/router.py
────────────────────
FastAPI SSE endpoint for streaming live investigation events.
Supports Last-Event-ID header and query param for reconnect replay.
"""
from __future__ import annotations

import json
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse

from app.core.exceptions import InvestigationNotFoundError
from app.core.security import AuthUser, require_user
from app.events.service import EventService
from app.investigations.service import InvestigationService

router = APIRouter(prefix="/investigations", tags=["events"])


def get_event_service() -> EventService:
    return EventService()


def get_investigation_service() -> InvestigationService:
    return InvestigationService()


@router.get(
    "/{investigation_id}/stream",
    response_class=StreamingResponse,
    summary="Server-Sent Events stream for live investigation updates",
)
async def stream_investigation_events(
    request: Request,
    investigation_id: str,
    last_event_id: str | None = Header(None, alias="Last-Event-ID"),
    last_seq: int = Query(0, description="Fallback sequence offset if Last-Event-ID not supported"),
    user: AuthUser = Depends(require_user),
    inv_service: InvestigationService = Depends(get_investigation_service),
    event_service: EventService = Depends(get_event_service),
) -> StreamingResponse:
    """
    SSE stream of structured AgentEvents.
    Clients supply Last-Event-ID header upon reconnection to resume seamlessly.
    """
    # 1. Verify existence & ownership
    try:
        await inv_service.get_investigation(investigation_id, user)
    except InvestigationNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found",
        )

    # Determine starting sequence
    start_seq = 0
    if last_event_id and last_event_id.isdigit():
        start_seq = int(last_event_id)
    elif last_seq > 0:
        start_seq = last_seq

    async def event_generator() -> AsyncGenerator[str, None]:
        # Send initial keepalive comment
        yield ": ping\n\n"

        async for event in event_service.stream_events(
            investigation_id=investigation_id,
            last_sequence_number=start_seq,
        ):
            # Check client disconnect
            if await request.is_disconnected():
                break

            data_str = json.dumps(event.model_dump(mode="json"), default=str)
            msg = (
                f"id: {event.sequence_number}\n"
                f"event: {event.event_type.value}\n"
                f"data: {data_str}\n\n"
            )
            yield msg

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
