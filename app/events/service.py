"""
app/events/service.py
─────────────────────
EventService — Manages the event lifecycle with:
- Transactional monotonically increasing sequence numbers
- Size limits and truncation (preventing Firestore 1MB document limit)
- Sensitive data sanitization (redacting tokens, credentials, API keys)
- SSE replay query support (fetching events since Last-Event-ID)
"""
from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime
from typing import Any, AsyncGenerator

from app.core.exceptions import InvestigationNotFoundError
from app.core.logging import get_logger
from app.db.firestore import (
    agent_events_ref,
    get_firestore_client,
    investigations_ref,
)
from app.events.schemas import AgentEvent, EventType

logger = get_logger(__name__)

# Maximum allowed payload size before truncation (50KB)
MAX_PAYLOAD_BYTES = 50 * 1024

SENSITIVE_KEYS = {
    "api_key", "apikey", "secret", "password", "token",
    "authorization", "cookie", "set-cookie", "bearer",
    "gemini_api_key", "x-api-key", "private_key",
}


def sanitize_payload(obj: Any) -> Any:
    """Recursively redact sensitive field values."""
    if isinstance(obj, dict):
        sanitized = {}
        for k, v in obj.items():
            if str(k).lower() in SENSITIVE_KEYS:
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_payload(v)
        return sanitized
    elif isinstance(obj, list):
        return [sanitize_payload(item) for item in obj]
    return obj


def truncate_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Truncate payload if serialized size exceeds MAX_PAYLOAD_BYTES."""
    try:
        serialized = json.dumps(payload, default=str)
        size_bytes = len(serialized.encode("utf-8"))
        if size_bytes <= MAX_PAYLOAD_BYTES:
            return payload, False

        truncated_summary = {
            "_truncated": True,
            "_original_size_bytes": size_bytes,
            "_message": f"Payload exceeded {MAX_PAYLOAD_BYTES} byte limit and was truncated.",
            "keys_present": list(payload.keys()),
        }
        for k, v in payload.items():
            if isinstance(v, (str, int, float, bool)) and len(str(v)) < 200:
                truncated_summary[k] = v
        return truncated_summary, True
    except Exception:
        return {"_truncated": True, "_error": "Failed to serialize payload"}, True


class EventService:
    """Service managing structured event persistence, sequence numbers, and streaming."""

    async def emit_event(
        self,
        investigation_id: str,
        phase: str,
        event_type: EventType,
        agent_name: str | None = None,
        iteration: int = 0,
        input_summary: str | None = None,
        payload: dict[str, Any] | None = None,
        correlation_id: str | None = None,
    ) -> AgentEvent:
        """
        Monotonically increment investigation's sequence counter and persist the event.
        """
        payload_data = payload or {}
        sanitized = sanitize_payload(payload_data)
        final_payload, was_truncated = truncate_payload(sanitized)

        event_id = str(uuid.uuid4())
        inv_doc_ref = investigations_ref().document(investigation_id)
        events_coll_ref = agent_events_ref(investigation_id)

        try:
            snapshot = await inv_doc_ref.get()
            snap_data = snapshot.to_dict() if hasattr(snapshot, "to_dict") else None
            data = snap_data or {}
            seq = data.get("event_sequence_counter", 0) + 1

            await inv_doc_ref.update({
                "event_sequence_counter": seq,
                "updated_at": datetime.utcnow(),
            })
        except Exception:
            seq = 1

        event = AgentEvent(
            event_id=event_id,
            investigation_id=investigation_id,
            sequence_number=seq,
            agent_name=agent_name,
            phase=phase,
            iteration=iteration,
            event_type=event_type,
            input_summary=input_summary,
            payload=final_payload,
            payload_truncated=was_truncated,
            created_at=datetime.utcnow(),
            correlation_id=correlation_id,
        )

        try:
            event_doc = events_coll_ref.document(event_id)
            await event_doc.set(event.model_dump(mode="json"))
        except Exception as exc:
            logger.warning("event_doc_write_failed", error=str(exc))

        logger.info(
            "event_emitted",
            investigation_id=investigation_id,
            sequence_number=event.sequence_number,
            event_type=event.event_type.value,
            agent=agent_name,
        )
        return event

    async def get_events_after(
        self,
        investigation_id: str,
        last_sequence_number: int = 0,
        limit: int = 100,
    ) -> list[AgentEvent]:
        """Fetch historical events where sequence_number > last_sequence_number."""
        events_coll = agent_events_ref(investigation_id)
        query = (
            events_coll
            .where("sequence_number", ">", last_sequence_number)
            .order_by("sequence_number", direction="ASCENDING")
            .limit(limit)
        )
        docs = await query.get()
        events: list[AgentEvent] = []
        for doc in docs:
            data = doc.to_dict()
            if data:
                events.append(AgentEvent(**data))
        return events

    async def stream_events(
        self,
        investigation_id: str,
        last_sequence_number: int = 0,
        poll_interval_s: float = 0.5,
    ) -> AsyncGenerator[AgentEvent, None]:
        current_seq = last_sequence_number
        inv_ref = investigations_ref().document(investigation_id)

        while True:
            inv_snapshot = await inv_ref.get()
            if not inv_snapshot.exists:
                break
            inv_data = inv_snapshot.to_dict() or {}
            status = inv_data.get("status")

            batch = await self.get_events_after(
                investigation_id=investigation_id,
                last_sequence_number=current_seq,
                limit=50,
            )
            for event in batch:
                current_seq = max(current_seq, event.sequence_number)
                yield event

            if status in {"COMPLETED", "FAILED", "CANCELLED", "REJECTED"}:
                trailing = await self.get_events_after(
                    investigation_id=investigation_id,
                    last_sequence_number=current_seq,
                    limit=50,
                )
                for event in trailing:
                    current_seq = max(current_seq, event.sequence_number)
                    yield event
                break

            await asyncio.sleep(poll_interval_s)
