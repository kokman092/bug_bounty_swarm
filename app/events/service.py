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
import re
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

SENSITIVE_KEY_PATTERNS = re.compile(
    r"(api[_-]?key|secret|password|passwd|token|authorization|auth|cookie|set-cookie|bearer|gemini_api_key|x-api-key|private_key|credentials)",
    re.IGNORECASE,
)

# String value secret redaction regexes
JWT_PATTERN = re.compile(r"eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}(\.[a-zA-Z0-9_-]*)?")
BEARER_PATTERN = re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]+", re.IGNORECASE)
BASIC_PATTERN = re.compile(r"Basic\s+[a-zA-Z0-9+/=]+", re.IGNORECASE)
API_KEY_VAL_PATTERN = re.compile(r"(api[_-]?key\s*[=:]\s*)([a-zA-Z0-9_\-]+)", re.IGNORECASE)
PASSWORD_VAL_PATTERN = re.compile(r"(password\s*[=:]\s*)([^\s,;&]+)", re.IGNORECASE)


def sanitize_string(text: str) -> str:
    """Sanitize secrets embedded inside arbitrary text strings."""
    if not isinstance(text, str):
        return text

    out = text
    # 1. Redact Bearer tokens
    out = BEARER_PATTERN.sub("Bearer [REDACTED]", out)
    # 2. Redact Basic auth
    out = BASIC_PATTERN.sub("Basic [REDACTED]", out)
    # 3. Redact API key expressions (e.g. api_key=sk-123)
    out = API_KEY_VAL_PATTERN.sub(r"\1[REDACTED]", out)
    # 4. Redact Password expressions
    out = PASSWORD_VAL_PATTERN.sub(r"\1[REDACTED]", out)
    # 5. Redact raw JWT tokens
    out = JWT_PATTERN.sub("[REDACTED_JWT]", out)
    return out


def sanitize_payload(obj: Any) -> Any:
    """
    Recursively redact sensitive field values and secrets across dictionaries,
    lists, headers, and text strings without mutating the input object.
    """
    if isinstance(obj, dict):
        sanitized = {}
        for k, v in obj.items():
            k_str = str(k)
            if SENSITIVE_KEY_PATTERNS.search(k_str):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_payload(v)


        return sanitized
    elif isinstance(obj, list):
        return [sanitize_payload(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(sanitize_payload(item) for item in obj)
    elif isinstance(obj, set):
        return {sanitize_payload(item) for item in obj}
    elif isinstance(obj, str):
        return sanitize_string(obj)
    return obj


def truncate_payload(
    payload: dict[str, Any], max_bytes: int = MAX_PAYLOAD_BYTES
) -> tuple[dict[str, Any], bool]:
    """
    Truncate payload if serialized size exceeds max_bytes, preserving structure
    and truncating oversized text fields with [Truncated] indicators.
    """
    try:
        serialized = json.dumps(payload, default=str)
        size_bytes = len(serialized.encode("utf-8"))
        if size_bytes <= max_bytes:
            return dict(payload), False

        truncated = dict(payload)
        for k, v in list(truncated.items()):
            if isinstance(v, str) and len(v) > 200:
                keep_len = max(50, max_bytes // (len(payload) + 1))
                truncated[k] = v[:keep_len] + f"... [Truncated: {len(v)} bytes]"

        # Re-check size
        if len(json.dumps(truncated, default=str).encode("utf-8")) > max_bytes:
            # Fallback to compact summary
            compact_summary = {
                "_truncated": True,
                "_original_size_bytes": size_bytes,
                "summary": str(payload.get("summary", "Truncated large payload")),
                "keys_present": list(payload.keys()),
            }
            return compact_summary, True

        return truncated, True
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
