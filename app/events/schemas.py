"""
app/events/schemas.py
─────────────────────
Event schemas and payload models for the investigation event stream.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EventType(str, Enum):
    """Types of events emitted during an investigation."""
    INVESTIGATION_CREATED   = "INVESTIGATION_CREATED"
    INVESTIGATION_AUTHORIZED = "INVESTIGATION_AUTHORIZED"
    INVESTIGATION_STARTED   = "INVESTIGATION_STARTED"
    PHASE_STARTED           = "PHASE_STARTED"
    PHASE_COMPLETED         = "PHASE_COMPLETED"
    AGENT_STARTED           = "AGENT_STARTED"
    AGENT_COMPLETED         = "AGENT_COMPLETED"
    AGENT_THOUGHT           = "AGENT_THOUGHT"
    TOOL_CALLED             = "TOOL_CALLED"
    TOOL_COMPLETED          = "TOOL_COMPLETED"
    HYPOTHESIS_PROPOSED     = "HYPOTHESIS_PROPOSED"
    EVIDENCE_COLLECTED      = "EVIDENCE_COLLECTED"
    FINDING_VALIDATED       = "FINDING_VALIDATED"
    FINDING_REJECTED        = "FINDING_REJECTED"
    TEST_SKIPPED            = "TEST_SKIPPED"
    POLICY_BLOCKED          = "POLICY_BLOCKED"
    INVESTIGATION_COMPLETED = "INVESTIGATION_COMPLETED"
    INVESTIGATION_FAILED    = "INVESTIGATION_FAILED"
    INVESTIGATION_CANCELLED = "INVESTIGATION_CANCELLED"



class AgentEvent(BaseModel):
    """
    Standard event model written to Firestore `investigations/{id}/agent_events/{event_id}`
    and pushed over SSE stream to the frontend.
    """
    event_id: str = Field(..., description="Unique event identifier (UUID)")
    investigation_id: str = Field(..., description="Target investigation ID")
    sequence_number: int = Field(..., ge=1, description="Strict monotonically increasing sequence number")
    agent_name: str | None = Field(None, description="Name of the agent or service emitting the event")
    phase: str = Field(..., description="Current investigation phase (RECON, ATTACK_SURFACE, LOOP, REPORT)")
    iteration: int = Field(0, ge=0, description="Loop iteration (0 for non-loop phases)")
    event_type: EventType = Field(..., description="Event type discriminator")
    input_summary: str | None = Field(None, description="Human readable summary of agent input")
    payload: dict[str, Any] = Field(default_factory=dict, description="Structured event payload (capped to 16KB)")
    payload_truncated: bool = Field(False, description="Flag indicating if payload exceeded size cap")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Timestamp event was generated")
    correlation_id: str | None = Field(None, description="Correlation identifier for tracing related actions")
