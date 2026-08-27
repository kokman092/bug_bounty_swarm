"""
app/investigations/schemas.py
──────────────────────────────
Pydantic models for investigation API requests and responses.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, HttpUrl, field_validator

from app.investigations.domain import InvestigationPhase, InvestigationStatus


# ── Request Models ────────────────────────────────────────────────────────────

class SessionInput(BaseModel):
    """Authenticated user persona session credentials."""
    role: str = Field("attacker", description="'owner' (victim), 'attacker' (researcher), 'admin'")
    token: str | None = Field(None, description="Bearer or API token")
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)


class IngestBurpHistoryRequest(BaseModel):
    """Request body for POST /investigations/{id}/ingest/burp-history."""
    burp_xml: str | None = Field(None, description="Raw Burp Suite XML export string")
    har_json: dict | None = Field(None, description="Standard HAR 1.2 JSON object")


class CreateInvestigationRequest(BaseModel):
    """
    Request body for POST /investigations.
    """
    target_url: str = Field(
        ...,
        description="The URL to investigate. Must be in the authorized_targets allow-list.",
        min_length=10,
        max_length=2048,
        examples=["https://vuln-lab.example.com"],
    )
    idempotency_key: str | None = Field(
        None,
        description=(
            "Optional client-generated key to prevent duplicate submissions. "
            "If provided and a recent investigation with the same key exists, "
            "the existing investigation is returned."
        ),
        max_length=128,
    )
    sessions: list[SessionInput] = Field(
        default_factory=list,
        description="Optional authenticated user sessions (e.g. Victim Account A vs Attacker Account B) for BOLA/IDOR testing.",
    )
    burp_history_xml: str | None = Field(
        None,
        description="Optional Burp Suite XML export containing pre-recorded authenticated traffic.",
    )
    burp_history_har: dict | None = Field(
        None,
        description="Optional standard HAR 1.2 JSON containing pre-recorded traffic.",
    )

    @field_validator("target_url")
    @classmethod
    def url_must_have_scheme(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("target_url must start with http:// or https://")
        return v


# ── Response Models ───────────────────────────────────────────────────────────

class InvestigationResponse(BaseModel):
    """
    Response for GET /investigations/{id} and POST /investigations.
    Intentionally does not expose internal fields like cloud_task_name.
    """
    investigation_id: str
    target_url: str
    status: InvestigationStatus
    current_phase: InvestigationPhase | None = None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None
    error: str | None = None          # human-readable error (no stack traces)
    retry_count: int = 0


class CreateInvestigationResponse(BaseModel):
    """Response for POST /investigations (201 Created)."""
    investigation_id: str
    status: InvestigationStatus
    created_at: datetime
    message: str = "Investigation created. Connect to /stream for live updates."


class CancelInvestigationResponse(BaseModel):
    """Response for DELETE /investigations/{id} (202 Accepted)."""
    investigation_id: str
    status: InvestigationStatus
    message: str = "Cancellation requested."
