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
