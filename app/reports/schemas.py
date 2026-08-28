"""
app/reports/schemas.py
──────────────────────
Report schemas and data models.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.findings.schemas import Finding


class ReportFindingItem(BaseModel):
    finding_id: str
    title: str
    severity: str
    vuln_class: str
    affected_endpoint: str
    description: str
    impact: str
    reproduction_steps: list[str] = Field(default_factory=list)
    poc_curl: str = Field("", description="Concrete curl reproduction command")
    remediation: str
    confidence: str



class InvestigationReport(BaseModel):
    investigation_id: str
    target_url: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    generation_attempt: int = 1
    finding_count: int = 0
    findings: list[ReportFindingItem] = Field(default_factory=list)
    markdown_report: str
    markdown_report_ref: str | None = None  # GCS path if large
