"""
app/findings/schemas.py
───────────────────────
Schemas and Enums for vulnerability hypotheses and findings.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class VulnClass(str, Enum):
    IDOR            = "IDOR"
    BOLA            = "BOLA"
    AUTH_BYPASS     = "AuthBypass"
    SSRF            = "SSRF"
    SQLI            = "SQLi"
    MASS_ASSIGNMENT = "MassAssignment"
    MISCONFIG       = "Misconfig"
    INFO_DISCLOSURE = "InfoDisclosure"
    OTHER           = "Other"


class FindingStatus(str, Enum):
    PROPOSED     = "PROPOSED"
    VALIDATED    = "VALIDATED"
    REJECTED     = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class Confidence(str, Enum):
    HIGH   = "High"
    MEDIUM = "Medium"
    LOW    = "Low"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH     = "High"
    MEDIUM   = "Medium"
    LOW      = "Low"
    INFO     = "Info"


class TestStep(BaseModel):
    __test__ = False  # Prevent pytest from treating this Pydantic model as a test case
    step_number: int
    description: str
    method: str = "GET"
    path: str
    headers: dict[str, str] = Field(default_factory=dict)
    params: dict[str, str] = Field(default_factory=dict)
    json_body: dict[str, Any] | None = None


class Hypothesis(BaseModel):
    hypothesis_id: str
    vuln_class: VulnClass
    endpoint: str
    title: str
    rationale: str
    test_steps: list[TestStep] = Field(default_factory=list)
    no_further_hypotheses: bool = False


class Finding(BaseModel):
    finding_id: str
    investigation_id: str
    hypothesis_id: str
    title: str
    endpoint: str
    vuln_class: VulnClass
    status: FindingStatus
    confidence: Confidence | None = None
    severity: Severity = Severity.MEDIUM
    iterations_used: int = 1
    evidence_summary: str = ""
    raw_evidence_inline: dict[str, Any] | None = None
    evidence_ref: str | None = None  # GCS path if large
    review_feedback: str | None = None
    remediation_guidance: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    deduplicated_from: str | None = None
