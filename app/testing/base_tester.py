"""
app/testing/base_tester.py
──────────────────────────
Base test case runner and test result models for all OWASP testing domains.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.logging import get_logger
from app.findings.schemas import Confidence, FindingStatus, Severity, VulnClass
from app.tools.http_client import ScopeEnforcingHttpClient

logger = get_logger(__name__)


@dataclass
class TestResult:
    __test__ = False
    test_name: str
    target_url: str

    endpoint: str
    method: str
    vuln_class: VulnClass
    status: FindingStatus          # VALIDATED, REJECTED, INCONCLUSIVE
    confidence: Confidence
    severity: Severity
    reproducible: bool = False
    evidence_score: int = 0         # 0-10 scale
    observations: list[str] = field(default_factory=list)
    raw_evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)


class BaseTester:
    """Base class for all specialized OWASP domain testing engines."""

    def __init__(self, investigation_id: str, target_base_url: str) -> None:
        self.investigation_id = investigation_id
        self.target_base_url = target_base_url.rstrip("/")

    async def execute_test(self, endpoint_info: dict[str, Any]) -> list[TestResult]:
        """Override in specialized subclass to execute category tests."""
        raise NotImplementedError("Subclasses must implement execute_test")
