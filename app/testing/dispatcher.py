"""
app/testing/dispatcher.py
─────────────────────────
Test Dispatcher & Execution Coordinator.

Responsibilities:
  1. Receives PlannedTest from AttackPlanner.
  2. Resolves and instantiates the matching specialized OWASP tester.
  3. Executes test through the secure ScopeEnforcingHttpClient & PolicyEngine.
  4. Normalizes results into a standardized DispatchResult.
  5. Records test execution and deduplication history in AgentState.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Type

from app.core.agent_state import AgentState
from app.core.logging import get_logger
from app.findings.schemas import FindingStatus, VulnClass
from app.intelligence.attack_planner import PlannedTest
from app.testing.api_security.api_tester import ApiSecurityTester
from app.testing.authentication.auth_tester import AuthenticationTester
from app.testing.authorization.access_control_tester import AccessControlTester
from app.testing.base_tester import BaseTester, TestResult
from app.testing.configuration.config_tester import ConfigurationTester
from app.testing.injection.injection_tester import InjectionTester

logger = get_logger(__name__)

# Registry mapping test class names to specialized tester implementations
TESTER_REGISTRY: dict[str, Type[BaseTester]] = {
    "authentication": AuthenticationTester,
    "authorization": AccessControlTester,
    "injection": InjectionTester,
    "configuration": ConfigurationTester,
    "api_security": ApiSecurityTester,
}


@dataclass
class DispatchResult:
    """Standardized outcome from a dispatched security test."""
    test_id: str
    status: str                   # "signal" | "negative" | "error" | "skipped"
    tester_name: str
    endpoint: str
    method: str
    vuln_class: str
    raw_results: list[TestResult] = field(default_factory=list)
    error_message: str | None = None
    executed_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def has_signal(self) -> bool:
        """Returns True if any observation indicated a potential vulnerability."""
        return self.status == "signal" and len(self.raw_results) > 0


class TestDispatcher:
    """Coordinates execution between PlannedTests and specialized testers."""
    __test__ = False

    def __init__(

        self,
        investigation_id: str,
        target_url: str,
        agent_state: AgentState | None = None,
    ) -> None:
        self.investigation_id = investigation_id
        self.target_url = target_url.rstrip("/")
        self.agent_state = agent_state or AgentState(investigation_id, target_url)

    async def dispatch(self, planned_test: PlannedTest) -> DispatchResult:
        """
        Executes a planned test case, records results, and returns normalized dispatch output.
        """
        ep_profile = planned_test.endpoint
        test_class = planned_test.test_class.lower()
        param = planned_test.parameter or ""

        # 1. Deduplication Check
        if not planned_test.requires_reproducibility and self.agent_state.is_test_completed(
            ep_profile.endpoint, ep_profile.method, test_class, parameter=param
        ):
            logger.debug(
                "dispatcher_skipping_already_completed_test",
                test_id=planned_test.test_id,
                endpoint=ep_profile.endpoint,
            )
            return DispatchResult(
                test_id=planned_test.test_id,
                status="skipped",
                tester_name=planned_test.tester_name,
                endpoint=ep_profile.endpoint,
                method=ep_profile.method,
                vuln_class=test_class,
            )

        # 2. Resolve Specialized Tester
        tester_cls = TESTER_REGISTRY.get(test_class)
        if not tester_cls:
            err_msg = f"No tester registered for test class: '{test_class}'"
            logger.error("dispatcher_unregistered_tester", test_class=test_class)
            return DispatchResult(
                test_id=planned_test.test_id,
                status="error",
                tester_name="Unknown",
                endpoint=ep_profile.endpoint,
                method=ep_profile.method,
                vuln_class=test_class,
                error_message=err_msg,
            )

        # 3. Prepare Input & Instantiate Tester
        endpoint_info = {
            "path": ep_profile.endpoint,
            "method": ep_profile.method,
            "parameters": [param] if param else ep_profile.parameters,
            "requires_auth": ep_profile.authentication_required,
            "object_identifiers": ep_profile.object_identifiers,
        }

        tester_instance = tester_cls(self.investigation_id, self.target_url)

        # 4. Execute Test
        try:
            logger.info(
                "dispatcher_executing_test",
                test_id=planned_test.test_id,
                tester=planned_test.tester_name,
                endpoint=ep_profile.endpoint,
                method=ep_profile.method,
            )
            raw_results = await tester_instance.execute_test(endpoint_info)

            # Check if any finding was validated by tester
            has_validated = any(r.status == FindingStatus.VALIDATED for r in raw_results)
            outcome_status = "signal" if has_validated else "negative"

            # 5. Record Execution in AgentState
            verdict_status = FindingStatus.VALIDATED if has_validated else FindingStatus.REJECTED
            self.agent_state.record_test_execution(
                endpoint=ep_profile.endpoint,
                method=ep_profile.method,
                vuln_class=test_class,
                parameter=param,
                status=verdict_status,
            )

            return DispatchResult(
                test_id=planned_test.test_id,
                status=outcome_status,
                tester_name=planned_test.tester_name,
                endpoint=ep_profile.endpoint,
                method=ep_profile.method,
                vuln_class=test_class,
                raw_results=raw_results,
            )

        except Exception as exc:
            logger.warning(
                "dispatcher_tester_execution_error",
                test_id=planned_test.test_id,
                tester=planned_test.tester_name,
                error=str(exc),
            )
            return DispatchResult(
                test_id=planned_test.test_id,
                status="error",
                tester_name=planned_test.tester_name,
                endpoint=ep_profile.endpoint,
                method=ep_profile.method,
                vuln_class=test_class,
                error_message=str(exc),
            )
