"""
tests/unit/test_test_dispatcher.py
──────────────────────────────────
Unit tests for TestDispatcher:
  - Correct tester resolution and execution.
  - Handling of unknown testers.
  - Recording negative vs signal results in AgentState.
  - Skipping duplicate tests.
"""
import pytest
from app.core.agent_state import AgentState, EndpointProfile
from app.intelligence.attack_planner import PlannedTest
from app.testing.dispatcher import DispatchResult, TestDispatcher


@pytest.mark.asyncio
async def test_dispatcher_rejects_unknown_tester():
    state = AgentState("inv-disp-1", "http://vuln-lab.com:80/")
    dispatcher = TestDispatcher("inv-disp-1", "http://vuln-lab.com:80/", agent_state=state)

    ep = EndpointProfile(target="http://vuln-lab.com:80/", endpoint="/api/test", method="GET")
    planned = PlannedTest(
        test_id="test-unreg-1",
        endpoint=ep,
        test_class="unknown_future_scanner",
        tester_name="UnknownTester",
        priority=50,
    )

    res = await dispatcher.dispatch(planned)
    assert res.status == "error"
    assert "No tester registered" in (res.error_message or "")


@pytest.mark.asyncio
async def test_dispatcher_skips_already_completed_test():
    state = AgentState("inv-disp-2", "http://vuln-lab.com:80/")
    dispatcher = TestDispatcher("inv-disp-2", "http://vuln-lab.com:80/", agent_state=state)

    ep = EndpointProfile(target="http://vuln-lab.com:80/", endpoint="/api/test", method="GET")
    planned = PlannedTest(
        test_id="test-dup-1",
        endpoint=ep,
        test_class="configuration",
        tester_name="ConfigurationTester",
        priority=50,
    )

    # Mark as completed in state
    state.record_test_execution(
        endpoint="/api/test",
        method="GET",
        vuln_class="configuration",
    )

    res = await dispatcher.dispatch(planned)
    assert res.status == "skipped"
