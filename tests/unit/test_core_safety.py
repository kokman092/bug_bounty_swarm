"""
tests/unit/test_core_safety.py
──────────────────────────────
Unit tests for Core Safety & State components:
  - AgentState test identity computation & deduplication.
  - PolicyEngine rate limiting & destructive action blocking.
  - ScopeGuard integration.
"""
import pytest
from app.core.agent_state import AgentState, get_agent_state
from app.core.policy_engine import DestructiveActionError, PolicyEngine
from app.findings.schemas import FindingStatus


class TestAgentStateDeduplication:

    def test_test_identity_computation(self):
        id1 = AgentState.compute_test_identity(
            target="http://example.com/",
            endpoint="/api/orders/1",
            method="GET",
            vuln_class="BOLA",
            parameter="order_id",
            auth_context="attacker",
        )
        id2 = AgentState.compute_test_identity(
            target="http://example.com",
            endpoint="/api/orders/1",
            method="get",
            vuln_class="bola",
            parameter="ORDER_ID",
            auth_context="ATTACKER",
        )
        assert id1 == id2
        assert "http://example.com:GET:/api/orders/1:BOLA:order_id:attacker" == id1

    def test_record_and_prevent_duplicate_tests(self):
        state = AgentState(investigation_id="inv-test-state", target="http://target.com")
        
        assert state.is_test_completed("/api/users", "GET", "BOLA") is False
        
        state.record_test_execution(
            endpoint="/api/users",
            method="GET",
            vuln_class="BOLA",
            status=FindingStatus.REJECTED,
        )
        
        assert state.is_test_completed("/api/users", "GET", "BOLA") is True
        # Different vuln class is not completed
        assert state.is_test_completed("/api/users", "GET", "SQLi") is False


class TestPolicyEngineSafety:

    def test_blocks_destructive_sql_payload(self):
        engine = PolicyEngine()
        with pytest.raises(DestructiveActionError):
            engine.validate_action_safety("POST", "/api/query", payload="1'; DROP TABLE users;--")

    def test_blocks_destructive_system_paths(self):
        engine = PolicyEngine()
        with pytest.raises(DestructiveActionError):
            engine.validate_action_safety("DELETE", "/api/system/shutdown")

    def test_allows_safe_queries(self):
        engine = PolicyEngine()
        # Safe queries should pass without exception
        engine.validate_action_safety("GET", "/api/orders/1")
        engine.validate_action_safety("GET", "/api/search", payload={"q": "apple"})
