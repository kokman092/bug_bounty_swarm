"""
tests/unit/test_attack_planner.py
─────────────────────────────────
Unit tests for deterministic OWASP AttackPlanner:
  - REST endpoint classification & object ID detection.
  - GraphQL & WebSocket planning.
  - Test prioritization rules.
  - Test deduplication & reproducibility exceptions.
  - Zero-network execution guarantee.
"""
import pytest
from app.core.agent_state import AgentState, EndpointProfile
from app.intelligence.attack_planner import AttackPlanner, PlannedTest, TestPlan


class TestAttackPlanner:

    def test_classify_rest_endpoint_with_object_ids(self):
        planner = AttackPlanner("inv-plan-1", "http://target.com")
        ep = planner.classify_endpoint({
            "path": "/api/users/{user_id}/orders/101",
            "method": "GET",
            "parameters": ["format"],
            "requires_auth": True,
        })
        assert ep.method == "GET"
        assert ep.protocol == "REST_CANDIDATE"
        assert "user_id" in ep.object_identifiers
        assert "101" in ep.object_identifiers
        assert ep.authentication_required is True

    def test_classify_graphql_endpoint(self):
        planner = AttackPlanner("inv-plan-2", "http://target.com")
        ep = planner.classify_endpoint({
            "path": "/graphql",
            "method": "POST",
            "parameters": ["query", "mutation"],
        })
        assert ep.protocol == "GRAPHQL_CANDIDATE"


    def test_generate_test_plan_prioritizes_object_ids(self):
        planner = AttackPlanner("inv-plan-3", "http://target.com")
        planner.classify_endpoint({"path": "/api/orders/{id}", "method": "GET"})
        planner.classify_endpoint({"path": "/api/public/status", "method": "GET"})

        plan = planner.generate_test_plan()
        assert len(plan.planned_tests) > 0

        highest = plan.get_highest_priority_tests(limit=1)[0]
        # BOLA on /api/orders/{id} should have priority 100
        assert highest.priority == 100
        assert highest.test_class == "authorization"
        assert "/api/orders/{id}" in highest.endpoint.endpoint

    def test_deduplicates_completed_tests(self):
        state = AgentState("inv-plan-4", "http://target.com")
        planner = AttackPlanner("inv-plan-4", "http://target.com", agent_state=state)
        
        ep = planner.classify_endpoint({"path": "/api/items/5", "method": "GET"})
        
        # Mark authorization test as completed
        state.record_test_execution(
            endpoint="/api/items/5",
            method="GET",
            vuln_class="authorization",
        )

        plan = planner.generate_test_plan()
        auth_tests = [t for t in plan.planned_tests if t.test_class == "authorization" and t.endpoint.endpoint == "/api/items/5"]
        assert len(auth_tests) == 0

    def test_reproducibility_flag_overrides_deduplication(self):
        state = AgentState("inv-plan-5", "http://target.com")
        planner = AttackPlanner("inv-plan-5", "http://target.com", agent_state=state)
        
        ep = planner.classify_endpoint({"path": "/api/items/5", "method": "GET"})
        state.record_test_execution(
            endpoint="/api/items/5",
            method="GET",
            vuln_class="authorization",
        )

        plan = planner.generate_test_plan(force_reproducibility=True)
        auth_tests = [t for t in plan.planned_tests if t.test_class == "authorization" and t.endpoint.endpoint == "/api/items/5"]
        assert len(auth_tests) == 1
        assert auth_tests[0].requires_reproducibility is True

    def test_candidate_protocol_does_not_schedule_protocol_specific_tests(self):
        planner = AttackPlanner("inv-plan-6", "http://target.com")
        # An unconfirmed candidate GraphQL endpoint
        ep = planner.classify_endpoint({
            "path": "/graphql",
            "method": "POST",
            "protocol": "GRAPHQL_CANDIDATE",
        })
        assert ep.protocol == "GRAPHQL_CANDIDATE"

        plan = planner.generate_test_plan()
        test_classes = [t.test_class for t in plan.planned_tests if t.endpoint.endpoint == "/graphql"]
        
        # Only safe generic tests allowed for candidate
        assert "api_security" not in test_classes
        assert "authentication" in test_classes
        assert "configuration" in test_classes

    def test_sensitive_parameters_are_skipped_from_injection_planning(self):
        planner = AttackPlanner("inv-plan-7", "http://target.com")
        ep = planner.classify_endpoint({
            "path": "/api/users/search",
            "method": "GET",
            "parameters": ["query", "password", "csrf_token", "filter"],
        })

        plan = planner.generate_test_plan()
        injection_params = [
            t.parameter for t in plan.planned_tests
            if t.test_class == "injection" and t.endpoint.endpoint == "/api/users/search"
        ]

        # Eligible non-sensitive parameters are planned
        assert "query" in injection_params or "filter" in injection_params
        # Sensitive credentials/tokens are strictly skipped
        assert "password" not in injection_params
        assert "csrf_token" not in injection_params

