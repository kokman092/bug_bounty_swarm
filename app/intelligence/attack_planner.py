"""
app/intelligence/attack_planner.py
──────────────────────────────────
Deterministic OWASP Attack Planner & Test Selection Engine.

Responsibilities:
  1. Classify discovered endpoints into structured EndpointProfile models.
  2. Map protocol and endpoint characteristics against OWASP_TEST_MAP.
  3. Prioritize tests using an explainable, deterministic scoring system.
  4. Deduplicate planned tests against AgentState test execution history.
  5. Provide guaranteed structured test coverage.

CRITICAL CONSTRAINTS:
  - ZERO network requests.
  - Zero direct httpx/requests execution.
  - Pure planning, classification, and test prioritization.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.agent_state import AgentState, EndpointProfile
from app.core.logging import get_logger

logger = get_logger(__name__)


# ── Canonical OWASP Domain Test Map ──────────────────────────────────────────
OWASP_TEST_MAP = {
    "REST_CONFIRMED": {
        "default": [
            "authentication",
            "authorization",
            "injection",
            "configuration",
            "api_security",
        ]
    },
    "REST": {
        "default": [
            "authentication",
            "authorization",
            "injection",
            "configuration",
            "api_security",
        ]
    },
    "GRAPHQL_CONFIRMED": {
        "default": [
            "authentication",
            "authorization",
            "api_security",
            "configuration",
        ]
    },
    "WEBSOCKET_CONFIRMED": {
        "default": [
            "authentication",
            "authorization",
            "configuration",
        ]
    },
    # Candidate & Unknown protocols receive only generic safe baseline tests; NO protocol-specific test suites
    "REST_CANDIDATE": {
        "default": [
            "authentication",
            "authorization",
            "injection",
            "configuration",
        ]
    },
    "GRAPHQL_CANDIDATE": {
        "default": [
            "authentication",
            "configuration",
        ]
    },
    "WEBSOCKET_CANDIDATE": {
        "default": [
            "authentication",
            "configuration",
        ]
    },
    "UNKNOWN": {
        "default": [
            "authentication",
            "configuration",
        ]
    },
}



TESTER_NAME_MAP = {
    "authentication": "AuthenticationTester",
    "authorization": "AccessControlTester",
    "injection": "InjectionTester",
    "configuration": "ConfigurationTester",
    "api_security": "ApiSecurityTester",
}


@dataclass
class PlannedTest:
    """A single deterministic test case scheduled for execution by the Dispatcher."""
    test_id: str
    endpoint: EndpointProfile
    test_class: str               # authentication | authorization | injection | configuration | api_security
    tester_name: str
    priority: int                 # 0 to 100
    parameter: str | None = None
    auth_context: str = "attacker"
    reason: str = ""
    requires_reproducibility: bool = False


@dataclass
class TestPlan:
    """Collection of prioritized planned test cases for an investigation."""
    __test__ = False
    investigation_id: str
    target_url: str
    planned_tests: list[PlannedTest] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)


    def get_highest_priority_tests(self, limit: int = 10) -> list[PlannedTest]:
        """Returns the top N highest priority tests."""
        return sorted(self.planned_tests, key=lambda t: t.priority, reverse=True)[:limit]

    def get_tests_by_class(self, test_class: str) -> list[PlannedTest]:
        """Filters planned tests by OWASP test class."""
        return [t for t in self.planned_tests if t.test_class.lower() == test_class.lower()]


class AttackPlanner:
    """
    Deterministic OWASP test plan generator.
    Evaluates endpoint characteristics and generates prioritized test plans.
    """

    def __init__(
        self,
        investigation_id: str,
        target_url: str,
        agent_state: AgentState | None = None,
    ) -> None:
        self.investigation_id = investigation_id
        self.target_url = target_url.rstrip("/")
        self.agent_state = agent_state or AgentState(investigation_id, target_url)

    def classify_endpoint(self, ep_dict: dict[str, Any]) -> EndpointProfile:
        """
        Classifies raw discovery information into an EndpointProfile.
        Zero LLM hallucination: only extracts structured attributes from recon.
        """
        from app.discovery.api_mapper import APIMapper
        from app.discovery.parameter_discovery import ParameterDiscovery

        path = str(ep_dict.get("path") or ep_dict.get("endpoint") or "/")
        method = str(ep_dict.get("method") or "GET").upper()
        raw_params = list(ep_dict.get("parameters") or [])
        requires_auth = ep_dict.get("requires_auth", None)
        protocol = str(ep_dict.get("protocol") or "").upper() or APIMapper.classify_protocol(path)

        # 1. Extract path parameters and candidate object identifiers
        path_params, path_objs = ParameterDiscovery.extract_from_path(path)
        detected_objs: list[str] = list(path_objs)

        # 2. Process query/body parameters
        param_profiles = list(path_params)
        for rp in raw_params:
            if isinstance(rp, str):
                if not any(p.name == rp for p in param_profiles):
                    q_prof = ParameterDiscovery.extract_from_query_string(f"{path}?{rp}=1")
                    param_profiles.extend(q_prof)
            else:
                param_profiles.append(rp)

        for p in param_profiles:
            if hasattr(p, "object_identifier_candidate") and p.object_identifier_candidate:
                if p.name not in detected_objs:
                    detected_objs.append(p.name)

        content_type = "application/json" if method in ("POST", "PUT", "PATCH") else None

        # Heuristic check for common security path guesses without verified provenance
        UNVERIFIED_GUESS_PATHS = {"/.env", "/etc/passwd", "/swagger", "/openapi.json", "/api/v1/user/profile"}
        is_guess = path.lower() in UNVERIFIED_GUESS_PATHS
        has_real_provenance = any(
            isinstance(d, str) and d in ("openapi", "crawler", "javascript", "seed")
            or hasattr(d, "source_type") and getattr(d, "source_type") in ("openapi", "crawler", "javascript", "seed")
            for d in ep_dict.get("discovered_from", [])
        )
        if is_guess and not has_real_provenance:
            protocol = "CANDIDATE_UNVERIFIED"

        profile = EndpointProfile(
            target=self.target_url,
            endpoint=path,
            method=method,
            protocol=protocol,
            parameters=param_profiles,
            authentication_required=requires_auth,
            object_identifiers=detected_objs,
            content_type=content_type,
            discovered_from=ep_dict.get("discovered_from", ["recon"]),
        )
        self.agent_state.register_endpoint(profile)
        return profile



    def calculate_test_priority(
        self,
        endpoint: EndpointProfile,
        test_class: str,
        parameter: str = "",
    ) -> tuple[int, str]:
        """
        Calculates an explainable priority (0-100) and rationale for a test case.
        """
        method = endpoint.method.upper()
        path_lower = endpoint.endpoint.lower()

        # Priority 100: Explicit Role Matrix Authorization contract
        if test_class == "authorization" and (endpoint.expected_roles or endpoint.authorization_contract_id):
            roles_str = ", ".join(sorted(endpoint.expected_roles)) if endpoint.expected_roles else "specified roles"
            source_str = endpoint.authorization_contract_source or "explicit contract"
            return 100, f"High Priority: Explicit role contract from {source_str}: {endpoint.method} {endpoint.endpoint} allows {roles_str} only."


        # Priority 100: Authorization tests with confirmed object identifiers (BOLA / IDOR)
        if test_class == "authorization" and endpoint.object_identifiers:
            return 100, "High Priority: Endpoint exposes confirmed object identifier evidence susceptible to BOLA/IDOR."


        # Priority 95: Explicit Response Property Authorization contract (API3:2023)
        if test_class == "api_security" and (endpoint.response_contract_id or endpoint.response_contract_source):
            source_str = endpoint.response_contract_source or "explicit response contract"
            return 95, f"High Priority: Explicit response property contract from {source_str}: {endpoint.method} {endpoint.endpoint}."

        # Priority 90: Bounded Pagination & Resource Consumption (API4:2023)
        if test_class == "api_security" and endpoint.protocol == "REST_CONFIRMED":
            for p in endpoint.parameters:
                p_name = p.name if hasattr(p, "name") else (p.get("name") if isinstance(p, dict) else str(p))
                if p_name and p_name.lower() in ("limit", "size", "page_size", "per_page", "pagesize", "take", "first", "max_results", "count"):
                    doc_max = getattr(p, "documented_maximum", None)
                    schema_ref = getattr(p, "schema_reference", None) or "openapi"
                    return 90, f"High Priority: Documented query parameter {p_name}, maximum={doc_max or 'unspecified'}, source={schema_ref}."

        # Priority 80: Authenticated mutation endpoints (State changes)
        if method in ("POST", "PUT", "PATCH", "DELETE") and endpoint.authentication_required:
            if test_class in ("authorization", "api_security"):
                return 80, "High Priority: Authenticated state mutation requires property-level authorization checks."




        # Priority 70: Endpoints accepting structured JSON (Mass Assignment / Injection)
        if method in ("POST", "PUT", "PATCH") or endpoint.content_type == "application/json":
            if test_class == "api_security":
                return 70, "Medium-High Priority: JSON body accepted; test for Mass Assignment & unauthorized property binding."
            if test_class == "injection":
                return 70, "Medium-High Priority: Input parameters in mutation payload; test injection boundaries."

        # Priority 60: Public API endpoints with query parameters
        if endpoint.parameters and test_class == "injection":
            return 60, f"Medium Priority: Parameter '{parameter or endpoint.parameters[0]}' available for differential injection analysis."

        # Priority 50: Configuration checks (CORS, Security Headers, Stack Traces)
        if test_class == "configuration":
            return 50, "Standard Baseline: Evaluate CORS origin reflection, HTTP methods, and stack trace disclosure."

        # Priority 40: General authentication / discovery baselines
        if test_class == "authentication":
            return 45, "Standard Baseline: Test unauthenticated access and token stripping on API route."

        return 40, f"General Baseline: Standard {test_class} verification."

    def generate_test_plan(
        self,
        endpoint_profiles: list[EndpointProfile] | None = None,
        force_reproducibility: bool = False,
    ) -> TestPlan:
        """
        Builds a deduplicated, prioritized TestPlan across all endpoints and OWASP categories.
        """
        profiles = endpoint_profiles or self.agent_state.endpoint_profiles
        plan = TestPlan(
            investigation_id=self.investigation_id,
            target_url=self.target_url,
        )

        for profile in profiles:
            protocol = profile.protocol.upper()
            if protocol == "CANDIDATE_UNVERIFIED":
                logger.info(
                    "planner_skipped_unverified_candidate",
                    endpoint=profile.endpoint,
                    reason="unverified_endpoint_candidate",
                )
                continue

            protocol_map = OWASP_TEST_MAP.get(protocol, OWASP_TEST_MAP["REST"])


            test_classes = protocol_map.get("default", [])


            for tc in test_classes:
                tester_name = TESTER_NAME_MAP.get(tc, "BaseTester")

                # If injection test and endpoint has parameters, create planned tests per parameter
                if tc == "injection" and profile.parameters:
                    # Enforce Sensitive Parameter Policy: skip ineligible/sensitive parameters
                    eligible_params = []
                    for p in profile.parameters:
                        if hasattr(p, "eligible_for_automated_testing") and not p.eligible_for_automated_testing:
                            logger.info(
                                "planner_skipped_ineligible_parameter",
                                endpoint=profile.endpoint,
                                parameter=getattr(p, "name", str(p)),
                                reason=getattr(p, "sensitivity_reason", "Sensitive parameter excluded"),
                            )
                            continue
                        eligible_params.append(p)

                    for param in eligible_params[:3]:  # Top 3 eligible parameters
                        param_name = param.name if hasattr(param, "name") else str(param)
                        test_id = AgentState.compute_test_identity(
                            target=self.target_url,
                            endpoint=profile.endpoint,
                            method=profile.method,
                            vuln_class=tc,
                            parameter=param_name,
                            auth_context="attacker",
                        )
                        if not force_reproducibility and self.agent_state.is_test_completed(
                            profile.endpoint, profile.method, tc, parameter=param_name
                        ):
                            continue

                        priority, reason = self.calculate_test_priority(profile, tc, parameter=param_name)
                        plan.planned_tests.append(
                            PlannedTest(
                                test_id=test_id,
                                endpoint=profile,
                                test_class=tc,
                                tester_name=tester_name,
                                priority=priority,
                                parameter=param_name,
                                auth_context="attacker",
                                reason=reason,
                                requires_reproducibility=force_reproducibility,
                            )
                        )


                else:
                    test_id = AgentState.compute_test_identity(
                        target=self.target_url,
                        endpoint=profile.endpoint,
                        method=profile.method,
                        vuln_class=tc,
                        parameter="",
                        auth_context="attacker",
                    )
                    if not force_reproducibility and self.agent_state.is_test_completed(
                        profile.endpoint, profile.method, tc
                    ):
                        continue

                    priority, reason = self.calculate_test_priority(profile, tc)
                    plan.planned_tests.append(
                        PlannedTest(
                            test_id=test_id,
                            endpoint=profile,
                            test_class=tc,
                            tester_name=tester_name,
                            priority=priority,
                            parameter=None,
                            auth_context="attacker",
                            reason=reason,
                            requires_reproducibility=force_reproducibility,
                        )
                    )

        # Sort all planned tests by priority descending
        plan.planned_tests.sort(key=lambda t: t.priority, reverse=True)
        logger.info(
            "attack_plan_generated",
            investigation_id=self.investigation_id,
            endpoints_count=len(profiles),
            total_planned_tests=len(plan.planned_tests),
        )
        return plan
