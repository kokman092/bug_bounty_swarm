"""
app/core/agent_state.py
───────────────────────
Agent State Machine & Test Execution Memory:
  - Tracks discovered assets, endpoints, parameters, and authentication contexts.
  - Maintains state of completed vs pending OWASP tests per endpoint.
  - Prevents redundant/duplicate tests using stable composite test identities.
  - Records potential vs validated findings.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.discovery.models import DiscoveryObservation, EndpointProfile, ParameterProfile
from app.findings.schemas import Finding, FindingStatus, Hypothesis, VulnClass





@dataclass
class AgentState:
    investigation_id: str
    target: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    discovered_assets: list[str] = field(default_factory=list)
    endpoints: dict[str, EndpointProfile] = field(default_factory=dict)  # "METHOD:path" -> EndpointProfile
    endpoint_profiles: list[EndpointProfile] = field(default_factory=list)
    completed_tests: set[str] = field(default_factory=set)              # Deterministic test_identity strings
    failed_tests: set[str] = field(default_factory=set)
    pending_tests: list[dict[str, Any]] = field(default_factory=list)
    confirmed_findings: list[Finding] = field(default_factory=list)
    rejected_findings: list[Finding] = field(default_factory=list)

    def register_endpoint(
        self,
        endpoint_or_profile: EndpointProfile | str | None = None,
        method: str = "GET",
        endpoint: str | None = None,
        path: str | None = None,
        **kwargs: Any,
    ) -> EndpointProfile:
        """Registers or updates an EndpointProfile in AgentState."""
        if isinstance(endpoint_or_profile, EndpointProfile):
            profile = endpoint_or_profile
        else:
            raw_ep = endpoint_or_profile or endpoint or path or "/"
            profile = EndpointProfile(
                target=self.target,
                endpoint=raw_ep,
                method=method.upper(),
                **kwargs,
            )
        key = f"{profile.method.upper()}:{profile.endpoint}"
        self.endpoints[key] = profile
        if not any(ep.endpoint == profile.endpoint and ep.method == profile.method for ep in self.endpoint_profiles):
            self.endpoint_profiles.append(profile)
        return profile


    @staticmethod
    def compute_test_identity(
        target: str,
        endpoint: str,
        method: str,
        vuln_class: str,
        parameter: ParameterProfile | str = "",
        auth_context: str = "attacker",
    ) -> str:
        """
        Deterministic test identity key:
        target + endpoint + HTTP method + vulnerability class + parameter + auth_context
        """
        clean_target = target.rstrip("/")
        clean_ep = endpoint.split("?")[0].split("#")[0].strip()
        clean_m = method.upper().strip()
        clean_vc = vuln_class.upper().strip()
        param_name = parameter.name if isinstance(parameter, ParameterProfile) else str(parameter or "")
        clean_param = param_name.strip().lower()
        clean_auth = auth_context.strip().lower()
        return f"{clean_target}:{clean_m}:{clean_ep}:{clean_vc}:{clean_param}:{clean_auth}"




    def is_test_completed(
        self,
        endpoint: str,
        method: str,
        vuln_class: str,
        parameter: str = "",
        auth_context: str = "attacker",
    ) -> bool:
        test_id = self.compute_test_identity(
            self.target, endpoint, method, vuln_class, parameter, auth_context
        )
        return test_id in self.completed_tests

    def record_test_execution(
        self,
        endpoint: str,
        method: str,
        vuln_class: str,
        parameter: str = "",
        auth_context: str = "attacker",
        status: FindingStatus = FindingStatus.REJECTED,
    ) -> None:
        test_id = self.compute_test_identity(
            self.target, endpoint, method, vuln_class, parameter, auth_context
        )
        self.completed_tests.add(test_id)
        ep_key = f"{method.upper()}:{endpoint}"
        if ep_key in self.endpoints:
            self.endpoints[ep_key].completed_tests.add(vuln_class)


# Aliases for backward compatibility

InvestigationState = AgentState
DiscoveredEndpoint = EndpointProfile

# In-memory registry of active agent states per investigation
_ACTIVE_STATES: dict[str, AgentState] = {}


def get_agent_state(investigation_id: str, target_url: str = "") -> AgentState:
    if investigation_id not in _ACTIVE_STATES:
        _ACTIVE_STATES[investigation_id] = AgentState(
            investigation_id=investigation_id,
            target=target_url,
        )
    return _ACTIVE_STATES[investigation_id]
