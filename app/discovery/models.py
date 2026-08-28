"""
app/discovery/models.py
───────────────────────
Discovery observations, parameter profiles, and endpoint models.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class DiscoveryObservation:
    """A single factual discovery observation with full provenance tracking."""
    source_type: str
    # seed | crawler | html_form | javascript | openapi | graphql_introspection | websocket_handshake | robots | sitemap | manual
    source_location: str
    discovered_url: str
    method: str | None = None
    parameter_name: str | None = None
    parameter_location: str | None = None
    # path | query | json_body | form_body | header | cookie | graphql_variable
    content_type: str | None = None
    protocol: str | None = None
    # REST | GRAPHQL | WEBSOCKET | UNKNOWN
    confidence: str = "observed"
    evidence_reference: str | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ParameterProfile:
    """Structured parameter metadata and classification."""
    name: str
    location: str
    # path | query | json_body | form_body | header | cookie | graphql_variable
    type_hint: str | None = None
    required: bool | None = None
    object_identifier_candidate: bool = False
    reason: str | None = None
    sensitive: bool = False
    eligible_for_automated_testing: bool = True
    sensitivity_reason: str | None = None
    documented_minimum: int | None = None
    documented_maximum: int | None = None
    documented_default: int | None = None
    schema_reference: str | None = None
    source_observations: list[DiscoveryObservation] = field(default_factory=list)


    @property
    def identity_key(self) -> str:
        """Normalized identity key for parameter deduplication."""
        return f"{self.location.lower()}:{self.name.lower()}"


@dataclass
class EndpointProfile:
    """Canonical attack surface endpoint definition with rich discovery metadata."""
    target: str
    endpoint: str
    method: str = "GET"
    protocol: str = "UNKNOWN"
    # REST_CONFIRMED | REST_CANDIDATE | GRAPHQL_CONFIRMED | GRAPHQL_CANDIDATE | WEBSOCKET_CONFIRMED | WEBSOCKET_CANDIDATE | UNKNOWN
    parameters: list[ParameterProfile | str] = field(default_factory=list)
    object_identifiers: list[str] = field(default_factory=list)
    content_type: str | None = None
    authentication_required: bool | None = None  # None = unknown
    available_roles: list[str] = field(default_factory=lambda: ["owner", "attacker", "anonymous"])
    authorization_contract_id: str | None = None
    expected_roles: list[str] | None = None
    authorization_contract_source: str | None = None
    response_contract_id: str | None = None
    response_contract_source: str | None = None
    response_schema_reference: str | None = None

    discovered_from: list[DiscoveryObservation | str] = field(default_factory=list)
    completed_test_classes: set[str] = field(default_factory=set)



    @property
    def path(self) -> str:
        """Alias for endpoint for backward compatibility."""
        return self.endpoint

    @property
    def url(self) -> str:
        """Full URL representation."""
        clean_target = self.target.rstrip("/")
        clean_ep = self.endpoint if self.endpoint.startswith("/") else f"/{self.endpoint}"
        return f"{clean_target}{clean_ep}"

    @property
    def completed_tests(self) -> set[str]:
        """Alias for completed_test_classes."""
        return self.completed_test_classes

    @property
    def parameter_names(self) -> list[str]:
        """Convenience property returning parameter names as strings."""
        names = []
        for p in self.parameters:
            if isinstance(p, ParameterProfile):
                names.append(p.name)
            elif isinstance(p, str):
                names.append(p)
        return names
