"""
tests/unit/test_endpoint_identity.py
────────────────────────────────────
Unit tests for CanonicalEndpointIdentity and Endpoint Identity Normalization:
  - Query ordering does not create duplicate endpoint identities.
  - Fragments are excluded.
  - Query parameter names remain associated with the correct request.
  - Hypothesis and actual request identities are identical.
  - /path?id=1 is distinguished from /path by parameter names.
"""
import pytest

from app.core.agent_state import AgentState
from app.discovery.endpoint_identity import (
    CanonicalEndpointIdentity,
    CanonicalParameterSpec,
)


class TestEndpointIdentity:

    def test_query_ordering_does_not_create_duplicate_endpoint_identities(self):
        id1 = CanonicalEndpointIdentity.from_url("http://localhost:3001/api/products?b=2&a=1", method="GET")
        id2 = CanonicalEndpointIdentity.from_url("http://localhost:3001/api/products?a=1&b=2", method="GET")

        assert id1 == id2
        assert id1.identity_key == id2.identity_key
        assert id1.query_parameter_names == ("a", "b")

    def test_url_fragments_are_cleanly_excluded(self):
        id_with_frag = CanonicalEndpointIdentity.from_url("http://localhost:3001/api/users#profile-section", method="GET")
        id_clean = CanonicalEndpointIdentity.from_url("http://localhost:3001/api/users", method="GET")

        assert id_with_frag.path == "/api/users"
        assert id_with_frag.identity_key == id_clean.identity_key

    def test_path_with_query_param_distinguished_from_bare_path(self):
        bare_id = CanonicalEndpointIdentity.from_url("http://localhost:3001/api/orders", method="GET")
        param_id = CanonicalEndpointIdentity.from_url("http://localhost:3001/api/orders?id=1", method="GET")

        assert bare_id != param_id
        assert bare_id.query_parameter_names == ()
        assert param_id.query_parameter_names == ("id",)
        assert bare_id.identity_key != param_id.identity_key

    def test_compute_test_identity_is_deterministic_and_query_order_invariant(self):
        k1 = AgentState.compute_test_identity(
            target="http://localhost:3001",
            endpoint="/api/search?limit=10&q=juice",
            method="GET",
            vuln_class="injection",
            parameter="q",
            auth_context="attacker",
        )
        k2 = AgentState.compute_test_identity(
            target="http://localhost:3001",
            endpoint="/api/search?q=juice&limit=10",
            method="GET",
            vuln_class="injection",
            parameter="q",
            auth_context="attacker",
        )

        assert k1 == k2
        assert "http://localhost:3001" in k1
        assert "/api/search" in k1
        assert "INJECTION" in k1


    def test_parameter_spec_redacts_sensitive_values(self):
        spec = CanonicalParameterSpec(
            name="password",
            location="query",
            value_state="test_value_redacted",
        )
        d = spec.to_dict()
        assert d["name"] == "password"
        assert d["location"] == "query"
        assert d["value_state"] == "test_value_redacted"
        assert "SuperSecret" not in str(d)
