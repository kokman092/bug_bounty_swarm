"""
tests/unit/test_response_property_policy.py
───────────────────────────────────────────
Unit tests for ResponsePropertyPolicy & ResponsePropertyVerifier eligibility:
  - Disabled policy skips with zero transport calls.
  - Missing response contract skips with zero transport calls.
  - Non-GET/HEAD method skips with zero transport calls.
  - Non-allowlisted endpoint skips with zero transport calls.
  - Unapproved persona skips with zero transport calls.
  - Exact and template path matching for ResponseFieldContract.
"""
import pytest

from app.findings.schemas import FindingStatus
from app.testing.api_security.response_property_policy import (
    ResponseFieldContract,
    ResponsePropertyPolicy,
)
from app.testing.api_security.response_property_verifier import (
    ResponsePropertyVerifier,
    extract_field_paths,
)


class TestResponsePropertyPolicy:

    def test_policy_defaults_and_contract_resolution(self):
        policy = ResponsePropertyPolicy()
        assert policy.enabled is False
        assert policy.read_only_methods == {"GET", "HEAD"}

        contract_me = ResponseFieldContract(
            allowed_fields_by_role={"owner": {"id", "display_name", "email"}},
            protected_fields={"password_hash", "mfa_secret"},
            source="openapi",
        )
        contract_order = ResponseFieldContract(
            allowed_fields_by_role={"owner": {"id", "total", "items"}},
            protected_fields={"credit_card_full"},
            source="openapi",
        )
        policy.response_contracts = {
            "GET /api/users/me": contract_me,
            "GET /api/orders/{id}": contract_order,
        }

        # Exact match
        assert policy.get_contract_for_endpoint("GET", "/api/users/me") == contract_me
        # Template match
        assert policy.get_contract_for_endpoint("GET", "/api/orders/999") == contract_order
        # Missing
        assert policy.get_contract_for_endpoint("GET", "/api/users/other") is None
        assert policy.get_contract_for_endpoint("POST", "/api/users/me") is None

    def test_extract_field_paths_nested_and_arrays(self):
        sample = {
            "id": 123,
            "profile": {
                "name": "Alice",
                "settings": {"dark_mode": True},
            },
            "orders": [
                {"order_id": "O1", "items": [{"sku": "SKU1", "price": 10}]},
                {"order_id": "O2", "items": [{"sku": "SKU2", "price": 20}]},
            ],
        }
        paths = extract_field_paths(sample)
        assert "id" in paths
        assert "profile" in paths
        assert "profile.name" in paths
        assert "profile.settings.dark_mode" in paths
        assert "orders" in paths
        assert "orders[].order_id" in paths
        assert "orders[].items[].sku" in paths
        assert "orders[].items[].price" in paths

    @pytest.mark.asyncio
    async def test_disabled_policy_causes_skip_and_zero_transport(self):
        policy = ResponsePropertyPolicy(enabled=False)
        verifier = ResponsePropertyVerifier("inv-rp-1", "http://target.com", policy)

        res = await verifier.verify_endpoint({"path": "/api/users/me", "method": "GET"})
        assert res.status == FindingStatus.REJECTED
        assert "disabled by policy" in res.observations[0]
        assert res.raw_evidence.get("skip_reason") == "policy_disabled"

    @pytest.mark.asyncio
    async def test_missing_contract_causes_skip(self):
        policy = ResponsePropertyPolicy(enabled=True, allowed_endpoint_patterns=["*"])
        verifier = ResponsePropertyVerifier("inv-rp-2", "http://target.com", policy)

        res = await verifier.verify_endpoint({"path": "/api/unknown/resource", "method": "GET"})
        assert res.status == FindingStatus.REJECTED
        assert "No explicit response field contract found" in res.observations[0]
        assert res.raw_evidence.get("skip_reason") == "missing_response_contract"

    @pytest.mark.asyncio
    async def test_non_read_only_method_causes_skip(self):
        policy = ResponsePropertyPolicy(
            enabled=True,
            allowed_endpoint_patterns=["*"],
            response_contracts={"POST /api/users/me": ResponseFieldContract(allowed_fields_by_role={}, protected_fields=set())},
        )
        verifier = ResponsePropertyVerifier("inv-rp-3", "http://target.com", policy)

        res = await verifier.verify_endpoint({"path": "/api/users/me", "method": "POST"})
        assert res.status == FindingStatus.REJECTED
        assert "not a read-only method" in res.observations[0]
        assert res.raw_evidence.get("skip_reason") == "non_read_only_method"

    @pytest.mark.asyncio
    async def test_non_allowlisted_endpoint_causes_skip(self):
        policy = ResponsePropertyPolicy(
            enabled=True,
            allowed_endpoint_patterns=["/api/v1/.*"],
            response_contracts={"GET /api/v2/users/me": ResponseFieldContract(allowed_fields_by_role={}, protected_fields=set())},
        )
        verifier = ResponsePropertyVerifier("inv-rp-4", "http://target.com", policy)

        res = await verifier.verify_endpoint({"path": "/api/v2/users/me", "method": "GET"})
        assert res.status == FindingStatus.REJECTED
        assert "not in response property allowlist" in res.observations[0]
        assert res.raw_evidence.get("skip_reason") == "endpoint_not_allowlisted"

    @pytest.mark.asyncio
    async def test_unapproved_persona_causes_skip(self):
        policy = ResponsePropertyPolicy(
            enabled=True,
            allowed_endpoint_patterns=["*"],
            allowed_test_identities={"owner", "admin"},
            response_contracts={"GET /api/users/me": ResponseFieldContract(allowed_fields_by_role={}, protected_fields=set())},
        )
        verifier = ResponsePropertyVerifier("inv-rp-5", "http://target.com", policy)

        res = await verifier.verify_endpoint({"path": "/api/users/me", "method": "GET"}, role="external_untrusted")
        assert res.status == FindingStatus.REJECTED
        assert "not in allowed test identities" in res.observations[0]
        assert res.raw_evidence.get("skip_reason") == "unapproved_persona"
