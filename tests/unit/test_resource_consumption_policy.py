"""
tests/unit/test_resource_consumption_policy.py
───────────────────────────────────────────────
Unit tests for ResourceConsumptionPolicy & select_safe_probe_value clamping:
  - Documented maximum 20 gives probe value 20, never 40, 70, or 100.
  - Documented maximum 1000 and policy cap 100 gives probe value 100.
  - Documented maximum 500 and policy cap 1000 gives probe value 500.
  - No documented maximum uses default probe value 100 or lower configured cap.
  - Documented maximum is NEVER exceeded.
  - Disabled policy skips before transport.
  - Missing documented parameter skips before transport.
  - Non-GET/HEAD method skips before transport.
  - Candidate / unknown protocol skips before transport.
  - Non-allowlisted endpoint skips before transport.
  - Unapproved persona skips before transport.
  - Cursor, offset, page, search, filter, sort parameters are ignored.
"""
import pytest

from app.discovery.models import ParameterProfile
from app.findings.schemas import FindingStatus
from app.testing.api_security.resource_consumption_policy import (
    ResourceConsumptionPolicy,
    select_safe_probe_value,
)
from app.testing.api_security.resource_consumption_verifier import (
    ResourceConsumptionVerifier,
    parse_item_count,
)


class TestResourceConsumptionPolicy:

    def test_policy_defaults(self):
        policy = ResourceConsumptionPolicy()
        assert policy.enabled is False
        assert policy.read_only_methods == {"GET", "HEAD"}
        assert policy.max_requests_per_endpoint == 1
        assert policy.default_probe_parameter_value == 100
        assert policy.max_probe_parameter_value == 1000
        assert "limit" in policy.allowed_parameter_names
        assert "size" in policy.allowed_parameter_names

    def test_select_safe_probe_value_clamping(self):
        policy = ResourceConsumptionPolicy(default_probe_parameter_value=100, max_probe_parameter_value=1000)

        # 1. Documented max 20 gives probe 20 (never exceeds 20)
        p20 = ParameterProfile(name="limit", location="query", documented_maximum=20)
        assert select_safe_probe_value(p20, policy) == 20

        # 2. Documented max 1000 and policy cap 100 gives probe 100
        policy_strict = ResourceConsumptionPolicy(max_probe_parameter_value=100)
        p1000 = ParameterProfile(name="limit", location="query", documented_maximum=1000)
        assert select_safe_probe_value(p1000, policy_strict) == 100

        # 3. Documented max 500 and policy cap 1000 gives probe 500
        p500 = ParameterProfile(name="limit", location="query", documented_maximum=500)
        assert select_safe_probe_value(p500, policy) == 500

        # 4. No documented max uses default probe value 100
        p_none = ParameterProfile(name="limit", location="query", documented_maximum=None)
        assert select_safe_probe_value(p_none, policy) == 100

        # 5. Dict representation supported
        assert select_safe_probe_value({"name": "limit", "documented_maximum": 50}, policy) == 50

    def test_parse_item_count_helper(self):
        assert parse_item_count([1, 2, 3, 4, 5]) == 5
        assert parse_item_count({"items": [{"id": 1}, {"id": 2}]}) == 2
        assert parse_item_count({"data": [1, 2, 3, 4]}) == 4
        assert parse_item_count({"products": [{"id": 1}]}) == 1
        assert parse_item_count({"status": "ok"}) is None

    @pytest.mark.asyncio
    async def test_disabled_policy_skips_before_transport(self):
        policy = ResourceConsumptionPolicy(enabled=False)
        verifier = ResourceConsumptionVerifier("inv-rc-1", "http://target.com", policy)

        res = await verifier.verify_endpoint({"path": "/api/items", "method": "GET", "parameters": ["limit"]})
        assert res.status == FindingStatus.REJECTED
        assert "disabled by policy" in res.observations[0]
        assert res.raw_evidence.get("skip_reason") == "policy_disabled"

    @pytest.mark.asyncio
    async def test_non_read_only_method_skips_before_transport(self):
        policy = ResourceConsumptionPolicy(enabled=True, allowed_endpoint_patterns=["*"])
        verifier = ResourceConsumptionVerifier("inv-rc-2", "http://target.com", policy)

        res = await verifier.verify_endpoint({"path": "/api/items", "method": "POST", "parameters": ["limit"]})
        assert res.status == FindingStatus.REJECTED
        assert "not a read-only method" in res.observations[0]
        assert res.raw_evidence.get("skip_reason") == "non_read_only_method"

    @pytest.mark.asyncio
    async def test_unconfirmed_candidate_protocol_skips_before_transport(self):
        policy = ResourceConsumptionPolicy(enabled=True, allowed_endpoint_patterns=["*"])
        verifier = ResourceConsumptionVerifier("inv-rc-3", "http://target.com", policy)

        res = await verifier.verify_endpoint({
            "path": "/api/items",
            "method": "GET",
            "protocol": "REST_CANDIDATE",
            "parameters": ["limit"],
        })
        assert res.status == FindingStatus.REJECTED
        assert "candidate-only / unconfirmed" in res.observations[0]
        assert res.raw_evidence.get("skip_reason") == "unconfirmed_protocol"

    @pytest.mark.asyncio
    async def test_missing_documented_parameter_skips_before_transport(self):
        policy = ResourceConsumptionPolicy(enabled=True, allowed_endpoint_patterns=["*"])
        verifier = ResourceConsumptionVerifier("inv-rc-4", "http://target.com", policy)

        # Only cursor, offset, or sort provided (none in allowed pagination names)
        res = await verifier.verify_endpoint({
            "path": "/api/items",
            "method": "GET",
            "protocol": "REST_CONFIRMED",
            "parameters": ["cursor", "offset", "sort_by", "search_query"],
        })
        assert res.status == FindingStatus.REJECTED
        assert "No documented pagination/limit parameter" in res.observations[0]
        assert res.raw_evidence.get("skip_reason") == "missing_documented_pagination_parameter"

    @pytest.mark.asyncio
    async def test_non_allowlisted_endpoint_skips_before_transport(self):
        policy = ResourceConsumptionPolicy(enabled=True, allowed_endpoint_patterns=["/api/v1/.*"])
        verifier = ResourceConsumptionVerifier("inv-rc-5", "http://target.com", policy)

        res = await verifier.verify_endpoint({
            "path": "/api/v2/items",
            "method": "GET",
            "protocol": "REST_CONFIRMED",
            "parameters": ["limit"],
        })
        assert res.status == FindingStatus.REJECTED
        assert "not in resource consumption allowlist" in res.observations[0]
        assert res.raw_evidence.get("skip_reason") == "endpoint_not_allowlisted"

    @pytest.mark.asyncio
    async def test_unapproved_persona_skips_before_transport(self):
        policy = ResourceConsumptionPolicy(
            enabled=True,
            allowed_endpoint_patterns=["*"],
            allowed_test_identities={"owner", "admin"},
        )
        verifier = ResourceConsumptionVerifier("inv-rc-6", "http://target.com", policy)

        res = await verifier.verify_endpoint({
            "path": "/api/items",
            "method": "GET",
            "protocol": "REST_CONFIRMED",
            "parameters": ["limit"],
        }, role="untrusted_external")
        assert res.status == FindingStatus.REJECTED
        assert "not in allowed test identities" in res.observations[0]
        assert res.raw_evidence.get("skip_reason") == "unapproved_persona"
