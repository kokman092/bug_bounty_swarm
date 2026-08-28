"""
tests/unit/test_discovery_profile_merge.py
──────────────────────────────────────────
Unit tests for EndpointProfile merging and deduplication:
  - Identity matching by (target, endpoint, method, protocol).
  - Parameter deduplication with provenance merging.
  - Verification that different HTTP methods remain distinct.
  - Verification that different protocols on the same path remain distinct.
"""
import pytest
from app.core.agent_state import EndpointProfile
from app.discovery.api_mapper import APIMapper
from app.discovery.models import DiscoveryObservation, ParameterProfile


class TestDiscoveryProfileMerge:

    def test_merges_identical_endpoints_and_consolidates_parameters(self):
        obs1 = DiscoveryObservation(source_type="crawler", source_location="/home", discovered_url="/api/users")
        obs2 = DiscoveryObservation(source_type="openapi", source_location="/openapi.json", discovered_url="/api/users")

        param1 = ParameterProfile(name="page", location="query", source_observations=[obs1])
        param2 = ParameterProfile(name="limit", location="query", source_observations=[obs2])

        ep1 = EndpointProfile(
            target="http://target.com",
            endpoint="/api/users",
            method="GET",
            protocol="REST",
            parameters=[param1],
            discovered_from=[obs1],
        )

        ep2 = EndpointProfile(
            target="http://target.com",
            endpoint="/api/users",
            method="GET",
            protocol="REST",
            parameters=[param2],
            discovered_from=[obs2],
        )

        merged = APIMapper.merge_endpoint_profiles([ep1], [ep2])
        assert len(merged) == 1
        assert len(merged[0].parameters) == 2
        assert len(merged[0].discovered_from) == 2

    def test_different_methods_remain_distinct(self):
        ep_get = EndpointProfile(target="http://target.com", endpoint="/api/items", method="GET", protocol="REST")
        ep_post = EndpointProfile(target="http://target.com", endpoint="/api/items", method="POST", protocol="REST")

        merged = APIMapper.merge_endpoint_profiles([ep_get], [ep_post])
        assert len(merged) == 2
        methods = {ep.method for ep in merged}
        assert methods == {"GET", "POST"}

    def test_different_protocols_remain_distinct(self):
        ep_rest = EndpointProfile(target="http://target.com", endpoint="/stream", method="GET", protocol="REST")
        ep_ws = EndpointProfile(target="http://target.com", endpoint="/stream", method="GET", protocol="WEBSOCKET")

        merged = APIMapper.merge_endpoint_profiles([ep_rest], [ep_ws])
        assert len(merged) == 2
        protocols = {ep.protocol for ep in merged}
        assert protocols == {"REST", "WEBSOCKET"}
