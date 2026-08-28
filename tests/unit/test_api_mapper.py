"""
tests/unit/test_api_mapper.py
─────────────────────────────
Unit tests for APIMapper protocol evidence tiers and OpenAPI mapping:
  - Strict evidence tiers: REST_CONFIRMED, REST_CANDIDATE, GRAPHQL_CONFIRMED, GRAPHQL_CANDIDATE, WEBSOCKET_CONFIRMED, WEBSOCKET_CANDIDATE, UNKNOWN.
  - Path conventions alone are candidate only.
  - OpenAPI 3.x document parsing produces REST_CONFIRMED.
  - Invalid OpenAPI data produces 0 invented endpoints.
"""
import pytest
from app.discovery.api_mapper import APIMapper


class TestAPIMapper:

    def test_classify_protocol_websocket_tiers(self):
        # ws:// and wss:// or upgrade headers confirm WebSocket
        assert APIMapper.classify_protocol("ws://target.com/events") == "WEBSOCKET_CONFIRMED"
        assert APIMapper.classify_protocol("wss://target.com/chat") == "WEBSOCKET_CONFIRMED"
        assert APIMapper.classify_protocol("/stream", headers={"upgrade": "websocket"}) == "WEBSOCKET_CONFIRMED"

        # Path convention alone is candidate only
        assert APIMapper.classify_protocol("/api/ws") == "WEBSOCKET_CANDIDATE"
        assert APIMapper.classify_protocol("/socket.io") == "WEBSOCKET_CANDIDATE"

    def test_classify_protocol_graphql_tiers(self):
        # Path convention alone is candidate only
        assert APIMapper.classify_protocol("/graphql") == "GRAPHQL_CANDIDATE"
        assert APIMapper.classify_protocol("/api/v1/gql") == "GRAPHQL_CANDIDATE"

        # Confirmed via documented schema or observed GraphQL query payload
        assert APIMapper.classify_protocol("/custom/endpoint", content_sample='{"query": "mutation { createUser }"}') == "GRAPHQL_CONFIRMED"
        assert APIMapper.classify_protocol("/graphql", is_schema_documented=True) == "GRAPHQL_CONFIRMED"

    def test_classify_protocol_rest_tiers(self):
        # Path convention alone is candidate only
        assert APIMapper.classify_protocol("/api/v1/users") == "REST_CANDIDATE"
        assert APIMapper.classify_protocol("/rest/orders") == "REST_CANDIDATE"

        # Confirmed via OpenAPI schema or application/json header
        assert APIMapper.classify_protocol("/api/v1/users", is_schema_documented=True) == "REST_CONFIRMED"
        assert APIMapper.classify_protocol("/users", headers={"content-type": "application/json"}) == "REST_CONFIRMED"

    def test_classify_protocol_unknown_when_insufficient_evidence(self):
        assert APIMapper.classify_protocol("/about") == "UNKNOWN"
        assert APIMapper.classify_protocol("/contact-us") == "UNKNOWN"
        assert APIMapper.classify_protocol("/static/main.css") == "UNKNOWN"

    def test_map_openapi_spec_produces_confirmed_rest(self):
        spec = {
            "paths": {
                "/api/orders/{order_id}": {
                    "get": {
                        "summary": "Get Order",
                        "parameters": [
                            {"name": "order_id", "in": "path", "required": True, "schema": {"type": "integer"}},
                        ],
                        "security": [{"BearerAuth": []}],
                    },
                    "delete": {
                        "summary": "Cancel Order",
                        "security": [{"BearerAuth": []}],
                    },
                }
            }
        }
        profiles = APIMapper.map_openapi_spec("http://target.com", spec, source_location="/openapi.json")
        assert len(profiles) == 2

        get_profile = next(p for p in profiles if p.method == "GET")
        assert get_profile.endpoint == "/api/orders/{order_id}"
        assert get_profile.protocol == "REST"
        assert get_profile.authentication_required is True
        assert "order_id" in get_profile.object_identifiers
        assert len(get_profile.parameters) == 1

        del_profile = next(p for p in profiles if p.method == "DELETE")
        assert del_profile.endpoint == "/api/orders/{order_id}"
        assert del_profile.method == "DELETE"
        assert del_profile.authentication_required is True

    def test_invalid_openapi_produces_zero_invented_endpoints(self):
        invalid_spec = {"info": {"title": "Empty API"}, "components": {}}
        profiles = APIMapper.map_openapi_spec("http://target.com", invalid_spec, source_location="/invalid.json")
        assert len(profiles) == 0
