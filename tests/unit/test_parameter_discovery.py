"""
tests/unit/test_parameter_discovery.py
──────────────────────────────────────
Unit tests for ParameterDiscovery:
  - Path template variables & candidate object identifier detection.
  - Query string parameter extraction (values excluded).
  - HTML form parsing & sensitive field detection without storing values.
  - OpenAPI parameter and requestBody schema extraction.
  - Verification that numeric pagination is NOT classified as an object identifier.
"""
import pytest
from app.discovery.parameter_discovery import ParameterDiscovery


class TestParameterDiscovery:

    def test_extract_path_template_parameters(self):
        params, obj_ids = ParameterDiscovery.extract_from_path("/api/v1/users/{user_id}/orders/:order_id")
        assert len(params) == 2
        assert params[0].name == "user_id"
        assert params[0].location == "path"
        assert params[0].object_identifier_candidate is True
        assert params[1].name == "order_id"
        assert params[1].location == "path"
        assert params[1].object_identifier_candidate is True
        assert "user_id" in obj_ids
        assert "order_id" in obj_ids

    def test_query_parameter_extraction_excludes_values(self):
        # Even if values contain secret-looking data, they are not retained in ParameterProfile
        raw_url = "https://target.com/api/search?q=test&api_key=SECRET_VAL_123&page=1"
        profiles = ParameterDiscovery.extract_from_query_string(raw_url, source_location="/api/search")
        
        param_names = [p.name for p in profiles]
        assert "q" in param_names
        assert "api_key" in param_names
        assert "page" in param_names

        # Verify no values leaked into profile attributes
        for p in profiles:
            assert p.location == "query"
            assert "SECRET_VAL_123" not in p.name
            assert "SECRET_VAL_123" not in (p.reason or "")

    def test_pagination_is_not_falsely_classified_as_object_identifier(self):
        profiles = ParameterDiscovery.extract_from_query_string("/items?page=5&limit=20&sort=desc")
        for p in profiles:
            if p.name in ("page", "limit", "sort"):
                assert p.object_identifier_candidate is False

    def test_html_form_extraction_flags_sensitive_fields_without_storing_values(self):
        form_html = """
        <form method="POST" action="/api/v1/login" enctype="application/x-www-form-urlencoded">
            <input type="text" name="username" value="admin" />
            <input type="password" name="password" value="SuperSecretPassword123" />
            <input type="hidden" name="csrf_token" value="abc123csrf" />
            <button type="submit">Login</button>
        </form>
        """
        method, action, profiles = ParameterDiscovery.extract_from_html_form(form_html, source_url="/login")
        assert method == "POST"
        assert action == "/api/v1/login"
        assert len(profiles) == 3

        names = {p.name: p for p in profiles}
        assert "username" in names
        assert "password" in names
        assert "csrf_token" in names

        # Verify password and csrf fields were marked sensitive and excluded from automated testing
        assert names["password"].sensitive is True
        assert names["password"].eligible_for_automated_testing is False
        assert "SuperSecretPassword123" not in (names["password"].reason or "")
        assert "SuperSecretPassword123" not in names["password"].name

        assert names["csrf_token"].sensitive is True
        assert names["csrf_token"].eligible_for_automated_testing is False

        # Non-sensitive username remains eligible
        assert names["username"].sensitive is False
        assert names["username"].eligible_for_automated_testing is True

    def test_otp_token_and_cookie_parameters_are_ineligible_for_automated_testing(self):
        query_url = "/verify?otp=123456&session_cookie=sess_abc&bearer_token=tok_xyz&email=test@test.com"
        profiles = ParameterDiscovery.extract_from_query_string(query_url)
        name_map = {p.name: p for p in profiles}

        assert name_map["otp"].sensitive is True
        assert name_map["otp"].eligible_for_automated_testing is False

        assert name_map["session_cookie"].sensitive is True
        assert name_map["session_cookie"].eligible_for_automated_testing is False

        assert name_map["bearer_token"].sensitive is True
        assert name_map["bearer_token"].eligible_for_automated_testing is False

        assert name_map["email"].sensitive is False
        assert name_map["email"].eligible_for_automated_testing is True


    def test_openapi_schema_extraction(self):
        raw_params = [
            {"name": "accountId", "in": "path", "required": True, "schema": {"type": "string"}},
            {"name": "filter", "in": "query", "required": False, "schema": {"type": "string"}},
        ]
        request_body = {
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "amount": {"type": "number"},
                            "recipient_id": {"type": "string"},
                        },
                        "required": ["amount", "recipient_id"],
                    }
                }
            }
        }
        profiles, obj_ids = ParameterDiscovery.extract_from_openapi_schema(raw_params, request_body)
        names = {p.name: p for p in profiles}

        assert "accountId" in names
        assert names["accountId"].location == "path"
        assert names["accountId"].object_identifier_candidate is True
        assert "accountId" in obj_ids

        assert "amount" in names
        assert names["amount"].location == "json_body"
        assert names["amount"].required is True

        assert "recipient_id" in names
        assert names["recipient_id"].location == "json_body"
        assert names["recipient_id"].object_identifier_candidate is True
