"""
tests/unit/test_juice_shop_discovery.py
───────────────────────────────────────
Unit tests for OWASP Juice Shop Discovery & SPA Fallback Handling:
  - Juice Shop root fingerprint detection.
  - Unknown routes returning the same SPA fallback.
  - /api/Products classified as a real JSON API when returning JSON.
  - /openapi.json not classified as an OpenAPI document when it returns HTML.
  - /api/v1/user/profile skipped when not discovered or documented.
  - Guessed /.env candidate skipped as unverified.
  - Real directory listing classified separately from SPA fallback.
  - Discovered route provenance reaches EndpointProfile and AttackPlanner.
"""
import pytest
from unittest.mock import AsyncMock

from app.agents.hunter import HunterAgent
from app.discovery.models import DiscoveryObservation, EndpointProfile, ParameterProfile
from app.discovery.response_classifier import (
    ResponseClassifier,
    ResponseKind,
)
from app.findings.schemas import VulnClass
from app.intelligence.attack_planner import AttackPlanner
from app.tools.recon_tools import probe_common_api_paths


JUICE_SHOP_ROOT_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <base href="/">
  <link rel="icon" type="image/x-icon" href="assets/public/favicon_js.ico">
</head>
<body class="mat-typography mat-app-background light-theme">
  <app-root></app-root>
  <script src="runtime.js" defer></script>
  <script src="polyfills.js" defer></script>
  <script src="vendor.js" defer></script>
  <script src="main.js" defer></script>
</body>
</html>"""


class TestJuiceShopDiscovery:

    def test_juice_shop_root_fingerprint_detection(self):
        fp = ResponseClassifier.compute_spa_fingerprint(
            200, {"content-type": "text/html; charset=utf-8"}, JUICE_SHOP_ROOT_HTML
        )
        assert fp.title == "OWASP Juice Shop"
        assert fp.status_code == 200
        assert len(fp.app_markers) >= 2
        assert any("main.js" in s for s in fp.script_srcs)

    def test_unknown_routes_classified_as_spa_fallback(self):
        fp = ResponseClassifier.compute_spa_fingerprint(
            200, {"content-type": "text/html"}, JUICE_SHOP_ROOT_HTML
        )
        classifier = ResponseClassifier(root_fingerprint=fp)

        for guessed_path in ["/.env", "/etc/passwd", "/api/v1/user/profile", "/openapi.json"]:
            res = classifier.classify_response(
                url_or_path=guessed_path,
                status_code=200,
                headers={"content-type": "text/html"},
                body_text=JUICE_SHOP_ROOT_HTML,
            )
            assert res.response_kind == ResponseKind.SPA_FALLBACK
            assert not res.is_real_resource
            assert not res.testable_as_api

    def test_api_products_classified_as_json_api(self):
        classifier = ResponseClassifier()
        res = classifier.classify_response(
            url_or_path="/api/Products",
            status_code=200,
            headers={"content-type": "application/json"},
            body_text='{"status": "success", "data": [{"id": 1, "name": "Apple Juice"}]}',
        )
        assert res.response_kind == ResponseKind.JSON_API
        assert res.is_real_resource
        assert res.testable_as_api

    def test_openapi_json_not_classified_as_spec_when_returning_html(self):
        classifier = ResponseClassifier()
        res = classifier.classify_response(
            url_or_path="/openapi.json",
            status_code=200,
            headers={"content-type": "text/html"},
            body_text=JUICE_SHOP_ROOT_HTML,
        )
        assert res.response_kind != ResponseKind.JSON_API
        assert not res.testable_as_api

    def test_guessed_env_and_unverified_routes_skipped_by_attack_planner(self):
        planner = AttackPlanner("inv-juice-1", "http://localhost:3001")
        
        # Endpoint profile created from unverified guess
        ep_guess = planner.classify_endpoint({
            "path": "/.env",
            "method": "GET",
            "discovered_from": ["guess"],
        })
        assert ep_guess.protocol == "CANDIDATE_UNVERIFIED"

        # Confirmed endpoint profile created from real API observation
        obs = DiscoveryObservation(
            source_type="crawler",
            source_location="/main.js",
            discovered_url="/api/Products",
            method="GET",
            protocol="REST_CONFIRMED",
        )
        ep_real = EndpointProfile(
            target="http://localhost:3001",
            endpoint="/api/Products",
            method="GET",
            protocol="REST_CONFIRMED",
            parameters=[ParameterProfile(name="id", location="query")],
            discovered_from=[obs],
        )

        plan = planner.generate_test_plan([ep_guess, ep_real])

        # Verify only real endpoint is planned; /.env is skipped
        planned_endpoints = {t.endpoint.endpoint for t in plan.planned_tests}
        assert "/api/Products" in planned_endpoints
        assert "/.env" not in planned_endpoints

    @pytest.mark.asyncio
    async def test_hunter_agent_does_not_propose_unverified_guessed_routes(self, monkeypatch):
        hunter = HunterAgent("inv-juice-2")

        attack_surface = {
            "endpoints": [
                {"path": "/api/Products", "method": "GET", "parameters": ["id"]},
                {"path": "/rest/user/login", "method": "POST", "parameters": ["email", "password"]},
            ],
            "priority_endpoints": [
                {"path": "/api/Products", "method": "GET"},
            ],
        }

        # Mock LLM returning a generic unverified guess (/.env)
        async def mock_llm(*args, **kwargs):
            return '{"hypothesis_id": "hyp-1", "vuln_class": "InfoDisclosure", "endpoint": "/.env", "title": "Check .env", "rationale": "Env file check", "test_steps": []}'

        monkeypatch.setattr("app.agents.hunter.agenerate_structured_content", mock_llm)

        hyp = await hunter.run(
            attack_surface=attack_surface,
            already_proposed=[],
            iteration=1,
        )

        # Hunter agent replaces the guessed /.env with a confirmed attack surface endpoint
        assert hyp.endpoint in ("/api/Products", "/rest/user/login")
        assert hyp.endpoint != "/.env"
