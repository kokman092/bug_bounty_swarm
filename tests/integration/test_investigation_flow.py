"""
tests/integration/test_investigation_flow.py
────────────────────────────────────────────
Integration tests for FastAPI endpoints, authentication, and investigation creation.
"""
from unittest.mock import AsyncMock, patch
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.targets.schemas import NormalizedURL

client = TestClient(app)


class TestInvestigationEndpoints:

    def test_healthz_public(self):
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_unauthenticated_request_rejected(self):
        resp = client.post("/investigations", json={"target_url": "https://example.com"})
        assert resp.status_code == 401

    @patch("app.targets.authorization.AuthorizationService.authorize_investigation_target")
    @patch("app.db.firestore.investigations_ref")
    @patch("app.events.service.EventService.emit_event")
    @patch("app.investigations.service.InvestigationService._dispatch_investigation_task")
    def test_create_investigation_success(
        self,
        mock_dispatch,
        mock_emit,
        mock_inv_ref,
        mock_auth_target,
    ):
        mock_auth_target.return_value = NormalizedURL(
            original="https://vuln-lab.com/api",
            scheme="https",
            host="vuln-lab.com",
            port=443,
            path="/api",
            canonical="https://vuln-lab.com:443/api",
        )

        mock_doc = AsyncMock()
        mock_inv_ref.return_value.document.return_value = mock_doc

        headers = {"X-API-Key": "test_secret_key_12345678901234567890123456789012"}

        # Temporarily mock settings api_secret_key to match header
        with patch("app.core.config.get_settings") as mock_settings:
            mock_settings.return_value.api_secret_key = "test_secret_key_12345678901234567890123456789012"
            mock_settings.return_value.use_firebase_auth = False
            mock_settings.return_value.max_retries = 2

            resp = client.post(
                "/investigations",
                json={"target_url": "https://vuln-lab.com/api"},
                headers=headers,
            )

            assert resp.status_code == 201
            data = resp.json()
            assert "investigation_id" in data
            assert data["status"] == "AUTHORIZED"

    def test_target_port_3001_preservation_and_evidence_identity(self):
        """
        Proves:
          1. Configured target http://localhost:3001 is preserved.
          2. No request or endpoint identity substitutes port 3000.
          3. CanonicalEndpointIdentity records port 3001.
          4. Validation pipeline and planned test identities record port 3001.
        """
        from app.discovery.endpoint_identity import CanonicalEndpointIdentity
        from app.discovery.models import EndpointProfile, DiscoveryObservation
        from app.intelligence.attack_planner import AttackPlanner
        from app.validation.pipeline import ValidationPipeline
        from app.findings.schemas import FindingStatus, VulnClass
        from app.testing.base_tester import TestResult

        configured_target = "http://localhost:3001"
        inv_id = "inv-port-test-3001"

        # 1. Canonical Endpoint Identity derives port 3001 correctly
        canon = CanonicalEndpointIdentity.from_url(
            "/api/products?category=juice",
            method="GET",
            target_base_url=configured_target,
        )
        assert canon.port == 3001
        assert canon.host == "localhost"
        assert canon.scheme == "http"
        assert canon.path == "/api/products"
        assert canon.query_parameter_names == ("category",)
        assert "3000" not in canon.identity_key
        assert "localhost:3001" in canon.identity_key

        # 2. AttackPlanner creates profiles and test identities retaining port 3001
        planner = AttackPlanner(inv_id, configured_target)
        ep = planner.classify_endpoint({
            "path": "/api/products",
            "method": "GET",
            "discovered_from": [
                DiscoveryObservation(
                    source_type="crawler",
                    source_location="/main.js",
                    discovered_url="/api/products",
                    method="GET",
                    protocol="REST_CONFIRMED",
                )
            ],
        })
        assert ep.target == "http://localhost:3001"
        assert ep.url == "http://localhost:3001/api/products"
        assert "3000" not in ep.url

        plan = planner.generate_test_plan([ep])
        for test in plan.planned_tests:
            assert "3000" not in test.test_id
            assert "localhost:3001" in test.test_id

        # 3. ValidationPipeline preserves target URL and records port 3001
        pipeline = ValidationPipeline(
            investigation_id=inv_id,
            target_url=configured_target,
        )
        assert pipeline.target_url == "http://localhost:3001"

