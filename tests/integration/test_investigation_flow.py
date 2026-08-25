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
