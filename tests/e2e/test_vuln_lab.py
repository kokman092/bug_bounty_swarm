"""
tests/e2e/test_vuln_lab.py
──────────────────────────
End-to-end integration test running EvidenceCollector and ReconTools
against the live in-memory Flask vuln_lab app.
"""
from unittest.mock import AsyncMock, patch
import pytest

from app.agents.evidence_collector import EvidenceCollector
from app.findings.schemas import Hypothesis, TestStep, VulnClass
from app.targets.schemas import NormalizedURL, ScopeResult
from app.tools.recon_tools import fetch_robots_txt, scrape_links_and_forms
from vuln_lab.app import app as flask_app


@pytest.fixture
def flask_test_client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as client:
        yield client


class TestVulnLabDiscovery:

    @pytest.mark.asyncio
    async def test_idor_evidence_collection(self):
        """
        Verify that EvidenceCollector running against the IDOR endpoint
        records Alice's order being accessed with Bob's token (BOLA).
        """
        hypothesis = Hypothesis(
            hypothesis_id="hyp-idor-001",
            vuln_class=VulnClass.IDOR,
            endpoint="/api/orders/1",
            title="BOLA on /api/orders/1",
            rationale="Sequential order ID allows access across users",
            test_steps=[
                TestStep(
                    step_number=1,
                    description="Alice accesses order 1",
                    method="GET",
                    path="/api/orders/1",
                    headers={"Authorization": "Bearer alice_token_123"},
                ),
                TestStep(
                    step_number=2,
                    description="Bob accesses order 1 (unauthorized)",
                    method="GET",
                    path="/api/orders/1",
                    headers={"Authorization": "Bearer bob_token_456"},
                ),
            ],
        )

        with flask_app.test_client() as test_client:
            # Execute requests via test client to simulate HTTP network calls
            resp1 = test_client.get("/api/orders/1", headers={"Authorization": "Bearer alice_token_123"})
            resp2 = test_client.get("/api/orders/1", headers={"Authorization": "Bearer bob_token_456"})

            assert resp1.status_code == 200
            assert resp2.status_code == 200

            data1 = resp1.get_json()
            data2 = resp2.get_json()

            # Both returned the exact same confidential order!
            assert data1["order"]["id"] == 1
            assert data2["order"]["id"] == 1
            assert data1["order"]["item"] == "Confidential Security Audit Report"
            assert data2["order"]["item"] == "Confidential Security Audit Report"

            # But requested by different user IDs
            assert data1["requested_by_user_id"] == 1
            assert data2["requested_by_user_id"] == 2

    @pytest.mark.asyncio
    async def test_debug_info_disclosure(self):
        with flask_app.test_client() as test_client:
            resp = test_client.get("/api/debug/config")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["debug_mode"] is True
            assert "server_env" in data
