"""
tests/unit/test_vuln_lab_endpoints.py
─────────────────────────────────────
Unit tests for the refined local vulnerability lab (vuln_lab/app.py):
  - BOLA endpoints with multi-object ownership (orders, documents, invoices).
  - BFLA endpoints with role-based routing (settings, audit-logs, billing export).
  - Response-property endpoints with protected field exposure vs sanitized contract.
  - Pagination endpoints with documented maximum bounds.
  - JWT verification with secure vs intentionally insecure signature validation.
  - OpenAPI 3.0 specification validation.
"""
import base64
import hashlib
import hmac
import json
import pytest

from vuln_lab.app import app, LAB_JWT_SECRET


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def generate_test_jwt(sub: str, role: str, alg: str = "HS256", sign: bool = True) -> str:
    header = {"alg": alg, "typ": "JWT"}
    payload = {"sub": sub, "role": role}

    def b64_encode(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode("utf-8")).decode("utf-8").rstrip("=")

    h_b64 = b64_encode(header)
    p_b64 = b64_encode(payload)

    if not sign or alg == "none":
        return f"{h_b64}.{p_b64}."

    signing_input = f"{h_b64}.{p_b64}".encode("utf-8")
    sig = base64.urlsafe_b64encode(
        hmac.new(LAB_JWT_SECRET, signing_input, hashlib.sha256).digest()
    ).decode("utf-8").rstrip("=")
    return f"{h_b64}.{p_b64}.{sig}"


class TestVulnLabEndpoints:

    # 1. BOLA Multi-Object Tests
    def test_bola_vulnerable_and_secure_orders(self, client):
        # Bob accesses Alice's order (Order ID 1 owned by Alice ID 1)
        headers_bob = {"Authorization": "Bearer bob_token_456"}
        
        # Vulnerable route returns 200 (BOLA)
        res = client.get("/api/v1/orders/1", headers=headers_bob)
        assert res.status_code == 200
        assert res.json["order"]["id"] == 1
        assert res.json["accessed_by_user"] == "bob"

        # Secure route returns 403 (Protected)
        res_sec = client.get("/api/v1/secure/orders/1", headers=headers_bob)
        assert res_sec.status_code == 403

    def test_bola_vulnerable_and_secure_documents(self, client):
        # Bob accesses Alice's document (Doc ID 1 owned by Alice ID 1)
        headers_bob = {"Authorization": "Bearer bob_token_456"}
        res = client.get("/api/v1/documents/1", headers=headers_bob)
        assert res.status_code == 200
        assert res.json["document"]["id"] == 1

        # Secure counterpart returns 403
        res_sec = client.get("/api/v1/secure/documents/1", headers=headers_bob)
        assert res_sec.status_code == 403

    # 2. BFLA Multi-Role Tests
    def test_bfla_vulnerable_and_secure_admin_settings(self, client):
        headers_user = {"Authorization": "Bearer alice_token_123"}
        headers_admin = {"Authorization": "Bearer admin_master_token_789"}

        # Vulnerable route allows regular user (BFLA)
        res = client.get("/api/v1/admin/settings", headers=headers_user)
        assert res.status_code == 200
        assert res.json["cluster_mode"] == "multi_region"

        # Secure route rejects regular user
        res_sec_user = client.get("/api/v1/secure/admin/settings", headers=headers_user)
        assert res_sec_user.status_code == 403

        # Secure route permits admin
        res_sec_admin = client.get("/api/v1/secure/admin/settings", headers=headers_admin)
        assert res_sec_admin.status_code == 200

    def test_bfla_billing_export(self, client):
        headers_user = {"Authorization": "Bearer alice_token_123"}
        res = client.get("/api/v1/billing/export", headers=headers_user)
        assert res.status_code == 200
        assert res.json["export_format"] == "csv"

        res_sec = client.get("/api/v1/secure/billing/export", headers=headers_user)
        assert res_sec.status_code == 403

    # 3. Response Property Authorization (API3)
    def test_response_property_leakage_and_secure_contract(self, client):
        headers_alice = {"Authorization": "Bearer alice_token_123"}

        # Vulnerable route leaks sensitive fields
        res = client.get("/api/v1/users/me", headers=headers_alice)
        assert res.status_code == 200
        data = res.json
        assert "password_hash" in data
        assert "mfa_secret" in data
        assert "stripe_customer_id" in data

        # Secure route conforms to safe contract
        res_sec = client.get("/api/v1/secure/users/me", headers=headers_alice)
        assert res_sec.status_code == 200
        sec_data = res_sec.json
        assert "password_hash" not in sec_data
        assert "mfa_secret" not in sec_data
        assert sec_data["username"] == "alice"

    # 4. Pagination / Resource Limit (API4)
    def test_pagination_limits(self, client):
        res = client.get("/api/v1/catalog/items?limit=15")
        assert res.status_code == 200
        assert res.json["limit_applied"] == 15
        assert res.json["count"] == 15

        res_logs = client.get("/api/v1/logs?size=2")
        assert res_logs.status_code == 200
        assert res_logs.json["size_applied"] == 2
        assert res_logs.json["count"] == 2

    # 5. JWT Validation (API2)
    def test_jwt_insecure_and_secure_routes(self, client):
        # Generate unsigned alg=none token
        unsigned_token = generate_test_jwt("alice", "user", alg="none", sign=False)
        # Generate validly signed HS256 token
        signed_token = generate_test_jwt("alice", "user", alg="HS256", sign=True)

        # Insecure route accepts unsigned token
        res_insec = client.get("/api/v1/jwt/insecure", headers={"Authorization": f"Bearer {unsigned_token}"})
        assert res_insec.status_code == 200
        assert res_insec.json["status"] == "authenticated_insecure"

        # Secure route rejects unsigned token (401)
        res_sec_fail = client.get("/api/v1/jwt/secure", headers={"Authorization": f"Bearer {unsigned_token}"})
        assert res_sec_fail.status_code == 401

        # Secure route accepts signed token (200)
        res_sec_ok = client.get("/api/v1/jwt/secure", headers={"Authorization": f"Bearer {signed_token}"})
        assert res_sec_ok.status_code == 200
        assert res_sec_ok.json["status"] == "authenticated_secure"

    # 6. OpenAPI 3.0 Specification
    def test_openapi_spec_availability(self, client):
        res = client.get("/openapi.json")
        assert res.status_code == 200
        spec = res.json
        assert spec["openapi"] == "3.0.3"
        assert "/api/v1/orders/{id}" in spec["paths"]
        assert "/api/v1/catalog/items" in spec["paths"]
        assert "/api/v1/jwt/secure" in spec["paths"]
