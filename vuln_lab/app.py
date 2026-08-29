"""
vuln_lab/app.py
───────────────
Intentionally vulnerable Flask application simulating a realistic modern SaaS & e-commerce API.
Contains realistic vulnerabilities modeled after high-payout HackerOne reports:

1. BOLA / Multi-Tenant Secret IDOR on GET /api/v2/organizations/<id>/secrets
2. BOLA on GET /api/orders/<id> — Does not check if requesting user owns the order.
3. IDOR on GET /api/invoices/<id> — Cross-tenant invoice data retrieval.
4. SSRF on POST /api/integrations/webhook/test — Unsanitized outbound URL fetching.
5. Mass Assignment / PrivEsc on PUT /api/users/profile — Allows updating role to 'admin'.
6. SQL Injection on GET /api/products/search — Raw string concatenation in product query.
7. Broken Function Level Authorization on GET /api/admin/users — No role verification.
8. Information Disclosure on GET /api/debug/config — Internal environment metadata.
"""
from __future__ import annotations

import sqlite3
import urllib.request
import urllib.error
import os
import sys
from pathlib import Path

# Add project root to sys.path so direct script execution works
_root = str(Path(__file__).resolve().parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)

try:
    from vuln_lab.seed_data import init_db
except ImportError:
    from seed_data import init_db

app = Flask(__name__)


# Connect to in-memory SQLite database
_conn = sqlite3.connect(":memory:", check_same_thread=False)
_conn.row_factory = sqlite3.Row
init_db(_conn)


def get_current_user_token() -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    return None


def get_authenticated_user():
    token = get_current_user_token()
    if not token:
        return None
    cursor = _conn.cursor()
    cursor.execute("SELECT * FROM users WHERE token = ?", (token,))
    row = cursor.fetchone()
    return dict(row) if row else None


@app.route("/", methods=["GET"])
def index():
    return """
    <html>
        <head><title>Acme Cloud Enterprise Portal</title></head>
        <body style="font-family:sans-serif; padding:40px; background:#0f172a; color:#f8fafc;">
            <h1>🛡️ Acme Cloud Enterprise Platform API</h1>
            <p>Welcome to Acme Cloud REST API v2. Authenticate via <code>Authorization: Bearer &lt;token&gt;</code>.</p>
            <hr style="border-color:#334155;"/>
            <h3>Public API Reference</h3>
            <ul>
                <li><code>GET /api/products</code> - Catalog listing</li>
                <li><code>GET /api/products/search?q=...</code> - Product search query</li>
                <li><code>GET /api/v3/secure/profile/1</code> - Enterprise user profile</li>
                <li><code>GET /api/v2/organizations/1/secrets</code> - Organization API credentials</li>
                <li><code>GET /api/orders/1</code> - Order lookup</li>
                <li><code>POST /api/integrations/webhook/test</code> - Test outbound webhook</li>
                <li><code>PUT /api/users/profile</code> - Update user profile</li>
                <li><code>GET /api/admin/users</code> - Administrative user directory</li>
            </ul>
        </body>
    </html>
    """


@app.route("/robots.txt", methods=["GET"])
def robots():
    return (
        "User-agent: *\n"
        "Disallow: /api/admin/\n"
        "Disallow: /api/debug/\n"
        "Disallow: /api/v2/organizations/\n"
        "Disallow: /api/integrations/\n"
        "Sitemap: /sitemap.xml\n"
    )


@app.route("/sitemap.xml", methods=["GET"])
def sitemap():
    return """<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <url><loc>http://localhost:5000/api/v3/secure/profile/1</loc></url>
        <url><loc>http://localhost:5000/api/v2/organizations/1/secrets</loc></url>
        <url><loc>http://localhost:5000/api/orders/1</loc></url>
        <url><loc>http://localhost:5000/api/integrations/webhook/test</loc></url>
        <url><loc>http://localhost:5000/api/users/profile</loc></url>
        <url><loc>http://localhost:5000/api/products</loc></url>
    </urlset>
    """


@app.route("/api/products", methods=["GET"])
def list_products():
    cursor = _conn.cursor()
    cursor.execute("SELECT * FROM products")
    products = [dict(row) for row in cursor.fetchall()]
    return jsonify({"products": products})


# ── Vulnerability 1: SQL Injection on /api/products/search ────────────────────
@app.route("/api/products/search", methods=["GET"])
def search_products():
    query = request.args.get("q", "")
    cursor = _conn.cursor()
    # VULNERABILITY: Raw string interpolation without parameterized query!
    sql = f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
    try:
        cursor.execute(sql)
        results = [dict(row) for row in cursor.fetchall()]
        return jsonify({"query": query, "count": len(results), "results": results})
    except Exception as exc:
        return jsonify({"error": "Database query error", "detail": str(exc)}), 500


# ── Vulnerability 2: Multi-Tenant Org Secrets BOLA / IDOR ─────────────────────
@app.route("/api/v2/organizations/<int:org_id>/secrets", methods=["GET"])
def get_org_secrets(org_id: int):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    # VULNERABILITY: Validates token exists, but does NOT check if user belongs to org_id!
    cursor = _conn.cursor()
    cursor.execute("SELECT * FROM organizations WHERE id = ?", (org_id,))
    org = cursor.fetchone()
    if not org:
        return jsonify({"error": "Organization not found"}), 404

    return jsonify({
        "organization_id": org["id"],
        "name": org["name"],
        "owner_user_id": org["owner_user_id"],
        "api_key": org["api_key"],
        "billing_plan": org["billing_plan"],
        "card_last4": org["card_last4"],
        "webhook_secret": org["webhook_secret"],
        "accessed_by_user": user["username"],
    })


# ── Vulnerability 3: SSRF via Webhook Integration Endpoint ───────────────────
@app.route("/api/integrations/webhook/test", methods=["POST", "GET"])
def test_webhook():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    webhook_url = data.get("webhook_url") or request.args.get("webhook_url")
    if not webhook_url:
        return jsonify({"error": "Missing webhook_url parameter"}), 400

    # VULNERABILITY: Server initiates outbound HTTP request to arbitrary URL without allowlist/private IP checks!
    try:
        req = urllib.request.Request(
            webhook_url,
            headers={"User-Agent": "Acme-Webhook-Validator/2.1", "Accept": "*/*"}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            status_code = resp.status
            body_preview = resp.read(512).decode("utf-8", errors="replace")
            return jsonify({
                "status": "success",
                "target_url": webhook_url,
                "http_status": status_code,
                "response_body_preview": body_preview,
            })
    except Exception as exc:
        return jsonify({
            "status": "error",
            "target_url": webhook_url,
            "error_detail": str(exc),
        }), 200  # Returns 200 with error details (differential proof of reachable server)


# ── Vulnerability 4: Mass Assignment / Privilege Escalation ──────────────────
@app.route("/api/users/profile", methods=["PUT", "PATCH", "GET"])
def update_profile():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    if request.method == "GET":
        return jsonify({"user": user})

    data = request.get_json(silent=True) or {}
    cursor = _conn.cursor()

    # VULNERABILITY: Mass assignment — accepts 'role' without authorization check!
    new_email = data.get("email", user["email"])
    new_role = data.get("role", user["role"])  # Attacker can set role='admin'!

    cursor.execute(
        "UPDATE users SET email = ?, role = ? WHERE id = ?",
        (new_email, new_role, user["id"])
    )
    _conn.commit()

    cursor.execute("SELECT id, username, role, email FROM users WHERE id = ?", (user["id"],))
    updated_user = dict(cursor.fetchone())

    return jsonify({
        "status": "profile_updated",
        "user": updated_user,
        "privilege_escalation": updated_user["role"] == "admin",
    })


# ── Vulnerability 5: BOLA on /api/orders/<id> ─────────────────────────────────
@app.route("/api/orders/<int:order_id>", methods=["GET"])
def get_order(order_id: int):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    cursor = _conn.cursor()
    # VULNERABILITY: Fetches order by order_id WITHOUT checking user_id == user['id']!
    cursor.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    order = cursor.fetchone()
    if not order:
        return jsonify({"error": "Order not found"}), 404

    return jsonify({"order": dict(order), "requested_by_user_id": user["id"]})


# ── Vulnerability 6: IDOR on /api/invoices/<id> ───────────────────────────────
@app.route("/api/invoices/<int:invoice_id>", methods=["GET"])
def get_invoice(invoice_id: int):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    cursor = _conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE id = ?", (invoice_id,))
    order = cursor.fetchone()
    if not order:
        return jsonify({"error": "Invoice not found"}), 404

    return jsonify({
        "invoice_id": invoice_id,
        "amount": 999.00,
        "organization_id": 1,
        "status": "paid",
        "card_last4": "4242",
        "pdf_download_url": f"/api/invoices/{invoice_id}/download.pdf",
    })


# ── Additional Benchmark A Vulnerable Handlers ────────────────────────────────
@app.route("/api/v2/tenants/<int:tenant_id>/billing", methods=["GET"])
def get_tenant_billing(tenant_id: int):
    return jsonify({"tenant_id": tenant_id, "api_key": "sk_live_tenant_billing_secret", "card_last4": "9988", "balance": 5400.0})


@app.route("/api/documents/<int:doc_id>/download", methods=["GET"])
def get_doc_download(doc_id: int):
    return jsonify({"doc_id": doc_id, "secret_token": "doc_token_secret_alice_9988", "content": "CONFIDENTIAL_FINANCIAL_REPORT"})


@app.route("/api/users/<int:user_id>/private-keys", methods=["GET"])
def get_user_keys(user_id: int):
    return jsonify({"user_id": user_id, "api_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC_secret_deploy_key"})


@app.route("/api/support/tickets/<int:ticket_id>", methods=["GET"])
def get_ticket(ticket_id: int):
    return jsonify({"ticket_id": ticket_id, "secret_token": "ticket_token_998877", "internal_notes": "Customer private PIN"})


@app.route("/api/cloud/instances/<int:inst_id>/credentials", methods=["GET"])
def get_inst_creds(inst_id: int):
    return jsonify({"instance_id": inst_id, "api_key": "aws_secret_access_key_998877665544"})


@app.route("/api/v2/subscriptions/<int:sub_id>/invoices", methods=["GET"])
def get_sub_invoices(sub_id: int):
    return jsonify({"subscription_id": sub_id, "invoice_id": f"inv_sub_{sub_id}", "card_last4": "1122"})


@app.route("/api/audit-logs/export/<int:export_id>", methods=["GET"])
def get_audit_export(export_id: int):
    return jsonify({"export_id": export_id, "secret_token": "audit_export_token_master", "records": 1500})


# ── Vulnerability 7: Information Disclosure on /api/debug/config ─────────────
@app.route("/api/debug/config", methods=["GET"])
def debug_config():
    return jsonify({
        "server_env": "production_enterprise",
        "database": "sqlite3_cluster",
        "supported_auth": "Bearer token",
        "debug_mode": True,
        "internal_build": "v2.8.1-enterprise",
        "internal_services": {
            "metadata_service": "http://169.254.169.254/latest/meta-data/",
            "admin_service": "http://127.0.0.1:8000/internal",
        },
    })


# ── Vulnerability 8: Missing Function Authorization on /api/admin/users ───────
@app.route("/api/admin/users", methods=["GET"])
def admin_list_users():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    # VULNERABILITY: Validates token exists, but does NOT check role == 'admin'!
    cursor = _conn.cursor()
    cursor.execute("SELECT id, username, role, email, organization_id FROM users")
    users = [dict(row) for row in cursor.fetchall()]
    return jsonify({"users": users})


# ── Test Environment DB Reset ────────────────────────────────────────────────
@app.route("/api/test/reset-db", methods=["POST", "GET"])
def test_reset_db():
    init_db(_conn)
    return jsonify({"status": "db_reset_ok", "users_count": 3})



# ── Category B: Secure / Hardened Implementations (Expected: NO_FINDING) ─────
@app.route("/api/secure/orders/<int:order_id>", methods=["GET"])
def secure_get_order(order_id: int):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    cursor = _conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE id = ? AND user_id = ?", (order_id, user["id"]))
    order = cursor.fetchone()
    if not order:
        return jsonify({"error": "Forbidden: Resource does not belong to you or does not exist"}), 403
    return jsonify({"order": dict(order), "requested_by_user_id": user["id"]})


@app.route("/api/secure/products/search", methods=["GET"])
def secure_search_products():
    query = request.args.get("q", "")
    cursor = _conn.cursor()
    # Secure: Parameterized query prevents SQL injection
    param = f"%{query}%"
    cursor.execute("SELECT * FROM products WHERE name LIKE ? OR description LIKE ?", (param, param))
    results = [dict(row) for row in cursor.fetchall()]
    return jsonify({"query": query, "count": len(results), "results": results})


@app.route("/api/secure/users/profile", methods=["PUT", "PATCH"])
def secure_update_profile():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    cursor = _conn.cursor()
    # Secure: Strict DTO allowlist — only 'email' can be updated, 'role' is ignored
    new_email = data.get("email", user["email"])
    cursor.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user["id"]))
    _conn.commit()
    cursor.execute("SELECT id, username, role, email FROM users WHERE id = ?", (user["id"],))
    return jsonify({"status": "profile_updated", "user": dict(cursor.fetchone()), "privilege_escalation": False})


@app.route("/api/secure/integrations/webhook/test", methods=["POST"])
def secure_test_webhook():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    webhook_url = data.get("webhook_url", "")
    # Secure: Blocks loopback, private RFC1918, and metadata IP ranges
    disallowed = ["127.", "localhost", "169.254.", "10.", "192.168.", "172.16."]
    if any(d in webhook_url.lower() for d in disallowed):
        return jsonify({"error": "Disallowed target: SSRF protection active", "blocked": True}), 400
    return jsonify({"status": "queued", "target_url": webhook_url})


@app.route("/api/secure/admin/users", methods=["GET"])
def secure_admin_list_users():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    if user["role"] != "admin":
        return jsonify({"error": "Forbidden: Requires administrator role"}), 403
    cursor = _conn.cursor()
    cursor.execute("SELECT id, username, role, email FROM users")
    return jsonify({"users": [dict(row) for row in cursor.fetchall()]})


@app.route("/api/secure/invoices/<int:invoice_id>", methods=["GET"])
def secure_get_invoice(invoice_id: int):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"error": "Forbidden: Resource does not belong to you or does not exist"}), 403


@app.route("/api/secure/documents/<int:doc_id>/download", methods=["GET"])
def secure_get_doc(doc_id: int):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"error": "Forbidden: Requires cryptographic bearer token"}), 403


@app.route("/api/secure/v2/organizations/<int:org_id>/secrets", methods=["GET"])
def secure_get_org_secrets(org_id: int):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"error": "Forbidden: Caller is not a tenant administrator"}), 403


@app.route("/api/secure/customers/filter", methods=["GET"])
def secure_customer_filter():
    return jsonify({"count": 0, "results": []})


@app.route("/api/secure/system/config", methods=["GET"])
def secure_system_config():
    return jsonify({"error": "Forbidden: Requires mTLS cluster credentials"}), 403



# ── Category C: Ambiguous / Insufficient Evidence (Expected: NEEDS_HUMAN_VALIDATION) ──
@app.route("/api/ambiguous/debug/timing", methods=["GET"])
def ambiguous_timing():
    return jsonify({
        "status": "ok",
        "debug_trace": "timing_probe_active",
        "notice": "Internal latency metrics enabled but no secret data leaked",
    }), 200, {"X-Debug-Latency": "180ms", "X-App-Cluster": "node-us-west-4"}


@app.route("/api/ambiguous/feedback", methods=["GET"])
def ambiguous_reflected_input():
    # Input is reflected but properly HTML/JSON-encoded without executable context
    msg = request.args.get("msg", "")
    import html
    safe_msg = html.escape(msg)
    return jsonify({"message": safe_msg, "encoded": True})


# ── BENCHMARK 120-B: Unseen & Adversarial Test Endpoints ─────────────────────

# A. Unseen Vulnerable Endpoints (Category A)
@app.route("/api/v3/workspaces/<int:workspace_id>/tokens", methods=["GET"])
def v3_workspace_tokens(workspace_id: int):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    # VULNERABLE BOLA: Returns workspace private token without verifying user membership
    return jsonify({
        "workspace_id": workspace_id,
        "token_name": f"Production Deployment Key #{workspace_id}",
        "secret_token": f"sk_live_v3_workspace_{workspace_id}_secret_xyz987",
        "owner_id": 1,
    })


@app.route("/api/v3/export/pdf", methods=["POST", "GET"])
def v3_export_pdf():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    pdf_source = data.get("source_url") or request.args.get("source_url")
    if not pdf_source:
        return jsonify({"error": "Missing source_url"}), 400
    # VULNERABLE SSRF: Fetches source_url without egress filtering
    try:
        req = urllib.request.Request(pdf_source, headers={"User-Agent": "PDF-Render-Bot/3.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            return jsonify({
                "status": "rendered",
                "source": pdf_source,
                "response_body_preview": resp.read(256).decode("utf-8", errors="replace"),
            })
    except Exception as exc:
        return jsonify({"status": "fetch_error", "detail": str(exc)}), 200


@app.route("/api/v3/members/role", methods=["PUT", "PATCH"])
def v3_update_member_role():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    # VULNERABLE MASS ASSIGNMENT: Directly promotes user to admin
    role = data.get("role", "user")
    cursor = _conn.cursor()
    cursor.execute("UPDATE users SET role = ? WHERE id = ?", (role, user["id"]))
    _conn.commit()
    return jsonify({"status": "role_updated", "user_id": user["id"], "role": role, "privilege_escalation": role in ("admin", "super_admin", "root")})


# B. Adversarial Secure Endpoints (Category B — Looks vulnerable but correctly secured)
@app.route("/api/v3/secure/profile/<int:user_id>", methods=["GET"])
def v3_adversarial_profile(user_id: int):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    # ADVERSARIAL: Returns HTTP 200, but ignores path user_id and strictly returns caller's own data!
    return jsonify({
        "status": "success",
        "requested_id": user_id,
        "returned_user_id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "cross_account_leakage": False,
    })


@app.route("/api/v3/secure/proxy", methods=["POST"])
def v3_adversarial_proxy():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    target_url = data.get("target_url", "")
    # ADVERSARIAL SECURE SSRF: Disallows all private, loopback, and metadata destinations
    blocked_hosts = ["127.", "localhost", "169.254.", "10.", "192.168.", "172."]
    if any(b in target_url.lower() for b in blocked_hosts):
        return jsonify({"error": "Destination blocked by security egress filter", "blocked": True}), 400
    return jsonify({"status": "proxy_ok", "destination": target_url})


@app.route("/api/v3/secure/account/upgrade", methods=["POST", "PUT"])
def v3_adversarial_upgrade():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    # ADVERSARIAL SECURE: Looks like Mass Assignment, but requires signed billing token
    data = request.get_json(silent=True) or {}
    if not data.get("payment_intent_signature"):
        return jsonify({
            "status": "upgrade_rejected",
            "reason": "Missing verified payment authorization",
            "upgraded": False,
            "privilege_escalation": False,
        }), 400
    return jsonify({"status": "upgraded", "upgraded": True})


# C. Subtle Ambiguous Endpoints (Category C)
@app.route("/api/v3/ambiguous/graphql", methods=["POST", "GET"])
def v3_ambiguous_graphql():
    # Introspection returns type schema, but queries for private fields require auth token and return null
    return jsonify({
        "data": {
            "__schema": {"types": ["User", "Workspace", "PublicCatalog"]},
            "notice": "Public introspection enabled; field-level authorization active",
        }
    })


@app.route("/api/v3/ambiguous/search/suggest", methods=["GET"])
def v3_ambiguous_suggest():
    # Fast caching with natural latency variance (simulates false time-based SQLi alert)
    prefix = request.args.get("prefix", "")
    return jsonify({"suggestions": [f"{prefix}_demo", f"{prefix}_enterprise"], "cached": True})


# ── BENCHMARK C: Generalization & Edge Cases (API v4) ───────────────────────

# 1. Banking & Wallets (BOLA)
@app.route("/api/v4/wallets/<int:wallet_id>/balance", methods=["GET"])
def v4_wallet_balance(wallet_id: int):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    # Vulnerable BOLA: Exposes wallet balance and account number
    return jsonify({
        "wallet_id": wallet_id,
        "wallet_balance": 45250.75 if wallet_id == 1 else 120.00,
        "currency": "USD",
        "account_owner_id": 1,
    })


@app.route("/api/v4/cards/<int:card_id>/cvv", methods=["GET"])
def v4_card_cvv(card_id: int):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"card_id": card_id, "cvv": "842", "last4": "4242", "owner_id": 1})


# 2. Healthcare & Patients (BOLA / Privacy)
@app.route("/api/v4/patients/<int:patient_id>/records", methods=["GET"])
def v4_patient_records(patient_id: int):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "patient_id": patient_id,
        "patient_name": "John Doe" if patient_id == 1 else "Jane Smith",
        "diagnosis": "Confidential Medical Diagnosis A",
        "confidential": True,
        "owner_id": 1,
    })


# 3. Cloud Dispatch Webhook (SSRF)
@app.route("/api/v4/notifications/dispatch", methods=["POST"])
def v4_notification_dispatch():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    dest = data.get("destination_url", "")
    if not dest:
        return jsonify({"error": "Missing destination_url"}), 400
    try:
        req = urllib.request.Request(dest, headers={"User-Agent": "CloudNotifier/4.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            return jsonify({"status": "delivered", "response_body_preview": resp.read(128).decode("utf-8", errors="replace")})
    except Exception as exc:
        return jsonify({"status": "network_error", "detail": str(exc)}), 200


# 4. User Tier Mutation (Mass Assignment)
@app.route("/api/v4/users/tier", methods=["PATCH", "PUT"])
def v4_user_tier_update():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    tier = data.get("tier", "free")
    return jsonify({"status": "tier_updated", "user_id": user["id"], "tier": tier, "privilege_escalation": True})


# 5. Secure Counterparts
@app.route("/api/v4/secure/wallets/<int:wallet_id>/balance", methods=["GET"])
def v4_secure_wallet(wallet_id: int):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    if wallet_id != user["id"]:
        return jsonify({"error": "Forbidden: Wallet does not belong to caller"}), 403
    return jsonify({"wallet_id": wallet_id, "wallet_balance": 120.00, "currency": "USD"})


@app.route("/api/v4/secure/notifications/dispatch", methods=["POST"])
def v4_secure_dispatch():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    dest = data.get("destination_url", "")
    if any(b in dest.lower() for b in ["127.", "localhost", "169.254.", "10.", "192.168.", "172."]):
        return jsonify({"error": "Blocked by egress policy", "blocked": True}), 400
    return jsonify({"status": "dispatched", "destination": dest})


# 6. Edge Cases
@app.route("/api/v4/edge/async-job/<int:job_id>", methods=["GET"])
def v4_edge_async(job_id: int):
    return jsonify({"job_id": job_id, "status": "processing", "progress": 45}), 202


@app.route("/api/v4/edge/partial-stream/<int:doc_id>", methods=["GET"])
def v4_edge_partial(doc_id: int):
    return jsonify({"doc_id": doc_id, "snippet": "Partial chunk 1-50", "patient_name": "Public Anon Sample"}), 206


@app.route("/api/v4/edge/schema-validate", methods=["POST"])
def v4_edge_schema():
    return jsonify({"error": "Validation Failed", "fields": ["invalid_format"]}), 422


@app.route("/api/v4/edge/rate-limit-test", methods=["GET"])
def v4_edge_ratelimit():
    return jsonify({"error": "Rate limit exceeded; retry in 60s"}), 429


# ── BENCHMARK D: Extreme Generalization & Novel Enterprise Schemas (API v5) ──

# 1. Cloud Infra Kubeconfig Exfiltration (BOLA with novel key names)
@app.route("/api/v5/clusters/<int:cluster_id>/kubeconfig", methods=["GET"])
def v5_cluster_kubeconfig(cluster_id: int):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "cluster_uuid": f"k8s-cluster-{cluster_id}-prod",
        "creator_ref": 1,  # Belongs to Tenant Alice (ID 1)
        "kubeconfig": f"apiVersion: v1\nclusters:\n- cluster:\n    server: https://10.244.0.{cluster_id}:6443\n  name: prod\nusers:\n- name: admin\n  user:\n    token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.prod_cluster_token_xyz",
    })


# 2. Healthcare Prescriptions (IDOR with nested patient_ref)
@app.route("/api/v5/prescriptions/<int:rx_id>", methods=["GET"])
def v5_prescription_lookup(rx_id: int):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "prescription_id": rx_id,
        "patient_ref": 1,  # Patient Alice (ID 1)
        "medication": "Controlled Substance Class A",
        "dosage": "50mg daily",
        "prescribing_physician": "Dr. Smith",
    })


# 3. Enterprise Dispatch Webhook (SSRF with target_uri)
@app.route("/api/v5/webhooks/forward", methods=["POST"])
def v5_webhook_forward():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    dest = data.get("target_uri", "")
    if not dest:
        return jsonify({"error": "Missing target_uri"}), 400
    try:
        req = urllib.request.Request(dest, headers={"User-Agent": "EnterpriseForwarder/5.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            return jsonify({"status": "forwarded", "response_body_preview": resp.read(128).decode("utf-8", errors="replace")})
    except Exception as exc:
        return jsonify({"status": "network_error", "detail": str(exc)}), 200


# ── Standardized OWASP Local Lab Endpoints (API v1 with Explicit Contracts) ──

import base64
import hashlib
import hmac
import json

LAB_JWT_SECRET = b"synthetic_lab_jwt_secret_key_12345"


def verify_lab_jwt(token: str, require_valid_signature: bool = True) -> dict | None:
    """Verifies synthetic lab JWT tokens."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts
        
        # Pad base64
        def b64_decode(s: str) -> bytes:
            pad = len(s) % 4
            if pad > 0:
                s += "=" * (4 - pad)
            return base64.urlsafe_b64decode(s.encode("utf-8"))

        header = json.loads(b64_decode(header_b64).decode("utf-8"))
        payload = json.loads(b64_decode(payload_b64).decode("utf-8"))

        if not require_valid_signature:
            return payload

        if header.get("alg") == "none" or not sig_b64:
            return None

        # Verify HMAC-SHA256 signature
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        expected_sig = base64.urlsafe_b64encode(
            hmac.new(LAB_JWT_SECRET, signing_input, hashlib.sha256).digest()
        ).decode("utf-8").rstrip("=")

        if sig_b64.rstrip("=") != expected_sig:
            return None

        return payload
    except Exception:
        return None


# ── 1. BOLA / IDOR Endpoints with Multi-Object Relationships ─────────────────

@app.route("/api/v1/orders/<int:order_id>", methods=["GET"])
def v1_get_order(order_id: int):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    cursor = _conn.cursor()
    # VULNERABLE BOLA: Returns order by ID without checking if user_id == user['id']
    cursor.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    row = cursor.fetchone()
    if not row:
        return jsonify({"error": "Order not found"}), 404
    return jsonify({"order": dict(row), "accessed_by_user": user["username"]})


@app.route("/api/v1/documents/<int:doc_id>", methods=["GET"])
def v1_get_document(doc_id: int):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    cursor = _conn.cursor()
    # VULNERABLE BOLA: Returns confidential document without checking owner_user_id
    cursor.execute("SELECT * FROM documents WHERE id = ?", (doc_id,))
    row = cursor.fetchone()
    if not row:
        return jsonify({"error": "Document not found"}), 404
    return jsonify({"document": dict(row), "accessed_by_user": user["username"]})


@app.route("/api/v1/invoices/<int:invoice_id>", methods=["GET"])
def v1_get_invoice(invoice_id: int):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    cursor = _conn.cursor()
    # VULNERABLE BOLA: Returns invoice across tenant boundaries
    cursor.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,))
    row = cursor.fetchone()
    if not row:
        return jsonify({"error": "Invoice not found"}), 404
    return jsonify({"invoice": dict(row), "accessed_by_user": user["username"]})


@app.route("/api/v1/secure/orders/<int:order_id>", methods=["GET"])
def v1_secure_get_order(order_id: int):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    cursor = _conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE id = ? AND user_id = ?", (order_id, user["id"]))
    row = cursor.fetchone()
    if not row:
        return jsonify({"error": "Forbidden: Order does not belong to you"}), 403
    return jsonify({"order": dict(row), "accessed_by_user": user["username"]})


@app.route("/api/v1/secure/documents/<int:doc_id>", methods=["GET"])
def v1_secure_get_document(doc_id: int):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    cursor = _conn.cursor()
    cursor.execute("SELECT * FROM documents WHERE id = ? AND owner_user_id = ?", (doc_id, user["id"]))
    row = cursor.fetchone()
    if not row:
        return jsonify({"error": "Forbidden: Document does not belong to you"}), 403
    return jsonify({"document": dict(row), "accessed_by_user": user["username"]})


@app.route("/api/v1/secure/invoices/<int:invoice_id>", methods=["GET"])
def v1_secure_get_invoice(invoice_id: int):
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    cursor = _conn.cursor()
    cursor.execute("SELECT * FROM invoices WHERE id = ? AND organization_id = ?", (invoice_id, user["organization_id"]))
    row = cursor.fetchone()
    if not row:
        return jsonify({"error": "Forbidden: Invoice belongs to another organization"}), 403
    return jsonify({"invoice": dict(row), "accessed_by_user": user["username"]})


# ── 2. BFLA Endpoints with Explicit Role Rules ───────────────────────────────

@app.route("/api/v1/admin/settings", methods=["GET"])
def v1_admin_settings():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    # VULNERABLE BFLA: Allows regular user to read admin cluster settings
    return jsonify({
        "status": "ok",
        "cluster_mode": "multi_region",
        "encryption_at_rest": True,
        "backup_retention_days": 90,
        "caller_role": user["role"],
    })


@app.route("/api/v1/admin/audit-logs", methods=["GET"])
def v1_admin_audit_logs():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    # VULNERABLE BFLA: Allows regular user to read system audit logs
    cursor = _conn.cursor()
    cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 10")
    logs = [dict(r) for r in cursor.fetchall()]
    return jsonify({"audit_logs": logs, "caller_role": user["role"]})


@app.route("/api/v1/billing/export", methods=["GET"])
def v1_billing_export():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    # VULNERABLE BFLA: Allows any authenticated user to export master billing data
    return jsonify({
        "status": "ready",
        "export_format": "csv",
        "total_revenue_ytd": 845000.00,
        "caller_role": user["role"],
    })


@app.route("/api/v1/secure/admin/settings", methods=["GET"])
def v1_secure_admin_settings():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    if user["role"] != "admin":
        return jsonify({"error": "Forbidden: Requires administrator role"}), 403
    return jsonify({"cluster_mode": "multi_region", "encryption_at_rest": True, "caller_role": user["role"]})


@app.route("/api/v1/secure/admin/audit-logs", methods=["GET"])
def v1_secure_admin_audit_logs():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    if user["role"] != "admin":
        return jsonify({"error": "Forbidden: Requires administrator role"}), 403
    cursor = _conn.cursor()
    cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 10")
    return jsonify({"audit_logs": [dict(r) for r in cursor.fetchall()], "caller_role": user["role"]})


@app.route("/api/v1/secure/billing/export", methods=["GET"])
def v1_secure_billing_export():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    if user["role"] != "admin":
        return jsonify({"error": "Forbidden: Requires administrator role"}), 403
    return jsonify({"status": "ready", "export_format": "csv", "caller_role": user["role"]})


# ── 3. Response Property Authorization (API3:2023) ───────────────────────────

@app.route("/api/v1/users/me", methods=["GET"])
def v1_user_me():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    # VULNERABLE API3: Returns raw internal record including password_hash, mfa_secret, stripe_customer_id
    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "password_hash": user["password_hash"],
        "mfa_secret": user["mfa_secret"],
        "stripe_customer_id": user["stripe_customer_id"],
    })


@app.route("/api/v1/secure/users/me", methods=["GET"])
def v1_secure_user_me():
    user = get_authenticated_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    # SECURE: Returns only safe public profile attributes according to contract
    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "organization_id": user["organization_id"],
    })


# ── 4. Pagination / Resource Limit Endpoints (API4:2023) ──────────────────────

@app.route("/api/v1/catalog/items", methods=["GET"])
def v1_catalog_items():
    limit = request.args.get("limit", "10")
    try:
        limit_val = max(1, min(1000, int(limit)))
    except ValueError:
        limit_val = 10
    cursor = _conn.cursor()
    cursor.execute("SELECT * FROM catalog_items LIMIT ?", (limit_val,))
    items = [dict(r) for r in cursor.fetchall()]
    return jsonify({
        "limit_applied": limit_val,
        "count": len(items),
        "items": items,
    })


@app.route("/api/v1/logs", methods=["GET"])
def v1_logs_pagination():
    size = request.args.get("size", "10")
    try:
        size_val = max(1, min(1000, int(size)))
    except ValueError:
        size_val = 10
    cursor = _conn.cursor()
    cursor.execute("SELECT * FROM audit_logs LIMIT ?", (size_val,))
    logs = [dict(r) for r in cursor.fetchall()]
    return jsonify({
        "size_applied": size_val,
        "count": len(logs),
        "logs": logs,
    })


# ── 5. JWT Signature Verification Endpoints (API2:2023) ──────────────────────

@app.route("/api/v1/jwt/insecure", methods=["GET"])
def v1_jwt_insecure():
    token = get_current_user_token()
    if not token:
        return jsonify({"error": "Missing Bearer token"}), 401
    # VULNERABLE: Decodes JWT without signature validation / accepts alg=none
    payload = verify_lab_jwt(token, require_valid_signature=False)
    if not payload:
        return jsonify({"error": "Invalid token format"}), 401
    return jsonify({
        "status": "authenticated_insecure",
        "subject": payload.get("sub", "unknown"),
        "role": payload.get("role", "user"),
        "warning": "Signature check bypassed in legacy mode",
    })


@app.route("/api/v1/jwt/secure", methods=["GET"])
def v1_jwt_secure():
    token = get_current_user_token()
    if not token:
        return jsonify({"error": "Missing Bearer token"}), 401
    # SECURE: Strictly enforces HMAC-SHA256 signature and rejects alg=none
    payload = verify_lab_jwt(token, require_valid_signature=True)
    if not payload:
        return jsonify({"error": "Invalid or forged JWT signature"}), 401
    return jsonify({
        "status": "authenticated_secure",
        "subject": payload.get("sub", "unknown"),
        "role": payload.get("role", "user"),
    })


# ── 6. Explicit OpenAPI 3.0 Specification Endpoint ────────────────────────────

@app.route("/openapi.json", methods=["GET"])
def openapi_spec():
    """Serves complete OpenAPI 3.0 specification for all lab endpoints."""
    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "Acme Enterprise Vulnerability Lab API",
            "version": "1.0.0",
            "description": "Standardized local test lab with explicit authorization contracts, parameter bounds, and response contracts.",
        },
        "servers": [{"url": "http://localhost:5000"}],
        "components": {
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                }
            }
        },
        "paths": {
            "/api/v1/orders/{id}": {
                "get": {
                    "summary": "Get order details (BOLA vulnerable)",
                    "parameters": [{
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer", "minimum": 1, "maximum": 100}
                    }],
                    "responses": {"200": {"description": "Order details"}, "401": {"description": "Unauthorized"}}
                }
            },
            "/api/v1/secure/orders/{id}": {
                "get": {
                    "summary": "Get order details (BOLA secure)",
                    "parameters": [{
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer", "minimum": 1, "maximum": 100}
                    }],
                    "responses": {"200": {"description": "Order details"}, "403": {"description": "Forbidden"}}
                }
            },
            "/api/v1/documents/{id}": {
                "get": {
                    "summary": "Get document (BOLA vulnerable)",
                    "parameters": [{
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer", "minimum": 1, "maximum": 50}
                    }],
                    "responses": {"200": {"description": "Document content"}}
                }
            },
            "/api/v1/admin/settings": {
                "get": {
                    "summary": "Admin settings (BFLA vulnerable)",
                    "responses": {"200": {"description": "Cluster settings"}}
                }
            },
            "/api/v1/secure/admin/settings": {
                "get": {
                    "summary": "Admin settings (BFLA secure)",
                    "responses": {"200": {"description": "Cluster settings"}, "403": {"description": "Forbidden: Requires admin"}}
                }
            },
            "/api/v1/admin/audit-logs": {
                "get": {
                    "summary": "Audit logs (BFLA vulnerable)",
                    "responses": {"200": {"description": "System audit logs"}}
                }
            },
            "/api/v1/secure/admin/audit-logs": {
                "get": {
                    "summary": "Audit logs (BFLA secure)",
                    "responses": {"200": {"description": "System audit logs"}, "403": {"description": "Forbidden: Requires admin"}}
                }
            },
            "/api/v1/billing/export": {
                "get": {
                    "summary": "Billing export (BFLA vulnerable)",
                    "responses": {"200": {"description": "Billing export data"}}
                }
            },
            "/api/v1/secure/billing/export": {
                "get": {
                    "summary": "Billing export (BFLA secure)",
                    "responses": {"200": {"description": "Billing export data"}, "403": {"description": "Forbidden: Requires admin"}}
                }
            },
            "/api/v1/users/me": {
                "get": {
                    "summary": "Current user profile (API3 vulnerable)",
                    "responses": {"200": {"description": "Full profile leaking sensitive fields"}}
                }
            },
            "/api/v1/secure/users/me": {
                "get": {
                    "summary": "Current user profile (API3 secure)",
                    "responses": {"200": {"description": "Sanitized public profile"}}
                }
            },
            "/api/v1/catalog/items": {
                "get": {
                    "summary": "List catalog items with bounded limit",
                    "parameters": [{
                        "name": "limit",
                        "in": "query",
                        "required": False,
                        "schema": {"type": "integer", "default": 10, "minimum": 1, "maximum": 20}
                    }],
                    "responses": {"200": {"description": "Catalog item list"}}
                }
            },
            "/api/v1/logs": {
                "get": {
                    "summary": "List audit logs with bounded size",
                    "parameters": [{
                        "name": "size",
                        "in": "query",
                        "required": False,
                        "schema": {"type": "integer", "default": 10, "minimum": 1, "maximum": 50}
                    }],
                    "responses": {"200": {"description": "Log entry list"}}
                }
            },
            "/api/v1/jwt/insecure": {
                "get": {
                    "summary": "JWT authentication (API2 vulnerable, alg=none permitted)",
                    "security": [{"BearerAuth": []}],
                    "responses": {"200": {"description": "Authenticated"}, "401": {"description": "Unauthorized"}}
                }
            },
            "/api/v1/jwt/secure": {
                "get": {
                    "summary": "JWT authentication (API2 secure, strict HMAC-SHA256 signature)",
                    "security": [{"BearerAuth": []}],
                    "responses": {"200": {"description": "Authenticated"}, "401": {"description": "Unauthorized"}}
                }
            }
        }
    }
    return jsonify(spec)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)






