"""
vuln_lab/seed_data.py
─────────────────────
Seeds in-memory SQLite database with synthetic test users, organizations, orders,
documents, invoices, audit logs, and catalog items.
ALL DATA IS SYNTHETIC TEST FIXTURE DATA (No real PII or secrets).
"""
import sqlite3

USERS = [
    (1, "alice", "pbkdf2:sha256:1000$synthetic_alice_hash", "user", "alice_token_123", "alice@synthetic-test.local", 1, "mfa_secret_synthetic_alice", "cus_synthetic_alice_123"),
    (2, "bob", "pbkdf2:sha256:1000$synthetic_bob_hash", "user", "bob_token_456", "bob@synthetic-test.local", 2, "mfa_secret_synthetic_bob", "cus_synthetic_bob_456"),
    (3, "admin", "pbkdf2:sha256:1000$synthetic_admin_hash", "admin", "admin_master_token_789", "admin@synthetic-test.local", 1, "mfa_secret_synthetic_admin", "cus_synthetic_admin_789"),
]

ORGANIZATIONS = [
    (1, "Acme MegaCorp", 1, "sk_test_synthetic_acme_sec_998877", "Enterprise Elite", "4242", "synthetic_webhook_key_alice"),
    (2, "Bob Freelance LLC", 2, "sk_test_synthetic_bob_free_112233", "Free Tier", "1234", "synthetic_webhook_key_bob"),
    (3, "CyberDyne Systems", 1, "sk_test_synthetic_cyberdyne_998811", "Enterprise VIP", "9988", "synthetic_webhook_key_cyberdyne"),
]

ORDERS = [
    (1, 1, "Confidential Security Audit Report", 5000.00, "/invoices/inv_001.pdf"),
    (2, 1, "Enterprise License Pack", 12000.00, "/invoices/inv_002.pdf"),
    (3, 2, "Standard Widget Box", 49.99, "/invoices/inv_003.pdf"),
    (4, 2, "Pro Developer Addon", 199.00, "/invoices/inv_004.pdf"),
    (5, 1, "Confidential Pentest Report", 8500.00, "/invoices/inv_005.pdf"),
    (6, 1, "Enterprise SOC Subscription", 25000.00, "/invoices/inv_006.pdf"),
    (7, 1, "Cloud Migration Archive", 15000.00, "/invoices/inv_007.pdf"),
]

DOCUMENTS = [
    (1, 1, "Q3_Strategic_Roadmap.pdf", "SYNTHETIC_CONFIDENTIAL_ROADMAP_ALICE", 1),
    (2, 2, "Contractor_Invoice_Timesheet.pdf", "SYNTHETIC_TIMESHEET_BOB", 2),
    (3, 1, "Enterprise_Architecture_Draft.pdf", "SYNTHETIC_INTERNAL_SPEC_ALICE", 1),
]

INVOICES = [
    (1, 1, 1, 5000.00, "PAID", "4242", "/invoices/inv_001.pdf"),
    (2, 2, 2, 49.99, "PAID", "1234", "/invoices/inv_003.pdf"),
    (3, 1, 1, 12000.00, "PAID", "4242", "/invoices/inv_002.pdf"),
]

AUDIT_LOGS = [
    (1, "2026-08-28T10:00:00Z", "user_login", "alice", "10.0.0.1", "SUCCESS"),
    (2, "2026-08-28T10:05:00Z", "role_update", "admin", "10.0.0.2", "SUCCESS"),
    (3, "2026-08-28T10:10:00Z", "api_key_rotate", "admin", "10.0.0.2", "SUCCESS"),
    (4, "2026-08-28T10:15:00Z", "system_reconfig", "admin", "10.0.0.2", "SUCCESS"),
]

PRODUCTS = [
    (1, "Enterprise Shield", 999.00, "Enterprise cybersecurity defense appliance"),
    (2, "Developer Token Pack", 49.00, "100k API request credits"),
    (3, "Cloud Sentinel Sensor", 2499.00, "Real-time container vulnerability scanner"),
]

CATALOG_ITEMS = [
    (i, f"Synthetic Item #{i}", f"SKU-{1000+i}", "Infrastructure", 19.99 + (i * 2), True)
    for i in range(1, 101)
]


def init_db(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password_hash TEXT,
            role TEXT,
            token TEXT,
            email TEXT,
            organization_id INTEGER,
            mfa_secret TEXT,
            stripe_customer_id TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS organizations (
            id INTEGER PRIMARY KEY,
            name TEXT,
            owner_user_id INTEGER,
            api_key TEXT,
            billing_plan TEXT,
            card_last4 TEXT,
            webhook_secret TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            item TEXT,
            amount REAL,
            invoice_path TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY,
            owner_user_id INTEGER,
            filename TEXT,
            content TEXT,
            organization_id INTEGER
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY,
            organization_id INTEGER,
            user_id INTEGER,
            amount REAL,
            status TEXT,
            card_last4 TEXT,
            pdf_path TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            action TEXT,
            actor TEXT,
            ip_address TEXT,
            status TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL,
            description TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS catalog_items (
            id INTEGER PRIMARY KEY,
            name TEXT,
            sku TEXT,
            category TEXT,
            price REAL,
            in_stock BOOLEAN
        )
    """)

    cursor.executemany("INSERT OR REPLACE INTO users VALUES (?,?,?,?,?,?,?,?,?)", USERS)
    cursor.executemany("INSERT OR REPLACE INTO organizations VALUES (?,?,?,?,?,?,?)", ORGANIZATIONS)
    cursor.executemany("INSERT OR REPLACE INTO orders VALUES (?,?,?,?,?)", ORDERS)
    cursor.executemany("INSERT OR REPLACE INTO documents VALUES (?,?,?,?,?)", DOCUMENTS)
    cursor.executemany("INSERT OR REPLACE INTO invoices VALUES (?,?,?,?,?,?,?)", INVOICES)
    cursor.executemany("INSERT OR REPLACE INTO audit_logs VALUES (?,?,?,?,?,?)", AUDIT_LOGS)
    cursor.executemany("INSERT OR REPLACE INTO products VALUES (?,?,?,?)", PRODUCTS)
    cursor.executemany("INSERT OR REPLACE INTO catalog_items VALUES (?,?,?,?,?,?)", CATALOG_ITEMS)
    conn.commit()
