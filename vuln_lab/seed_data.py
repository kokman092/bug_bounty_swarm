"""
vuln_lab/seed_data.py
─────────────────────
Seeds in-memory SQLite database with test users, organizations, orders, and sensitive enterprise keys.
"""
import sqlite3

USERS = [
    (1, "alice", "pbkdf2:sha256:1000$alice_hash", "user", "alice_token_123", "alice@enterprise.corp", 1),
    (2, "bob", "pbkdf2:sha256:1000$bob_hash", "user", "bob_token_456", "bob@attacker.io", 2),
    (3, "admin", "pbkdf2:sha256:1000$admin_hash", "admin", "admin_master_token_789", "admin@internal.sec", 1),
]

ORGANIZATIONS = [
    (1, "Acme MegaCorp", 1, "sk_live_acme_sec_9988776655443322", "Enterprise Elite", "****-****-****-4242", "prod_webhook_key_secret_alice"),
    (2, "Bob Freelance LLC", 2, "sk_live_bob_free_1122334455667788", "Free Tier", "****-****-****-1234", "prod_webhook_key_secret_bob"),
    (3, "CyberDyne Systems", 1, "sk_live_cyberdyne_secret_998811", "Enterprise VIP", "****-****-****-9988", "prod_webhook_key_secret_cyberdyne"),
    (4, "Initech Global", 1, "sk_live_initech_secret_776655", "Enterprise Plus", "****-****-****-7766", "prod_webhook_key_secret_initech"),
    (5, "Umbrella Corp", 1, "sk_live_umbrella_secret_332211", "Custom Dedicated", "****-****-****-3322", "prod_webhook_key_secret_umbrella"),
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


PRODUCTS = [
    (1, "Enterprise Shield", 999.00, "Enterprise cybersecurity defense appliance"),
    (2, "Developer Token Pack", 49.00, "100k API request credits"),
    (3, "Cloud Sentinel Sensor", 2499.00, "Real-time container vulnerability scanner"),
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
            organization_id INTEGER
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
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL,
            description TEXT
        )
    """)

    cursor.executemany("INSERT OR REPLACE INTO users VALUES (?,?,?,?,?,?,?)", USERS)
    cursor.executemany("INSERT OR REPLACE INTO organizations VALUES (?,?,?,?,?,?,?)", ORGANIZATIONS)
    cursor.executemany("INSERT OR REPLACE INTO orders VALUES (?,?,?,?,?)", ORDERS)
    cursor.executemany("INSERT OR REPLACE INTO products VALUES (?,?,?,?)", PRODUCTS)
    conn.commit()

