"""
app/tools/param_normalizer.py
─────────────────────────────
Smart Parameter & URL Placeholder Normalizer.

Transforms LLM-generated template placeholders into valid concrete test fixtures:
  - `{{order_id}}` / `ORDER_ID_FOR_USER_A` / `order_A_123` → `1`
  - `{{org_id}}` / `ORG_ID_PLACEHOLDER` / `org_A_123` → `1`
  - `{{user_id}}` / `user_A_123` / `USER_ID_FOR_ALICE` → `1`
"""
from __future__ import annotations

import re


def normalize_test_path(path: str, role: str = "CONTROL") -> str:
    """
    Replaces symbolic placeholders and template strings in URL paths
    with valid concrete numerical or string IDs for testing.
    Preserves plural resource collection names like /orders, /organizations, /users.
    """
    clean_path = path

    # 1. Clean explicit template brackets: {{order_id}} -> 1, {id} -> 1
    clean_path = re.sub(r"\{\{[^}]+\}\}", "1", clean_path)
    clean_path = re.sub(r"\{[a-zA-Z_][a-zA-Z0-9_]*\}", "1", clean_path)

    # 2. Clean symbolic named placeholders that have suffixes (e.g. /org_A_123 -> /1, /order_123 -> /1, /user_A_123 -> /1)
    # Does NOT match plural collections (/organizations, /orders, /users, /invoices)
    clean_path = re.sub(r"/(?:org(?:anization)?|order|user|invoice|doc(?:ument)?|tenant|account|item|product)_[a-zA-Z0-9_]+", "/1", clean_path, flags=re.IGNORECASE)
    clean_path = re.sub(r"/(?:org(?:anization)?|order|user|invoice|doc(?:ument)?|tenant|account|item|product)\d+", "/1", clean_path, flags=re.IGNORECASE)

    # 3. Clean uppercase placeholder tokens like /ORDER_ID_FOR_USER_A -> /1, /VALID_ORDER_ID -> /1, /USER_ID_FOR_ALICE -> /1
    clean_path = re.sub(r"/[A-Z0-9_]+(?:_ID|_FOR_|_PLACEHOLDER|_ALICE|_BOB|_VICTIM|_ATTACKER)[A-Z0-9_]*", "/1", clean_path)

    # 4. Normalize collaborator / callback domains
    clean_path = clean_path.replace("<COLLABORATOR_DOMAIN>", "127.0.0.1")
    clean_path = clean_path.replace("{{collaborator}}", "127.0.0.1")

    return clean_path
