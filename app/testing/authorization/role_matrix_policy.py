"""
app/testing/authorization/role_matrix_policy.py
───────────────────────────────────────────────
Role Matrix Policy & Explicit Authorization Contract Specification for BFLA testing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RoleMatrixPolicy:
    """Configuration-backed policy for safe multi-persona role matrix authorization verification."""
    enabled: bool = False
    require_explicit_authorization: bool = True
    allowed_test_identities: set[str] = field(
        default_factory=lambda: {"owner", "attacker", "admin", "tester", "researcher", "alice", "bob", "anonymous"}
    )
    allowed_endpoint_patterns: list[str] = field(default_factory=list)
    read_only_methods: set[str] = field(default_factory=lambda: {"GET", "HEAD"})
    max_personas_per_endpoint: int = 3
    max_requests_per_endpoint: int = 3
    expected_access_rules: dict[str, set[str]] = field(default_factory=dict)
    # Example mapping:
    # {
    #   "GET /api/admin/reports": {"admin"},
    #   "GET /api/orders/{id}": {"owner", "admin"},
    #   "GET /api/public/status": {"anonymous", "owner", "attacker", "admin"}
    # }

    def get_expected_roles_for_endpoint(self, method: str, path: str) -> set[str] | None:
        """
        Resolves explicit expected allowed roles for a given method and path.
        Returns None if no explicit authorization contract exists.
        """
        clean_method = method.upper().strip()
        clean_path = path.split("?")[0].strip()
        key = f"{clean_method} {clean_path}"

        # 1. Exact match
        if key in self.expected_access_rules:
            return self.expected_access_rules[key]

        # 2. Template / normalized match (e.g. /api/orders/1 -> /api/orders/{id})
        for pattern_key, roles in self.expected_access_rules.items():
            if " " in pattern_key:
                p_method, p_path = pattern_key.split(" ", 1)
                if p_method.upper().strip() == clean_method:
                    # Convert {var} or :var to regex pattern
                    regex_pat = "^" + re.sub(r"\{[^}]+\}|:[a-zA-Z0-9_]+", r"[^/]+", p_path.strip()) + "$"
                    try:
                        if re.match(regex_pat, clean_path):
                            return roles
                    except re.error:
                        pass

        return None

    def is_endpoint_allowed(self, path: str) -> bool:
        """Checks if path is covered by allowed endpoint patterns."""
        if not self.allowed_endpoint_patterns:
            return False
        clean_path = path.split("?")[0].strip()
        for pattern in self.allowed_endpoint_patterns:
            if pattern == "*" or pattern == clean_path:
                return True
            try:
                if re.match(pattern, clean_path):
                    return True
            except re.error:
                if pattern in clean_path:
                    return True
        return False
