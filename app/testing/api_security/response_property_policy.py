"""
app/testing/api_security/response_property_policy.py
────────────────────────────────────────────────────
Policy & Contract Specification for Response Property-Level Authorization (API3:2023).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ResponseFieldContract:
    """Explicit field contract defining permitted and protected response fields per persona."""
    allowed_fields_by_role: dict[str, set[str]]
    protected_fields: set[str] = field(default_factory=set)
    source: str = "explicit_policy"
    schema_reference: str | None = None
    role_allowlists_complete: bool = False



@dataclass
class ResponsePropertyPolicy:
    """Configuration-backed policy governing safe response property authorization testing."""
    enabled: bool = False
    require_explicit_authorization: bool = True
    allowed_test_identities: set[str] = field(
        default_factory=lambda: {"owner", "attacker", "admin", "tester", "researcher", "alice", "bob", "anonymous"}
    )
    allowed_endpoint_patterns: list[str] = field(default_factory=list)
    read_only_methods: set[str] = field(default_factory=lambda: {"GET", "HEAD"})
    max_requests_per_endpoint: int = 2
    response_contracts: dict[str, ResponseFieldContract] = field(default_factory=dict)
    # Example mapping:
    # {
    #   "GET /api/users/me": ResponseFieldContract(
    #       allowed_fields_by_role={
    #           "owner": {"id", "display_name", "email"},
    #           "admin": {"id", "display_name", "email", "account_status"},
    #       },
    #       protected_fields={"password_hash", "mfa_secret", "session_token", "api_key"},
    #       source="openapi+role_policy",
    #       schema_reference="openapi:/paths/~1api~1users~1me/get"
    #   )
    # }

    def get_contract_for_endpoint(self, method: str, path: str) -> ResponseFieldContract | None:
        """Resolves explicit ResponseFieldContract for a given method and path."""
        clean_method = method.upper().strip()
        clean_path = path.split("?")[0].strip()
        key = f"{clean_method} {clean_path}"

        if key in self.response_contracts:
            return self.response_contracts[key]

        # Template match (e.g., /api/users/{id})
        for pattern_key, contract in self.response_contracts.items():
            if " " in pattern_key:
                p_method, p_path = pattern_key.split(" ", 1)
                if p_method.upper().strip() == clean_method:
                    regex_pat = "^" + re.sub(r"\{[^}]+\}|:[a-zA-Z0-9_]+", r"[^/]+", p_path.strip()) + "$"
                    try:
                        if re.match(regex_pat, clean_path):
                            return contract
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
