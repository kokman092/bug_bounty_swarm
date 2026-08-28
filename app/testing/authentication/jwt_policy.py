"""
app/testing/authentication/jwt_policy.py
────────────────────────────────────────
Eligibility and safety configuration policy for JWT signature rejection verification.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class JwtRejectionTestPolicy:
    """Configuration policy governing safe negative-control JWT rejection testing."""
    enabled: bool = False
    require_explicit_authorization: bool = True
    allowed_test_identities: set[str] = field(
        default_factory=lambda: {"owner", "attacker", "tester", "researcher", "alice", "bob"}
    )
    allowed_endpoint_patterns: list[str] = field(default_factory=list)
    allow_alg_none_probe: bool = False
    allow_invalid_signature_probe: bool = True
    read_only_methods: set[str] = field(default_factory=lambda: {"GET", "HEAD"})
    max_requests_per_endpoint: int = 3

    def is_endpoint_allowed(self, path: str) -> bool:
        """Checks if endpoint path matches the explicit allowlist patterns."""
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

    def is_identity_allowed(self, identity_role: str) -> bool:
        """Checks if identity belongs to an approved test persona."""
        return identity_role.lower().strip() in {i.lower() for i in self.allowed_test_identities}
