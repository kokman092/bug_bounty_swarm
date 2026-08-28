"""
app/testing/api_security/resource_consumption_policy.py
───────────────────────────────────────────────────────
Policy specification for safe, bounded pagination & resource consumption verification (API4:2023).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ResourceConsumptionPolicy:
    """Configuration policy governing safe single-probe resource consumption testing."""
    enabled: bool = False
    require_explicit_authorization: bool = True
    allowed_test_identities: set[str] = field(
        default_factory=lambda: {"owner", "attacker", "admin", "tester", "researcher", "alice", "bob", "anonymous"}
    )
    allowed_endpoint_patterns: list[str] = field(default_factory=list)
    read_only_methods: set[str] = field(default_factory=lambda: {"GET", "HEAD"})
    max_requests_per_endpoint: int = 1

    # Absolute safety caps controlled by the tester, not target input:
    default_probe_parameter_value: int = 100
    max_probe_parameter_value: int = 1000
    max_response_bytes_to_read: int = 262144  # 256 KB
    max_response_time_seconds: float = 5.0

    # Require trusted source metadata before testing:
    require_documented_parameter: bool = True

    # Eligibility:
    allowed_parameter_names: set[str] = field(
        default_factory=lambda: {
            "limit", "size", "page_size", "per_page", "pageSize",
            "count", "take", "first", "max_results"
        }
    )

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


def select_safe_probe_value(
    parameter: Any,
    policy: ResourceConsumptionPolicy,
) -> int:
    """
    Calculates safe probe value strictly at or below documented maximum and policy cap.
    Never attempts to exceed a documented maximum.
    """
    doc_max = getattr(parameter, "documented_maximum", None) if not isinstance(parameter, dict) else parameter.get("documented_maximum")
    if doc_max is not None and isinstance(doc_max, (int, float)) and doc_max > 0:
        return int(min(doc_max, policy.max_probe_parameter_value))

    return int(min(policy.default_probe_parameter_value, policy.max_probe_parameter_value))

