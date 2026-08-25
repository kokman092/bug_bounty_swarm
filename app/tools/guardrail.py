"""
app/tools/guardrail.py
──────────────────────
Target Authorization & In-Scope Safety Guardrail.

Enforces strict defense-in-depth validation to prevent probes against unauthorized domains,
private external infrastructure, or out-of-scope assets.
"""
from __future__ import annotations

import os
from urllib.parse import urlparse

# Default authorized local testbed targets
DEFAULT_AUTHORIZED_TARGETS = [
    "http://127.0.0.1:5000",
    "http://localhost:5000",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:3001",
    "http://localhost:3001",
]


def get_authorized_targets() -> list[str]:
    """Retrieves the list of currently authorized target base URLs."""
    env_targets = os.environ.get("AUTHORIZED_TARGETS", "")
    if env_targets:
        parsed = [t.strip().rstrip("/") for t in env_targets.split(",") if t.strip()]
        return parsed or DEFAULT_AUTHORIZED_TARGETS
    return DEFAULT_AUTHORIZED_TARGETS


def is_authorized_target(target_base_url: str) -> bool:
    """
    Validates whether a target URL is explicitly authorized for testing.
    Verifies scheme, hostname, and port against the active allow-list.
    """
    if not target_base_url:
        return False

    normalized_url = target_base_url.strip().rstrip("/")
    allowlist = get_authorized_targets()

    # Exact base URL match
    if normalized_url in allowlist:
        return True

    # Hostname + Port level match
    parsed_target = urlparse(normalized_url)
    for allowed in allowlist:
        parsed_allowed = urlparse(allowed)
        if (
            parsed_target.scheme == parsed_allowed.scheme
            and parsed_target.hostname == parsed_allowed.hostname
            and parsed_target.port == parsed_allowed.port
        ):
            return True

    return False
