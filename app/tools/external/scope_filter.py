"""
app/tools/external/scope_filter.py
──────────────────────────────────
Safe Harbor Scope Filter for External Tool Outputs.

Ensures that subdomains and URLs discovered by external tools (Subfinder, Katana, etc.)
are checked against the target authorization scope before passing to the AI agents.
"""
from __future__ import annotations

from typing import Any
from app.targets.authorization import AuthorizationService
from app.targets.normalization import normalize_url


async def filter_discovered_targets(
    raw_urls_or_hosts: list[str],
    investigation_id: str,
    auth_service: AuthorizationService | None = None,
) -> list[str]:
    """
    Filters a list of discovered hostnames or URLs, returning only those
    explicitly authorized within the investigation's scope.
    """
    auth = auth_service or AuthorizationService()
    authorized: list[str] = []

    for item in raw_urls_or_hosts:
        clean = item.strip()
        if not clean:
            continue

        # Ensure scheme is present for scope checking
        if not clean.startswith("http://") and not clean.startswith("https://"):
            test_url = f"https://{clean}"
        else:
            test_url = clean

        try:
            scope_res = await auth.check_scope(test_url, investigation_id)
            if scope_res.allowed:
                authorized.append(clean)
        except Exception:
            continue

    return authorized
