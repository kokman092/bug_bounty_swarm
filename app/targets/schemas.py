"""
app/targets/schemas.py
────────────────────────
Pydantic models for target authorization.
"""
from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class ScopeType(str, Enum):
    """How an authorized target's scope is matched."""
    EXACT = "EXACT"                     # http://foo.com/api must match exactly
    SUBDOMAIN_WILDCARD = "SUBDOMAIN_WILDCARD"  # *.foo.com matches sub.foo.com
    PATH_PREFIX = "PATH_PREFIX"         # http://foo.com/api/* matches all sub-paths


class AuthorizedTarget(BaseModel):
    """
    Represents one entry in the authorized_targets Firestore collection.
    """
    target_id: str
    url_normalized: str           # canonical form (scheme + host + port)
    url_raw: str                  # original input for display
    scope_type: ScopeType = ScopeType.EXACT
    scope_value: str              # the pattern to match against
    allowed_schemes: list[str] = Field(default_factory=lambda: ["https"])
    custom_headers: dict[str, str] = Field(default_factory=dict) # e.g. X-Bug-Bounty, User-Agent
    out_of_scope_patterns: list[str] = Field(default_factory=list) # e.g. ["/logout", "admin.target.com"]
    added_by: str
    notes: str = ""
    active: bool = True


class NormalizedURL(BaseModel):
    """
    Result of URL normalization.
    All fields are in canonical form.
    """
    original: str
    scheme: str           # "http" or "https" — lowercase
    host: str             # lowercase hostname, no port
    port: int             # explicit port (80 for http, 443 for https)
    path: str             # normalized path (always starts with /)
    canonical: str        # full canonical URL: scheme://host:port/path

    @property
    def host_with_port(self) -> str:
        """Return host:port only if non-default, else just host."""
        defaults = {"http": 80, "https": 443}
        if self.port == defaults.get(self.scheme):
            return self.host
        return f"{self.host}:{self.port}"


class ScopeResult(BaseModel):
    """
    Result of a scope authorization check.
    """
    allowed: bool
    reason: str
    matched_target_id: str | None = None
    normalized_url: str | None = None
