"""
app/targets/session_vault.py
────────────────────────────
Multi-Persona Session Vault for Authenticated Application Testing.

Stores real user sessions (Cookies, Bearer tokens, API Keys, Custom Headers)
provided by human researchers from Burp Suite:
  - `owner` / `victim` (e.g. Account A)
  - `attacker` / `researcher` (e.g. Account B)
  - `admin` (Privileged Role)
  - `anonymous` (No Credentials)
"""
from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class UserSession(BaseModel):
    """Represents an authenticated user persona session."""
    role: str = Field("attacker", description="owner, attacker, admin, anonymous")
    token: str | None = Field(None, description="Bearer or API Token")
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)

    def get_resolved_headers(self) -> dict[str, str]:
        """Builds merged headers including Authorization and Cookie strings."""
        merged = dict(self.headers)
        if self.token and "authorization" not in {k.lower() for k in merged}:
            token_val = self.token if self.token.lower().startswith("bearer ") else f"Bearer {self.token}"
            merged["Authorization"] = token_val

        if self.cookies and "cookie" not in {k.lower() for k in merged}:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            merged["Cookie"] = cookie_str

        return merged


class SessionVault:
    """Manages multi-tenant identity sessions for an investigation."""

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        self._sessions: dict[str, UserSession] = {}

    def add_session(self, session: UserSession) -> None:
        role_key = session.role.lower().strip()
        self._sessions[role_key] = session

    def get_session(self, role: str) -> UserSession | None:
        role_key = role.lower().strip()
        # Handle common role aliases
        if role_key in ("control", "victim", "alice"):
            return self._sessions.get("owner") or self._sessions.get("victim") or self._sessions.get("alice")
        if role_key in ("test", "bob", "attacker"):
            return self._sessions.get("attacker") or self._sessions.get("bob")
        if role_key in ("admin", "administrator"):
            return self._sessions.get("admin")
        return self._sessions.get(role_key)

    def resolve_headers_for_role(self, role: str) -> dict[str, str]:
        """Resolves full request headers for a given test step role."""
        session = self.get_session(role)
        if session:
            return session.get_resolved_headers()

        # Seeded default fallbacks if no human session provided
        role_clean = role.lower().strip()
        if role_clean in ("control", "owner", "victim", "alice"):
            return {"Authorization": "Bearer alice_token_123"}
        if role_clean in ("test", "attacker", "bob"):
            return {"Authorization": "Bearer bob_token_456"}
        if role_clean in ("admin", "administrator"):
            return {"Authorization": "Bearer admin_master_token_789"}
        return {}


# Global in-memory session vault registry per investigation
_GLOBAL_VAULTS: dict[str, SessionVault] = {}


def get_session_vault(investigation_id: str) -> SessionVault:
    """Retrieves or creates the session vault for an investigation."""
    if investigation_id not in _GLOBAL_VAULTS:
        _GLOBAL_VAULTS[investigation_id] = SessionVault(investigation_id)
    return _GLOBAL_VAULTS[investigation_id]
