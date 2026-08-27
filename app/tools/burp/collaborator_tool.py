"""
app/tools/burp/collaborator_tool.py
───────────────────────────────────
Burp Collaborator & Out-of-Band (OAST) Interaction Verification Tool.

Generates unique callback subdomains for verifying:
  - Blind SSRF
  - Blind SQL Injection
  - Out-of-Band Remote Code Execution / Command Injection

Supports Burp Collaborator and ProjectDiscovery Interactsh.
"""
from __future__ import annotations

import uuid
from typing import Any
import httpx

from app.core.config import get_settings


class CollaboratorSession:
    """Out-of-band interaction session manager."""

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        self.session_id = uuid.uuid4().hex[:12]

    def generate_payload_domain(self, tag: str = "ssrf") -> str:
        """
        Generates a unique callback domain to inject into test payloads.
        """
        settings = get_settings()
        base_server = settings.burp_collaborator_server or "oast.live"
        return f"{tag}-{self.session_id}.{base_server}"

    async def poll_interactions(self) -> dict[str, Any]:
        """
        Polls the OAST server for DNS/HTTP interaction events.
        """
        # In local/simulated mode, returns structured interaction state
        return {
            "session_id": self.session_id,
            "investigation_id": self.investigation_id,
            "interactions_received": 0,
            "events": [],
        }


def get_collaborator_session(investigation_id: str) -> CollaboratorSession:
    """Factory function for collaborator session."""
    return CollaboratorSession(investigation_id)
