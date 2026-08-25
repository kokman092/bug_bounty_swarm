"""
app/agents/scope_ingestion.py
─────────────────────────────
ScopeIngestionAgent — Automatically parses HackerOne/Bugcrowd program policies,
extracts in-scope targets, out-of-scope restrictions, and injects researcher handles
into custom verification headers (X-Bug-Bounty, User-Agent).
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.firestore import authorized_targets_ref
from app.targets.normalization import normalize_url
from app.targets.schemas import AuthorizedTarget, ScopeType

logger = get_logger(__name__)

_PROMPT_PATH = Path(__file__).parent / "prompts" / "scope_ingestion.txt"


class ScopeIngestionAgent:
    """Agent for automatic program policy ingestion and scope authorization."""

    def __init__(self, researcher_handle: str = "security_researcher") -> None:
        self.researcher_handle = researcher_handle.strip().lstrip("@")

    async def ingest_policy(
        self,
        policy_text: str,
        program_name: str = "CustomProgram",
    ) -> list[AuthorizedTarget]:
        """
        Parses program policy text via Gemini and generates structured AuthorizedTarget records.
        """
        logger.info("scope_ingestion_started", program=program_name, researcher=self.researcher_handle)
        settings = get_settings()

        prompt_template = _PROMPT_PATH.read_text(encoding="utf-8")
        system_instruction = prompt_template.replace("{researcher_handle}", self.researcher_handle)

        user_prompt = f"""
Program Name: {program_name}
Researcher Handle: {self.researcher_handle}

RAW PROGRAM POLICY & SCOPE DEFINITION:
{policy_text}

Extract all in-scope assets, out-of-scope exclusions, and researcher identification headers.
"""

        try:
            import google.generativeai as genai
            genai.configure(api_key=settings.gemini_api_key)
            model = genai.GenerativeModel(
                model_name="gemini-2.5-flash",
                system_instruction=system_instruction,
                generation_config={"response_mime_type": "application/json", "temperature": 0.1},
            )
            resp = await model.generate_content_async(user_prompt)
            data = json.loads(resp.text)
        except Exception as exc:
            logger.warning("gemini_scope_ingestion_fallback", error=str(exc))
            # Fallback deterministic parser for common domains
            data = self._fallback_parse(policy_text, program_name)

        targets: list[AuthorizedTarget] = []
        required_headers = data.get("required_headers", {
            "X-Bug-Bounty": f"hackerone-{self.researcher_handle}",
            "User-Agent": f"BugBountySwarm-Agent/1.0 (+https://hackerone.com/{self.researcher_handle})",
        })
        out_of_scope = data.get("out_of_scope_patterns", [])

        for item in data.get("in_scope_targets", []):
            url_raw = item.get("url_raw", "").strip()
            if not url_raw:
                continue

            scope_type_str = item.get("scope_type", "EXACT").upper()
            scope_type = ScopeType(scope_type_str) if scope_type_str in ScopeType.__members__ else ScopeType.EXACT

            # Normalization helper
            url_norm = url_raw
            if not url_norm.startswith(("http://", "https://")) and "*" not in url_norm:
                url_norm = f"https://{url_norm}"

            try:
                if "*" not in url_norm:
                    norm = normalize_url(url_norm)
                    canonical = norm.canonical
                else:
                    canonical = url_norm
            except Exception:
                canonical = url_norm

            target = AuthorizedTarget(
                target_id=f"target-{uuid.uuid4().hex[:8]}",
                url_normalized=canonical,
                url_raw=url_raw,
                scope_type=scope_type,
                scope_value=item.get("scope_value", canonical),
                allowed_schemes=item.get("allowed_schemes", ["https", "http"]),
                custom_headers=required_headers,
                out_of_scope_patterns=out_of_scope,
                added_by=self.researcher_handle,
                notes=f"{program_name}: {item.get('notes', 'Ingested via ScopeIngestionAgent')}",
                active=True,
            )
            targets.append(target)

            # Persist to Firestore if available
            try:
                ref = authorized_targets_ref().document(target.target_id)
                await ref.set(target.model_dump(mode="json"))
            except Exception:
                pass

        logger.info("scope_ingestion_completed", targets_count=len(targets))
        return targets

    def _fallback_parse(self, policy_text: str, program_name: str) -> dict[str, Any]:
        """Simple regex fallback if Gemini API is unreachable."""
        import re
        domains = re.findall(r'(?:https?://)?([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', policy_text)
        unique_domains = list(set(domains))[:5]

        targets = []
        for d in unique_domains:
            targets.append({
                "url_raw": f"https://{d}",
                "scope_type": "EXACT",
                "scope_value": f"https://{d}:443/",
                "allowed_schemes": ["https"],
                "notes": f"Auto-extracted domain from {program_name}",
            })

        return {
            "program_name": program_name,
            "platform": "HackerOne",
            "in_scope_targets": targets,
            "out_of_scope_patterns": ["/logout", "admin.*"],
            "required_headers": {
                "X-Bug-Bounty": f"hackerone-{self.researcher_handle}",
                "User-Agent": f"BugBountySwarm-Agent/1.0 (+https://hackerone.com/{self.researcher_handle})",
            },
            "rate_limit_per_minute": 60,
            "policy_summary": f"Extracted {len(targets)} domains for {program_name}",
        }
