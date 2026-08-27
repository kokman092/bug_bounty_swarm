"""
app/tools/external/subfinder.py
───────────────────────────────
Subfinder Tool Wrapper with Certificate Transparency Fallback.

1. Binary Mode: Executes `subfinder -d <domain> -silent -json` if available.
2. Fallback Mode: Queries Certificate Transparency (`crt.sh`) JSON API via `ScopeEnforcingHttpClient`.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from typing import Any
import httpx

from app.core.logging import get_logger
from app.tools.external.scope_filter import filter_discovered_targets

logger = get_logger(__name__)


async def run_subfinder(
    domain: str,
    investigation_id: str,
) -> dict[str, Any]:
    """
    Discovers passive subdomains for a root domain using Subfinder CLI
    or Certificate Transparency (crt.sh) fallback.
    """
    clean_domain = domain.strip().lower()
    # Strip protocol if present
    if "://" in clean_domain:
        clean_domain = clean_domain.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]

    # Don't run subfinder on local IPs or localhost
    if clean_domain in ("localhost", "127.0.0.1", "0.0.0.0") or clean_domain.endswith(".local") or clean_domain.endswith(".run.app"):
        return {
            "engine": "subfinder",
            "mode": "skipped",
            "target": clean_domain,
            "reason": "Single host / local IP target (wildcard subdomain discovery skipped)",
            "subdomains": [clean_domain],
        }

    subfinder_bin = shutil.which("subfinder")

    if subfinder_bin:
        # Binary execution mode
        try:
            proc = await asyncio.create_subprocess_exec(
                subfinder_bin,
                "-d", clean_domain,
                "-silent",
                "-json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30.0)

            raw_subdomains = []
            for line in stdout.decode("utf-8", errors="ignore").splitlines():
                if line.strip():
                    try:
                        data = json.loads(line)
                        raw_subdomains.append(data.get("host", ""))
                    except ValueError:
                        raw_subdomains.append(line.strip())

            valid_subdomains = [s for s in raw_subdomains if s and clean_domain in s]
            filtered = await filter_discovered_targets(valid_subdomains, investigation_id)

            return {
                "engine": "subfinder",
                "mode": "cli_binary",
                "target": clean_domain,
                "discovered_count": len(filtered),
                "subdomains": sorted(list(set(filtered))),
            }
        except Exception as exc:
            logger.warning("subfinder_cli_failed_falling_back", error=str(exc))

    # Fallback mode: Certificate Transparency (crt.sh)
    try:
        crt_url = f"https://crt.sh/?q=%.{clean_domain}&output=json"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(crt_url, headers={"User-Agent": "BugBounty-Swarm/1.0"})
            if resp.status_code == 200:
                records = resp.json()
                raw_subs = set()
                for rec in records:
                    name_val = rec.get("name_value", "")
                    for entry in name_val.split("\n"):
                        clean_entry = entry.strip().lstrip("*.").lower()
                        if clean_entry and clean_domain in clean_entry:
                            raw_subs.add(clean_entry)

                filtered = await filter_discovered_targets(list(raw_subs), investigation_id)
                return {
                    "engine": "subfinder",
                    "mode": "crt_sh_fallback",
                    "target": clean_domain,
                    "discovered_count": len(filtered),
                    "subdomains": sorted(list(filtered)),
                }
    except Exception as exc:
        logger.debug("crt_sh_fallback_error", error=str(exc))

    return {
        "engine": "subfinder",
        "mode": "fallback_empty",
        "target": clean_domain,
        "discovered_count": 1,
        "subdomains": [clean_domain],
    }
