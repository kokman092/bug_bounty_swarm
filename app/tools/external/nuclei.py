"""
app/tools/external/nuclei.py
────────────────────────────
Nuclei Vulnerability & Exposure Scanner Tool Wrapper.

1. Binary Mode: Executes `nuclei -u <target> -t http/misconfiguration,http/exposures -silent -json` if available.
2. Fallback Mode: Lightweight built-in exposure rule checker.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from typing import Any
from urllib.parse import urljoin

from app.core.logging import get_logger
from app.targets.normalization import normalize_url
from app.tools.http_client import ScopeEnforcingHttpClient

logger = get_logger(__name__)


async def run_nuclei_scan(
    target_url: str,
    investigation_id: str,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """
    Executes vulnerability exposure scans using Nuclei CLI or
    built-in Python exposure template fallback.
    """
    nuclei_bin = shutil.which("nuclei")

    if nuclei_bin:
        # Binary execution mode
        try:
            cmd = [
                nuclei_bin,
                "-u", target_url,
                "-silent",
                "-json",
                "-tags", ",".join(tags or ["exposure", "misconfig", "auth-bypass"]),
                "-timeout", "5",
                "-rate-limit", "50",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60.0)

            findings = []
            for line in stdout.decode("utf-8", errors="ignore").splitlines():
                if line.strip():
                    try:
                        data = json.loads(line)
                        findings.append({
                            "template_id": data.get("template-id"),
                            "name": data.get("info", {}).get("name"),
                            "severity": data.get("info", {}).get("severity"),
                            "matched_at": data.get("matched-at"),
                            "extracted_results": data.get("extracted-results", []),
                        })
                    except ValueError:
                        continue

            return {
                "engine": "nuclei",
                "mode": "cli_binary",
                "findings_count": len(findings),
                "findings": findings,
            }
        except Exception as exc:
            logger.warning("nuclei_cli_failed_falling_back", error=str(exc))

    # Fallback Mode: Quick exposure rule check
    base = normalize_url(target_url)
    root = f"{base.scheme}://{base.host_with_port}"

    EXPOSURE_PATHS = [
        ("/.env", "Environment file exposure", "Critical"),
        ("/.git/config", "Git repository metadata exposure", "High"),
        ("/api/debug/config", "Internal configuration disclosure", "High"),
        ("/swagger.json", "Exposed Swagger documentation", "Info"),
        ("/openapi.json", "Exposed OpenAPI specification", "Info"),
        ("/phpinfo.php", "PHPInfo server diagnostic leak", "Medium"),
    ]

    fallback_findings = []
    async with ScopeEnforcingHttpClient(investigation_id) as client:
        for path, name, sev in EXPOSURE_PATHS:
            try:
                resp = await client.get(urljoin(root, path))
                if resp.status_code == 200 and len(resp.content) > 10:
                    text = client.get_response_text_safe(resp)
                    # Check for genuine content markers
                    if path == "/.env" and ("=" in text or "KEY" in text or "SECRET" in text):
                        fallback_findings.append({"name": name, "severity": sev, "matched_at": path})
                    elif path == "/api/debug/config" and ("build" in text or "database" in text or "debug" in text):
                        fallback_findings.append({"name": name, "severity": sev, "matched_at": path})
                    elif ("swagger" in path or "openapi" in path) and "paths" in text:
                        fallback_findings.append({"name": name, "severity": sev, "matched_at": path})
            except Exception:
                continue

    return {
        "engine": "nuclei",
        "mode": "native_template_fallback",
        "findings_count": len(fallback_findings),
        "findings": fallback_findings,
    }
