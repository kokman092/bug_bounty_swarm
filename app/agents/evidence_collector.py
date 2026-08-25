"""
app/agents/evidence_collector.py
────────────────────────────────
Deterministic EvidenceCollector Service (NO LLM).

Executes structured HTTP test steps proposed by HunterAgent.
Guarantees:
  - Every single HTTP call is re-validated through ScopeEnforcingHttpClient.
  - Responses are bounded in size.
  - Structured diffs are calculated deterministically.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

from app.core.exceptions import ScopeViolationError
from app.core.logging import get_logger
from app.findings.schemas import Hypothesis, TestStep
from app.targets.normalization import normalize_url
from app.tools.evidence_tools import compute_response_diff
from app.tools.http_client import ScopeEnforcingHttpClient

logger = get_logger(__name__)


class EvidenceCollector:
    """
    Deterministic execution engine for vulnerability hypothesis validation.
    """

    def __init__(self, investigation_id: str, target_url: str) -> None:
        self.investigation_id = investigation_id
        self.target_url = target_url

    async def collect_evidence(self, hypothesis: Hypothesis) -> dict[str, Any]:
        """
        Execute each test step defined in hypothesis.test_steps and record results.
        """
        logger.info(
            "evidence_collection_started",
            hypothesis_id=hypothesis.hypothesis_id,
            steps_count=len(hypothesis.test_steps),
        )

        step_results: list[dict[str, Any]] = []
        base_norm = normalize_url(self.target_url)

        async with ScopeEnforcingHttpClient(self.investigation_id) as client:
            for step in hypothesis.test_steps:
                # Construct full absolute URL
                if step.path.startswith("http"):
                    target_step_url = step.path
                else:
                    target_step_url = urljoin(
                        f"{base_norm.scheme}://{base_norm.host_with_port}/",
                        step.path.lstrip("/"),
                    )

                # Resolve symbolic authorization tokens if specified in step headers
                resolved_headers = dict(step.headers or {})
                auth_hdr = resolved_headers.get("Authorization") or resolved_headers.get("authorization")
                if auth_hdr:
                    auth_lower = str(auth_hdr).lower()
                    if "admin" in auth_lower:
                        resolved_headers["Authorization"] = "Bearer admin_token_789"
                    elif "alice" in auth_lower or "tenant_a" in auth_lower or "owner" in auth_lower or "victim" in auth_lower:
                        resolved_headers["Authorization"] = "Bearer alice_token_123"
                    elif "bob" in auth_lower or "tenant_b" in auth_lower or "user" in auth_lower or "attacker" in auth_lower:
                        resolved_headers["Authorization"] = "Bearer bob_token_456"
                    else:
                        resolved_headers["Authorization"] = str(auth_hdr)

                step_record: dict[str, Any] = {
                    "step_number": step.step_number,
                    "description": step.description,
                    "method": step.method.upper(),
                    "url": target_step_url,
                    "request_headers": resolved_headers,
                    "request_params": step.params,
                }

                try:
                    m = step.method.upper()
                    if m == "POST":
                        resp = await client.post(
                            url=target_step_url,
                            headers=resolved_headers,
                            params=step.params,
                            json_body=step.json_body,
                        )
                    elif m == "PUT":
                        resp = await client.put(
                            url=target_step_url,
                            headers=resolved_headers,
                            params=step.params,
                            json_body=step.json_body,
                        )
                    elif m == "PATCH":
                        resp = await client.patch(
                            url=target_step_url,
                            headers=resolved_headers,
                            params=step.params,
                            json_body=step.json_body,
                        )
                    else:
                        resp = await client.get(
                            url=target_step_url,
                            headers=resolved_headers,
                            params=step.params,
                        )

                    body_sample = client.get_response_text_safe(resp)

                    step_record["status_code"] = resp.status_code
                    step_record["response_headers"] = dict(resp.headers)
                    step_record["body"] = body_sample[:4000]  # sample for review
                    step_record["body_length"] = len(resp.content)
                    step_record["success"] = True

                except ScopeViolationError as exc:
                    step_record["success"] = False
                    step_record["error"] = f"Scope violation: {exc.message}"
                    logger.warning("step_scope_violation", step=step.step_number, url=target_step_url)
                except Exception as exc:
                    step_record["success"] = False
                    step_record["error"] = str(exc)
                    logger.warning("step_execution_error", step=step.step_number, error=str(exc))

                step_results.append(step_record)

        # Compute diffs if 2 steps were executed (standard A vs B comparison)
        diff = None
        if len(step_results) >= 2 and step_results[0].get("success") and step_results[1].get("success"):
            diff = compute_response_diff(step_results[0], step_results[1])

        evidence_report = {
            "hypothesis_id": hypothesis.hypothesis_id,
            "steps_executed": step_results,
            "comparison_diff": diff,
            "all_steps_succeeded": all(r.get("success", False) for r in step_results),
        }

        logger.info(
            "evidence_collection_completed",
            hypothesis_id=hypothesis.hypothesis_id,
            all_succeeded=evidence_report["all_steps_succeeded"],
        )
        return evidence_report
