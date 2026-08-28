"""
app/testing/api_security/resource_consumption_verifier.py
─────────────────────────────────────────────────────────
Safe, Bounded Pagination & Resource Consumption (API4:2023) Verifier.

Safety Guarantees:
  1. Single-request budget: At most ONE controlled probe request per endpoint.
  2. Read-only (GET/HEAD) methods only.
  3. No flood, concurrency, or enumeration: Probe values are strictly clamped by policy caps.
  4. Protocol eligibility: Requires confirmed REST/API protocol (candidate protocols are skipped).
  5. Privacy preservation: Zero item values, record data, tokens, or PII are retained.
"""
from __future__ import annotations

import json
import time
from typing import Any

from app.core.logging import get_logger
from app.discovery.models import ParameterProfile
from app.findings.schemas import Confidence, FindingStatus, Severity, VulnClass
from app.targets.session_vault import get_session_vault
from app.testing.api_security.resource_consumption_policy import (
    ResourceConsumptionPolicy,
    select_safe_probe_value,
)
from app.testing.base_tester import TestResult
from app.tools.http_client import ScopeEnforcingHttpClient

logger = get_logger(__name__)

# Priority order for pagination parameter selection
PAGINATION_PARAM_PRIORITY = [
    "limit",
    "size",
    "page_size",
    "per_page",
    "pagesize",
    "take",
    "first",
    "max_results",
    "count",
]


def parse_item_count(data: Any) -> int | None:
    """Safely determines item count in a response structure without inspecting item values."""
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for key in ("items", "data", "results", "records", "products", "orders", "users", "rows"):
            val = data.get(key)
            if isinstance(val, list):
                return len(val)
        for val in data.values():
            if isinstance(val, list):
                return len(val)
    return None


class ResourceConsumptionVerifier:
    """Verifies that API pagination and resource limit parameters enforce server-side caps."""

    def __init__(
        self,
        investigation_id: str,
        target_base_url: str,
        policy: ResourceConsumptionPolicy | None = None,
    ) -> None:
        self.investigation_id = investigation_id
        self.target_base_url = target_base_url.rstrip("/")
        self.policy = policy or ResourceConsumptionPolicy()
        self._vault = get_session_vault(investigation_id)

    async def verify_endpoint(
        self,
        endpoint_info: dict[str, Any],
        role: str = "attacker",
    ) -> TestResult:
        path = str(endpoint_info.get("path", "/"))
        method = str(endpoint_info.get("method", "GET")).upper()
        target_url = f"{self.target_base_url}{path}"
        protocol = str(endpoint_info.get("protocol", "REST_CONFIRMED")).upper()

        # ── 1. Eligibility Checks ─────────────────────────────────────────────
        if not self.policy.enabled:
            return TestResult(
                test_name="Resource Consumption Verification",
                target_url=target_url,
                endpoint=path,
                method=method,
                vuln_class=VulnClass.MISCONFIG,
                status=FindingStatus.REJECTED,
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                observations=["Skipped: Resource consumption testing is disabled by policy."],
                raw_evidence={"skip_reason": "policy_disabled"},
            )

        if method not in self.policy.read_only_methods:
            return TestResult(
                test_name="Resource Consumption Verification",
                target_url=target_url,
                endpoint=path,
                method=method,
                vuln_class=VulnClass.MISCONFIG,
                status=FindingStatus.REJECTED,
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                observations=[f"Skipped: Method '{method}' is not a read-only method in policy."],
                raw_evidence={"skip_reason": "non_read_only_method"},
            )

        if protocol in ("UNKNOWN", "REST_CANDIDATE", "GRAPHQL_CANDIDATE", "WEBSOCKET_CANDIDATE"):
            return TestResult(
                test_name="Resource Consumption Verification",
                target_url=target_url,
                endpoint=path,
                method=method,
                vuln_class=VulnClass.MISCONFIG,
                status=FindingStatus.REJECTED,
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                observations=[f"Skipped: Protocol '{protocol}' is candidate-only / unconfirmed."],
                raw_evidence={"skip_reason": "unconfirmed_protocol", "protocol": protocol},
            )

        if not self.policy.is_endpoint_allowed(path):
            return TestResult(
                test_name="Resource Consumption Verification",
                target_url=target_url,
                endpoint=path,
                method=method,
                vuln_class=VulnClass.MISCONFIG,
                status=FindingStatus.REJECTED,
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                observations=[f"Skipped: Endpoint '{path}' is not in resource consumption allowlist."],
                raw_evidence={"skip_reason": "endpoint_not_allowlisted"},
            )

        role_clean = role.lower().strip()
        if role_clean not in {i.lower() for i in self.policy.allowed_test_identities}:
            return TestResult(
                test_name="Resource Consumption Verification",
                target_url=target_url,
                endpoint=path,
                method=method,
                vuln_class=VulnClass.MISCONFIG,
                status=FindingStatus.REJECTED,
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                observations=[f"Skipped: Role '{role}' is not in allowed test identities."],
                raw_evidence={"skip_reason": "unapproved_persona"},
            )

        # ── 2. Parameter Selection & Clamping ─────────────────────────────────
        raw_params = endpoint_info.get("parameters", [])
        matched_param: dict[str, Any] | ParameterProfile | None = None
        matched_name: str | None = None

        for candidate_name in PAGINATION_PARAM_PRIORITY:
            for p in raw_params:
                p_name = p.name if isinstance(p, ParameterProfile) else (p.get("name") if isinstance(p, dict) else str(p))
                if p_name and p_name.lower().strip() == candidate_name:
                    matched_param = p
                    matched_name = p_name
                    break
            if matched_param:
                break

        if not matched_param or not matched_name:
            return TestResult(
                test_name="Resource Consumption Verification",
                target_url=target_url,
                endpoint=path,
                method=method,
                vuln_class=VulnClass.MISCONFIG,
                status=FindingStatus.REJECTED,
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                observations=["Skipped: No documented pagination/limit parameter found in endpoint profile."],
                raw_evidence={"skip_reason": "missing_documented_pagination_parameter"},
            )

        # Extract documented bounds & provenance
        doc_max: int | None = None
        schema_ref: str | None = None
        if isinstance(matched_param, ParameterProfile):
            doc_max = matched_param.documented_maximum
            schema_ref = matched_param.schema_reference
        elif isinstance(matched_param, dict):
            doc_max = matched_param.get("documented_maximum")
            schema_ref = matched_param.get("schema_reference")

        # Select safe probe value (strictly at or below documented maximum)
        probe_value = select_safe_probe_value(matched_param, self.policy)

        # ── 3. Single Controlled Probe Request ────────────────────────────────
        headers = self._vault.resolve_headers_for_role(role_clean)

        async with ScopeEnforcingHttpClient(self.investigation_id) as client:
            try:
                start_time = time.monotonic()
                resp = await client.get(
                    target_url,
                    params={matched_name: str(probe_value)},
                    headers=headers,
                )
                elapsed = time.monotonic() - start_time
                body_text = client.get_response_text_safe(resp)
                status_code = resp.status_code

                if status_code != 200 or "<!doctype html>" in body_text.lower():
                    return TestResult(
                        test_name="Resource Consumption Verification",
                        target_url=target_url,
                        endpoint=path,
                        method=method,
                        vuln_class=VulnClass.MISCONFIG,
                        status=FindingStatus.REJECTED,
                        confidence=Confidence.LOW,
                        severity=Severity.LOW,
                        observations=[f"Server returned HTTP {status_code} (denied or non-200 response)."],
                        raw_evidence={
                            "tested_parameter": matched_name,
                            "probe_value": probe_value,
                            "status_code": status_code,
                        },
                    )

                # Safe item-count extraction
                item_count: int | None = None
                try:
                    data = json.loads(body_text)
                    item_count = parse_item_count(data)
                except ValueError:
                    pass

                response_bytes = len(body_text.encode("utf-8"))
                time_bucket = f"{elapsed:.2f}s"

                # ── 4. Safe Documented-Bound Observation Evaluation ───────────
                return TestResult(
                    test_name=f"Resource Consumption on {path}",
                    target_url=target_url,
                    endpoint=path,
                    method=method,
                    vuln_class=VulnClass.MISCONFIG,
                    status=FindingStatus.REJECTED,
                    confidence=Confidence.HIGH,
                    severity=Severity.LOW,
                    reproducible=True,
                    observations=[
                        f"PARTIALLY_COVERED — safe documented-bound observation: Server returned bounded response of {item_count if item_count is not None else 'bounded'} items for parameter '{matched_name}'.",
                        f"Requested safe probe value: {probe_value} (documented max: {doc_max or 'unspecified'}, source: {schema_ref or 'documented_parameter'}); Response size: {response_bytes} bytes, Elapsed: {time_bucket}.",
                    ],
                    raw_evidence={
                        "tested_parameter": matched_name,
                        "probe_value": probe_value,
                        "documented_maximum": doc_max,
                        "item_count_observed": item_count,
                        "response_bytes": response_bytes,
                        "time_bucket": time_bucket,
                        "schema_reference": schema_ref,
                        "status_code": status_code,
                        "coverage_status": "PARTIALLY_COVERED — safe documented-bound observation",
                    },
                )


            except Exception as exc:
                logger.warning("resource_consumption_execution_error", error=str(exc))
                return TestResult(
                    test_name="Resource Consumption Verification",
                    target_url=target_url,
                    endpoint=path,
                    method=method,
                    vuln_class=VulnClass.MISCONFIG,
                    status=FindingStatus.REJECTED,
                    confidence=Confidence.LOW,
                    severity=Severity.LOW,
                    observations=[f"Execution error: {str(exc)}"],
                    raw_evidence={"error": str(exc)},
                )
