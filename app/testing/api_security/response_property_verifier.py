"""
app/testing/api_security/response_property_verifier.py
───────────────────────────────────────────────────────
Safe, Read-Only Response Property-Level Authorization (API3:2023) Verifier.

Safety & Privacy Guarantees:
  1. Compares observed response field paths against trusted contracts/OpenAPI schemas.
  2. No field-name heuristics or guessing: Signal only when a field is explicitly
     marked protected or explicitly excluded from role allowlists.
  3. Read-only GET/HEAD requests only: Zero mutations.
  4. Privacy preservation: Zero raw values, passwords, hashes, tokens, or PII are stored,
     logged, or persisted in TestResult metadata. Only field paths and type metadata are retained.
  5. JSON response parsing strictly bounded by size limits.
"""
from __future__ import annotations

import json
from typing import Any

from app.core.logging import get_logger
from app.findings.schemas import Confidence, FindingStatus, Severity, VulnClass
from app.targets.session_vault import get_session_vault
from app.testing.api_security.response_property_policy import (
    ResponseFieldContract,
    ResponsePropertyPolicy,
)
from app.testing.base_tester import TestResult
from app.tools.http_client import ScopeEnforcingHttpClient

logger = get_logger(__name__)


def extract_field_paths(data: Any, prefix: str = "") -> set[str]:
    """
    Recursively extracts all field paths from structured JSON objects and arrays.
    Example: {'user': {'name': 'A', 'roles': [{'id': 1}]}} ->
             {'user', 'user.name', 'user.roles', 'user.roles[].id'}
    """
    paths: set[str] = set()
    if isinstance(data, dict):
        for key, value in data.items():
            current = f"{prefix}.{key}" if prefix else str(key)
            paths.add(current)
            paths.update(extract_field_paths(value, current))
    elif isinstance(data, list):
        for item in data:
            current = f"{prefix}[]" if prefix else "[]"
            paths.add(current)
            paths.update(extract_field_paths(item, current))
    return paths


class ResponsePropertyVerifier:
    """Verifies that API response properties adhere to explicit role-based field contracts."""

    def __init__(
        self,
        investigation_id: str,
        target_base_url: str,
        policy: ResponsePropertyPolicy | None = None,
    ) -> None:
        self.investigation_id = investigation_id
        self.target_base_url = target_base_url.rstrip("/")
        self.policy = policy or ResponsePropertyPolicy()
        self._vault = get_session_vault(investigation_id)

    async def verify_endpoint(
        self,
        endpoint_info: dict[str, Any],
        role: str = "owner",
    ) -> TestResult:
        path = str(endpoint_info.get("path", "/"))
        method = str(endpoint_info.get("method", "GET")).upper()
        target_url = f"{self.target_base_url}{path}"

        # ── 1. Eligibility Checks ─────────────────────────────────────────────
        if not self.policy.enabled:
            return TestResult(
                test_name="Response Property Authorization Verification",
                target_url=target_url,
                endpoint=path,
                method=method,
                vuln_class=VulnClass.MASS_ASSIGNMENT,
                status=FindingStatus.REJECTED,
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                observations=["Skipped: Response property testing is disabled by policy."],
                raw_evidence={"skip_reason": "policy_disabled"},
            )

        if method not in self.policy.read_only_methods:
            return TestResult(
                test_name="Response Property Authorization Verification",
                target_url=target_url,
                endpoint=path,
                method=method,
                vuln_class=VulnClass.MASS_ASSIGNMENT,
                status=FindingStatus.REJECTED,
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                observations=[f"Skipped: Method '{method}' is not a read-only method in policy."],
                raw_evidence={"skip_reason": "non_read_only_method"},
            )

        if not self.policy.is_endpoint_allowed(path):
            return TestResult(
                test_name="Response Property Authorization Verification",
                target_url=target_url,
                endpoint=path,
                method=method,
                vuln_class=VulnClass.MASS_ASSIGNMENT,
                status=FindingStatus.REJECTED,
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                observations=[f"Skipped: Endpoint '{path}' is not in response property allowlist."],
                raw_evidence={"skip_reason": "endpoint_not_allowlisted"},
            )

        contract = self.policy.get_contract_for_endpoint(method, path)
        if contract is None:
            return TestResult(
                test_name="Response Property Authorization Verification",
                target_url=target_url,
                endpoint=path,
                method=method,
                vuln_class=VulnClass.MASS_ASSIGNMENT,
                status=FindingStatus.REJECTED,
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                observations=["Skipped: No explicit response field contract found for endpoint."],
                raw_evidence={"skip_reason": "missing_response_contract"},
            )

        role_clean = role.lower().strip()
        if role_clean not in {i.lower() for i in self.policy.allowed_test_identities}:
            return TestResult(
                test_name="Response Property Authorization Verification",
                target_url=target_url,
                endpoint=path,
                method=method,
                vuln_class=VulnClass.MASS_ASSIGNMENT,
                status=FindingStatus.REJECTED,
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                observations=[f"Skipped: Role '{role}' is not in allowed test identities."],
                raw_evidence={"skip_reason": "unapproved_persona"},
            )

        # ── 2. Authorized Baseline Request & Safe Extraction ──────────────────
        headers = self._vault.resolve_headers_for_role(role_clean)

        async with ScopeEnforcingHttpClient(self.investigation_id) as client:
            try:
                resp = await client.get(target_url, headers=headers)
                body_text = client.get_response_text_safe(resp)

                if resp.status_code != 200 or "<!doctype html>" in body_text.lower():
                    return TestResult(
                        test_name="Response Property Authorization Verification",
                        target_url=target_url,
                        endpoint=path,
                        method=method,
                        vuln_class=VulnClass.MASS_ASSIGNMENT,
                        status=FindingStatus.REJECTED,
                        confidence=Confidence.LOW,
                        severity=Severity.LOW,
                        observations=[f"Skipped: Endpoint returned HTTP {resp.status_code} (non-200 or HTML fallback)."],
                        raw_evidence={"skip_reason": "non_200_or_html_response", "status_code": resp.status_code},
                    )

                try:
                    data = json.loads(body_text)
                except ValueError:
                    return TestResult(
                        test_name="Response Property Authorization Verification",
                        target_url=target_url,
                        endpoint=path,
                        method=method,
                        vuln_class=VulnClass.MASS_ASSIGNMENT,
                        status=FindingStatus.REJECTED,
                        confidence=Confidence.LOW,
                        severity=Severity.LOW,
                        observations=["Skipped: Response body is not valid JSON."],
                        raw_evidence={"skip_reason": "invalid_json_payload"},
                    )

                observed_fields = extract_field_paths(data)

                # ── 3. Contract Evaluation ────────────────────────────────────
                # 3a. Explicit Protected Fields Violation (Always a signal if present)
                leaked_protected: set[str] = set()
                for f in observed_fields:
                    base_name = f.split(".")[-1].replace("[]", "")
                    if f in contract.protected_fields or base_name in contract.protected_fields:
                        leaked_protected.add(f)

                # 3b. Role Allowlist & Forbidden Fields Violation
                allowed_for_role = contract.allowed_fields_by_role.get(role_clean)
                forbidden_role_fields: set[str] = set()
                schema_drift_fields: set[str] = set()

                if allowed_for_role is not None:
                    for f in observed_fields:
                        base_name = f.split(".")[-1].replace("[]", "")
                        if f not in allowed_for_role and base_name not in allowed_for_role:
                            # Check if explicitly allocated to another role (forbidden for this role)
                            other_roles_fields: set[str] = set()
                            for r, r_fields in contract.allowed_fields_by_role.items():
                                if r != role_clean:
                                    other_roles_fields.update(r_fields)

                            if f in other_roles_fields or base_name in other_roles_fields:
                                forbidden_role_fields.add(f)
                            elif contract.role_allowlists_complete:
                                # When allowlists are complete, any omitted unpermitted field is a violation
                                forbidden_role_fields.add(f)
                            else:
                                # Incomplete contract: unlisted field is informational schema-drift, not a security signal
                                schema_drift_fields.add(f)

                violating_fields = leaked_protected | forbidden_role_fields


                # Candidate Signal: Violations detected
                if violating_fields:
                    return TestResult(
                        test_name=f"Broken Property-Level Authorization / Excessive Data Exposure on {path}",
                        target_url=target_url,
                        endpoint=path,
                        method=method,
                        vuln_class=VulnClass.MASS_ASSIGNMENT,
                        status=FindingStatus.VALIDATED,
                        confidence=Confidence.HIGH,
                        severity=Severity.HIGH if leaked_protected else Severity.MEDIUM,
                        reproducible=True,
                        evidence_score=9,
                        observations=[
                            f"Response property authorization violation on {path} for role '{role_clean}'.",
                            f"Disclosed protected/forbidden fields: {', '.join(sorted(violating_fields))}",
                            f"Contract Provenance: {contract.source} (Schema: {contract.schema_reference or 'N/A'})",
                        ],
                        raw_evidence={
                            "tested_role": role_clean,
                            "violating_fields": sorted(list(violating_fields)),
                            "contract_source": contract.source,
                            "schema_reference": contract.schema_reference,
                            "status_code": 200,
                            "field_count_observed": len(observed_fields),
                        },
                        remediation="Apply response property filtering or Data Transfer Objects (DTOs) ensuring protected fields and unpermitted role attributes are never serialized in API responses.",
                    )

                # Secure / Negative Result: Complies with explicit contract
                return TestResult(
                    test_name=f"Response Property Authorization on {path}",
                    target_url=target_url,
                    endpoint=path,
                    method=method,
                    vuln_class=VulnClass.MASS_ASSIGNMENT,
                    status=FindingStatus.REJECTED,
                    confidence=Confidence.HIGH,
                    severity=Severity.LOW,
                    reproducible=True,
                    observations=[
                        f"Response property validation passed: Observed fields comply with explicit contract for role '{role_clean}'.",
                        f"Contract Provenance: {contract.source}",
                    ],
                    raw_evidence={
                        "tested_role": role_clean,
                        "contract_source": contract.source,
                        "field_count_observed": len(observed_fields),
                    },
                )

            except Exception as exc:
                logger.warning("response_property_execution_error", error=str(exc))
                return TestResult(
                    test_name="Response Property Authorization Verification",
                    target_url=target_url,
                    endpoint=path,
                    method=method,
                    vuln_class=VulnClass.MASS_ASSIGNMENT,
                    status=FindingStatus.REJECTED,
                    confidence=Confidence.LOW,
                    severity=Severity.LOW,
                    observations=[f"Execution error: {str(exc)}"],
                    raw_evidence={"error": str(exc)},
                )
