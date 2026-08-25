"""
vuln_lab/benchmark_d_extreme.py
───────────────────────────────
Benchmark D: Extreme Generalization Dataset (100 Test Cases).

Novel Enterprise Schemas:
  - 30 Category A: Vulnerable (Kubernetes Kubeconfig BOLA, Healthcare Rx IDOR, Forwarding Webhook SSRF, Permission Slug PrivEsc)
  - 30 Category B: Hardened Enterprise Counterparts (Creator Ref Check, Egress Proxy Filters)
  - 20 Category C: Ambiguous Telemetry (Rate Limits, Diagnostic Notices)
  - 20 Category D: Novel Edge Cases (HTTP 202, 206, 422, 429)

Tests v6 Semantic Evidence Engine without hardcoded rules.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any


@dataclass
class BenchmarkCaseD:
    case_id: str
    category: str
    title: str
    endpoint: str
    method: str
    vuln_type: str
    scope_in: bool = True
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: dict[str, Any] | None = None
    expected_validation_status: str = "CONFIRMED"
    rationale: str = ""


def generate_benchmark_d_cases() -> list[BenchmarkCaseD]:
    cases: list[BenchmarkCaseD] = []

    # 1. CATEGORY A: 30 Vulnerable
    count_a = 0
    # 10 Kubeconfig BOLA
    for i in range(1, 11):
        count_a += 1
        cases.append(BenchmarkCaseD(
            case_id=f"D-A-{count_a:02d}",
            category="A_VULNERABLE",
            title=f"Kubernetes Cluster #{i} Kubeconfig Secret Leak",
            endpoint=f"/api/v5/clusters/{i}/kubeconfig",
            method="GET",
            vuln_type="BOLA",
            request_headers={"Authorization": "Bearer bob_token_456"},
            expected_validation_status="CONFIRMED",
            rationale="Discloses cluster JWT token and server IP belonging to Tenant Alice",
        ))

    # 10 Healthcare Rx IDOR
    for i in range(1, 11):
        count_a += 1
        cases.append(BenchmarkCaseD(
            case_id=f"D-A-{count_a:02d}",
            category="A_VULNERABLE",
            title=f"Prescription Medication Record #{i} Leak",
            endpoint=f"/api/v5/prescriptions/{i}",
            method="GET",
            vuln_type="IDOR",
            request_headers={"Authorization": "Bearer bob_token_456"},
            expected_validation_status="CONFIRMED",
            rationale="Discloses controlled medication record belonging to Patient Alice",
        ))

    # 5 Forwarding Webhook SSRF
    ssrf_targets = [
        ("http://127.0.0.1:5000/api/debug/config", "Loopback Config"),
        ("http://169.254.169.254/latest/meta-data/", "Cloud Metadata"),
        ("http://10.0.0.1/admin", "Internal Gateway"),
        ("http://127.0.0.1:8000/metrics", "Prometheus Metrics"),
        ("http://localhost:5000/api/admin/users", "Admin Directory"),
    ]
    for url, desc in ssrf_targets:
        count_a += 1
        cases.append(BenchmarkCaseD(
            case_id=f"D-A-{count_a:02d}",
            category="A_VULNERABLE",
            title=f"Enterprise Webhook Forward SSRF to {desc}",
            endpoint="/api/v5/webhooks/forward",
            method="POST",
            vuln_type="SSRF",
            request_headers={"Authorization": "Bearer bob_token_456", "Content-Type": "application/json"},
            request_body={"target_uri": url},
            expected_validation_status="CONFIRMED",
            rationale=f"Server forwards request to {url} without egress verification",
        ))

    # 5 Permission Slug Mass Assignment
    slugs = ["super_admin", "cluster_owner", "root", "security_officer", "compliance_lead"]
    for s in slugs:
        count_a += 1
        cases.append(BenchmarkCaseD(
            case_id=f"D-A-{count_a:02d}",
            category="A_VULNERABLE",
            title=f"Permission Slug Escalation to '{s}'",
            endpoint="/api/v5/permissions/toggle",
            method="POST",
            vuln_type="MassAssignment",
            request_headers={"Authorization": "Bearer bob_token_456", "Content-Type": "application/json"},
            request_body={"permission_slug": s},
            expected_validation_status="CONFIRMED",
            rationale=f"Permission slug '{s}' accepted without authorization",
        ))

    # 2. CATEGORY B: 30 Secure
    count_b = 0
    # 15 Secure Clusters
    for i in range(1, 16):
        count_b += 1
        cases.append(BenchmarkCaseD(
            case_id=f"D-B-{count_b:02d}",
            category="B_SECURE",
            title=f"Secure Cluster Access Control #{i}",
            endpoint=f"/api/v5/secure/clusters/{i}/kubeconfig",
            method="GET",
            vuln_type="BOLA",
            request_headers={"Authorization": "Bearer bob_token_456"},
            expected_validation_status="FALSE_POSITIVE",
            rationale="Creator verification middleware denies access with HTTP 403",
        ))

    # 15 Secure Webhooks
    for i in range(1, 16):
        count_b += 1
        cases.append(BenchmarkCaseD(
            case_id=f"D-B-{count_b:02d}",
            category="B_SECURE",
            title=f"Secure Forwarding Policy #{i}",
            endpoint="/api/v5/secure/webhooks/forward",
            method="POST",
            vuln_type="SSRF",
            request_headers={"Authorization": "Bearer bob_token_456", "Content-Type": "application/json"},
            request_body={"target_uri": f"http://127.0.0.{i}/secret"},
            expected_validation_status="FALSE_POSITIVE",
            rationale="Egress policy blocks private IP with HTTP 400",
        ))

    # 3. CATEGORY C: 20 Ambiguous
    for i in range(1, 11):
        cases.append(BenchmarkCaseD(
            case_id=f"D-C-{i:02d}",
            category="C_AMBIGUOUS",
            title=f"Cluster Latency Diagnostic #{i}",
            endpoint="/api/ambiguous/debug/timing",
            method="GET",
            vuln_type="InfoDisclosure",
            request_headers={"Authorization": "Bearer bob_token_456"},
            expected_validation_status="NEEDS_HUMAN_VALIDATION",
            rationale="Exposes timing header without data leak",
        ))

    for i in range(1, 11):
        cases.append(BenchmarkCaseD(
            case_id=f"D-C-{i+10:02d}",
            category="C_AMBIGUOUS",
            title=f"Reflected Notification Feedback #{i}",
            endpoint=f"/api/ambiguous/feedback?msg=cluster_test_{i}",
            method="GET",
            vuln_type="XSS",
            request_headers={"Authorization": "Bearer bob_token_456"},
            expected_validation_status="NEEDS_HUMAN_VALIDATION",
            rationale="Entity-encoded reflection",
        ))

    # 4. CATEGORY D: 20 Novel Edge Cases
    for i in range(1, 6):
        cases.append(BenchmarkCaseD(
            case_id=f"D-D-{i:02d}",
            category="D_EDGE_CASE",
            title=f"Async Cluster Deploy #{i} (HTTP 202)",
            endpoint=f"/api/v4/edge/async-job/{i}",
            method="GET",
            vuln_type="InfoDisclosure",
            request_headers={"Authorization": "Bearer bob_token_456"},
            expected_validation_status="NEEDS_HUMAN_VALIDATION",
            rationale="HTTP 202 job metadata",
        ))

    for i in range(1, 6):
        cases.append(BenchmarkCaseD(
            case_id=f"D-D-{i+5:02d}",
            category="D_EDGE_CASE",
            title=f"Partial Prescription Snippet #{i} (HTTP 206)",
            endpoint=f"/api/v4/edge/partial-stream/{i}",
            method="GET",
            vuln_type="BOLA",
            request_headers={"Authorization": "Bearer bob_token_456"},
            expected_validation_status="NEEDS_HUMAN_VALIDATION",
            rationale="HTTP 206 public demo sample",
        ))

    for i in range(1, 6):
        cases.append(BenchmarkCaseD(
            case_id=f"D-D-{i+10:02d}",
            category="D_EDGE_CASE",
            title=f"Invalid Cluster YAML Payload #{i} (HTTP 422)",
            endpoint="/api/v4/edge/schema-validate",
            method="POST",
            vuln_type="MassAssignment",
            request_headers={"Authorization": "Bearer bob_token_456", "Content-Type": "application/json"},
            request_body={"invalid_yaml": "---"},
            expected_validation_status="FALSE_POSITIVE",
            rationale="Schema validator cleanly rejected invalid body with HTTP 422",
        ))

    for i in range(1, 6):
        cases.append(BenchmarkCaseD(
            case_id=f"D-D-{i+15:02d}",
            category="D_EDGE_CASE",
            title=f"Cluster API Throttling #{i} (HTTP 429)",
            endpoint="/api/v4/edge/rate-limit-test",
            method="GET",
            vuln_type="RateLimit",
            request_headers={"Authorization": "Bearer bob_token_456"},
            expected_validation_status="NEEDS_HUMAN_VALIDATION",
            rationale="Rate limit active",
        ))

    return cases
