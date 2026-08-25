"""
vuln_lab/run_full_440_suite.py
──────────────────────────────
Master 440-Case Evaluation Suite with Automated Error Analysis.

Datasets Evaluated:
  - Benchmark A (120 Known Cases)
  - Benchmark B (120 Adversarial Cases)
  - Benchmark C (100 Generalization Cases)
  - Benchmark D (100 Extreme Enterprise Cases)
  = 440 Total Live HTTP Endpoints

Engine: Semantic Evidence Engine (AEV v6)
Features:
  - Explicit Confusion Matrix (TP, FP, FN, TN, NHV)
  - Automated Error Classification & Failure Diagnostics
  - 5-Branch Explainable Evidence Graph Generation
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx

from app.agents.validator import SemanticEvidenceEngine, EvidenceGraph
from vuln_lab.benchmark_120 import generate_120_cases
from vuln_lab.benchmark_120_b import generate_benchmark_b_cases
from vuln_lab.benchmark_c_generalization import generate_benchmark_c_cases
from vuln_lab.benchmark_d_extreme import generate_benchmark_d_cases
from vuln_lab.analysis.error_classifier import ErrorClassifier, FailureDiagnostic
from vuln_lab.analysis.regression_diff import ConfusionMatrix, RegressionDiffTracker
from vuln_lab.analysis.failure_report import FailureReportGenerator


async def execute_live_http(client: httpx.AsyncClient, base_url: str, case: Any) -> tuple[int, Any, float]:
    url = f"{base_url}{case.endpoint}"
    t0 = time.perf_counter()
    try:
        if case.method == "POST":
            resp = await client.post(url, headers=case.request_headers, json=case.request_body)
        elif case.method == "PUT":
            resp = await client.put(url, headers=case.request_headers, json=case.request_body)
        elif case.method == "PATCH":
            resp = await client.patch(url, headers=case.request_headers, json=case.request_body)
        else:
            resp = await client.get(url, headers=case.request_headers)

        status_code = resp.status_code
        try:
            body = resp.json()
        except Exception:
            body = resp.text
    except Exception as exc:
        status_code = 500
        body = {"error": str(exc)}

    latency = round((time.perf_counter() - t0) * 1000, 1)
    return status_code, body, latency


async def run_master_440_suite(target_url: str = "http://127.0.0.1:5000"):
    cases_a = generate_120_cases()
    cases_b = generate_benchmark_b_cases()
    cases_c = generate_benchmark_c_cases()
    cases_d = generate_benchmark_d_cases()

    engine = SemanticEvidenceEngine()
    error_classifier = ErrorClassifier()
    diff_tracker = RegressionDiffTracker()
    report_gen = FailureReportGenerator()

    all_suites = [
        ("Benchmark A (120 Known)", cases_a),
        ("Benchmark B (120 Adversarial)", cases_b),
        ("Benchmark C (100 Generalization)", cases_c),
        ("Benchmark D (100 Extreme Enterprise)", cases_d),
    ]

    total_endpoints = sum(len(c) for _, c in all_suites)
    print("\n" + "=" * 95)
    print("MASTER 440-CASE EVALUATION SUITE (v6 Semantic Evidence Engine)")
    print("=" * 95)
    print(f"Target: {target_url} | Total Live Requests: {total_endpoints}\n")

    suite_matrices: dict[str, ConfusionMatrix] = {}
    all_diagnostics: list[FailureDiagnostic] = []
    sample_graphs: list[EvidenceGraph] = []

    async with httpx.AsyncClient(timeout=10.0) as client:
        # Reset DB on server
        try:
            r = await client.post(f"{target_url}/api/test/reset-db")
            print(f"[*] Server Database Reset: HTTP {r.status_code} - {r.json()}\n")
        except Exception as e:
            print(f"[!] Server Reset Notice: {e}\n")

        t_global = time.perf_counter()

        for suite_name, cases in all_suites:
            print(f"[*] Executing {suite_name} ({len(cases)} requests)...")
            t_suite = time.perf_counter()
            tp, fp, fn, tn, nhv = 0, 0, 0, 0, 0

            for idx, c in enumerate(cases, 1):
                status_code, body, lat = await execute_live_http(client, target_url, c)
                req_body = getattr(c, "request_body", None)

                verdict, val_block, conf, eg = engine.evaluate_finding(
                    vuln_type=c.vuln_type,
                    method=c.method,
                    endpoint=c.endpoint,
                    http_status=status_code,
                    response_body=body,
                    request_body=req_body,
                )

                if len(sample_graphs) < 4 and verdict in ("CONFIRMED", "FALSE_POSITIVE"):
                    sample_graphs.append(eg)

                expected = c.expected_validation_status

                # Confusion matrix classification
                if expected == "CONFIRMED":
                    if verdict == "CONFIRMED":
                        tp += 1
                    else:
                        fn += 1
                        diag = error_classifier.diagnose_failure(c.case_id, c.vuln_type, c.endpoint, expected, verdict, eg.evidence_level.value, eg, status_code, body, req_body)
                        all_diagnostics.append(diag)
                elif expected == "FALSE_POSITIVE":
                    if verdict == "CONFIRMED":
                        fp += 1
                        diag = error_classifier.diagnose_failure(c.case_id, c.vuln_type, c.endpoint, expected, verdict, eg.evidence_level.value, eg, status_code, body, req_body)
                        all_diagnostics.append(diag)
                    else:
                        tn += 1
                elif expected == "NEEDS_HUMAN_VALIDATION":
                    if verdict == "CONFIRMED":
                        fp += 1
                        diag = error_classifier.diagnose_failure(c.case_id, c.vuln_type, c.endpoint, expected, verdict, eg.evidence_level.value, eg, status_code, body, req_body)
                        all_diagnostics.append(diag)
                    else:
                        nhv += 1

            cm = ConfusionMatrix(tp, fp, fn, tn, nhv)
            suite_matrices[suite_name] = cm
            suite_sec = round(time.perf_counter() - t_suite, 2)
            print(f"    [OK] Finished in {suite_sec}s -> TP:{tp} FP:{fp} FN:{fn} Prec:{cm.precision:.1f}% Rec:{cm.recall:.1f}% F1:{cm.f1_score:.1f}")

        total_sec = round(time.perf_counter() - t_global, 2)
        print(f"\n[ALL COMPLETE] Dispatched 440 live network requests in {total_sec}s\n")

    # Global Matrix
    tot_tp = sum(m.tp for m in suite_matrices.values())
    tot_fp = sum(m.fp for m in suite_matrices.values())
    tot_fn = sum(m.fn for m in suite_matrices.values())
    tot_tn = sum(m.tn for m in suite_matrices.values())
    tot_nhv = sum(m.nhv for m in suite_matrices.values())
    master_cm = ConfusionMatrix(tot_tp, tot_fp, tot_fn, tot_tn, tot_nhv)

    print("=" * 95)
    print("MASTER 440-CASE RESULTS TABLE (v6 Semantic Evidence Engine)")
    print("=" * 95)
    print(f"{'Benchmark Dataset':<36} {'Cases':<7} {'TP':<5} {'FP':<5} {'FN':<5} {'TN':<5} {'Precision':<11} {'Recall':<9} {'F1'}")
    print("-" * 95)
    for s_name, m in suite_matrices.items():
        print(f"{s_name:<36} {m.total:<7} {m.tp:<5} {m.fp:<5} {m.fn:<5} {m.tn:<5} {m.precision:>5.1f}%      {m.recall:>5.1f}%    {m.f1_score:>5.1f}")
    print("-" * 95)
    print(f"{'TOTAL MASTER CORPUS (440 LIVE)':<36} {master_cm.total:<7} {master_cm.tp:<5} {master_cm.fp:<5} {master_cm.fn:<5} {master_cm.tn:<5} {master_cm.precision:>5.1f}%      {master_cm.recall:>5.1f}%    {master_cm.f1_score:>5.1f}")
    print("=" * 95 + "\n")

    # Display Confusion Matrix
    print(diff_tracker.format_confusion_matrix_table("Master 440-Case Benchmark Corpus", master_cm))

    # Display Sample 5-Branch Evidence Graphs
    print("5-BRANCH EXPLAINABLE EVIDENCE GRAPH EXAMPLES:")
    print("-" * 95)
    for eg in sample_graphs:
        print(eg.render_ascii_tree())
        print()
    print("=" * 95 + "\n")

    # Display Automated Error Diagnostics if any
    if all_diagnostics:
        print(report_gen.generate_report(all_diagnostics[:5]))

    return {
        "suite_matrices": suite_matrices,
        "master_matrix": master_cm,
        "diagnostics": all_diagnostics,
    }


if __name__ == "__main__":
    asyncio.run(run_master_440_suite())
