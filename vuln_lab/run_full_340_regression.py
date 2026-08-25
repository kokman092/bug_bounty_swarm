"""
vuln_lab/run_full_340_regression.py
───────────────────────────────────
Unified 340-Case Multi-Benchmark Regression Suite:
  - Benchmark A (120 cases): Known Controlled Dataset
  - Benchmark B (120 cases): Adversarial Deceptive Traps
  - Benchmark C (100 cases): Generalization & Novel Edge Cases

Evaluates AEV v5 (Context-Aware Evidence Validator) across all 340 live HTTP endpoints.
Outputs full regression metrics and 5-branch Evidence Graph trees.
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

from app.agents.validator import ContextAwareEvidenceValidator, EvidenceGraph
from vuln_lab.benchmark_120 import generate_120_cases
from vuln_lab.benchmark_120_b import generate_benchmark_b_cases
from vuln_lab.benchmark_c_generalization import generate_benchmark_c_cases


async def execute_case_live(client: httpx.AsyncClient, base_url: str, case: Any) -> tuple[int, Any, float]:
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


async def run_full_340_regression(target_url: str = "http://127.0.0.1:5000") -> dict[str, Any]:
    cases_a = generate_120_cases()
    cases_b = generate_benchmark_b_cases()
    cases_c = generate_benchmark_c_cases()

    validator = ContextAwareEvidenceValidator()

    print("\n" + "=" * 90)
    print("EXECUTING UNIFIED 340-CASE REGRESSION SUITE AGAINST", target_url)
    print("=" * 90)
    print(f"Total Datasets: 3 | Total Live Endpoints: {len(cases_a) + len(cases_b) + len(cases_c)}")
    print(f"  - Benchmark A (Known Controlled)       : {len(cases_a)} cases")
    print(f"  - Benchmark B (Adversarial Traps)      : {len(cases_b)} cases")
    print(f"  - Benchmark C (Generalization & Edge)  : {len(cases_c)} cases\n")

    suite_results: dict[str, dict[str, Any]] = {}
    sample_graphs: list[EvidenceGraph] = []

    async with httpx.AsyncClient(timeout=10.0) as client:
        # Reset DB
        try:
            r = await client.post(f"{target_url}/api/test/reset-db")
            print(f"[*] Database reset on server: HTTP {r.status_code} - {r.json()}\n")
        except Exception as e:
            print(f"[!] DB reset notice: {e}\n")

        t_global = time.perf_counter()

        for suite_name, case_list in [
            ("Benchmark A (120 Known)", cases_a),
            ("Benchmark B (120 Adversarial)", cases_b),
            ("Benchmark C (100 Generalization)", cases_c),
        ]:
            print(f"[*] Running {suite_name}...")
            t_suite = time.perf_counter()
            suite_data = []

            for idx, c in enumerate(case_list, 1):
                status_code, body, latency = await execute_case_live(client, target_url, c)
                req_body = getattr(c, "request_body", None)

                verdict, val_block, conf, eg = validator.evaluate_finding(
                    vuln_type=c.vuln_type,
                    method=c.method,
                    endpoint=c.endpoint,
                    http_status=status_code,
                    response_body=body,
                    request_body=req_body,
                )

                if len(sample_graphs) < 4 and verdict in ("CONFIRMED", "FALSE_POSITIVE", "NEEDS_HUMAN_VALIDATION"):
                    sample_graphs.append(eg)

                suite_data.append({
                    "case_id": c.case_id,
                    "expected": c.expected_validation_status,
                    "actual": verdict,
                    "evidence_level": eg.evidence_level.value,
                    "confidence": conf,
                    "http_status": status_code,
                })

            tp = sum(1 for r in suite_data if r["expected"] == "CONFIRMED" and r["actual"] == "CONFIRMED")
            fp = sum(1 for r in suite_data if r["expected"] in ("FALSE_POSITIVE", "NEEDS_HUMAN_VALIDATION") and r["actual"] == "CONFIRMED")
            fn = sum(1 for r in suite_data if r["expected"] == "CONFIRMED" and r["actual"] != "CONFIRMED")
            tn = sum(1 for r in suite_data if r["expected"] == "FALSE_POSITIVE" and r["actual"] == "FALSE_POSITIVE")
            nhv = sum(1 for r in suite_data if r["expected"] == "NEEDS_HUMAN_VALIDATION" and r["actual"] == "NEEDS_HUMAN_VALIDATION")

            prec = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 100.0
            rec = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 100.0
            f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0

            suite_time = round(time.perf_counter() - t_suite, 2)
            print(f"    [OK] Finished in {suite_time}s -> TP:{tp} FP:{fp} FN:{fn} Prec:{prec:.1f}% Rec:{rec:.1f}% F1:{f1:.1f}")

            suite_results[suite_name] = {
                "total": len(case_list),
                "tp": tp, "fp": fp, "fn": fn, "tn": tn, "nhv": nhv,
                "precision": round(prec, 1),
                "recall": round(rec, 1),
                "f1": round(f1, 1),
            }

        total_time = round(time.perf_counter() - t_global, 2)
        print(f"\n[ALL DONE] Dispatched and evaluated 340 live HTTP requests in {total_time}s\n")

    # Global summary table
    print("=" * 90)
    print("340-CASE REGRESSION SUITE RESULTS (v5 Context-Aware Evidence Validator)")
    print("=" * 90)
    print(f"{'Benchmark Dataset':<34} {'Cases':<7} {'TP':<5} {'FP':<5} {'FN':<5} {'Precision':<11} {'Recall':<9} {'F1'}")
    print("-" * 90)

    tot_cases = sum(s["total"] for s in suite_results.values())
    tot_tp = sum(s["tp"] for s in suite_results.values())
    tot_fp = sum(s["fp"] for s in suite_results.values())
    tot_fn = sum(s["fn"] for s in suite_results.values())
    tot_prec = (tot_tp / (tot_tp + tot_fp)) * 100 if (tot_tp + tot_fp) > 0 else 100.0
    tot_rec = (tot_tp / (tot_tp + tot_fn)) * 100 if (tot_tp + tot_fn) > 0 else 100.0
    tot_f1 = (2 * tot_prec * tot_rec / (tot_prec + tot_rec)) if (tot_prec + tot_rec) > 0 else 0.0

    for s_name, s in suite_results.items():
        print(f"{s_name:<34} {s['total']:<7} {s['tp']:<5} {s['fp']:<5} {s['fn']:<5} {s['precision']:>5.1f}%      {s['recall']:>5.1f}%    {s['f1']:>5.1f}")
    print("-" * 90)
    print(f"{'TOTAL (Full 340 Regression)':<34} {tot_cases:<7} {tot_tp:<5} {tot_fp:<5} {tot_fn:<5} {tot_prec:>5.1f}%      {tot_rec:>5.1f}%    {tot_f1:>5.1f}")
    print("=" * 90 + "\n")

    print("SAMPLE 5-BRANCH EXPLAINABLE EVIDENCE GRAPHS:")
    print("-" * 90)
    for eg in sample_graphs:
        print(eg.render_ascii_tree())
        print()
    print("=" * 90 + "\n")

    return {
        "suite_results": suite_results,
        "total_precision": round(tot_prec, 1),
        "total_recall": round(tot_rec, 1),
        "total_f1": round(tot_f1, 1),
    }


if __name__ == "__main__":
    asyncio.run(run_full_340_regression())
