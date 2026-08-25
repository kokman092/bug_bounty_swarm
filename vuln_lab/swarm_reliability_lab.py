"""
BugBounty Swarm — Reliability Lab
==================================
Runs run_live_swarm.py N times against your local vuln lab and measures
how consistently the multi-agent debate loop behaves. This tells you
whether your system is demo-ready BEFORE you record anything.

Usage:
    python swarm_reliability_lab.py http://127.0.0.1:5000 --runs 10

Requires: run_live_swarm.py in the same directory (or adjust SWARM_SCRIPT
below), and your vuln lab already running on the target URL.
"""

import subprocess
import re
import time
import json
import argparse
import statistics
from pathlib import Path

SWARM_SCRIPT = "run_live_swarm.py"
OUTPUT_DIR = Path("reliability_lab_results")


def run_once(target_url: str, timeout: int = 60) -> dict:
    """Runs one live swarm execution and parses its stdout for signals."""
    start = time.time()
    try:
        result = subprocess.run(
            ["python", SWARM_SCRIPT, target_url],
            capture_output=True, text=True, timeout=timeout
        )
        output = result.stdout + result.stderr
        crashed = result.returncode != 0
    except subprocess.TimeoutExpired:
        output = ""
        crashed = True
    duration = time.time() - start

    rejected_count = len(re.findall(r"Verdict:\s*REJECTED", output, re.IGNORECASE))
    validated_count = len(re.findall(r"Verdict:\s*VALIDATED|CONFIRMED", output, re.IGNORECASE))
    iteration_matches = re.findall(r"Iteration\s+(\d+)", output)
    max_iteration = max((int(i) for i in iteration_matches), default=0)

    had_pivot_sequence = rejected_count >= 1 and validated_count >= 1
    empty_run = validated_count == 0

    return {
        "duration_sec": round(duration, 2),
        "crashed": crashed,
        "rejected_count": rejected_count,
        "validated_count": validated_count,
        "max_iteration": max_iteration,
        "had_pivot_sequence": had_pivot_sequence,
        "empty_run": empty_run,
        "raw_output": output,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target_url")
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()

    OUTPUT_DIR.mkdir(exist_ok=True)
    results = []

    print(f"Running {args.runs} trials against {args.target_url}...\n")
    for i in range(1, args.runs + 1):
        print(f"[Trial {i}/{args.runs}] running...", end=" ", flush=True)
        r = run_once(args.target_url, args.timeout)
        results.append(r)
        (OUTPUT_DIR / f"trial_{i}.log").write_text(r["raw_output"])
        status = (
            "CRASHED" if r["crashed"] else
            "PIVOT (reject->validate)" if r["had_pivot_sequence"] else
            "EMPTY (no findings)" if r["empty_run"] else
            "STRAIGHT-CONFIRM (no rejection shown)"
        )
        print(f"{status}  ({r['duration_sec']}s, {r['max_iteration']} iterations)")

    n = len(results)
    crashed = sum(r["crashed"] for r in results)
    pivots = sum(r["had_pivot_sequence"] for r in results)
    empty = sum(r["empty_run"] for r in results)
    straight = n - crashed - pivots - empty
    durations = [r["duration_sec"] for r in results if not r["crashed"]]

    print("\n" + "=" * 60)
    print("RELIABILITY SUMMARY")
    print("=" * 60)
    print(f"Total trials:                 {n}")
    print(f"Crashed / timed out:          {crashed}  ({crashed/n*100:.0f}%)")
    print(f"Reject -> pivot -> validate:  {pivots}  ({pivots/n*100:.0f}%)  <- YOUR DEMO MOMENT")
    print(f"Empty (no findings at all):   {empty}  ({empty/n*100:.0f}%)")
    print(f"Straight confirm (no reject): {straight}  ({straight/n*100:.0f}%)")
    if durations:
        print(f"\nAvg duration:  {statistics.mean(durations):.2f}s")
        print(f"Max duration:  {max(durations):.2f}s")
        print(f"Min duration:  {min(durations):.2f}s")

    verdict = (
        "DEMO-READY: pivot sequence appears reliably." if pivots / n >= 0.5 else
        "RISKY: pivot sequence is inconsistent, use the best recorded take or tune temperature/lab ordering." if pivots > 0 else
        "NOT DEMO-READY: no run showed a reject->pivot sequence. Revisit hunter.py hypothesis ordering or lab endpoint discoverability."
    )
    print(f"\nVERDICT: {verdict}")

    summary_path = OUTPUT_DIR / "summary.json"
    summary_path.write_text(json.dumps({
        "total": n, "crashed": crashed, "pivots": pivots,
        "empty": empty, "straight": straight,
        "avg_duration": statistics.mean(durations) if durations else None,
        "verdict": verdict,
    }, indent=2))
    print(f"\nFull logs and summary saved to {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()