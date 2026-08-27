"""
BugBounty Swarm — Reliability Lab
==================================
Runs run_live_swarm.py N times against your local vuln lab and measures
how consistently the multi-agent debate loop behaves. This tells you
whether your system is demo-ready BEFORE you record anything.

Usage:
    python swarm_reliability_lab.py http://127.0.0.1:5000 --runs 10
"""
import argparse
import json
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
SWARM_SCRIPT = str(PROJECT_ROOT / "run_live_swarm.py")
OUTPUT_DIR = PROJECT_ROOT / "reliability_lab_results"


import os

def check_target_alive(target_url: str) -> bool:
    """Quick health check to ensure vuln lab is responding."""
    try:
        import urllib.request
        with urllib.request.urlopen(target_url, timeout=3) as resp:
            return resp.status in (200, 301, 302, 404)
    except Exception:
        return False


def run_once(target_url: str, timeout: int = 180) -> dict:
    """Runs one live swarm execution and parses its stdout for signals."""
    start = time.time()
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"

    try:
        result = subprocess.run(
            [sys.executable, SWARM_SCRIPT, target_url],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(PROJECT_ROOT),
            env=env,
            encoding="utf-8",
            errors="replace",
        )
        output = (result.stdout or "") + "\n" + (result.stderr or "")
        crashed = result.returncode != 0
    except subprocess.TimeoutExpired as exc:
        raw_out = exc.stdout or b""
        if isinstance(raw_out, bytes):
            output = raw_out.decode("utf-8", errors="replace")
        else:
            output = str(raw_out)
        crashed = True
    except Exception as exc:
        output = f"Execution Error: {exc}"
        crashed = True

    duration = time.time() - start

    rejected_count = len(re.findall(r"FINDING_REJECTED|Verdict:\s*REJECTED|REJECTED", output, re.IGNORECASE))
    validated_count = len(re.findall(r"FINDING_VALIDATED|Verdict:\s*VALIDATED|Verdict:\s*CONFIRMED|CONFIRMED", output, re.IGNORECASE))
    iteration_matches = re.findall(r"iter(?:ation)?\s*#?(\d+)", output, re.IGNORECASE)
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
    parser.add_argument("target_url", nargs="?", default="http://127.0.0.1:5000")
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()

    OUTPUT_DIR.mkdir(exist_ok=True)
    results = []

    print(f"Checking target {args.target_url}...")
    if not check_target_alive(args.target_url):
        print(f"[!] Target {args.target_url} is not reachable! Make sure vuln lab is running (python -m vuln_lab.app).")
    else:
        print(f"[OK] Target {args.target_url} is UP and responding.\n")

    print(f"Running {args.runs} trials against {args.target_url}...\n")
    for i in range(1, args.runs + 1):
        print(f"[Trial {i:02d}/{args.runs:02d}] running...", end=" ", flush=True)
        r = run_once(args.target_url, args.timeout)
        results.append(r)
        log_file = OUTPUT_DIR / f"trial_{i:02d}.log"
        log_file.write_text(r["raw_output"], encoding="utf-8")
        status = (
            "CRASHED" if r["crashed"] else
            "PIVOT (reject->validate)" if r["had_pivot_sequence"] else
            "EMPTY (no findings)" if r["empty_run"] else
            "STRAIGHT-CONFIRM (no rejection shown)"
        )
        print(f"{status}  ({r['duration_sec']}s, log_size={len(r['raw_output'])}B, {r['max_iteration']} iters, rej={r['rejected_count']}, val={r['validated_count']})")
        # Brief pause between trials to stay safely under RPM limits
        time.sleep(2)

    n = len(results)
    crashed = sum(1 for r in results if r["crashed"])
    pivots = sum(1 for r in results if r["had_pivot_sequence"])
    empty = sum(1 for r in results if r["empty_run"] and not r["crashed"])
    straight = sum(1 for r in results if not r["crashed"] and not r["had_pivot_sequence"] and not r["empty_run"])
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
    }, indent=2), encoding="utf-8")
    print(f"\nFull logs and summary saved to {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
