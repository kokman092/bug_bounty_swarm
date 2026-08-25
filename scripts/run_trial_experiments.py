"""
run_trial_experiments.py
────────────────────────
Runs 5 consecutive live autonomous multi-agent swarm assessments against http://127.0.0.1:5000.
Records reliability, rejection-pivot occurrences, latency, and findings.
"""
import asyncio
import json
import time
from app.agents.orchestrator import AgentOrchestrator
from app.events.schemas import EventType
from app.events.service import EventService
from app.findings.schemas import Finding, FindingStatus
from app.findings.service import FindingService
from app.reports.schemas import InvestigationReport
from app.reports.service import ReportService


class InMemoryFindingService(FindingService):
    def __init__(self):
        self._findings = {}

    async def save_finding(self, investigation_id: str, finding: Finding) -> Finding:
        self._findings.setdefault(investigation_id, []).append(finding)
        return finding

    async def list_findings(self, investigation_id: str, status_filter: FindingStatus | None = None) -> list[Finding]:
        findings = self._findings.get(investigation_id, [])
        if status_filter:
            return [f for f in findings if f.status == status_filter]
        return findings


class InMemoryReportService(ReportService):
    def __init__(self):
        self._reports = {}

    async def save_report(self, report: InvestigationReport) -> InvestigationReport:
        self._reports[report.investigation_id] = report
        return report

    async def get_report(self, investigation_id: str) -> InvestigationReport:
        return self._reports.get(investigation_id)


class ConsoleTelemetryEmitter(EventService):
    async def emit_event(
        self,
        investigation_id: str,
        phase: str,
        event_type: EventType,
        agent_name: str | None = None,
        iteration: int = 0,
        input_summary: str | None = None,
        payload: dict | None = None,
        correlation_id: str | None = None,
    ):
        event_badge = f"[{event_type.value}]"
        agent_label = f"{agent_name or 'System'}"
        iter_label = f" (iter #{iteration})" if iteration > 0 else ""
        print(f"[*] {agent_label}{iter_label} {event_badge}: {input_summary}")


async def run_single_trial(trial_num: int) -> dict:
    inv_id = f"trial-run-{trial_num:02d}"
    print(f"\n{'='*80}\n>>> STARTING TRIAL #{trial_num} (Investigation ID: {inv_id})\n{'='*80}")
    
    event_service = ConsoleTelemetryEmitter()
    finding_service = InMemoryFindingService()
    report_service = InMemoryReportService()
    
    orchestrator = AgentOrchestrator(
        investigation_id=inv_id,
        target_url="http://127.0.0.1:5000/",
        event_service=event_service,
        finding_service=finding_service,
        report_service=report_service,
    )
    
    t0 = time.perf_counter()
    report = await orchestrator.run()
    elapsed = time.perf_counter() - t0
    
    all_findings = await finding_service.list_findings(inv_id)
    rejected = [f for f in all_findings if f.status == FindingStatus.REJECTED]
    validated = [f for f in all_findings if f.status == FindingStatus.VALIDATED]
    
    # Check if a reject-then-pivot cycle occurred
    has_reject_pivot = len(rejected) > 0 and len(validated) > 0
    
    result = {
        "trial_number": trial_num,
        "investigation_id": inv_id,
        "elapsed_seconds": round(elapsed, 2),
        "total_proposals": len(all_findings),
        "rejected_count": len(rejected),
        "validated_count": len(validated),
        "has_reject_pivot_cycle": has_reject_pivot,
        "validated_endpoints": [f.endpoint for f in validated],
        "rejected_endpoints": [f.endpoint for f in rejected],
        "report_finding_count": report.finding_count if report else 0,
    }
    
    print(f"\n[Trial #{trial_num} Summary] Elapsed: {elapsed:.2f}s | Rejected: {len(rejected)} | Validated: {len(validated)} | Reject->Pivot: {has_reject_pivot}")
    return result

async def main():
    trials_count = 5
    results = []
    
    print(f"Executing {trials_count} Live Swarm Trials against http://127.0.0.1:5000/...")
    
    for i in range(1, trials_count + 1):
        try:
            res = await run_single_trial(i)
            results.append(res)
        except Exception as exc:
            print(f"[Trial #{i} FAILED WITH ERROR]: {exc}")
            results.append({"trial_number": i, "error": str(exc), "has_reject_pivot_cycle": False})
        
        # Brief pause between trials
        await asyncio.sleep(2)
        
    print("\n" + "=" * 80)
    print("ALL 5 TRIALS COMPLETED — STATISTICAL SUMMARY")
    print("=" * 80)
    print(json.dumps(results, indent=2))
    
    successful_trials = [r for r in results if "error" not in r]
    pivot_rate = sum(1 for r in successful_trials if r["has_reject_pivot_cycle"]) / len(successful_trials) if successful_trials else 0
    avg_latency = sum(r["elapsed_seconds"] for r in successful_trials) / len(successful_trials) if successful_trials else 0
    
    print(f"\nTotal Completed Trials: {len(successful_trials)} / {trials_count}")
    print(f"Reject->Pivot Cycle Occurrence Rate: {pivot_rate * 100:.1f}%")
    print(f"Average Investigation Latency: {avg_latency:.2f}s")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(main())
