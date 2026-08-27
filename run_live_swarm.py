"""
run_live_swarm.py
─────────────────
Direct CLI runner to execute the live multi-agent swarm against the target lab
and stream all telemetry, reasoning, and findings directly to your terminal.
"""
import asyncio
import json
import os
import sys
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.resolve()))

from app.agents.orchestrator import AgentOrchestrator
from app.core.config import get_settings
from app.events.schemas import EventType
from app.events.service import EventService
from app.findings.schemas import Finding, FindingStatus
from app.findings.service import FindingService
from app.reports.schemas import InvestigationReport
from app.reports.service import ReportService
from app.targets.authorization import AuthorizationService


class InMemoryFindingService(FindingService):
    def __init__(self):
        self._store = {}

    async def save_finding(self, investigation_id: str, finding: Finding) -> Finding:
        if investigation_id not in self._store:
            self._store[investigation_id] = []
        self._store[investigation_id].append(finding)
        return finding

    async def list_findings(self, investigation_id: str, status_filter: FindingStatus | None = None) -> list[Finding]:
        findings = self._store.get(investigation_id, [])
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
    """Event service that prints live colorized telemetry to the console."""

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

        print(f"\n[*] \033[1;34m{agent_label}\033[0m{iter_label} \033[1;33m{event_badge}\033[0m: {input_summary}")

        if payload and event_type in {
            EventType.HYPOTHESIS_PROPOSED,
            EventType.EVIDENCE_COLLECTED,
            EventType.FINDING_VALIDATED,
            EventType.FINDING_REJECTED,
        }:
            preview = json.dumps(payload, indent=2, default=str)
            print("\033[90m" + (preview[:1000] + "..." if len(preview) > 1000 else preview) + "\033[0m")


async def main():
    target_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"
    investigation_id = "inv-live-demo-001"

    print("\033[1;32m" + "=" * 80 + "\033[0m")
    print("\033[1;32m[+] BUGBOUNTY SWARM -- AUTONOMOUS AI AGENT SECURITY ASSESSMENT\033[0m")
    print(f"\033[1;36mTarget URL:\033[0m {target_url}")
    print(f"\033[1;36mInvestigation ID:\033[0m {investigation_id}")
    print("\033[1;32m" + "=" * 80 + "\033[0m")

    # Step 1: Authorize Target through 4-layer guardrail
    print("\n[1/4] [*] Running 4-Layer Scope Guardrail...")
    auth_service = AuthorizationService()
    try:
        norm_url = await auth_service.authorize_investigation_target(target_url, investigation_id)
        print(f"  [OK] Target Authorized: {norm_url.canonical}")
    except Exception as exc:
        print(f"  [ERROR] Target Rejected by Guardrail: {exc}")
        return

    # Step 2: Initialize Event & Finding Services
    event_service = ConsoleTelemetryEmitter()
    finding_service = InMemoryFindingService()
    report_service = InMemoryReportService()

    # Step 3: Run Multi-Agent Orchestration
    print("\n[2/4] [*] Launching Multi-Agent Swarm...")
    orchestrator = AgentOrchestrator(
        investigation_id=investigation_id,
        target_url=norm_url.canonical,
        event_service=event_service,
        finding_service=finding_service,
        report_service=report_service,
    )

    t0 = time.perf_counter()
    report = await orchestrator.run()
    elapsed = time.perf_counter() - t0

    # Step 4: Summary Results
    print("\n" + "=" * 80)
    print("\033[1;32m[3/4] [SUCCESS] INVESTIGATION COMPLETED\033[0m")
    print(f"Time Elapsed: {elapsed:.2f}s")
    print(f"Total Confirmed Findings: {len(report.findings)}")
    print("=" * 80)

    for i, finding in enumerate(report.findings, 1):
        vuln_cls = getattr(finding, "vuln_class", "N/A")
        ep = getattr(finding, "affected_endpoint", getattr(finding, "endpoint", "N/A"))
        sev_val = getattr(finding, "severity", "HIGH")
        conf_val = getattr(finding, "confidence", "HIGH")
        desc = getattr(finding, "description", getattr(finding, "evidence_summary", ""))

        print(f"\n[{i}] {finding.title}")
        print(f"    Vulnerability Type: {vuln_cls}")
        print(f"    Target Endpoint:    {ep}")
        print(f"    Severity:           {str(sev_val).upper()}")
        print(f"    Confidence:         {str(conf_val).upper()}")
        print(f"    Summary:            {str(desc)[:150]}...")



    print("\n[4/4] [OK] Security Assessment Report Ready.")
    print("=" * 80 + "\n")

    try:
        if report and report.markdown_report:
            print("\n\033[1;35m--- Rendered Markdown Report ---\033[0m\n")
            print(report.markdown_report)
    except Exception:
        pass


if __name__ == "__main__":
    asyncio.run(main())
