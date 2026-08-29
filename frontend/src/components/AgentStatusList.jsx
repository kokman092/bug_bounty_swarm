import React from "react";
import {
  CheckCircle2, CircleDashed, Clock, AlertTriangle,
  ShieldCheck, Crosshair, Map, ScanSearch, BookOpen, FileText,
  Bot, Sparkles, Cpu, Activity, ShieldAlert
} from "lucide-react";

const ENTERPRISE_AGENTS = [
  {
    id: "agent-recon-01",
    phaseKey: "RECON",
    name: "ReconAgent",
    role: "Passive & Active Reconnaissance",
    model: "gemini-3.5-flash",
    Icon: ScanSearch,
    desc: "Discovers endpoints, sitemaps, robots.txt & OpenAPI specs",
    color: "cyan",
  },
  {
    id: "agent-surface-02",
    phaseKey: "ATTACK_SURFACE",
    name: "AttackSurfaceAgent",
    role: "Parameter & Boundary Normalizer",
    model: "gemini-3.5-flash",
    Icon: Map,
    desc: "Maps {{order_id}} templates to concrete testable endpoints",
    color: "blue",
  },
  {
    id: "agent-hunter-03",
    phaseKey: "LOOP",
    name: "HunterAgent",
    role: "Adversarial Hypothesis Prober",
    model: "gemini-3.5-flash",
    Icon: Crosshair,
    desc: "Formulates multi-tenant BOLA, IDOR & SSRF attack vectors",
    color: "purple",
  },
  {
    id: "agent-evidence-04",
    phaseKey: "LOOP",
    name: "EvidenceCollector",
    role: "Deterministic Socket Prober",
    model: "Python Async / HTTPX",
    Icon: BookOpen,
    desc: "Executes differential socket probes via SessionVault",
    color: "amber",
  },
  {
    id: "agent-review-05",
    phaseKey: "LOOP",
    name: "ReviewerAgent",
    role: "Anti-Hallucination Gatekeeper",
    model: "gemini-3.5-flash",
    Icon: ShieldCheck,
    desc: "5-branch semantic validator rejecting false positives",
    color: "emerald",
  },
  {
    id: "agent-report-06",
    phaseKey: "REPORT",
    name: "ReporterAgent",
    role: "HackerOne Advisory Author",
    model: "gemini-3.5-flash",
    Icon: FileText,
    desc: "Compiles CVSS 3.1 reports with curl PoCs & remediation code",
    color: "indigo",
  },
];

const COLOR_MAP = {
  cyan:    { bg: "bg-cyan-950/30",   border: "border-cyan-500/40",   glow: "shadow-cyan-500/20",   text: "text-cyan-400",   badge: "bg-cyan-500/10 text-cyan-300 border-cyan-500/30" },
  blue:    { bg: "bg-blue-950/30",   border: "border-blue-500/40",   glow: "shadow-blue-500/20",   text: "text-blue-400",   badge: "bg-blue-500/10 text-blue-300 border-blue-500/30" },
  purple:  { bg: "bg-purple-950/30", border: "border-purple-500/40", glow: "shadow-purple-500/20", text: "text-purple-400", badge: "bg-purple-500/10 text-purple-300 border-purple-500/30" },
  amber:   { bg: "bg-amber-950/30",  border: "border-amber-500/40",  glow: "shadow-amber-500/20",  text: "text-amber-400",  badge: "bg-amber-500/10 text-amber-300 border-amber-500/30" },
  emerald: { bg: "bg-emerald-950/30",border: "border-emerald-500/40",glow: "shadow-emerald-500/20",text: "text-emerald-400",badge: "bg-emerald-500/10 text-emerald-300 border-emerald-500/30" },
  indigo:  { bg: "bg-indigo-950/30", border: "border-indigo-500/40", glow: "shadow-indigo-500/20", text: "text-indigo-400", badge: "bg-indigo-500/10 text-indigo-300 border-indigo-500/30" },
};

export function AgentStatusList({ currentPhase, status, events = [], findings = [] }) {
  const phases = ["RECON", "ATTACK_SURFACE", "LOOP", "REPORT", "DONE"];
  const currentIndex = phases.indexOf(currentPhase);

  const iterCount      = events.filter(e => e.event_type === "HYPOTHESIS_PROPOSED").length;
  const validatedCount = findings.filter(f => f.verdict === "VALIDATED" || f.status === "VALIDATED" || f.event_type === "FINDING_VALIDATED" || f.review?.verdict === "VALIDATED").length;
  const rejectedCount  = findings.filter(f => f.verdict === "REJECTED"  || f.status === "REJECTED"  || f.event_type === "FINDING_REJECTED"  || f.review?.verdict === "REJECTED").length;


  const getAgentState = (agent) => {
    const idx = phases.indexOf(agent.phaseKey);
    if (status === "FAILED" && idx === currentIndex) return "failed";
    if (status === "COMPLETED" || currentPhase === "DONE") return "done";
    if (idx < currentIndex) return "done";
    if (idx === currentIndex && status === "RUNNING") return "active";
    return "pending";
  };

  return (
    <div className="glass-panel rounded-2xl p-5 shadow-2xl border border-indigo-500/20 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/5 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-indigo-500/10 border border-indigo-500/30">
            <Cpu className="w-4 h-4 text-indigo-400" />
          </div>
          <div>
            <h2 className="text-xs font-bold tracking-widest text-indigo-300 uppercase">Enterprise Agent Fleet</h2>
            <p className="text-[10px] text-zinc-500">6 Specialized Swarm Units</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className={`text-[11px] px-2.5 py-0.5 rounded-full font-bold border ${
            status === "COMPLETED" ? "bg-emerald-950/80 text-emerald-400 border-emerald-500/40" :
            status === "RUNNING"   ? "bg-indigo-950/80 text-indigo-300 border-indigo-500/40 animate-pulse" :
            status === "FAILED"    ? "bg-red-950/80 text-red-400 border-red-500/40" :
            "bg-zinc-900 text-zinc-500 border-zinc-800"}`}>
            {status === "RUNNING" ? `ACTIVE (${currentPhase})` : status}
          </span>
        </div>
      </div>

      {/* 6-Agent List */}
      <div className="space-y-2">
        {ENTERPRISE_AGENTS.map((agent) => {
          const state = getAgentState(agent);
          const c = COLOR_MAP[agent.color];
          const isActive = state === "active";
          const isDone = state === "done";
          const Icon = agent.Icon;

          return (
            <div
              key={agent.id}
              className={`p-3 rounded-xl border transition-all duration-300 ${
                isActive
                  ? `${c.bg} ${c.border} shadow-lg ${c.glow} ring-1 ring-white/10`
                  : isDone
                  ? "bg-emerald-950/10 border-emerald-500/20"
                  : "bg-black/30 border-white/5 hover:border-white/10"
              }`}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-start gap-3">
                  <div className={`p-2 rounded-lg mt-0.5 ${
                    isActive ? "bg-white/10 text-white" : isDone ? "bg-emerald-500/10 text-emerald-400" : "bg-zinc-900 text-zinc-600"
                  }`}>
                    <Icon className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className={`text-xs font-bold ${isActive ? "text-white" : isDone ? "text-zinc-200" : "text-zinc-400"}`}>
                        {agent.name}
                      </span>
                      <span className={`text-[9px] px-1.5 py-0.2 rounded border font-mono ${c.badge}`}>
                        {agent.model}
                      </span>
                    </div>
                    <div className="text-[11px] text-zinc-400 mt-0.5">{agent.desc}</div>
                    
                    {isActive && agent.phaseKey === "LOOP" && (
                      <div className="flex items-center gap-1.5 mt-1.5 text-[10px] font-mono text-amber-400">
                        <Activity className="w-3 h-3 animate-spin" />
                        <span>Iteration #{iterCount || 1} executing differential access tests...</span>
                      </div>
                    )}
                  </div>
                </div>

                <div className="ml-3 flex-shrink-0">
                  {isDone && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                  {isActive && <CircleDashed className="w-4 h-4 text-cyan-400 animate-spin" />}
                  {state === "failed" && <AlertTriangle className="w-4 h-4 text-red-400" />}
                  {state === "pending" && <Clock className="w-4 h-4 text-zinc-700" />}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Metrics Footer */}
      {(validatedCount > 0 || rejectedCount > 0 || iterCount > 0) && (
        <div className="pt-3 border-t border-white/5 grid grid-cols-3 gap-2">
          <div className="p-2 rounded-xl bg-emerald-950/30 border border-emerald-500/30 text-center">
            <div className="text-lg font-black text-emerald-400">{validatedCount}</div>
            <div className="text-[9px] text-emerald-300/80 font-bold uppercase tracking-wider">Validated</div>
          </div>
          <div className="p-2 rounded-xl bg-zinc-900/60 border border-zinc-800 text-center">
            <div className="text-lg font-black text-zinc-400">{rejectedCount}</div>
            <div className="text-[9px] text-zinc-500 font-bold uppercase tracking-wider">Rejected</div>
          </div>
          <div className="p-2 rounded-xl bg-amber-950/30 border border-amber-500/30 text-center">
            <div className="text-lg font-black text-amber-400">{iterCount}</div>
            <div className="text-[9px] text-amber-300/80 font-bold uppercase tracking-wider">Pivots / Iters</div>
          </div>
        </div>
      )}
    </div>
  );
}
