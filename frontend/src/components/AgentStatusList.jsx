import React from "react";
import {
  CheckCircle2, CircleDashed, Clock, AlertTriangle,
  ShieldCheck, Crosshair, Map, ScanSearch, BookOpen, FileText
} from "lucide-react";

const AGENTS = [
  { id: "RECON",          name: "Endpoint Discovery",     Icon: ScanSearch, desc: "Sitemap crawl & SPA route mapping",          color: "cyan"   },
  { id: "ATTACK_SURFACE", name: "Attack Surface Analyzer", Icon: Map,        desc: "Auth boundary & parameter modeling",        color: "blue"   },
  { id: "LOOP",           name: "Exploit Prober",         Icon: Crosshair,  desc: "Differential BOLA / IDOR verification",     color: "amber",
    sub: [
      { name: "Socket Evidence Collector", Icon: BookOpen,    desc: "Deterministic HTTP socket probing" },
      { name: "Semantic Review Engine",    Icon: ShieldCheck, desc: "5-branch confidence evaluation" },
    ],
  },
  { id: "REPORT", name: "Triage Report Author", Icon: FileText, desc: "HackerOne / Bugcrowd report synthesis", color: "indigo" },
];

const C = {
  cyan:   { bg: "bg-cyan-950/40",   border: "border-cyan-500/50",   text: "text-cyan-400"   },
  blue:   { bg: "bg-blue-950/40",   border: "border-blue-500/50",   text: "text-blue-400"   },
  amber:  { bg: "bg-amber-950/40",  border: "border-amber-500/50",  text: "text-amber-400"  },
  indigo: { bg: "bg-indigo-950/40", border: "border-indigo-500/50", text: "text-indigo-400" },
};

export function AgentStatusList({ currentPhase, status, events = [], findings = [] }) {
  const phases = ["RECON", "ATTACK_SURFACE", "LOOP", "REPORT", "DONE"];
  const currentIndex = phases.indexOf(currentPhase);

  const iterCount      = events.filter(e => e.event_type === "HYPOTHESIS_PROPOSED").length;
  const validatedCount = findings.filter(f => f.verdict === "VALIDATED" || f.status === "VALIDATED").length;
  const rejectedCount  = findings.filter(f => f.verdict === "REJECTED"  || f.status === "REJECTED").length;

  const getState = (phaseId) => {
    const idx = phases.indexOf(phaseId);
    if (status === "FAILED" && idx === currentIndex) return "failed";
    if (status === "COMPLETED" || currentPhase === "DONE") return "done";
    if (idx < currentIndex) return "done";
    if (idx === currentIndex && status === "RUNNING") return "active";
    return "pending";
  };

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 shadow-lg space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-indigo-400" />
          <h2 className="text-sm font-semibold tracking-wider text-zinc-200 uppercase">Agent Swarm Pipeline</h2>
        </div>
        <span className={`text-xs px-2 py-0.5 rounded-full font-bold border ${
          status === "COMPLETED" ? "bg-emerald-950 text-emerald-400 border-emerald-800" :
          status === "RUNNING"   ? "bg-blue-950 text-blue-400 border-blue-800 animate-pulse" :
          status === "FAILED"    ? "bg-red-950 text-red-400 border-red-800" :
          "bg-zinc-800 text-zinc-500 border-zinc-700"}`}>
          {status}
        </span>
      </div>

      <div className="space-y-2.5">
        {AGENTS.map(({ id, name, Icon, desc, color, sub }) => {
          const state = getState(id);
          const c = C[color];
          const isActive = state === "active";
          const isDone   = state === "done";
          return (
            <div key={id}>
              <div className={`flex items-start justify-between p-3.5 rounded-lg border transition-all duration-300 ${
                isActive ? `${c.bg} ${c.border} shadow-sm` :
                isDone   ? "bg-emerald-950/10 border-emerald-900/30" :
                           "bg-zinc-950/40 border-zinc-800/60"}`}>
                <div className="flex items-start gap-2.5">
                  <Icon className={`w-4 h-4 mt-0.5 ${isActive ? c.text : isDone ? "text-emerald-500" : "text-zinc-600"}`} />
                  <div>
                    <div className={`text-sm font-semibold ${isActive ? "text-white" : isDone ? "text-zinc-200" : "text-zinc-500"}`}>{name}</div>
                    <div className="text-xs text-zinc-500 mt-0.5">{desc}</div>
                    {isActive && id === "LOOP" && (
                      <div className={`text-xs mt-1 font-mono ${c.text}`}>
                        {iterCount ? `Iteration ${iterCount} running…` : "Generating first hypothesis…"}
                      </div>
                    )}
                  </div>
                </div>
                <div className="ml-4 mt-0.5">
                  {isDone             && <CheckCircle2 className="w-5 h-5 text-emerald-400" />}
                  {isActive           && <CircleDashed className="w-5 h-5 text-white animate-spin" />}
                  {state === "failed" && <AlertTriangle className="w-5 h-5 text-red-400" />}
                  {state === "pending"&& <Clock className="w-5 h-5 text-zinc-600" />}
                </div>
              </div>
              {sub && isActive && (
                <div className="ml-4 mt-1.5 space-y-1.5">
                  {sub.map(({ name: sn, Icon: SI, desc: sd }) => (
                    <div key={sn} className="flex items-center gap-2 px-3 py-2 bg-zinc-950/60 border border-zinc-800/50 rounded-lg">
                      <SI className="w-3.5 h-3.5 text-zinc-500" />
                      <span className="text-xs text-zinc-400 font-medium">{sn}</span>
                      <span className="text-xs text-zinc-600">— {sd}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {(validatedCount > 0 || rejectedCount > 0 || iterCount > 0) && (
        <div className="pt-3 border-t border-zinc-800 grid grid-cols-3 gap-2">
          {[
            { n: validatedCount, label: "Validated",  cls: "text-emerald-400" },
            { n: rejectedCount,  label: "Rejected",   cls: "text-zinc-500"    },
            { n: iterCount,      label: "Iterations", cls: "text-amber-400"   },
          ].map(({ n, label, cls }) => (
            <div key={label} className="text-center p-2 bg-zinc-950/50 rounded-lg border border-zinc-800/60">
              <div className={`text-xl font-black ${cls}`}>{n}</div>
              <div className="text-[10px] text-zinc-600 uppercase tracking-wider">{label}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
