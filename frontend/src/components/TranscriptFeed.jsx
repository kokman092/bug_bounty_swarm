import React, { useRef, useEffect, useState } from "react";
import {
  Terminal,
  ShieldAlert,
  CheckCircle,
  Search,
  Bug,
  FileText,
  Zap,
  Info,
  ChevronDown,
  ChevronRight,
  Code2,
  Cpu,
  Globe,
  ArrowRight,
  XCircle,
  Layers,
  Activity,
  Send,
  DownloadCloud,
  FileCode,
  ShieldCheck
} from "lucide-react";

const EVENT_META = {
  INVESTIGATION_CREATED:   { label: "INITIALIZATION", cls: "bg-zinc-800 text-zinc-300 border-zinc-700",                Icon: Info        },
  INVESTIGATION_STARTED:   { label: "FLEET DISPATCH", cls: "bg-blue-950 text-blue-300 border-blue-700 animate-pulse",   Icon: Zap         },
  INVESTIGATION_COMPLETED: { label: "MISSION DONE",   cls: "bg-emerald-950 text-emerald-300 border-emerald-600",        Icon: CheckCircle },
  INVESTIGATION_FAILED:    { label: "MISSION ERROR",  cls: "bg-rose-950 text-rose-300 border-rose-700",                 Icon: ShieldAlert },
  HYPOTHESIS_PROPOSED:     { label: "HYPOTHESIS",     cls: "bg-amber-950 text-amber-300 border-amber-700",               Icon: Bug         },
  EVIDENCE_COLLECTED:      { label: "HTTP SOCKET PROBE", cls: "bg-cyan-950 text-cyan-300 border-cyan-700",              Icon: Send        },
  FINDING_VALIDATED:       { label: "✓ CONFIRMED BREACH", cls: "bg-emerald-950 text-emerald-200 border-emerald-500 shadow-md", Icon: CheckCircle },
  FINDING_REJECTED:        { label: "CHALLENGED (REJECTED)", cls: "bg-zinc-900 text-zinc-300 border-zinc-700",          Icon: XCircle     },
  REPORT_GENERATED:        { label: "FINAL REPORT",   cls: "bg-purple-950 text-purple-300 border-purple-700",           Icon: FileText    },
};

const PHASE_COLOR = {
  RECON:          "text-cyan-400 border-cyan-800 bg-cyan-950/40",
  ATTACK_SURFACE: "text-blue-400 border-blue-800 bg-blue-950/40",
  LOOP:           "text-amber-400 border-amber-800 bg-amber-950/40",
  REPORT:         "text-purple-400 border-purple-800 bg-purple-950/40",
  DONE:           "text-emerald-400 border-emerald-800 bg-emerald-950/40",
};

// ── Verbatim HTTP API Request & Response Display ──────────────────────────────
function VerbatimHttpProbeDisplay({ payload }) {
  const steps = payload?.steps_executed || payload?.steps || [];
  if (!steps || steps.length === 0) return null;

  return (
    <div className="mt-3 space-y-3">
      <div className="flex items-center gap-2 text-xs font-bold font-mono uppercase tracking-wider text-cyan-400">
        <Send className="w-3.5 h-3.5 text-cyan-400" />
        Live Network Socket Traffic (Raw HTTP Request & Response Trace)
      </div>

      {steps.map((step, idx) => {
        const is2xx = step.status_code >= 200 && step.status_code < 300;
        const is404 = step.status_code === 404;
        const isAuthErr = step.status_code === 401 || step.status_code === 403;

        const statusBadge = is2xx
          ? "bg-emerald-950 text-emerald-300 border-emerald-600"
          : is404
          ? "bg-rose-950 text-rose-300 border-rose-700"
          : isAuthErr
          ? "bg-amber-950 text-amber-300 border-amber-700"
          : "bg-zinc-900 text-zinc-300 border-zinc-700";

        return (
          <div key={idx} className="p-3.5 bg-black/80 border border-zinc-800 rounded-xl space-y-2.5 font-mono text-xs shadow-inner">
            {/* Request Line */}
            <div className="flex items-center justify-between gap-2 flex-wrap pb-2 border-b border-zinc-800">
              <div className="flex items-center gap-2">
                <span className="px-2.5 py-0.5 rounded font-bold text-xs bg-cyan-950 border border-cyan-700 text-cyan-300">
                  {step.method || "GET"}
                </span>
                <span className="text-zinc-100 font-semibold text-xs break-all">{step.url}</span>
              </div>

              {step.status_code && (
                <span className={`px-2.5 py-0.5 rounded font-bold text-xs border ${statusBadge}`}>
                  HTTP {step.status_code}
                </span>
              )}
            </div>

            {/* Description */}
            {step.description && (
              <div className="text-zinc-400 font-sans text-xs">
                <span className="text-zinc-500 font-bold font-mono uppercase text-[10px]">Test Step Intent: </span>
                {step.description}
              </div>
            )}

            {/* Request Headers */}
            {step.request_headers && Object.keys(step.request_headers).length > 0 && (
              <div>
                <div className="text-[10px] text-zinc-400 font-bold uppercase tracking-wider mb-1">
                  Outgoing Request Headers:
                </div>
                <div className="text-[11px] text-zinc-300 bg-zinc-950 p-2 rounded-lg border border-zinc-900 space-y-0.5">
                  {Object.entries(step.request_headers).map(([k, v]) => (
                    <div key={k} className="truncate">
                      <span className="text-zinc-500">{k}:</span> <span className="text-cyan-300">{String(v)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Request JSON Body */}
            {step.json_body && (
              <div>
                <div className="text-[10px] text-zinc-400 font-bold uppercase tracking-wider mb-1">
                  Request Payload (Body JSON):
                </div>
                <pre className="text-[11px] text-amber-300 bg-zinc-950 p-2 rounded-lg border border-zinc-900 whitespace-pre-wrap">
                  {JSON.stringify(step.json_body, null, 2)}
                </pre>
              </div>
            )}

            {/* Response Body */}
            {step.body && (
              <div>
                <div className="text-[10px] text-zinc-400 font-bold uppercase tracking-wider mb-1">
                  Server Response Content ({step.body_length || step.body.length} bytes):
                </div>
                <pre className="text-[11px] text-emerald-400 bg-zinc-950 p-2.5 rounded-lg border border-zinc-900 max-h-48 overflow-y-auto whitespace-pre-wrap leading-relaxed">
                  {typeof step.body === "object" ? JSON.stringify(step.body, null, 2) : step.body}
                </pre>
              </div>
            )}

            {step.error && (
              <div className="p-2.5 bg-rose-950/60 border border-rose-800 rounded-lg text-xs text-rose-300">
                ❌ Socket Execution Notice: {step.error}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── 5-Branch Semantic Evidence Graph Visualizer ───────────────────────────────
function EvidenceGraphTreeDisplay({ treeText, verdict }) {
  if (!treeText) return null;
  const lines = treeText.split("\n");
  const isConfirmed = verdict === "VALIDATED" || verdict === "CONFIRMED";

  return (
    <div className={`mt-3 p-3.5 rounded-xl font-mono text-xs border leading-relaxed ${
      isConfirmed
        ? "bg-emerald-950/30 border-emerald-700/60 text-emerald-200"
        : "bg-zinc-950/90 border-zinc-800 text-zinc-300"
    }`}>
      <div className="flex items-center gap-2 font-bold uppercase tracking-wider text-xs text-zinc-400 mb-2 pb-1.5 border-b border-zinc-800/80">
        <Layers className="w-4 h-4 text-indigo-400" />
        5-Branch Semantic Evidence Graph (Deterministic Validation Decision)
      </div>
      {lines.map((line, idx) => {
        const isVerif = line.includes("[VERIFIED]");
        const isInconc = line.includes("[INCONCLUSIVE]");
        const isBreach = line.includes("LEVEL 4") || line.includes("CONFIRMED");
        return (
          <div key={idx} className={`whitespace-pre ${
            isBreach ? "text-emerald-300 font-bold" : isVerif ? "text-cyan-300 font-semibold" : isInconc ? "text-amber-400 font-medium" : "text-zinc-500"
          }`}>
            {line}
          </div>
        );
      })}
    </div>
  );
}

export function TranscriptFeed({ events = [] }) {
  const feedEndRef = useRef(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [filterPhase, setFilterPhase] = useState("ALL");

  useEffect(() => {
    if (autoScroll) {
      feedEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [events, autoScroll]);

  // Exact word count & token estimator across all events
  const totalWords = events.reduce((acc, evt) => {
    const summaryWords = (evt.input_summary || "").split(/\s+/).filter(Boolean).length;
    const payloadWords = JSON.stringify(evt.payload || {}).split(/\s+/).filter(Boolean).length;
    return acc + summaryWords + payloadWords;
  }, 0);

  const filteredEvents = filterPhase === "ALL"
    ? events
    : events.filter(e => e.phase === filterPhase);

  return (
    <div className="bg-zinc-900/95 border border-zinc-800 rounded-2xl p-5 shadow-2xl flex flex-col h-[750px] backdrop-blur-xl">
      {/* Header Bar with Live Word & Token Telemetry */}
      <div className="flex items-center justify-between pb-4 border-b border-zinc-800 mb-3 flex-wrap gap-2">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-indigo-950 border border-indigo-700 text-indigo-400 shadow-md">
            <Terminal className="w-5 h-5 text-indigo-400" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h2 className="text-sm font-bold tracking-wider text-zinc-100 uppercase">
                Attack Surface Telemetry & Execution Log
              </h2>
              <span className="px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-zinc-900 border border-zinc-700 text-zinc-300">
                {events.length} Telemetry Events
              </span>
            </div>
            <p className="text-xs text-zinc-400 font-mono mt-0.5">
              Deterministic Layer 7 Probing • Verbatim Payloads & Socket Telemetry
            </p>
          </div>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-2">
          <select
            value={filterPhase}
            onChange={(e) => setFilterPhase(e.target.value)}
            className="bg-zinc-950 border border-zinc-700 rounded-xl px-3 py-1.5 text-xs font-mono text-zinc-300 focus:outline-none focus:border-indigo-500"
          >
            <option value="ALL">All Events ({events.length})</option>
            <option value="RECON">Recon Phase</option>
            <option value="ATTACK_SURFACE">Attack Surface</option>
            <option value="LOOP">Validation Loop</option>
            <option value="REPORT">Final Report</option>
          </select>

          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`px-3 py-1.5 rounded-xl text-xs font-mono border transition-all ${
              autoScroll
                ? "bg-indigo-950 border-indigo-600 text-indigo-300 shadow-sm"
                : "bg-zinc-950 border-zinc-800 text-zinc-500"
            }`}
          >
            {autoScroll ? "● Auto-Scroll ON" : "○ Auto-Scroll PAUSED"}
          </button>
        </div>
      </div>

      {/* Events Stream Body */}
      <div className="flex-1 overflow-y-auto space-y-3.5 font-mono text-xs pr-2 custom-scrollbar">
        {filteredEvents.length === 0 ? (
          <div className="text-zinc-600 italic text-center py-36 font-sans text-sm">
            <Cpu className="w-10 h-10 mx-auto mb-3 text-zinc-700 animate-pulse" />
            <p className="text-zinc-300 font-medium text-base">Swarm Fleet Idle</p>
            <p className="text-zinc-500 text-xs mt-1">Select a target preset above and click "Launch Swarm" to stream every word of agent reasoning.</p>
          </div>
        ) : (
          filteredEvents.map((evt, i) => {
            const meta = EVENT_META[evt.event_type] || {
              label: evt.event_type,
              cls: "bg-zinc-800 text-zinc-300 border-zinc-700",
              Icon: Info
            };
            const MetaIcon = meta.Icon;
            const phaseBadge = PHASE_COLOR[evt.phase] || "text-zinc-400 border-zinc-800 bg-zinc-950";
            const isConfirmed = evt.event_type === "FINDING_VALIDATED";
            const isRejected = evt.event_type === "FINDING_REJECTED";
            const isHypo = evt.event_type === "HYPOTHESIS_PROPOSED";
            const isEvidence = evt.event_type === "EVIDENCE_COLLECTED";

            return (
              <div
                key={evt.event_id || `${i}-${evt.sequence_number}`}
                className={`p-4 rounded-2xl border transition-all duration-200 ${
                  isConfirmed
                    ? "bg-emerald-950/30 border-emerald-600 shadow-[0_0_25px_rgba(16,185,129,0.2)]"
                    : isRejected
                    ? "bg-zinc-950 border-zinc-800 hover:border-zinc-700"
                    : "bg-zinc-950/90 border-zinc-800/90 hover:border-zinc-700"
                }`}
              >
                {/* Meta Header Row */}
                <div className="flex items-center justify-between mb-2.5 gap-2 flex-wrap">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-zinc-500 font-bold">#{evt.sequence_number}</span>
                    <span className="font-extrabold text-zinc-100 text-sm tracking-tight">{evt.agent_name || "System"}</span>
                    {evt.iteration > 0 && (
                      <span className="px-2 py-0.5 text-xs rounded-md font-mono bg-zinc-900 border border-zinc-800 text-amber-400 font-bold">
                        iter-{evt.iteration}
                      </span>
                    )}
                    {evt.phase && (
                      <span className={`px-2 py-0.5 text-xs rounded-md font-mono border font-semibold ${phaseBadge}`}>
                        {evt.phase}
                      </span>
                    )}
                  </div>

                  <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold border ${meta.cls}`}>
                    <MetaIcon className="w-3.5 h-3.5" />
                    {meta.label}
                  </span>
                </div>

                {/* Input Summary in Plain English */}
                <div className="text-zinc-100 font-sans text-sm font-semibold leading-relaxed">
                  {evt.input_summary}
                </div>

                {/* Verbatim Recon Summary / Discovered Endpoints */}
                {evt.payload?.endpoints_discovered !== undefined && (
                  <div className="mt-2.5 p-3 bg-cyan-950/20 border border-cyan-900/50 rounded-xl space-y-1 text-xs">
                    <div className="text-cyan-300 font-bold">
                      📡 Discovered {evt.payload.endpoints_discovered} Attack Surface Endpoints
                    </div>
                    {evt.payload.summary && (
                      <div className="text-zinc-300 font-sans text-xs leading-relaxed">
                        {evt.payload.summary}
                      </div>
                    )}
                  </div>
                )}

                {/* Verbatim Hypothesis Reasoning */}
                {isHypo && evt.payload?.title && (
                  <div className="mt-3 p-3.5 bg-amber-950/25 border border-amber-800/60 rounded-xl space-y-2 text-xs">
                    <div className="flex items-center justify-between flex-wrap gap-1">
                      <span className="font-bold text-amber-300 text-sm">🎯 Hypothesis: {evt.payload.title}</span>
                      <span className="text-xs font-mono px-2 py-0.5 rounded bg-black/60 text-amber-300 border border-amber-800">
                        Class: {evt.payload.vuln_class}
                      </span>
                    </div>

                    {evt.payload.endpoint && (
                      <div className="text-xs font-mono text-cyan-300 bg-black/60 px-2.5 py-1 rounded-lg inline-block border border-zinc-800">
                        Target Route: <span className="font-bold text-white">{evt.payload.endpoint}</span>
                      </div>
                    )}

                    {evt.payload.rationale && (
                      <div className="text-zinc-200 font-sans text-xs leading-relaxed pt-1">
                        <span className="text-zinc-400 font-bold font-mono uppercase text-[10px] block mb-0.5">Gemini Reasoning & Rationale:</span>
                        {evt.payload.rationale}
                      </div>
                    )}
                  </div>
                )}

                {/* Verbatim Reviewer Rationale / Decision Reasoning */}
                {(isConfirmed || isRejected) && evt.payload?.reason && (
                  <div className={`mt-3 p-3.5 rounded-xl border text-xs leading-relaxed space-y-1.5 ${
                    isConfirmed ? "bg-emerald-950/30 border-emerald-700 text-emerald-200" : "bg-zinc-950 border-zinc-800 text-zinc-300"
                  }`}>
                    <div className="flex items-center gap-2 font-bold uppercase tracking-wider text-xs">
                      {isConfirmed ? <ShieldCheck className="w-4 h-4 text-emerald-400" /> : <XCircle className="w-4 h-4 text-zinc-400" />}
                      <span className={isConfirmed ? "text-emerald-300" : "text-zinc-300"}>
                        ReviewAgent Evaluation ({evt.payload.verdict} • {evt.payload.confidence} Confidence • {evt.payload.technical_severity || "Low"} Severity)
                      </span>
                    </div>
                    <p className="font-sans text-xs text-zinc-200 pt-1 leading-relaxed">
                      {evt.payload.reason}
                    </p>
                  </div>
                )}

                {/* Verbatim HTTP Socket Probing View */}
                {isEvidence && <VerbatimHttpProbeDisplay payload={evt.payload} />}

                {/* 5-Branch Semantic Evidence Graph Tree */}
                {(isConfirmed || isRejected) && evt.payload?.evidence_graph_tree && (
                  <EvidenceGraphTreeDisplay
                    treeText={evt.payload.evidence_graph_tree}
                    verdict={evt.payload.verdict}
                  />
                )}
              </div>
            );
          })
        )}
        <div ref={feedEndRef} />
      </div>
    </div>
  );
}
