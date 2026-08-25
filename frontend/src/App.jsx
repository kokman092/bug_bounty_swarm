import React, { useState, useEffect } from "react";
import {
  Shield,
  Play,
  Square,
  Key,
  Globe,
  AlertCircle,
  RefreshCw,
  Cpu,
  User,
  Server,
  Layers,
  Sparkles,
  Terminal,
  Activity,
  Lock,
  ExternalLink
} from "lucide-react";
import { SwarmApiClient } from "./api/client";
import { InvestigationEventClient } from "./api/sse";
import { AgentStatusList } from "./components/AgentStatusList";
import { TranscriptFeed } from "./components/TranscriptFeed";
import { ReportViewer } from "./components/ReportViewer";

const DEFAULT_KEY = "test_secret_key_12345678901234567890123456789012";

const getInitialKey = () => {
  const saved = localStorage.getItem("swarm_api_key");
  if (saved && saved.length >= 32) {
    return saved;
  }
  localStorage.setItem("swarm_api_key", DEFAULT_KEY);
  return DEFAULT_KEY;
};

const api = new SwarmApiClient("", DEFAULT_KEY);

const PRESET_TARGETS = [
  { label: "OWASP Juice Shop", url: "http://localhost:3001", badge: "Docker Port 3001", icon: "🧪" },
  { label: "Built-in Multi-Tenant Lab", url: "http://localhost:5000", badge: "FastAPI Testbed", icon: "🛡️" },
  { label: "Local Staging Backend", url: "http://localhost:8000", badge: "Internal API", icon: "⚡" },
];

export default function App() {
  const [apiKey, setApiKey] = useState(getInitialKey());
  const [targetUrl, setTargetUrl] = useState("http://localhost:3001");
  const [researcherHandle, setResearcherHandle] = useState("security_researcher");
  const [investigationId, setInvestigationId] = useState(null);
  const [status, setStatus] = useState("IDLE");
  const [currentPhase, setCurrentPhase] = useState("RECON");
  const [events, setEvents] = useState([]);
  const [findings, setFindings] = useState([]);
  const [report, setReport] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);
  const [isStarting, setIsStarting] = useState(false);
  const [activeTab, setActiveTab] = useState("transcript");

  useEffect(() => {
    api.setApiKey(apiKey);
  }, [apiKey]);

  const handleApiKeyChange = (e) => {
    const key = e.target.value;
    setApiKey(key);
    api.setApiKey(key);
  };

  const startInvestigation = async (e) => {
    if (e) e.preventDefault();
    setErrorMsg(null);
    setIsStarting(true);
    setEvents([]);
    setFindings([]);
    setReport(null);

    // Sync active key with client
    api.setApiKey(apiKey || DEFAULT_KEY);

    try {
      const res = await api.createInvestigation(targetUrl);
      setInvestigationId(res.investigation_id);
      setStatus("RUNNING");
      setCurrentPhase("RECON");

      // Connect SSE
      const sseClient = new InvestigationEventClient(
        "",
        apiKey || DEFAULT_KEY,
        (event) => {
          setEvents((prev) => [...prev, event]);
          if (event.phase) setCurrentPhase(event.phase);
          // Capture finding verdicts from SSE payload
          if (event.event_type === "FINDING_VALIDATED" || event.event_type === "FINDING_REJECTED") {
            setFindings((prev) => [...prev, { ...(event.payload || {}), event_type: event.event_type }]);
          }
          if (event.event_type === "INVESTIGATION_COMPLETED") {
            setStatus("COMPLETED");
            loadReport(res.investigation_id);
          } else if (event.event_type === "INVESTIGATION_FAILED") {
            setStatus("FAILED");
          }
        },
        (err) => console.warn("SSE stream notice:", err),
        (statusState) => console.log("SSE State:", statusState)
      );

      sseClient.connect(res.investigation_id);
    } catch (err) {
      let msg = "Failed to initiate investigation";
      if (typeof err === "string") {
        msg = err;
      } else if (err && typeof err.message === "string") {
        msg = err.message;
      } else if (err) {
        msg = JSON.stringify(err);
      }
      setErrorMsg(msg);
      setStatus("IDLE");
    } finally {
      setIsStarting(false);
    }
  };

  const loadReport = async (id) => {
    try {
      const rep = await api.getReport(id);
      setReport(rep);
    } catch (e) {
      console.error("Failed to load final report", e);
    }
  };

  return (
    <div className="min-h-screen bg-[#07090e] text-zinc-100 antialiased selection:bg-indigo-500 selection:text-white flex flex-col font-sans">
      {/* Top Enterprise Security Navigation Bar */}
      <header className="border-b border-zinc-800/80 bg-zinc-950/80 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-zinc-900 border border-zinc-800 text-indigo-400">
              <Shield className="w-5 h-5 text-indigo-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-sm tracking-wider text-zinc-100 uppercase">
                  BUGBOUNTY SWARM
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-zinc-900 border border-zinc-700 text-zinc-300">
                  ENTERPRISE DAST
                </span>
              </div>
              <p className="text-[10px] text-zinc-400 font-mono">
                Continuous Attack Surface & Exploit Verification Engine
              </p>
            </div>
          </div>

          {/* Cloud Badges & Status */}
          <div className="flex items-center gap-3">
            <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-zinc-900/90 border border-zinc-800 text-xs font-mono text-zinc-400">
              <Server className="w-3.5 h-3.5 text-zinc-400" />
              <span>GCP Cloud Run • us-central1</span>
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            </div>

            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-zinc-900/90 border border-zinc-800 text-xs font-mono">
              <div className={`w-2 h-2 rounded-full ${
                status === "RUNNING" ? "bg-amber-400 animate-ping" : status === "COMPLETED" ? "bg-emerald-400" : "bg-zinc-600"
              }`} />
              <span className="text-zinc-300 font-bold uppercase tracking-wider">{status}</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 flex-1 w-full space-y-6">
        {/* Mission Control Target Config Bar */}
        <section className="bg-zinc-900/80 border border-zinc-800/90 rounded-2xl p-5 shadow-2xl backdrop-blur-xl">
          <form onSubmit={startInvestigation} className="space-y-4">
            {/* Top row: Target input and action button */}
            <div className="flex flex-col md:flex-row gap-3 items-center">
              <div className="relative flex-1 w-full">
                <Globe className="w-4 h-4 text-zinc-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="Enter target URL (e.g., http://localhost:3001)"
                  disabled={status === "RUNNING"}
                  className="w-full bg-zinc-950/90 border border-zinc-800 rounded-xl pl-10 pr-4 py-2.5 text-xs font-mono text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all disabled:opacity-60"
                />
              </div>

              {/* Researcher Handle Input */}
              <div className="relative w-full md:w-64">
                <User className="w-4 h-4 text-zinc-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={researcherHandle}
                  onChange={(e) => setResearcherHandle(e.target.value)}
                  placeholder="HackerOne Handle"
                  disabled={status === "RUNNING"}
                  className="w-full bg-zinc-950/90 border border-zinc-800 rounded-xl pl-10 pr-4 py-2.5 text-xs font-mono text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all disabled:opacity-60"
                />
              </div>

              {/* Launch Button */}
              <button
                type="submit"
                disabled={status === "RUNNING" || isStarting}
                className={`w-full md:w-auto px-6 py-2.5 rounded-xl text-xs font-bold font-mono tracking-wider uppercase transition-all duration-200 flex items-center justify-center gap-2 shrink-0 ${
                  status === "RUNNING"
                    ? "bg-amber-950/40 border border-amber-800/80 text-amber-300 cursor-not-allowed"
                    : "bg-indigo-600 hover:bg-indigo-500 text-white shadow-[0_0_20px_rgba(99,102,241,0.4)] border border-indigo-400"
                }`}
              >
                {status === "RUNNING" ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin text-amber-400" />
                    Scanning Target…
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-current" />
                    Launch Swarm
                  </>
                )}
              </button>
            </div>

            {/* Presets Row */}
            <div className="flex items-center gap-2 flex-wrap pt-1 border-t border-zinc-800/60">
              <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider">Quick Presets:</span>
              {PRESET_TARGETS.map((preset) => (
                <button
                  key={preset.url}
                  type="button"
                  onClick={() => setTargetUrl(preset.url)}
                  disabled={status === "RUNNING"}
                  className={`px-2.5 py-1 rounded-lg text-[11px] font-mono border transition-all flex items-center gap-1.5 ${
                    targetUrl === preset.url
                      ? "bg-indigo-950/70 border-indigo-700 text-indigo-300 shadow-sm"
                      : "bg-zinc-950 border-zinc-800/80 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700"
                  }`}
                >
                  <span>{preset.icon}</span>
                  <span>{preset.label}</span>
                  <span className="text-[9px] px-1 py-0.2 rounded bg-black/40 text-zinc-500 font-sans">
                    {preset.badge}
                  </span>
                </button>
              ))}
            </div>
          </form>

          {errorMsg && (
            <div className="mt-3 p-3 rounded-xl bg-rose-950/30 border border-rose-900/60 text-rose-300 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
              <span>{errorMsg}</span>
            </div>
          )}
        </section>

        {/* Fleet Architecture & Status Strip */}
        <AgentStatusList currentPhase={currentPhase} status={status} events={events} findings={findings} />

        {/* Main Work Area: Live Transcript & Reasoning Feed */}
        <section className="grid grid-cols-1 gap-6">
          <TranscriptFeed events={events} />
        </section>

        {/* Confirmed Findings & HackerOne Report Section */}
        {report && (
          <section className="mt-8">
            <ReportViewer report={report} targetUrl={targetUrl} />
          </section>
        )}
      </main>

      {/* Footer Telemetry */}
      <footer className="border-t border-zinc-800/80 bg-zinc-950/80 py-4 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3 text-[11px] font-mono text-zinc-500">
          <div className="flex items-center gap-3">
            <span>🛡️ 4-Layer Zero-Trust Scope Guardrail</span>
            <span>•</span>
            <span>Deterministic Evidence Prober</span>
            <span>•</span>
            <span>HackerOne Safe Harbor Ready</span>
          </div>
          <div>
            Built for <span className="text-zinc-300 font-semibold">The All Things Agentic Hackathon</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
