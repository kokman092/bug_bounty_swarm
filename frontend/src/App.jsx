import React, { useState, useEffect, useRef } from "react";
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
  ExternalLink,
  Trash2,
  ChevronDown,
  ChevronUp,
  Upload,
  FileText,
  CheckCircle2,
  Settings,
  Flame,
  Radio,
  BookOpen,
  Crosshair,
  ShieldCheck,
  Zap,
  Info
} from "lucide-react";
import { SwarmApiClient, CLOUD_RUN_URL } from "./api/client";
import { InvestigationEventClient } from "./api/sse";
import { AgentStatusList } from "./components/AgentStatusList";
import { TranscriptFeed } from "./components/TranscriptFeed";
import { ReportViewer } from "./components/ReportViewer";
import { AgentRegistryModal } from "./components/AgentRegistryModal";

const DEFAULT_KEY = "test_secret_key_12345678901234567890123456789012";

const api = new SwarmApiClient("", DEFAULT_KEY);

const PRESET_TARGETS = [
  { label: "Built-in Vuln Lab", url: "http://127.0.0.1:5000", badge: "Local Multi-Tenant Lab", icon: "🛡️" },
  { label: "Cloud Run SaaS Lab", url: "https://vuln-target-lab-339717745624.us-central1.run.app", badge: "Live Cloud Target", icon: "⚡" },
  { label: "OWASP Juice Shop", url: "http://localhost:3001", badge: "Docker Microservice", icon: "🧪" },
];

export default function App() {
  // ─── Settings auto-populated from /api/config at boot ───────────────────────
  const [apiKey, setApiKey] = useState(DEFAULT_KEY);
  const [geminiModel, setGeminiModel] = useState(() => localStorage.getItem("swarm_gemini_model") || "gemini-3.5-flash-lite");
  const [swarmVersion, setSwarmVersion] = useState("2.0.0");
  const [configLoaded, setConfigLoaded] = useState(false);
  const [showSettingsDrawer, setShowSettingsDrawer] = useState(false);
  const [showRegistryModal, setShowRegistryModal] = useState(false);
  const [registryData, setRegistryData] = useState(null);
  const [activeHost, setActiveHost] = useState("Local Daemon (:8000)");
  const [connectedHostUrl, setConnectedHostUrl] = useState("http://127.0.0.1:8000");

  const [targetUrl, setTargetUrl] = useState(() => localStorage.getItem("swarm_target_url") || "http://127.0.0.1:5000");
  const [researcherHandle, setResearcherHandle] = useState(() => localStorage.getItem("swarm_researcher_handle") || "security_researcher");
  
  // Authenticated Sessions & Burp Upload State
  const [showAuthDrawer, setShowAuthDrawer] = useState(false);
  const [victimCookie, setVictimCookie] = useState(() => localStorage.getItem("swarm_victim_cookie") || "");
  const [victimToken, setVictimToken] = useState(() => localStorage.getItem("swarm_victim_token") || "token_user_1_alice");
  const [attackerCookie, setAttackerCookie] = useState(() => localStorage.getItem("swarm_attacker_cookie") || "");
  const [attackerToken, setAttackerToken] = useState(() => localStorage.getItem("swarm_attacker_token") || "token_user_2_bob");
  const [burpFile, setBurpFile] = useState(null);
  const [burpFileContent, setBurpFileContent] = useState(null);
  const [burpFileType, setBurpFileType] = useState(null);

  const [investigationId, setInvestigationId] = useState(null);
  const [status, setStatus] = useState("IDLE");
  const [currentPhase, setCurrentPhase] = useState("RECON");
  const [events, setEvents] = useState([]);
  const [findings, setFindings] = useState([]);
  const [report, setReport] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);
  const [isStarting, setIsStarting] = useState(false);
  const [activeTab, setActiveTab] = useState("telemetry"); // 'telemetry' | 'findings' | 'report' | 'registry'
  
  const sseClientRef = useRef(null);
  const fileInputRef = useRef(null);

  // ─── Boot: auto-fetch config & registry from backend ────────────────────────
  useEffect(() => {
    api.fetchConfig().then((cfg) => {
      if (cfg) {
        if (cfg.api_key) {
          setApiKey(cfg.api_key);
          api.setApiKey(cfg.api_key);
        }
        if (cfg.gemini_model) {
          setGeminiModel(cfg.gemini_model);
          localStorage.setItem("swarm_gemini_model", cfg.gemini_model);
        }
        if (cfg.swarm_version) setSwarmVersion(cfg.swarm_version);
        if (cfg.connectedHost) {
          setConnectedHostUrl(cfg.connectedHost);
          setActiveHost(cfg.connectedHost.includes("run.app") ? "Cloud Run (us-central1)" : "Local Daemon (:8000)");
        }
      }
      setConfigLoaded(true);
    }).catch(() => setConfigLoaded(true));


    api.fetchAgentRegistry().then((reg) => {
      if (reg) setRegistryData(reg);
    }).catch(() => {});
  }, []);

  // Sync API Key
  useEffect(() => {
    api.setApiKey(apiKey);
    localStorage.setItem("swarm_api_key", apiKey);
  }, [apiKey]);

  // Persist input values
  useEffect(() => {
    localStorage.setItem("swarm_target_url", targetUrl);
  }, [targetUrl]);

  useEffect(() => {
    localStorage.setItem("swarm_researcher_handle", researcherHandle);
  }, [researcherHandle]);

  useEffect(() => {
    localStorage.setItem("swarm_victim_cookie", victimCookie);
  }, [victimCookie]);

  useEffect(() => {
    localStorage.setItem("swarm_victim_token", victimToken);
  }, [victimToken]);

  useEffect(() => {
    localStorage.setItem("swarm_attacker_cookie", attackerCookie);
  }, [attackerCookie]);

  useEffect(() => {
    localStorage.setItem("swarm_attacker_token", attackerToken);
  }, [attackerToken]);

  // Auto-reconnect or restore on mount only if confirmed running on backend
  useEffect(() => {
    const savedId = localStorage.getItem("swarm_active_investigation_id");
    if (!savedId) return;

    const checkAndResume = async () => {
      try {
        const inv = await api.getInvestigation(savedId);
        if (inv && (inv.status === "RUNNING" || inv.status === "AUTHORIZED")) {
          setInvestigationId(savedId);
          setStatus("RUNNING");
          if (inv.current_phase) setCurrentPhase(inv.current_phase);
          connectSSE(savedId);
        } else if (inv && inv.status === "COMPLETED") {
          setInvestigationId(savedId);
          setStatus("COMPLETED");
          loadReport(savedId);
        } else {
          // Stale investigation - reset to clean idle state
          localStorage.removeItem("swarm_active_investigation_id");
          localStorage.removeItem("swarm_status");
          setStatus("IDLE");
        }
      } catch (err) {
        // Backend not reachable or inv not found - reset to clean idle state
        localStorage.removeItem("swarm_active_investigation_id");
        localStorage.removeItem("swarm_status");
        setStatus("IDLE");
      }
    };

    checkAndResume();

    return () => {
      if (sseClientRef.current) {
        sseClientRef.current.disconnect?.();
      }
    };
  }, []);

  const connectSSE = (id) => {
    if (sseClientRef.current) {
      sseClientRef.current.disconnect?.();
    }

    const sseClient = new InvestigationEventClient(
      api.getBaseUrl() || "",
      apiKey || DEFAULT_KEY,
      (event) => {
        setEvents((prev) => [...prev, event]);
        if (event.phase) setCurrentPhase(event.phase);
        if (event.event_type === "FINDING_VALIDATED" || event.event_type === "FINDING_REJECTED") {
          setFindings((prev) => [...prev, { ...(event.payload || {}), event_type: event.event_type }]);
        }
        if (event.event_type === "INVESTIGATION_COMPLETED") {
          setStatus("COMPLETED");
          loadReport(id);
        } else if (event.event_type === "INVESTIGATION_FAILED") {
          setStatus("FAILED");
        }
      },
      (err) => console.warn("SSE stream notice:", err),
      (statusState) => console.log("SSE State:", statusState)
    );

    sseClientRef.current = sseClient;
    sseClient.connect(id);
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setBurpFile(file);
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target.result;
      setBurpFileContent(text);
      if (file.name.endsWith(".xml")) {
        setBurpFileType("xml");
      } else if (file.name.endsWith(".har") || file.name.endsWith(".json")) {
        try {
          const parsed = JSON.parse(text);
          setBurpFileContent(parsed);
          setBurpFileType("har");
        } catch {
          setBurpFileType("xml");
        }
      }
    };
    reader.readAsText(file);
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

    // Construct Sessions Array
    const sessions = [];
    if (victimCookie.trim() || victimToken.trim()) {
      const cookiesObj = {};
      victimCookie.split(";").forEach((pair) => {
        if (pair.includes("=")) {
          const [k, v] = pair.split("=", 2);
          cookiesObj[k.trim()] = v.trim();
        }
      });
      sessions.push({
        role: "owner",
        token: victimToken.trim() || null,
        cookies: cookiesObj,
      });
    }

    if (attackerCookie.trim() || attackerToken.trim()) {
      const cookiesObj = {};
      attackerCookie.split(";").forEach((pair) => {
        if (pair.includes("=")) {
          const [k, v] = pair.split("=", 2);
          cookiesObj[k.trim()] = v.trim();
        }
      });
      sessions.push({
        role: "attacker",
        token: attackerToken.trim() || null,
        cookies: cookiesObj,
      });
    }

    const payload = {
      target_url: targetUrl,
      sessions: sessions.length > 0 ? sessions : undefined,
      burp_history_xml: burpFileType === "xml" ? burpFileContent : undefined,
      burp_history_har: burpFileType === "har" ? burpFileContent : undefined,
    };

    try {
      const res = await api.createInvestigation(payload);
      setInvestigationId(res.investigation_id);
      localStorage.setItem("swarm_active_investigation_id", res.investigation_id);
      setStatus("RUNNING");
      setCurrentPhase("RECON");

      connectSSE(res.investigation_id);
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

  const resetHunt = () => {
    if (sseClientRef.current) {
      sseClientRef.current.disconnect?.();
    }
    localStorage.removeItem("swarm_active_investigation_id");
    localStorage.removeItem("swarm_events");
    localStorage.removeItem("swarm_findings");
    localStorage.removeItem("swarm_report");
    localStorage.setItem("swarm_status", "IDLE");
    setInvestigationId(null);
    setStatus("IDLE");
    setCurrentPhase("RECON");
    setEvents([]);
    setFindings([]);
    setReport(null);
    setErrorMsg(null);
    setBurpFile(null);
    setBurpFileContent(null);
  };

  const handleStopSwarm = async () => {
    if (investigationId) {
      try {
        await api.cancelInvestigation(investigationId);
      } catch (err) {
        console.warn("Cancel request notice:", err);
      }
    }
    if (sseClientRef.current) {
      sseClientRef.current.disconnect?.();
    }
    setStatus("IDLE");
    localStorage.setItem("swarm_status", "IDLE");
  };

  const validatedFindings = findings.filter(f => f.verdict === "VALIDATED" || f.status === "VALIDATED");
  const rejectedFindings = findings.filter(f => f.verdict === "REJECTED" || f.status === "REJECTED");



  return (
    <div className="min-h-screen bg-[#050811] text-zinc-100 antialiased selection:bg-indigo-500 selection:text-white flex flex-col font-sans">
      
      {/* Top Enterprise Command Header */}
      <header className="border-b border-white/10 bg-[#080D1A]/90 backdrop-blur-2xl sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          
          {/* Logo & Platform Info */}
          <div className="flex items-center gap-3.5">
            <div className="p-2.5 rounded-2xl bg-gradient-to-br from-indigo-500/20 via-purple-500/20 to-cyan-500/20 border border-indigo-500/40 shadow-lg shadow-indigo-500/10">
              <Shield className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-black text-sm tracking-wider bg-clip-text text-transparent bg-gradient-to-r from-white via-indigo-200 to-cyan-300">
                  BUGBOUNTY SWARM
                </span>
                <span className="px-2 py-0.5 rounded-md text-[10px] font-mono font-bold bg-indigo-500/10 border border-indigo-500/30 text-indigo-300">
                  FORTIFIED FLEET
                </span>
              </div>
              <p className="text-[10px] text-zinc-400 font-mono flex items-center gap-1.5">
                <span>Autonomous Multi-Agent DAST</span>
                <span className="text-zinc-600">•</span>
                <span className="text-cyan-400">Gemini 3.5 Flash</span>
              </p>
            </div>
          </div>

          {/* Quick Actions & Live Status */}
          <div className="flex items-center gap-2.5">
            
            {/* Enterprise Agent Registry Explorer */}
            <button
              type="button"
              onClick={() => setShowRegistryModal(true)}
              className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 hover:border-indigo-500/30 text-xs font-semibold text-zinc-300 hover:text-white transition shadow-sm"
            >
              <Cpu className="w-3.5 h-3.5 text-indigo-400" />
              <span>Agent Registry (6)</span>
            </button>

            {/* Live Backend Documentation Link */}
            <a
              href={connectedHostUrl ? `${connectedHostUrl}/docs` : "http://127.0.0.1:8000/docs"}
              target="_blank"
              rel="noreferrer"
              className="hidden md:flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-cyan-950/40 hover:bg-cyan-900/40 border border-cyan-500/30 text-xs font-mono text-cyan-300 hover:text-cyan-200 transition shadow-sm"
            >
              <Globe className="w-3.5 h-3.5 text-cyan-400" />
              <span>Swagger API Docs</span>
              <ExternalLink className="w-3 h-3 ml-0.5 text-cyan-500" />
            </a>


            {/* Reset / New Hunt Button */}
            {investigationId && (
              <button
                type="button"
                onClick={resetHunt}
                title="Start a new hunt and reset view"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-red-950/40 hover:bg-red-900/40 border border-red-500/30 text-xs font-mono text-red-300 hover:text-red-200 transition"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>New Hunt</span>
              </button>
            )}

            {/* Active Status Badge */}
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-black/40 border border-white/10 text-xs font-mono">
              <span className={`w-2 h-2 rounded-full ${
                status === "RUNNING" ? "bg-cyan-400 animate-ping" : status === "COMPLETED" ? "bg-emerald-400" : "bg-zinc-600"
              }`} />
              <span className="text-zinc-300 font-bold uppercase tracking-wider">{status}</span>
            </div>

            {/* Settings Toggle */}
            <button
              type="button"
              onClick={() => setShowSettingsDrawer(!showSettingsDrawer)}
              className="p-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-zinc-400 hover:text-white transition"
              title="Runtime Engine Settings"
            >
              <Settings className="w-4 h-4" />
            </button>
          </div>

        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 flex-1 w-full space-y-6">

        {/* Hero Target Input & Launchpad */}
        <section className="glass-panel-glow rounded-3xl p-6 shadow-2xl relative overflow-hidden">
          <div className="absolute top-0 right-0 w-96 h-96 bg-indigo-500/5 rounded-full blur-3xl pointer-events-none" />
          
          <form onSubmit={startInvestigation} className="space-y-4 relative z-10">
            <div className="flex flex-col md:flex-row gap-3 items-center">
              
              {/* Target URL Input */}
              <div className="relative flex-1 w-full">
                <Globe className="w-4 h-4 text-cyan-400 absolute left-4 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="Enter target URL (e.g. http://127.0.0.1:5000 or https://target-app.com)"
                  disabled={status === "RUNNING"}
                  className="w-full bg-[#070B16] border border-white/10 rounded-2xl pl-11 pr-4 py-3.5 text-xs font-mono text-white placeholder-zinc-500 focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 transition-all disabled:opacity-60"
                />
              </div>

              {/* Persona / Researcher Handle */}
              <div className="relative w-full md:w-60">
                <User className="w-4 h-4 text-purple-400 absolute left-4 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={researcherHandle}
                  onChange={(e) => setResearcherHandle(e.target.value)}
                  placeholder="HackerOne Handle"
                  disabled={status === "RUNNING"}
                  className="w-full bg-[#070B16] border border-white/10 rounded-2xl pl-11 pr-4 py-3.5 text-xs font-mono text-white placeholder-zinc-500 focus:outline-none focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 transition-all disabled:opacity-60"
                />
              </div>

              {/* Launch / Stop Action Button */}
              {status === "RUNNING" || isStarting ? (
                <div className="flex items-center gap-2 w-full md:w-auto">
                  <div className="px-5 py-3.5 rounded-2xl bg-indigo-950/60 border border-indigo-500/40 text-cyan-300 text-xs font-bold font-mono flex items-center gap-2 shadow-lg flex-1 md:flex-initial justify-center">
                    <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
                    <span>Investigating...</span>
                  </div>
                  <button
                    type="button"
                    onClick={handleStopSwarm}
                    className="px-4 py-3.5 rounded-2xl bg-red-600/80 hover:bg-red-500 text-white text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 transition shadow-lg shadow-red-500/20 active:scale-95 flex-1 md:flex-initial justify-center"
                    title="Stop active swarm investigation"
                  >
                    <Square className="w-3.5 h-3.5 fill-current" />
                    <span>Stop Swarm</span>
                  </button>
                </div>
              ) : (
                <button
                  type="submit"
                  disabled={isStarting || !targetUrl.trim()}
                  className="w-full md:w-auto px-6 py-3.5 rounded-2xl font-bold text-xs tracking-wider flex items-center justify-center gap-2 uppercase transition-all shadow-xl bg-gradient-to-r from-indigo-600 via-purple-600 to-cyan-600 hover:from-indigo-500 hover:via-purple-500 hover:to-cyan-500 text-white shadow-indigo-500/25 active:scale-95"
                >
                  <Zap className="w-4 h-4 text-cyan-300" />
                  <span>Launch Swarm</span>
                </button>
              )}

            </div>

            {/* Quick Preset Targets & Session Vault Toggle */}
            <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-white/5">
              
              {/* Target Quick Chips */}
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[10px] text-zinc-500 font-mono uppercase tracking-wider flex items-center gap-1">
                  <Flame className="w-3 h-3 text-amber-400" /> Presets:
                </span>
                {PRESET_TARGETS.map((preset) => (
                  <button
                    key={preset.url}
                    type="button"
                    disabled={status === "RUNNING"}
                    onClick={() => setTargetUrl(preset.url)}
                    className={`px-2.5 py-1 rounded-xl text-[11px] font-mono border transition flex items-center gap-1.5 ${
                      targetUrl === preset.url
                        ? "bg-indigo-500/20 border-indigo-500/50 text-indigo-300 shadow-sm"
                        : "bg-black/30 border-white/5 text-zinc-400 hover:text-zinc-200 hover:border-white/10"
                    }`}
                  >
                    <span>{preset.icon}</span>
                    <span>{preset.label}</span>
                  </button>
                ))}
              </div>

              {/* Multi-Tenant Session Vault Button */}
              <button
                type="button"
                onClick={() => setShowAuthDrawer(!showAuthDrawer)}
                className="flex items-center gap-1.5 px-3 py-1 rounded-xl bg-purple-950/30 hover:bg-purple-900/30 border border-purple-500/30 text-[11px] font-mono text-purple-300 transition"
              >
                <Lock className="w-3 h-3 text-purple-400" />
                <span>SessionVault & Burp ({victimToken ? "2 Personas" : "Anon"})</span>
                {showAuthDrawer ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              </button>

            </div>

            {/* Session Vault & Burp Drawer */}
            {showAuthDrawer && (
              <div className="mt-4 p-4 rounded-2xl bg-black/50 border border-purple-500/20 space-y-4 animate-in fade-in slide-in-from-top-2 duration-200">
                <div className="flex items-center justify-between border-b border-white/5 pb-2">
                  <span className="text-xs font-bold text-purple-300 flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-purple-400" />
                    Multi-Tenant Persona Credentials (BOLA / IDOR Verification)
                  </span>
                  <span className="text-[10px] text-zinc-500 font-mono">Auto-Swapped via EvidenceCollector</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Victim Persona */}
                  <div className="space-y-2 p-3 rounded-xl bg-zinc-950/60 border border-white/5">
                    <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400">
                      <User className="w-3.5 h-3.5" />
                      <span>Account A (Legitimate Owner)</span>
                    </div>
                    <input
                      type="text"
                      value={victimToken}
                      onChange={(e) => setVictimToken(e.target.value)}
                      placeholder="Bearer Token (e.g. alice_token_123)"
                      className="w-full bg-[#050811] border border-white/10 rounded-lg px-3 py-2 text-xs font-mono text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-emerald-500"
                    />
                    <input
                      type="text"
                      value={victimCookie}
                      onChange={(e) => setVictimCookie(e.target.value)}
                      placeholder="Session Cookies (e.g. session=abc; user_id=1)"
                      className="w-full bg-[#050811] border border-white/10 rounded-lg px-3 py-2 text-xs font-mono text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-emerald-500"
                    />
                  </div>

                  {/* Attacker Persona */}
                  <div className="space-y-2 p-3 rounded-xl bg-zinc-950/60 border border-white/5">
                    <div className="flex items-center gap-2 text-xs font-semibold text-rose-400">
                      <Crosshair className="w-3.5 h-3.5" />
                      <span>Account B (Unauthorized Attacker)</span>
                    </div>
                    <input
                      type="text"
                      value={attackerToken}
                      onChange={(e) => setAttackerToken(e.target.value)}
                      placeholder="Bearer Token (e.g. bob_token_456)"
                      className="w-full bg-[#050811] border border-white/10 rounded-lg px-3 py-2 text-xs font-mono text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-rose-500"
                    />
                    <input
                      type="text"
                      value={attackerCookie}
                      onChange={(e) => setAttackerCookie(e.target.value)}
                      placeholder="Session Cookies (e.g. session=xyz; user_id=2)"
                      className="w-full bg-[#050811] border border-white/10 rounded-lg px-3 py-2 text-xs font-mono text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-rose-500"
                    />
                  </div>
                </div>

                {/* Burp Suite / HAR History Ingestion */}
                <div className="p-3 rounded-xl bg-zinc-950/60 border border-white/5 flex flex-col md:flex-row items-center justify-between gap-3">
                  <div>
                    <div className="text-xs font-semibold text-zinc-200 flex items-center gap-1.5">
                      <Upload className="w-3.5 h-3.5 text-amber-400" />
                      <span>Burp Suite Proxy History (.xml / .har)</span>
                    </div>
                    <p className="text-[11px] text-zinc-500">Ingest recorded HTTP proxy logs for offline deep parameter analysis</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept=".xml,.har,.json"
                      onChange={handleFileUpload}
                      className="hidden"
                    />
                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      className="px-3 py-1.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-mono text-zinc-300 hover:text-white transition"
                    >
                      {burpFile ? burpFile.name : "Select File..."}
                    </button>
                    {burpFile && (
                      <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono">
                        Loaded
                      </span>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Error Message Banner */}
            {errorMsg && (
              <div className="p-3 rounded-xl bg-red-950/60 border border-red-500/40 text-xs font-mono text-red-300 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
                <span>{errorMsg}</span>
              </div>
            )}
          </form>
        </section>

        {/* 2-Column Main Workspace */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          
          {/* Left Column: 6-Agent Swarm Pipeline & Governance */}
          <div className="lg:col-span-4 space-y-4">
            <AgentStatusList
              currentPhase={currentPhase}
              status={status}
              events={events}
              findings={findings}
            />

            {/* Model Armor & Zero-Trust Telemetry Card */}
            <div className="glass-panel rounded-2xl p-4 border border-white/5 space-y-2.5">
              <div className="flex items-center justify-between text-xs font-bold text-zinc-300">
                <span className="flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <span>Model Armor Guardrails</span>
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
                  ENFORCING
                </span>
              </div>
              <div className="text-[11px] text-zinc-400 space-y-1 font-mono">
                <div className="flex items-center justify-between">
                  <span>RFC 1918 Private Subnets:</span>
                  <span className="text-emerald-400">Blocked</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Cloud Metadata (169.254):</span>
                  <span className="text-emerald-400">Blocked</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>DNS Rebinding Shield:</span>
                  <span className="text-emerald-400">Active</span>
                </div>
              </div>
            </div>
          </div>

          {/* Right Column: Multi-Tab Telemetry & Findings Workspace */}
          <div className="lg:col-span-8 glass-panel rounded-3xl p-6 shadow-2xl border border-white/10 flex flex-col min-h-[600px]">
            
            {/* Workspace Navigation Tabs */}
            <div className="flex items-center justify-between border-b border-white/10 pb-4 mb-4">
              <div className="flex items-center gap-2">
                
                {/* Tab 1: Live Event Stream */}
                <button
                  type="button"
                  onClick={() => setActiveTab("telemetry")}
                  className={`px-3.5 py-2 rounded-xl text-xs font-bold transition flex items-center gap-2 ${
                    activeTab === "telemetry"
                      ? "bg-indigo-600 text-white shadow-lg shadow-indigo-500/25"
                      : "bg-white/5 hover:bg-white/10 text-zinc-400 hover:text-white border border-white/5"
                  }`}
                >
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Live Event Stream</span>
                  <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-black/40 font-mono">
                    {events.length}
                  </span>
                </button>

                {/* Tab 2: Verified Findings */}
                <button
                  type="button"
                  onClick={() => setActiveTab("findings")}
                  className={`px-3.5 py-2 rounded-xl text-xs font-bold transition flex items-center gap-2 ${
                    activeTab === "findings"
                      ? "bg-emerald-600 text-white shadow-lg shadow-emerald-500/25"
                      : "bg-white/5 hover:bg-white/10 text-zinc-400 hover:text-white border border-white/5"
                  }`}
                >
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>Verified Findings</span>
                  {validatedFindings.length > 0 && (
                    <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-emerald-950 border border-emerald-400 text-emerald-300 font-mono font-bold">
                      {validatedFindings.length}
                    </span>
                  )}
                </button>

                {/* Tab 3: Security Report */}
                <button
                  type="button"
                  onClick={() => setActiveTab("report")}
                  className={`px-3.5 py-2 rounded-xl text-xs font-bold transition flex items-center gap-2 ${
                    activeTab === "report"
                      ? "bg-purple-600 text-white shadow-lg shadow-purple-500/25"
                      : "bg-white/5 hover:bg-white/10 text-zinc-400 hover:text-white border border-white/5"
                  }`}
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>HackerOne Report</span>
                  {report && (
                    <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  )}
                </button>

              </div>

              {/* Active Stream Indicator */}
              <div className="flex items-center gap-2 text-xs font-mono text-zinc-500">
                <Activity className={`w-3.5 h-3.5 ${status === "RUNNING" ? "text-cyan-400 animate-spin" : "text-zinc-600"}`} />
                <span>{status === "RUNNING" ? "SSE Connected" : "Dormant"}</span>
              </div>
            </div>

            {/* Tab 1 Content: Transcript Stream */}
            {activeTab === "telemetry" && (
              <div className="flex-1">
                <TranscriptFeed events={events} />
              </div>
            )}

            {/* Tab 2 Content: Verified Findings Cards */}
            {activeTab === "findings" && (
              <div className="flex-1 space-y-4">
                {validatedFindings.length === 0 ? (
                  <div className="p-12 text-center text-zinc-500 font-mono space-y-2">
                    <ShieldCheck className="w-8 h-8 text-zinc-700 mx-auto" />
                    <div>No validated vulnerabilities confirmed yet.</div>
                    <p className="text-xs text-zinc-600">The swarm requires non-identical differential HTTP proof across personas to eliminate false positives.</p>
                  </div>
                ) : (
                  validatedFindings.map((f, idx) => (
                    <div key={idx} className="p-5 rounded-2xl bg-black/40 border border-emerald-500/30 space-y-3 shadow-xl">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                            {f.vulnerability_class || "BOLA / IDOR"}
                          </span>
                          <span className="text-sm font-bold text-white">{f.endpoint || f.target_url}</span>
                        </div>
                        <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/40">
                          {f.severity || "HIGH"} (CVSS 6.5)
                        </span>
                      </div>

                      <p className="text-xs text-zinc-300 leading-relaxed">
                        {f.reasoning || f.summary || "Deterministic access control bypass verified: unauthorized persona received sensitive object payload."}
                      </p>

                      {f.curl_poc && (
                        <div className="space-y-1">
                          <span className="text-[10px] text-zinc-500 font-mono font-bold uppercase">Reproduction PoC:</span>
                          <pre className="p-2.5 rounded-xl bg-[#04060C] border border-white/5 text-[11px] font-mono text-cyan-300 overflow-x-auto">
                            {f.curl_poc}
                          </pre>
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            )}

            {/* Tab 3 Content: Full Report Viewer */}
            {activeTab === "report" && (
              <div className="flex-1">
                {report ? (
                  <ReportViewer report={report} investigationId={investigationId} />
                ) : (
                  <div className="p-12 text-center text-zinc-500 font-mono space-y-2">
                    <FileText className="w-8 h-8 text-zinc-700 mx-auto" />
                    <div>Report will compile automatically upon investigation completion.</div>
                  </div>
                )}
              </div>
            )}

          </div>

        </div>

      </main>

      {/* Enterprise Agent Registry Modal */}
      <AgentRegistryModal
        isOpen={showRegistryModal}
        onClose={() => setShowRegistryModal(false)}
        registryData={registryData}
      />

    </div>
  );
}
