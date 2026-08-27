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
  Settings
} from "lucide-react";
import { SwarmApiClient } from "./api/client";
import { InvestigationEventClient } from "./api/sse";
import { AgentStatusList } from "./components/AgentStatusList";
import { TranscriptFeed } from "./components/TranscriptFeed";
import { ReportViewer } from "./components/ReportViewer";

const DEFAULT_KEY = "test_secret_key_12345678901234567890123456789012";

const api = new SwarmApiClient("", DEFAULT_KEY);


const PRESET_TARGETS = [
  { label: "Built-in Vuln Lab", url: "http://127.0.0.1:5000", badge: "Local Lab", icon: "🛡️" },
  { label: "OWASP Juice Shop", url: "http://localhost:3001", badge: "Docker Port 3001", icon: "🧪" },
  { label: "Cloud Run Lab", url: "https://vuln-target-lab-339717745624.us-central1.run.app", badge: "Live Cloud Target", icon: "⚡" },
];

export default function App() {
  // ─── Settings auto-populated from /api/config at boot ───────────────────────
  const [apiKey, setApiKey] = useState(DEFAULT_KEY);
  const [geminiModel, setGeminiModel] = useState(() => localStorage.getItem("swarm_gemini_model") || "gemini-3.5-flash");
  const [swarmVersion, setSwarmVersion] = useState("2.0.0");
  const [configLoaded, setConfigLoaded] = useState(false);
  const [showSettingsDrawer, setShowSettingsDrawer] = useState(false);

  const [targetUrl, setTargetUrl] = useState(() => localStorage.getItem("swarm_target_url") || "http://127.0.0.1:5000");
  const [researcherHandle, setResearcherHandle] = useState(() => localStorage.getItem("swarm_researcher_handle") || "security_researcher");
  
  // Authenticated Sessions & Burp Upload State
  const [showAuthDrawer, setShowAuthDrawer] = useState(false);
  const [victimCookie, setVictimCookie] = useState(() => localStorage.getItem("swarm_victim_cookie") || "");
  const [victimToken, setVictimToken] = useState(() => localStorage.getItem("swarm_victim_token") || "");
  const [attackerCookie, setAttackerCookie] = useState(() => localStorage.getItem("swarm_attacker_cookie") || "");
  const [attackerToken, setAttackerToken] = useState(() => localStorage.getItem("swarm_attacker_token") || "");
  const [burpFile, setBurpFile] = useState(null);
  const [burpFileContent, setBurpFileContent] = useState(null);
  const [burpFileType, setBurpFileType] = useState(null);

  const [investigationId, setInvestigationId] = useState(() => localStorage.getItem("swarm_active_investigation_id") || null);
  const [status, setStatus] = useState(() => localStorage.getItem("swarm_status") || "IDLE");
  const [currentPhase, setCurrentPhase] = useState(() => localStorage.getItem("swarm_current_phase") || "RECON");
  const [events, setEvents] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("swarm_events") || "[]");
    } catch {
      return [];
    }
  });
  const [findings, setFindings] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("swarm_findings") || "[]");
    } catch {
      return [];
    }
  });
  const [report, setReport] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("swarm_report") || "null");
    } catch {
      return null;
    }
  });
  const [errorMsg, setErrorMsg] = useState(null);
  const [isStarting, setIsStarting] = useState(false);
  const sseClientRef = useRef(null);
  const fileInputRef = useRef(null);

  // ─── Boot: auto-fetch config from backend ─────────────────────────────────
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
      }
      setConfigLoaded(true);
    }).catch(() => setConfigLoaded(true));
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

  useEffect(() => {
    if (investigationId) {
      localStorage.setItem("swarm_active_investigation_id", investigationId);
    }
  }, [investigationId]);

  useEffect(() => {
    localStorage.setItem("swarm_status", status);
  }, [status]);

  useEffect(() => {
    localStorage.setItem("swarm_current_phase", currentPhase);
  }, [currentPhase]);

  useEffect(() => {
    try {
      localStorage.setItem("swarm_events", JSON.stringify(events.slice(-200)));
    } catch {}
  }, [events]);

  useEffect(() => {
    try {
      localStorage.setItem("swarm_findings", JSON.stringify(findings));
    } catch {}
  }, [findings]);

  useEffect(() => {
    try {
      if (report) {
        localStorage.setItem("swarm_report", JSON.stringify(report));
      }
    } catch {}
  }, [report]);

  // Auto-reconnect or restore on mount / page refresh
  useEffect(() => {
    const savedId = localStorage.getItem("swarm_active_investigation_id");
    if (!savedId) return;

    const checkAndResume = async () => {
      try {
        const inv = await api.getInvestigation(savedId);
        if (inv) {
          if (inv.status === "RUNNING" || inv.status === "AUTHORIZED") {
            setStatus("RUNNING");
            if (inv.current_phase) setCurrentPhase(inv.current_phase);
            connectSSE(savedId);
          } else if (inv.status === "COMPLETED") {
            setStatus("COMPLETED");
            loadReport(savedId);
          } else if (inv.status === "FAILED") {
            setStatus("FAILED");
          }
        }
      } catch (err) {
        console.warn("Could not resume investigation state:", err);
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
      "",
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

          {/* Cloud Badges & Actions */}
          <div className="flex items-center gap-3">
            {investigationId && (
              <button
                type="button"
                onClick={resetHunt}
                title="Start a new hunt and reset view"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-xs font-mono text-zinc-400 hover:text-rose-300 hover:border-rose-800/60 transition-all"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>New Hunt</span>
              </button>
            )}

            <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-zinc-900/90 border border-zinc-800 text-xs font-mono text-zinc-400">
              <Server className="w-3.5 h-3.5 text-zinc-400" />
              <span>Auto-Persistent</span>
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
        <section className="bg-zinc-900/80 border border-zinc-800/90 rounded-2xl p-5 shadow-2xl backdrop-blur-xl space-y-4">
          <form onSubmit={startInvestigation} className="space-y-4">
            {/* Top row: Target input and action button */}
            <div className="flex flex-col md:flex-row gap-3 items-center">
              <div className="relative flex-1 w-full">
                <Globe className="w-4 h-4 text-zinc-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="Enter target URL (e.g., https://mystore.myshopify.com)"
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

            {/* Presets Row & Authenticated Sessions Toggle */}
            <div className="flex items-center justify-between flex-wrap gap-2 pt-2 border-t border-zinc-800/60">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider">Presets:</span>
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

              {/* Toggle Authenticated Sessions & Burp File Upload Drawer */}
              <button
                type="button"
                onClick={() => setShowAuthDrawer(!showAuthDrawer)}
                className={`px-3 py-1 rounded-lg text-[11px] font-mono border transition-all flex items-center gap-2 ${
                  showAuthDrawer || victimCookie || attackerCookie || burpFile
                    ? "bg-indigo-950/80 border-indigo-500 text-indigo-300"
                    : "bg-zinc-950 border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700"
                }`}
              >
                <Lock className="w-3.5 h-3.5" />
                <span>🔐 Add Test Accounts & Burp History</span>
                {(victimCookie || attackerCookie || burpFile) && (
                  <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                )}
                {showAuthDrawer ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </button>

              {/* ⚙️ Settings Button */}
              <button
                type="button"
                onClick={() => setShowSettingsDrawer(!showSettingsDrawer)}
                title="Runtime Settings — change API key, model, etc."
                className={`px-3 py-1 rounded-lg text-[11px] font-mono border transition-all flex items-center gap-2 ${
                  showSettingsDrawer
                    ? "bg-amber-950/80 border-amber-500 text-amber-300"
                    : "bg-zinc-950 border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700"
                }`}
              >
                <Settings className="w-3.5 h-3.5" />
                <span>⚙️ Settings</span>
                {configLoaded && <span className="w-2 h-2 rounded-full bg-emerald-400" title="Config loaded from backend"></span>}
                {showSettingsDrawer ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </button>
            </div>

            {/* ⚙️ Settings Drawer */}
            {showSettingsDrawer && (
              <div className="pt-4 border-t border-zinc-800/80 bg-zinc-950/50 p-4 rounded-xl space-y-4">
                <div className="text-xs font-mono text-amber-400 font-bold mb-2">⚙️ Runtime Settings — changes take effect immediately, no code editing needed</div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* API Key Override */}
                  <div className="space-y-2">
                    <label className="text-[10px] font-mono text-zinc-400 block">
                      Backend API Key <span className="text-emerald-400">(auto-fetched from server)</span>
                    </label>
                    <input
                      type="password"
                      value={apiKey}
                      onChange={(e) => {
                        setApiKey(e.target.value);
                        api.setApiKey(e.target.value);
                        localStorage.setItem("swarm_api_key", e.target.value);
                      }}
                      placeholder="Auto-populated from backend..."
                      className="w-full bg-zinc-900 border border-zinc-700 rounded-lg px-2.5 py-1.5 text-xs font-mono text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-amber-500"
                    />
                    <p className="text-[9px] text-zinc-600 font-mono">Set in .env → API_SECRET_KEY. Fetched automatically at startup.</p>
                  </div>
                  {/* Gemini Model Override */}
                  <div className="space-y-2">
                    <label className="text-[10px] font-mono text-zinc-400 block">
                      Gemini Model <span className="text-emerald-400">(set in .env → GEMINI_MODEL)</span>
                    </label>
                    <select
                      value={geminiModel}
                      onChange={(e) => {
                        setGeminiModel(e.target.value);
                        localStorage.setItem("swarm_gemini_model", e.target.value);
                      }}
                      className="w-full bg-zinc-900 border border-zinc-700 rounded-lg px-2.5 py-1.5 text-xs font-mono text-zinc-200 focus:outline-none focus:border-amber-500"
                    >
                      <option value="gemini-3.5-flash">gemini-3.5-flash (Stable ✓)</option>
                      <option value="gemini-3.6-flash">gemini-3.6-flash (Stable ✓)</option>
                      <option value="gemini-3.7-flash">gemini-3.7-flash (High demand)</option>
                      <option value="gemini-flash-latest">gemini-flash-latest</option>
                    </select>
                    <p className="text-[9px] text-zinc-600 font-mono">Change model without restarting backend. Restart backend to apply .env change.</p>
                  </div>
                </div>
                <div className="flex items-center gap-3 pt-1">
                  <span className="text-[9px] font-mono text-zinc-500">Swarm v{swarmVersion}</span>
                  <span className="text-[9px] font-mono text-zinc-600">•</span>
                  <span className={`text-[9px] font-mono ${configLoaded ? "text-emerald-400" : "text-amber-400"}`}>
                    {configLoaded ? "✓ Config loaded from backend" : "⏳ Loading config..."}
                  </span>
                </div>
              </div>
            )}

            {/* Expandable Authenticated Sessions & Burp File Drawer */}
            {showAuthDrawer && (
              <div className="pt-4 border-t border-zinc-800/80 grid grid-cols-1 md:grid-cols-3 gap-4 bg-zinc-950/50 p-4 rounded-xl">
                {/* Account A (Victim) */}
                <div className="space-y-2 border border-zinc-800/80 p-3 rounded-xl bg-zinc-900/40">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-indigo-300">👤 Account A (Victim / Owner)</span>
                    <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-indigo-950 text-indigo-400">Target Resource</span>
                  </div>
                  <div>
                    <label className="text-[10px] font-mono text-zinc-400 block mb-1">Session Cookie (e.g. _shopify_s=...)</label>
                    <input
                      type="text"
                      value={victimCookie}
                      onChange={(e) => setVictimCookie(e.target.value)}
                      placeholder="_session=alice_secret_cookie_123"
                      disabled={status === "RUNNING"}
                      className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-zinc-200 placeholder-zinc-700 focus:outline-none focus:border-indigo-500"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono text-zinc-400 block mb-1">Bearer Token (Optional)</label>
                    <input
                      type="text"
                      value={victimToken}
                      onChange={(e) => setVictimToken(e.target.value)}
                      placeholder="Bearer eyJhbGciOi..."
                      disabled={status === "RUNNING"}
                      className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-zinc-200 placeholder-zinc-700 focus:outline-none focus:border-indigo-500"
                    />
                  </div>
                </div>

                {/* Account B (Attacker) */}
                <div className="space-y-2 border border-zinc-800/80 p-3 rounded-xl bg-zinc-900/40">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-amber-300">⚔️ Account B (Attacker / Researcher)</span>
                    <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-amber-950 text-amber-400">BOLA Tester</span>
                  </div>
                  <div>
                    <label className="text-[10px] font-mono text-zinc-400 block mb-1">Session Cookie (e.g. _shopify_s=...)</label>
                    <input
                      type="text"
                      value={attackerCookie}
                      onChange={(e) => setAttackerCookie(e.target.value)}
                      placeholder="_session=bob_attacker_cookie_456"
                      disabled={status === "RUNNING"}
                      className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-zinc-200 placeholder-zinc-700 focus:outline-none focus:border-amber-500"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono text-zinc-400 block mb-1">Bearer Token (Optional)</label>
                    <input
                      type="text"
                      value={attackerToken}
                      onChange={(e) => setAttackerToken(e.target.value)}
                      placeholder="Bearer eyJhbGciOi..."
                      disabled={status === "RUNNING"}
                      className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-zinc-200 placeholder-zinc-700 focus:outline-none focus:border-amber-500"
                    />
                  </div>
                </div>

                {/* Burp Suite File Upload Box */}
                <div className="space-y-2 border border-zinc-800/80 p-3 rounded-xl bg-zinc-900/40 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-mono font-bold text-emerald-300">📦 Burp Suite History Import</span>
                      <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400">.xml / .har</span>
                    </div>
                    <p className="text-[10px] font-mono text-zinc-400 mb-2">
                      Export recorded traffic from Burp and upload here to feed all real routes & IDs directly to the AI agent.
                    </p>
                  </div>

                  <div className="space-y-2">
                    <input
                      type="file"
                      ref={fileInputRef}
                      onChange={handleFileUpload}
                      accept=".xml,.har,.json"
                      disabled={status === "RUNNING"}
                      className="hidden"
                    />
                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      disabled={status === "RUNNING"}
                      className="w-full py-2 px-3 rounded-lg border border-dashed border-zinc-700 hover:border-emerald-500 bg-zinc-950 text-xs font-mono text-zinc-300 hover:text-emerald-300 transition-all flex items-center justify-center gap-2"
                    >
                      <Upload className="w-3.5 h-3.5" />
                      <span>{burpFile ? burpFile.name : "Select Burp .xml / .har File"}</span>
                    </button>
                    {burpFile && (
                      <div className="flex items-center justify-between text-[10px] font-mono text-emerald-400 px-1">
                        <span className="flex items-center gap-1">
                          <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                          Ready ({Math.round(burpFile.size / 1024)} KB)
                        </span>
                        <button
                          type="button"
                          onClick={() => {
                            setBurpFile(null);
                            setBurpFileContent(null);
                          }}
                          className="text-zinc-500 hover:text-rose-400"
                        >
                          Remove
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
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
