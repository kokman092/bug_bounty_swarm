import React from "react";
import { Shield, Cpu, Lock, Activity, Database, CheckCircle, ExternalLink, X } from "lucide-react";

const DEFAULT_AGENTS = [
  {
    id: "agent-recon-01",
    name: "ReconAgent",
    version: "2.0.0",
    role: "Attack Surface Discovery & Passive Intelligence",
    model_binding: "gemini-3.5-flash",
    description: "Autonomous attack surface discovery engine utilizing passive certificate transparency logs, robots.txt, XML sitemaps, and OpenAPI decomposition.",
    capabilities: ["Passive robots.txt & XML sitemap parsing", "OpenAPI / Swagger v2/v3 schema decomposition", "Subfinder CT log Certificate Transparency enumeration", "Katana AST route extractor"],
    governance_scope: "Read-Only / Safe Harbor In-Scope Subdomains"
  },
  {
    id: "agent-attacksurface-02",
    name: "AttackSurfaceAgent",
    version: "2.0.0",
    role: "Parameter Analysis & Boundary Normalization",
    model_binding: "gemini-3.5-flash",
    description: "Smart Parameter Normalizer translating symbolic URL template placeholders (e.g. {{order_id}} -> 1) into concrete, testable routes.",
    capabilities: ["Symbolic-to-numerical route parameter translation", "Burp Suite Base64 XML & HAR 1.2 history traffic ingestion", "Tenant isolation partition matrix mapping"],
    governance_scope: "Semantic Synthesis / Model Armor Guarded"
  },
  {
    id: "agent-hunter-03",
    name: "HunterAgent",
    version: "2.0.0",
    role: "Multi-Persona Differential Vulnerability Prober",
    model_binding: "gemini-3.5-flash",
    description: "Autonomous BOLA, IDOR, SSRF, and AuthBypass hypothesis engine formulating multi-persona access matrices across 4 distinct tenant identities.",
    capabilities: ["Autonomous BOLA / IDOR hypothesis formulation", "AuthMatrix: 4-persona differential verification (Admin, User A, User B, Anon)", "State-machine parameter tampering sequences"],
    governance_scope: "Active Differential Probing / Non-Destructive Safe Harbor"
  },
  {
    id: "agent-collector-04",
    name: "EvidenceCollector",
    version: "2.0.0",
    role: "Deterministic Exploit Execution & Proof-of-Concept Capture",
    model_binding: "Deterministic Engine / SessionVault",
    description: "High-precision HTTP socket engine capturing differential deltas, response headers, status codes, and executable reproduction curl scripts.",
    capabilities: ["Multi-Persona Session Vault automated credential swapping", "High-precision HTTP differential delta capture", "PoC curl reproduction script generation"],
    governance_scope: "Strict Rate-Limited Probe Execution (10 req/s)"
  },
  {
    id: "agent-reviewer-05",
    name: "ReviewerAgent",
    version: "2.0.0",
    role: "False Positive Elimination & CVSS 3.1 Scoring",
    model_binding: "gemini-3.5-flash",
    description: "Adaptive Evidence Validator enforcing a strict 0% hallucination gate. Rejects false-positive SPA fallbacks and calculates precise CVSS 3.1 vectors.",
    capabilities: ["Adaptive Evidence Validation: verifies non-identical bodies", "CVSS 3.1 Base Score & Vector string calculation", "Strict 0% hallucination verification gate"],
    governance_scope: "Deterministic Verification Gate"
  },
  {
    id: "agent-reporter-06",
    name: "ReporterAgent",
    version: "2.0.0",
    role: "Executive Synthesis & HackerOne Report Generation",
    model_binding: "gemini-3.5-flash",
    description: "Compiles verified findings into HackerOne/Bugcrowd compliant markdown reports with step-by-step reproduction curl commands and code remediation.",
    capabilities: ["HackerOne / Bugcrowd compliant Markdown report synthesis", "Actionable developer remediation & code mitigation advisory", "Burp Suite XML (<items>) export generator"],
    governance_scope: "Secure Storage & Encrypted Export"
  }
];

export function AgentRegistryModal({ isOpen, onClose, registryData }) {
  if (!isOpen) return null;

  const agents = registryData?.agents && registryData.agents.length > 0
    ? registryData.agents
    : DEFAULT_AGENTS;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
      <div className="relative w-full max-w-4xl max-h-[90vh] glass-panel-glow rounded-3xl p-6 overflow-hidden flex flex-col border border-indigo-500/30">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between pb-4 border-b border-white/10">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-indigo-500/20 border border-indigo-500/40">
              <Shield className="w-6 h-6 text-indigo-400" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                Enterprise Agent Registry
                <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-mono">
                  v2.0.0 Live
                </span>
              </h2>
              <p className="text-xs text-zinc-400">Institutional catalog of published agents, model bindings & governance</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-xl bg-white/5 hover:bg-white/10 text-zinc-400 hover:text-white transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Governance Banner */}
        <div className="my-4 grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="p-3 rounded-xl bg-black/40 border border-white/5">
            <div className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider flex items-center gap-1.5">
              <Lock className="w-3 h-3 text-cyan-400" /> Identity Control
            </div>
            <div className="text-xs font-semibold text-zinc-200 mt-1">Zero-Trust Persona Tokens</div>
          </div>
          <div className="p-3 rounded-xl bg-black/40 border border-white/5">
            <div className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider flex items-center gap-1.5">
              <Shield className="w-3 h-3 text-emerald-400" /> Model Armor
            </div>
            <div className="text-xs font-semibold text-zinc-200 mt-1">ScopeEnforcing Guardrail</div>
          </div>
          <div className="p-3 rounded-xl bg-black/40 border border-white/5">
            <div className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider flex items-center gap-1.5">
              <Activity className="w-3 h-3 text-purple-400" /> Observability
            </div>
            <div className="text-xs font-semibold text-zinc-200 mt-1">OpenTelemetry SSE Events</div>
          </div>
          <div className="p-3 rounded-xl bg-black/40 border border-white/5">
            <div className="text-[10px] text-zinc-500 font-bold uppercase tracking-wider flex items-center gap-1.5">
              <Database className="w-3 h-3 text-amber-400" /> Memory Bank
            </div>
            <div className="text-xs font-semibold text-zinc-200 mt-1">Firestore + GCS Overflow</div>
          </div>
        </div>

        {/* Agents Grid */}
        <div className="flex-1 overflow-y-auto pr-1 space-y-3">
          {agents.map((agent) => (
            <div
              key={agent.id}
              className="p-4 rounded-2xl bg-zinc-950/60 border border-white/10 hover:border-indigo-500/30 transition"
            >
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2.5">
                  <div className="px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 text-xs font-mono font-bold">
                    {agent.id}
                  </div>
                  <span className="text-sm font-bold text-white">{agent.name}</span>
                  <span className="text-xs text-zinc-400">({agent.role})</span>
                </div>
                <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-cyan-950/60 text-cyan-400 border border-cyan-500/30">
                  {agent.model_binding}
                </span>
              </div>

              {agent.description && (
                <p className="text-xs text-zinc-300 mb-3">{agent.description}</p>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px]">
                <div className="p-2 rounded-lg bg-black/40 border border-white/5">
                  <span className="text-zinc-500 font-bold uppercase text-[9px]">Capabilities: </span>
                  <span className="text-zinc-300">{Array.isArray(agent.capabilities) ? agent.capabilities.join(", ") : agent.capabilities}</span>
                </div>
                <div className="p-2 rounded-lg bg-black/40 border border-white/5">
                  <span className="text-zinc-500 font-bold uppercase text-[9px]">Governance Scope: </span>
                  <span className="text-zinc-300">{agent.governance_scope || (Array.isArray(agent.governance_rules) ? agent.governance_rules.join("; ") : agent.governance_rules) || "Enterprise Zero-Trust Safe Harbor"}</span>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="pt-4 mt-2 border-t border-white/10 flex items-center justify-between text-xs text-zinc-400">
          <span>Live Endpoint: <code className="text-indigo-300">/api/agents</code></span>
          <a
            href="https://bugbounty-swarm-backend-kva52deviq-uc.a.run.app/api/agents"
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1.5 text-indigo-400 hover:text-indigo-300 font-semibold"
          >
            Open Live JSON <ExternalLink className="w-3.5 h-3.5" />
          </a>
        </div>

      </div>
    </div>
  );
}
