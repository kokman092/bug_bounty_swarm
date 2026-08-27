import React from "react";
import { Shield, Cpu, Lock, Activity, Database, CheckCircle, ExternalLink, X } from "lucide-react";

export function AgentRegistryModal({ isOpen, onClose, registryData }) {
  if (!isOpen) return null;

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
          {registryData?.agents ? (
            registryData.agents.map((agent) => (
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

                <p className="text-xs text-zinc-300 mb-3">{agent.description}</p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px]">
                  <div className="p-2 rounded-lg bg-black/40 border border-white/5">
                    <span className="text-zinc-500 font-bold uppercase text-[9px]">Capabilities: </span>
                    <span className="text-zinc-300">{agent.capabilities?.join(", ")}</span>
                  </div>
                  <div className="p-2 rounded-lg bg-black/40 border border-white/5">
                    <span className="text-zinc-500 font-bold uppercase text-[9px]">Governance Rules: </span>
                    <span className="text-zinc-300">{agent.governance_rules?.join("; ")}</span>
                  </div>
                </div>
              </div>
            ))
          ) : (
            <div className="p-8 text-center text-zinc-500">Loading catalog from live Cloud Run endpoint...</div>
          )}
        </div>

        {/* Footer */}
        <div className="pt-4 mt-2 border-t border-white/10 flex items-center justify-between text-xs text-zinc-400">
          <span>Live Endpoint: <code className="text-indigo-300">/api/agents</code></span>
          <a
            href="https://bugbounty-swarm-backend-339717745624.us-central1.run.app/api/agents"
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
