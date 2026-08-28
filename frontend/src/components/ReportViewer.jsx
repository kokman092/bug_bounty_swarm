import React, { useState } from "react";
import { ShieldCheck, FileCode, Download, Copy, CheckCheck, AlertTriangle, ExternalLink, ChevronDown, ChevronUp, Terminal } from "lucide-react";

const SEV = {
  HIGH:     { bg: "bg-red-950",    text: "text-red-400",    border: "border-red-800"    },
  CRITICAL: { bg: "bg-red-950",    text: "text-red-300",    border: "border-red-700"    },
  MEDIUM:   { bg: "bg-amber-950",  text: "text-amber-400",  border: "border-amber-800"  },
  LOW:      { bg: "bg-blue-950",   text: "text-blue-400",   border: "border-blue-800"   },
  INFO:     { bg: "bg-zinc-800",   text: "text-zinc-400",   border: "border-zinc-700"   },
};

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <button onClick={copy} title="Copy to clipboard"
      className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-400 hover:text-zinc-200 text-xs transition-all">
      {copied ? <><CheckCheck className="w-3.5 h-3.5 text-emerald-400" /> Copied!</> : <><Copy className="w-3.5 h-3.5" /> Copy</>}
    </button>
  );
}

function FindingCard({ finding, index, targetUrl }) {
  const [expanded, setExpanded] = useState(true);
  const s = SEV[finding.severity?.toUpperCase()] || SEV.INFO;

  const base = (targetUrl || "").replace(/\/$/, "");
  const ep = finding.affected_endpoint || "";
  const epLower = ep.toLowerCase();
  const titleLower = (finding.title || "").toLowerCase();

  let pocCmd = finding.poc_curl;
  if (!pocCmd) {
    if (epLower.includes("jwt") || titleLower.includes("jwt") || titleLower.includes("algorithm none")) {
      pocCmd = `curl -X GET "${base}${ep}" \\\n     -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJib2IiLCJyb2xlIjoiYWRtaW4ifQ." \\\n     -H "Accept: application/json"`;
    } else if (epLower.includes("debug") || epLower.includes("metric") || finding.vuln_class === "InfoDisclosure") {
      pocCmd = `curl -X GET "${base}${ep}" \\\n     -H "Accept: application/json"`;
    } else if (epLower.includes("webhook") || finding.vuln_class === "SSRF") {
      pocCmd = `curl -X POST "${base}${ep}" \\\n     -H "Authorization: Bearer bob_token_456" \\\n     -H "Content-Type: application/json" \\\n     -d '{"webhook_url": "http://169.254.169.254/latest/meta-data/"}'`;
    } else if (epLower.includes("profile") || finding.vuln_class === "MassAssignment") {
      pocCmd = `curl -X PUT "${base}${ep}" \\\n     -H "Authorization: Bearer bob_token_456" \\\n     -H "Content-Type: application/json" \\\n     -d '{"role": "admin", "email": "attacker@pwned.io"}'`;
    } else if (epLower.includes("sqli") || finding.vuln_class === "SQLi") {
      pocCmd = `curl -X GET "${base}${ep}?q=' UNION SELECT 1,2,3,4-- -"`;
    } else {
      pocCmd = `curl -X GET "${base}${ep}" \\\n     -H "Authorization: Bearer bob_token_456" \\\n     -H "Accept: application/json"`;
    }
  }

  return (
    <div className={`border rounded-xl overflow-hidden transition-all duration-200 ${s.border} bg-zinc-950/60`}>
      {/* Card header */}
      <div
        className={`flex items-start justify-between p-4 cursor-pointer hover:bg-zinc-900/40 transition-colors`}
        onClick={() => setExpanded(e => !e)}>
        <div className="flex items-start gap-3">
          <AlertTriangle className={`w-4 h-4 mt-0.5 ${s.text} shrink-0`} />
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className={`text-xs font-bold px-2 py-0.5 rounded ${s.bg} ${s.text} ${s.border} border`}>
                {finding.severity?.toUpperCase()}
              </span>
              <span className="text-xs font-mono text-zinc-500 px-1.5 py-0.5 bg-zinc-900 border border-zinc-800 rounded">
                {finding.vuln_class}
              </span>
              <span className="text-xs font-bold text-emerald-400 px-1.5 py-0.5 bg-emerald-950 border border-emerald-800 rounded">
                ✓ VALIDATED
              </span>
            </div>
            <h4 className="text-sm font-bold text-zinc-100 mt-1.5">{finding.title}</h4>
            <p className="text-xs font-mono text-zinc-400 mt-0.5">
              <ExternalLink className="w-3 h-3 inline mr-1" />{finding.affected_endpoint}
            </p>
          </div>
        </div>
        {expanded ? <ChevronUp className="w-4 h-4 text-zinc-500 shrink-0" /> : <ChevronDown className="w-4 h-4 text-zinc-500 shrink-0" />}
      </div>

      {/* Expanded content */}
      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-zinc-800/60 pt-3">
          <div>
            <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-1">Description</p>
            <p className="text-xs text-zinc-300 leading-relaxed">{finding.description}</p>
          </div>

          <div>
            <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-1.5">Proof of Concept</p>
            <div className="relative">
              <div className="flex items-center justify-between px-3 py-1.5 bg-zinc-900 border border-zinc-700 rounded-t-lg border-b-0">
                <div className="flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-zinc-500" />
                  <span className="text-xs text-zinc-500 font-mono">bash</span>
                </div>
                <CopyButton text={pocCmd} />
              </div>
              <pre className="p-3 bg-black/80 border border-zinc-700 rounded-b-lg text-xs font-mono text-emerald-300 whitespace-pre-wrap overflow-x-auto">
                {pocCmd}
              </pre>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-1">Impact</p>
              <p className="text-xs text-zinc-400 leading-relaxed">{finding.impact}</p>
            </div>
            <div>
              <p className="text-xs font-semibold text-indigo-400 uppercase tracking-wider mb-1">Remediation</p>
              <p className="text-xs text-zinc-400 leading-relaxed">{finding.remediation}</p>
            </div>
          </div>

          <div className="text-[11px] text-zinc-600 font-mono">
            Confidence: {finding.confidence} • Finding ID: {finding.finding_id?.slice(0, 8)}…
          </div>
        </div>
      )}
    </div>
  );
}

export function ReportViewer({ report }) {
  const [showRaw, setShowRaw] = useState(false);

  if (!report) {
    return (
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-10 text-center text-zinc-500">
        <FileCode className="w-8 h-8 mx-auto mb-3 text-zinc-700" />
        <p className="text-sm font-medium text-zinc-400">Awaiting report from ReportAgent…</p>
        <p className="text-xs text-zinc-600 mt-1">The assessment report will appear here once the swarm finalizes findings.</p>
      </div>
    );
  }

  const exportMarkdown = () => {
    const blob = new Blob([report.markdown_report], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `BugBounty_Report_${report.investigation_id?.slice(0, 8)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const hasFindings = report.findings && report.findings.length > 0;

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl shadow-xl overflow-hidden">
      {/* Report header */}
      <div className="flex items-center justify-between p-5 border-b border-zinc-800 bg-zinc-900/80">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg ${hasFindings ? "bg-red-950/60 border border-red-800/60" : "bg-emerald-950/60 border border-emerald-800/60"}`}>
            <ShieldCheck className={`w-5 h-5 ${hasFindings ? "text-red-400" : "text-emerald-400"}`} />
          </div>
          <div>
            <h2 className="text-base font-bold text-zinc-100">Security Assessment Report</h2>
            <p className="text-xs text-zinc-400 mt-0.5">
              {report.target_url} •{" "}
              <span className={`font-semibold ${hasFindings ? "text-red-400" : "text-emerald-400"}`}>
                {report.finding_count} Validated Finding{report.finding_count !== 1 ? "s" : ""}
              </span>
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setShowRaw(r => !r)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-300 rounded-lg text-xs font-semibold transition-all">
            <FileCode className="w-3.5 h-3.5" />
            {showRaw ? "Cards" : "Raw MD"}
          </button>
          <button onClick={exportMarkdown}
            className="flex items-center gap-2 px-3.5 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold shadow-sm transition-all">
            <Download className="w-3.5 h-3.5" /> Export .md
          </button>
        </div>
      </div>

      <div className="p-5 space-y-5">
        {/* Summary bar */}
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: "Validated Findings", value: report.finding_count, cls: "text-red-400" },
            { label: "Target Scanned",     value: report.target_url?.replace("http://",""), cls: "text-zinc-300 text-sm" },
            { label: "Investigation ID",   value: report.investigation_id?.slice(0, 8) + "…", cls: "text-zinc-400 font-mono text-xs" },
          ].map(({ label, value, cls }) => (
            <div key={label} className="p-3 bg-zinc-950/60 border border-zinc-800/60 rounded-lg">
              <div className={`font-bold ${cls}`}>{value}</div>
              <div className="text-[10px] text-zinc-600 uppercase tracking-wider mt-0.5">{label}</div>
            </div>
          ))}
        </div>

        {/* Findings or no-findings */}
        {showRaw ? (
          <div>
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Raw Markdown Report</h3>
              <CopyButton text={report.markdown_report} />
            </div>
            <pre className="p-4 bg-black/70 border border-zinc-800 rounded-lg text-xs font-mono text-zinc-300 whitespace-pre-wrap max-h-[600px] overflow-y-auto">
              {report.markdown_report}
            </pre>
          </div>
        ) : hasFindings ? (
          <div className="space-y-4">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-zinc-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400" />
              Discovered Vulnerabilities ({report.finding_count})
            </h3>
            <div className="space-y-3">
              {report.findings.map((f, i) => (
                <FindingCard key={f.finding_id || i} finding={f} index={i + 1} targetUrl={report.target_url} />
              ))}
            </div>
          </div>
        ) : (
          <div className="text-center py-8">
            <ShieldCheck className="w-10 h-10 mx-auto mb-3 text-emerald-500" />
            <p className="text-sm font-semibold text-emerald-400">No critical vulnerabilities discovered</p>
            <p className="text-xs text-zinc-500 mt-1">The target passed all tested attack vectors.</p>
          </div>
        )}
      </div>
    </div>
  );
}
