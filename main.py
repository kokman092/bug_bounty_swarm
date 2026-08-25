"""
BugBounty Swarm — Cloud Run Production Gateway & Landing Page
"""
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(
    title="BugBounty Swarm — Cloud Run Production API",
    description="Autonomous multi-agent security research fleet powered by Google Gemini 3.5 Flash",
    version="2.5.0",
)

@app.get("/healthz", tags=["health"])
async def healthz():
    return {
        "status": "ok",
        "service": "bugbounty-swarm",
        "cloud_provider": "Google Cloud Run",
        "region": "us-central1",
        "track": "The Fortified Enterprise Fleet",
        "ai_engine": "Gemini 3.5 Flash"
    }

@app.get("/", tags=["root"])
async def root(request: Request):
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BugBounty Swarm — Autonomous AI Security Fleet</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #07090e;
            --card-bg: rgba(15, 23, 42, 0.75);
            --border-color: rgba(56, 189, 248, 0.15);
            --primary: #38bdf8;
            --accent: #6366f1;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg-dark);
            background-image: 
                radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.12) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(56, 189, 248, 0.08) 0px, transparent 50%);
            color: var(--text-main);
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 2.5rem 1.5rem;
        }
        .container { max-width: 1050px; width: 100%; }
        .header { text-align: center; margin-bottom: 2.5rem; }
        .badge-row { display: flex; gap: 0.75rem; justify-content: center; flex-wrap: wrap; margin-bottom: 1.25rem; }
        .badge {
            display: inline-flex; align-items: center; gap: 0.4rem;
            padding: 0.35rem 0.85rem; border-radius: 9999px;
            font-size: 0.78rem; font-weight: 600;
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid var(--border-color);
            color: #cbd5e1;
        }
        .badge.live { background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.3); color: #34d399; }
        .badge.track { background: rgba(99, 102, 241, 0.15); border-color: rgba(99, 102, 241, 0.3); color: #a5b4fc; }
        .pulse-dot { width: 8px; height: 8px; border-radius: 50%; background: #10b981; box-shadow: 0 0 10px #10b981; animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
        h1 {
            font-size: 2.75rem; font-weight: 800; letter-spacing: -0.03em;
            background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 50%, #38bdf8 100%);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            margin-bottom: 0.75rem;
        }
        .subtitle { font-size: 1.15rem; color: var(--text-muted); max-width: 750px; margin: 0 auto 1.5rem; line-height: 1.6; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; margin-bottom: 2.5rem; }
        .card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 1rem;
            padding: 1.75rem;
            backdrop-filter: blur(12px);
            transition: transform 0.2s, border-color 0.2s;
        }
        .card:hover { transform: translateY(-3px); border-color: rgba(56, 189, 248, 0.4); }
        .card-title { font-size: 1.1rem; font-weight: 700; color: #f1f5f9; margin-bottom: 0.5rem; display: flex; align-items: center; gap: 0.5rem; }
        .card-text { font-size: 0.92rem; color: var(--text-muted); line-height: 1.55; }
        .mono { font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; }
        .fleet-box {
            background: rgba(15, 23, 42, 0.9);
            border: 1px solid var(--border-color);
            border-radius: 1rem;
            padding: 2rem;
            margin-bottom: 2.5rem;
        }
        .fleet-title { font-size: 1.25rem; font-weight: 700; margin-bottom: 1.25rem; color: #38bdf8; display: flex; align-items: center; gap: 0.5rem; }
        .agents-flow {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem;
        }
        .agent-node {
            background: rgba(30, 41, 59, 0.6);
            border: 1px solid rgba(148, 163, 184, 0.15);
            border-radius: 0.75rem;
            padding: 1rem;
            text-align: center;
        }
        .agent-name { font-weight: 700; font-size: 0.9rem; color: #f8fafc; margin-bottom: 0.25rem; }
        .agent-role { font-size: 0.75rem; color: #94a3b8; }
        .agent-badge { display: inline-block; font-size: 0.65rem; padding: 0.15rem 0.45rem; border-radius: 4px; margin-top: 0.5rem; font-weight: 600; background: rgba(56, 189, 248, 0.15); color: #38bdf8; }
        .actions { display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap; }
        .btn {
            display: inline-flex; align-items: center; gap: 0.5rem;
            padding: 0.85rem 1.75rem; border-radius: 0.75rem;
            font-weight: 700; font-size: 0.95rem; text-decoration: none;
            transition: all 0.2s;
        }
        .btn-primary { background: linear-gradient(135deg, #38bdf8 0%, #6366f1 100%); color: #07090e; box-shadow: 0 4px 20px rgba(56, 189, 248, 0.25); }
        .btn-primary:hover { opacity: 0.95; transform: translateY(-2px); }
        .btn-secondary { background: rgba(30, 41, 59, 0.8); border: 1px solid var(--border-color); color: #f8fafc; }
        .btn-secondary:hover { background: rgba(51, 65, 85, 0.8); }
        footer { margin-top: auto; padding-top: 3rem; text-align: center; font-size: 0.85rem; color: #64748b; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="badge-row">
                <span class="badge live"><span class="pulse-dot"></span> Google Cloud Run: ONLINE (us-central1)</span>
                <span class="badge track">🏆 The Fortified Enterprise Fleet</span>
                <span class="badge">Gemini 3.5 Flash Active</span>
            </div>
            <h1>BugBounty Swarm</h1>
            <p class="subtitle">Autonomous multi-agent security research fleet that discovers, challenges, and validates real-world API vulnerabilities with zero hallucinations.</p>
            <div class="actions">
                <a href="/docs" class="btn btn-primary">📖 Interactive API Docs (Swagger)</a>
                <a href="/healthz" class="btn btn-secondary">🔍 System Health Probe</a>
            </div>
        </div>

        <div class="fleet-box">
            <div class="fleet-title">⚡ 6-Agent Autonomous Architecture Pipeline</div>
            <div class="agents-flow">
                <div class="agent-node">
                    <div class="agent-name">ReconAgent</div>
                    <div class="agent-role">Dynamic Crawling & Sitemap</div>
                    <div class="agent-badge">Gemini 3.5 Flash</div>
                </div>
                <div class="agent-node">
                    <div class="agent-name">AttackSurface</div>
                    <div class="agent-role">BOLA/IDOR & SSRF Mapping</div>
                    <div class="agent-badge">Gemini 3.5 Flash</div>
                </div>
                <div class="agent-node">
                    <div class="agent-name">HunterAgent</div>
                    <div class="agent-role">Differential Test Synthesis</div>
                    <div class="agent-badge">Gemini 3.5 Flash</div>
                </div>
                <div class="agent-node">
                    <div class="agent-name">EvidenceCollector</div>
                    <div class="agent-role">Deterministic Socket Diffing</div>
                    <div class="agent-badge">Python Engine</div>
                </div>
                <div class="agent-node">
                    <div class="agent-name">ReviewAgent</div>
                    <div class="agent-role">5-Branch Evidence Graph</div>
                    <div class="agent-badge">AEV v6.1</div>
                </div>
                <div class="agent-node">
                    <div class="agent-name">ReportAgent</div>
                    <div class="agent-role">HackerOne Markdown Report</div>
                    <div class="agent-badge">Executive Triage</div>
                </div>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <div class="card-title">🛡️ 4-Layer Scope Guardrails</div>
                <div class="card-text">
                    Enforces strict canonical URL normalization, RFC 1918 private IP blocking, AWS/GCP metadata barrier (<span class="mono">169.254.169.254</span>), and DNS rebinding prevention.
                </div>
            </div>
            <div class="card">
                <div class="card-title">🧠 Anti-Hallucination Barrier</div>
                <div class="card-text">
                    Findings must survive deterministic differential execution across distinct personas (Alice/Bob) before graduating to <span class="mono">VALIDATED</span>.
                </div>
            </div>
            <div class="card">
                <div class="card-title">📡 Real-Time SSE Telemetry</div>
                <div class="card-text">
                    Streams live thought progression, socket execution payloads, and evidence trees with monotonic sequence numbering and <span class="mono">Last-Event-ID</span> rehydration.
                </div>
            </div>
        </div>

        <footer>
            Built for <strong>All Things Agentic Hackathon 2026</strong> • Powered by Google Gemini & Google Cloud Run
        </footer>
    </div>
</body>
</html>
"""
        return HTMLResponse(content=html_content)

    return {
        "service": "BugBounty Swarm Fleet v2.5",
        "status": "ONLINE",
        "deployment": "Google Cloud Run (Serverless)",
        "region": "us-central1",
        "track": "The Fortified Enterprise Fleet",
        "ai_engine": "Google Gemini 3.5 Flash",
        "docs_url": "/docs",
        "health_url": "/healthz",
    }
