"""
app/main.py
───────────
FastAPI application assembly and middleware configuration.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.core.exceptions import SwarmBaseException
from app.core.logging import configure_logging, get_logger
from app.events.router import router as events_router
from app.investigations.router import internal_router as internal_inv_router
from app.investigations.router import router as investigations_router
from app.reports.router import router as reports_router

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown handlers."""
    settings = get_settings()
    configure_logging(
        log_level=settings.log_level,
        is_development=settings.is_development,
    )
    logger.info(
        "app_startup",
        environment=settings.environment,
        use_emulator=settings.use_firestore_emulator,
    )
    yield
    logger.info("app_shutdown")


app = FastAPI(
    title="BugBounty Swarm API",
    description="AI-powered multi-agent security assessment swarm with Google ADK",
    version="1.0.0",
    lifespan=lifespan,
)

# ── CORS Middleware ────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
    ],
    allow_origin_regex=r"https?://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Global Exception Handler for Application Exceptions ────────────────────────
@app.exception_handler(SwarmBaseException)
async def swarm_exception_handler(
    request: Request, exc: SwarmBaseException
) -> JSONResponse:
    logger.error(
        "swarm_exception",
        error_code=exc.error_code,
        message=exc.message,
        path=request.url.path,
    )
    return JSONResponse(
        status_code=exc.http_status,
        content={
            "error": exc.error_code,
            "message": exc.message,
        },
    )


# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(investigations_router)
app.include_router(events_router)
app.include_router(reports_router)
app.include_router(internal_inv_router)


# ── Health Check Endpoint (Public) ────────────────────────────────────────────
@app.get("/healthz", tags=["health"], summary="Health check endpoint for Cloud Run")
@app.get("/health", tags=["health"], summary="Health check endpoint for Cloud Run")
@app.get("/api/health", tags=["health"], summary="Health check endpoint for Cloud Run")
async def health_check() -> dict[str, str]:
    settings = get_settings()
    return {
        "status": "ok",
        "health": "healthy",
        "version": settings.swarm_version,
        "service": "bugbounty-swarm",
        "cloud_provider": "Google Cloud Run",
        "region": "us-central1",
        "ai_engine": settings.gemini_model,
        "track": "The Fortified Enterprise Fleet",
    }



# ── Config Endpoint (Public — used by frontend at boot time) ──────────────────
@app.get("/api/config", tags=["config"], summary="Public config fetched by the frontend dashboard")
async def get_frontend_config() -> dict:
    """
    Returns non-secret runtime configuration to the frontend.
    The frontend uses this to configure itself at startup without hardcoded values.
    """
    settings = get_settings()
    return {
        "api_key": settings.api_secret_key,
        "gemini_model": settings.gemini_model,
        "swarm_version": settings.swarm_version,
        "burp_proxy_enabled": settings.burp_proxy_enabled,
        "environment": settings.environment,
    }


# ── Enterprise Agent Registry (Fortified Enterprise Fleet Catalog) ─────────────
@app.get("/api/agents", tags=["registry"], summary="Enterprise Agent Registry Catalog")
@app.get("/api/registry", tags=["registry"], summary="Enterprise Agent Registry Catalog")
async def get_agent_registry() -> dict:
    """
    Official Agent Registry Catalog for the Fortified Enterprise Fleet.
    Exposes published institutional agents, versioning, capability manifests,
    governance controls, model bindings, and observability contracts.
    """
    settings = get_settings()
    return {
        "registry_version": "2.0.0",
        "enterprise_fleet": "The Fortified Enterprise Fleet",
        "platform": "Google Gemini Enterprise Agent Platform",
        "default_llm_engine": settings.gemini_model,
        "governance": {
            "identity_control": "Zero-Trust API Key & Firebase Token Binding",
            "model_armor": "ScopeEnforcingHttpClient + SSRF/Private IP Gatekeeper",
            "telemetry_standard": "OpenTelemetry-Compliant Event Sourcing (SSE / Cloud Logging)",
            "memory_bank": "Multi-Tenant Persistent Firestore State Store",
        },
        "agents": [
            {
                "id": "agent-recon-01",
                "name": "ReconAgent",
                "version": "2.0.0",
                "role": "Attack Surface Discovery & Passive Intelligence",
                "model_binding": settings.gemini_model,
                "lifecycle_state": "ACTIVE",
                "capabilities": [
                    "Passive robots.txt & XML sitemap parsing",
                    "OpenAPI / Swagger v2/v3 schema discovery & route decomposition",
                    "Subfinder CT log Certificate Transparency passive enumeration",
                    "Katana AST crawl & route extractor",
                    "Nuclei template baseline scanning & tech-stack fingerprinting"
                ],
                "inputs": ["target_url: str", "investigation_id: str"],
                "outputs": ["AttackSurfaceManifest: dict", "DiscoveredEndpoints: list[str]"],
                "governance_scope": "Read-Only / Safe Harbor In-Scope Subdomains"
            },
            {
                "id": "agent-attacksurface-02",
                "name": "AttackSurfaceAgent",
                "version": "2.0.0",
                "role": "Parameter Analysis & Boundary Normalization",
                "model_binding": settings.gemini_model,
                "lifecycle_state": "ACTIVE",
                "capabilities": [
                    "Smart Parameter Normalizer: transforms template placeholders to concrete IDs",
                    "Symbolic-to-numerical route parameter translation (e.g. {{order_id}} -> 1)",
                    "Burp Suite Base64 XML & HAR 1.2 history traffic ingestion",
                    "Tenant isolation partition matrix mapping"
                ],
                "inputs": ["raw_endpoints: list[str]", "burp_traffic: Optional[bytes]"],
                "outputs": ["NormalizedAttackSurface: list[NormalizedRoute]"],
                "governance_scope": "Semantic Synthesis / Model Armor Guarded"
            },
            {
                "id": "agent-hunter-03",
                "name": "HunterAgent",
                "version": "2.0.0",
                "role": "Multi-Persona Differential Vulnerability Prober",
                "model_binding": settings.gemini_model,
                "lifecycle_state": "ACTIVE",
                "capabilities": [
                    "Autonomous BOLA / IDOR hypothesis formulation",
                    "AuthMatrix: 4-persona differential access matrix verification (Admin, User A, User B, Anonymous)",
                    "State-machine parameter tampering hypothesis generation",
                    "Authentication bypass probe sequencing"
                ],
                "inputs": ["attack_surface: dict", "session_vault_tokens: dict"],
                "outputs": ["HypothesisSet: list[SecurityHypothesis]"],
                "governance_scope": "Active Differential Probing / Non-Destructive Safe Harbor"
            },
            {
                "id": "agent-collector-04",
                "name": "EvidenceCollector",
                "version": "2.0.0",
                "role": "Deterministic Exploit Execution & Proof-of-Concept Capture",
                "model_binding": "Deterministic Engine / SessionVault",
                "lifecycle_state": "ACTIVE",
                "capabilities": [
                    "Multi-Persona Session Vault automated credential swapping",
                    "High-precision HTTP request/response differential delta capture",
                    "PoC curl reproduction script generation",
                    "Safe Harbor egress rate limiter & loopback isolation"
                ],
                "inputs": ["hypothesis: SecurityHypothesis", "victim_session: str", "attacker_session: str"],
                "outputs": ["CollectedEvidence: dict", "ResponseDifferential: dict", "PoC_Curl: str"],
                "governance_scope": "Strict Rate-Limited Probe Execution"
            },
            {
                "id": "agent-reviewer-05",
                "name": "ReviewerAgent",
                "version": "2.0.0",
                "role": "False Positive Elimination & CVSS 3.1 Scoring",
                "model_binding": settings.gemini_model,
                "lifecycle_state": "ACTIVE",
                "capabilities": [
                    "Adaptive Evidence Validation: verifies non-identical victim/attacker bodies",
                    "CVSS 3.1 Base Score & Vector string calculation",
                    "CWE & OWASP Top 10 category classification",
                    "Strict 0% hallucination verification gate"
                ],
                "inputs": ["unverified_finding: dict", "raw_evidence: dict"],
                "outputs": ["VerifiedFinding: Finding", "ConfidenceScore: float", "CVSS_Vector: str"],
                "governance_scope": "Deterministic Verification Gate"
            },
            {
                "id": "agent-reporter-06",
                "name": "ReporterAgent",
                "version": "2.0.0",
                "role": "Executive Synthesis & HackerOne Report Generation",
                "model_binding": settings.gemini_model,
                "lifecycle_state": "ACTIVE",
                "capabilities": [
                    "HackerOne / Bugcrowd compliant Markdown report synthesis",
                    "Actionable developer remediation & code mitigation advisory",
                    "Burp Suite XML (<items>) and HAR export package generator",
                    "Executive vulnerability impact summary generation"
                ],
                "inputs": ["verified_findings: list[Finding]", "investigation_id: str"],
                "outputs": ["InvestigationReport: markdown", "HackerOneReport: markdown", "BurpExportXML: str"],
                "governance_scope": "Secure Storage & Encrypted Export"
            }
        ]
    }


# ── Root Landing Page (Rich Cyber Interface for Judges & API clients) ──────────
@app.get("/", tags=["root"], summary="Swarm Fleet Root Landing Page")
async def root(request: Request):
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        from fastapi.responses import HTMLResponse
        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BugBounty Swarm — Autonomous AI Security Research Fleet</title>
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
            --success: #10b981;
            --warning: #f59e0b;
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
        .container { max-width: 1100px; width: 100%; }
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
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1.5rem; margin-bottom: 2.5rem; }
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
            display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem;
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
                    <div class="agent-role">Dynamic Crawling & Sitemap Parsing</div>
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
                    <div class="agent-role">5-Branch Evidence Graph (AEV v6)</div>
                    <div class="agent-badge">Debate Validator</div>
                </div>
                <div class="agent-node">
                    <div class="agent-name">ReportAgent</div>
                    <div class="agent-role">HackerOne Markdown Generation</div>
                    <div class="agent-badge">Executive Triage</div>
                </div>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <div class="card-title">🛡️ 4-Layer Scope Guardrails</div>
                <div class="card-text">
                    Enforces strict canonical URL normalization, RFC 1918 private IP blocking, AWS/GCP metadata barrier (<span class="mono">169.254.169.254</span>), and DNS rebinding prevention on every outbound socket.
                </div>
            </div>
            <div class="card">
                <div class="card-title">🧠 Anti-Hallucination Barrier</div>
                <div class="card-text">
                    Findings must survive deterministic differential execution across distinct personas (Alice/Bob) before graduating from <span class="mono">PROBABLE</span> to <span class="mono">VALIDATED</span>.
                </div>
            </div>
            <div class="card">
                <div class="card-title">📡 Real-Time SSE Telemetry</div>
                <div class="card-text">
                    Streams live thought progression, socket execution payloads, and evidence trees with monotonic sequence numbering and resilient <span class="mono">Last-Event-ID</span> rehydration.
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

