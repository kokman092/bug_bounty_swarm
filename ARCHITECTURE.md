# BugBounty Swarm — Comprehensive Architecture & Technical Specification

> **Submission for**: *The All Things Agentic Hackathon* (Google Cloud & Gemini)  
> **Track**: Autonomous Multi-Agent Systems & Enterprise Heavy Lifting (The Fortified Enterprise Fleet)  
> **Core Technologies**: Google Gemini 3.5 Flash, Google GenAI SDK (`google.genai`), FastAPI, Google Cloud Run, Cloud Firestore, Cloud Storage, Server-Sent Events (SSE)

---

## 1. Executive Summary & Value Proposition

Security teams and bug bounty researchers spend **thousands of hours manually inspecting API endpoints**, diffing request parameters, checking access controls across user sessions, and writing vulnerability reports.

**BugBounty Swarm** is an autonomous, multi-agent AI system that **takes on the heavy lifting** of authorized web application security assessments. It replaces tedious manual probing with a disciplined swarm of specialized Gemini-powered agents coordinated through a deterministic validation loop.

### Key Innovations:
1. **Division of Cognitive Labor**: Specialized agents for Recon, Attack Surface Analysis, Hypothesis Generation, Strict Review, and Reporting.
2. **Deterministic Anti-Hallucination Barrier**: Unlike naive LLM agents that hallucinate attack results, our `EvidenceCollector` deterministically executes HTTP tests in Python and diffs multi-identity responses before any claim is accepted.
3. **4-Layer Scope Guardrail**: Enforces strict URL normalization, RFC 1918 / Cloud metadata (`169.254.169.254`) blocking, DNS rebinding detection, and per-request scope verification.
4. **Resilient Cloud Event Architecture**: Atomic transactional sequence numbering in Firestore with `Last-Event-ID` SSE replay and real-time streaming telemetry.

---

## 2. End-to-End System Architecture

```mermaid
flowchart TB
    subgraph ClientLayer ["1. Presentation Layer (React + Vite)"]
        UI["Cybersecurity Dashboard\n(Real-Time Transcript & Status)"]
        SSE_Client["Resilient SSE Client\n(Last-Event-ID + Sequence Dedup)"]
        UI <--> SSE_Client
    end

    subgraph GatewayLayer ["2. API & Guardrail Layer (Cloud Run)"]
        API["FastAPI Gateway\n(/investigations, /stream, /report)"]
        AuthMiddleware["Auth & Rate Limiter\n(X-API-Key / Firebase Auth)"]
        ScopeGuard["4-Layer Scope Guardrail\n(URL Normalization + SSRF Block)"]
        API --> AuthMiddleware --> ScopeGuard
    end

    subgraph QueueLayer ["3. Durable Task Orchestration"]
        CT["Google Cloud Tasks\n(Rate-Limited Durable Queue)"]
        Runner["InvestigationRunner\n(State Machine & Checkpointing)"]
        CT --> Runner
    end

    subgraph AgentSwarm ["4. Autonomous Agent Swarm (Google ADK & Gemini)"]
        Orchestrator["Swarm Orchestrator"]
        
        subgraph Pipeline ["Agent Pipeline"]
            Recon["ReconAgent\n(Gemini 2.5 Flash + Tools)"]
            Surface["AttackSurfaceAgent\n(Gemini 2.5 Pro)"]
            
            subgraph Loop ["Finding Validation Loop (Max 4 Iterations)"]
                Hunter["HunterAgent\n(Hypothesis Generator)"]
                Collector["EvidenceCollector\n(DETERMINISTIC Python - No LLM)"]
                Reviewer["ReviewAgent\n(Gemini 2.5 Pro Triager)"]
                
                Hunter -->|Test Steps| Collector
                Collector -->|Diff & HTTP Proof| Reviewer
                Reviewer -->|Rejected / Next| Hunter
            end
            
            Reporter["ReportAgent\n(Gemini 2.5 Pro Markdown Compiler)"]
        end
        
        Orchestrator --> Recon
        Recon -->|Trimmed Summary| Surface
        Surface -->|Priority Vectors| Hunter
        Reviewer -->|Validated Findings| Reporter
    end

    subgraph TargetLayer ["5. Authorized Target"]
        VulnLab["Vulnerable Target API\n(Flask + SQLite, Isolated VPC)"]
    end

    subgraph DataLayer ["6. Persistence & Observability (Google Cloud)"]
        Firestore[("Cloud Firestore\n(Native NoSQL)")]
        GCS[("Cloud Storage\n(Evidence Overflow)")]
        Logging["Cloud Logging\n(Structured JSON Tracing)"]
    end

    ClientLayer <==>|HTTPS / SSE| GatewayLayer
    GatewayLayer -->|Enqueue Task| QueueLayer
    Runner --> AgentSwarm
    Collector -->|ScopeEnforcingHttpClient| VulnLab
    Recon -->|ScopeEnforcingHttpClient| VulnLab
    AgentSwarm -->|Atomic Event Sequences| Firestore
    AgentSwarm -->|Raw Payloads >16KB| GCS
    AgentSwarm -->|Audit Logs| Logging
```

---

## 3. Agent Pipeline & Cognitive Flow

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant Dashboard as React Dashboard
    participant Gateway as FastAPI (Cloud Run)
    participant Orchestrator as Agent Orchestrator
    participant Recon as ReconAgent (Flash)
    participant Surface as AttackSurfaceAgent (Pro)
    participant Hunter as HunterAgent (Pro)
    participant Collector as EvidenceCollector (Python)
    participant Reviewer as ReviewAgent (Pro)
    participant Reporter as ReportAgent (Pro)
    participant DB as Cloud Firestore

    User->>Dashboard: Input target URL & Launch
    Dashboard->>Gateway: POST /investigations
    Gateway->>Gateway: 4-Layer Scope & SSRF Validation
    Gateway->>DB: Create Investigation (AUTHORIZED)
    Gateway-->>Dashboard: 201 Created (investigation_id)
    Dashboard->>Gateway: GET /investigations/{id}/stream (SSE)

    Gateway->>Orchestrator: Run Investigation Pipeline
    
    %% Phase 1: Recon
    Orchestrator->>Recon: Scrape robots.txt, sitemaps, endpoints
    Recon-->>Orchestrator: Structured ReconResult JSON
    Orchestrator->>DB: Emit Event (RECON_COMPLETED)
    
    %% Phase 2: Attack Surface
    Orchestrator->>Surface: Synthesize prioritized attack vectors
    Surface-->>Orchestrator: Attack Surface Map (BOLA/IDOR prioritized)
    Orchestrator->>DB: Emit Event (SURFACE_ANALYZED)
    
    %% Phase 3: Loop
    loop Hypothesis & Validation Loop (Max 4 Iterations)
        Orchestrator->>Hunter: Propose testable hypothesis + test steps
        Hunter-->>Orchestrator: Hypothesis JSON (Method, Path, Multi-token headers)
        Orchestrator->>DB: Emit Event (HYPOTHESIS_PROPOSED)
        
        Orchestrator->>Collector: Deterministic Probing with ScopeEnforcingClient
        Collector->>Collector: Execute Step 1 (User A) & Step 2 (User B)
        Collector-->>Orchestrator: HTTP Evidence + Response Diff Matrix
        Orchestrator->>DB: Emit Event (EVIDENCE_COLLECTED)
        
        Orchestrator->>Reviewer: Triage hypothesis vs concrete evidence
        Reviewer-->>Orchestrator: Verdict: VALIDATED / REJECTED
        Orchestrator->>DB: Save Finding & Emit Verdict Event
    end

    %% Phase 4: Report
    Orchestrator->>Reporter: Compile Validated Findings directly from DB
    Reporter-->>Orchestrator: Executive Markdown Report
    Orchestrator->>DB: Save Report & Status: COMPLETED
    Orchestrator->>DB: Emit Event (INVESTIGATION_COMPLETED)
    
    Gateway-->>Dashboard: SSE pushes COMPLETED event
    Dashboard->>Gateway: GET /investigations/{id}/report
    Gateway-->>Dashboard: Full Report JSON + Markdown
    Dashboard-->>User: Render Interactive Report & Markdown Export
```

---

## 4. Google Cloud & Gemini Integration Matrix

| Component | GCP / Gemini Technology | Role in Architecture |
|---|---|---|
| **Reconnaissance** | `gemini-2.5-flash` | High-speed structural parsing of HTML, JavaScript endpoints, and robots.txt. |
| **Attack Surface Prioritization** | `gemini-2.5-pro` | Deep contextual reasoning across OWASP API Security Top 10 vectors. |
| **Vulnerability Hypothesis** | `gemini-2.5-pro` | Formulates deterministic, multi-step HTTP attack vectors and identity swaps. |
| **Evidence Validation** | Deterministic Python Engine | **Zero Hallucination Barrier**: Strict status code and response differential evaluation. |
| **Security Triaging & Judging** | `gemini-2.5-pro` | Evaluates evidence rigorously against false positives and hallucinations. |
| **Executive Reporting** | `gemini-2.5-pro` | Generates publication-ready Markdown reports with reproduction steps & remediations. |
| **Serverless API Hosting** | **Google Cloud Run** | Auto-scaling containerized FastAPI gateway with CPU allocation for active SSE streams. |
| **State & Telemetry Store** | **Cloud Firestore (Native)** | Monotonically sequenced event logs and JSON-native findings collections. |
| **Durable Task Queue** | **Google Cloud Tasks** | Rate-limited, retryable background dispatch decoupling API requests from agent execution. |
| **Evidence Overflow Storage** | **Cloud Storage (GCS)** | Offloads large HTTP responses and report bodies exceeding Firestore document limits. |

---

## 5. Security & Ethical Guardrails

1. **Model-Armor Style Scope Filter**:
   - URL Normalization resolves trailing slashes, default ports, case differences, and path traversal (`..`).
   - Rejects non-HTTP/HTTPS protocols (`file://`, `gopher://`, `ftp://`).
2. **SSRF & Private Network Defense**:
   - Prohibits all RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopbacks (`127.0.0.0/8`, `::1`), and link-local cloud metadata addresses (`169.254.169.254`, `metadata.google.internal`).
3. **DNS Rebinding Prevention**:
   - Re-resolves hostnames at request time and compares against authorization-time IPs.
4. **Per-Request Enforcement**:
   - Agents are barred from raw `httpx` or `requests`. All traffic flows through `ScopeEnforcingHttpClient`.
5. **Credential & Secret Sanitization**:
   - All outgoing event payloads, logs, and agent prompts pass through a recursive regex sanitizer redacting JWT tokens, passwords, cookies, and API keys.

---

## 6. Investigation State Machine

```
CREATED
  │  (target received)
  ▼
AUTHORIZING
  │  (URL normalization, allow-list lookup, SSRF check)
  ├─► REJECTED (Terminal)
  ▼
AUTHORIZED
  │  (persisted to Firestore)
  ▼
QUEUED
  │  (Cloud Task enqueued)
  ▼
RUNNING
  │  (Agent Swarm active)
  ├──► CANCELLING ──► CANCELLED (Terminal)
  ├──► FAILED ──► RETRYING ──► RUNNING (Max 2 retries)
  │                 │
  │                 └──► FAILED (Terminal, retries exhausted)
  ▼
FINALIZING
  │  (ReportAgent compiling)
  ▼
COMPLETED (Terminal)
```
