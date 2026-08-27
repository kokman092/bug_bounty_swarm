# 🏆 All Things Agentic Hackathon — Devpost Official Submission

**Project Name:** BugBounty Swarm  
**Tagline:** Autonomous multi-agent AI security research fleet that discovers, challenges, and validates real-world API vulnerabilities with zero hallucinations.  
**Primary Track:** **The Fortified Enterprise Fleet** ($180,000 Global Prize Pool • $50,000 Grand Prize)  
**Secondary Track / Eligible Awards:** **The Taskmaster**, **Best Architectural Design**, **Best Multimodal UX**, **Individual/Hobbyist**  
**Live Google Cloud Run Backend:** [https://bugbounty-swarm-backend-339717745624.us-central1.run.app/docs](https://bugbounty-swarm-backend-339717745624.us-central1.run.app/docs)  
**Enterprise Agent Registry (Live):** [https://bugbounty-swarm-backend-339717745624.us-central1.run.app/api/agents](https://bugbounty-swarm-backend-339717745624.us-central1.run.app/api/agents)  
**GitHub Repository:** [https://github.com/kokman092/bug_bounty_swarm](https://github.com/kokman092/bug_bounty_swarm)  
**Google Cloud Project ID:** `project-4183c876-9be4-4bc7-9f2` (Region: `us-central1`)  

---

## 📌 Executive Pitch & Summary

Most AI security tools are single-shot prompt wrappers that regurgitate theoretical vulnerabilities or flood developers with false positives. **BugBounty Swarm** is an autonomous, multi-agent AI security research fleet built on **Google Gemini 3.5 Flash**, **Google GenAI SDK**, **FastAPI**, **Google Cloud Firestore**, and **Google Cloud Run**.

Instead of a single chatbot, BugBounty Swarm deploys a collaborative, adversarial fleet of 6 specialized agents that **actively investigate web targets, generate test hypotheses, execute live HTTP differential sockets, challenge each other's findings in real-time debate loops, and compile triage-ready HackerOne reports**.

---

## 🏛️ Track Alignment: The Fortified Enterprise Fleet

```
┌───────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 THE FORTIFIED ENTERPRISE FLEET                                    │
├─────────────────────────────────┬─────────────────────────────────────────────────────────────────┤
│ 1. Discovery & Lifecycle        │ Agent Registry cataloging specialized, decoupled agents:        │
│    (Agent Registry)             │ ReconAgent, AttackSurfaceAgent, HunterAgent, ReviewAgent,       │
│                                 │ ReportAgent with strict lifecycle state transitions.            │
├─────────────────────────────────┼─────────────────────────────────────────────────────────────────┤
│ 2. Core Execution & State       │ Cloud Run Agent Runtime executing long-running asynchronous     │
│    (Runtime & Memory Bank)      │ background investigations with Firestore Memory Bank for        │
│                                 │ cross-session state, deduplication, and feedback propagation.   │
├─────────────────────────────────┼─────────────────────────────────────────────────────────────────┤
│ 3. Security & Governance        │ - Agent Identity: Zero-Trust test personas (Alice, Bob, Admin)  │
│    (Zero-Trust, Model Armor)    │ - Agent Gateway: 4-Layer Scope Guardrails (SSRF, metadata block)│
│                                 │ - Adaptive Evidence Validator: Semantic 5-branch Evidence Graph │
├─────────────────────────────────┼─────────────────────────────────────────────────────────────────┤
│ 4. Observability & Telemetry    │ Real-time Server-Sent Events (SSE) telemetry stream, structured │
│    (Audit Logs & Reasoning)     │ JSON logging, and interactive React mission-control dashboard.   │
└─────────────────────────────────┴─────────────────────────────────────────────────────────────────┘
```

---

## 🤖 The 6-Agent Catalog

1. **ReconAgent** (`v2.0.0` | Gemini 3.5 Flash): Live crawls target applications, parses `robots.txt`, `sitemap.xml`, and OpenAPI/Swagger schemas.
2. **AttackSurfaceAgent** (`v2.0.0` | Gemini 3.5 Flash): Symbolic parameter normalizer (`{{id}}` $\rightarrow$ `1`), mapping and prioritizing high-risk routes.
3. **HunterAgent** (`v2.0.0` | Gemini 3.5 Flash): Formulates concrete, multi-step HTTP test hypotheses using pre-authorized researcher personas.
4. **EvidenceCollector** (`v2.0.0` | Python & `httpx`): Executes non-destructive HTTP requests with automated session credential injection via `SessionVault` — **guaranteeing zero LLM hallucinations**.
5. **ReviewerAgent** (`v2.0.0` | Gemini 3.5 Flash & AEV v6.1): Evaluates evidence against the **5-Branch Semantic Evidence Graph** (`Scope`, `Authentication`, `Authorization`, `Impact`, `Reproducibility`), actively rejecting false positives.
6. **ReporterAgent** (`v2.0.0` | Gemini 3.5 Flash): Compiles validated findings into publication-ready HackerOne/Bugcrowd Markdown reports with reproducible `curl` commands and actionable remediation code.

---

## 🧪 Empirical Benchmark & Reliability Lab Results

```
============================================================
RELIABILITY SUMMARY
============================================================
Total Trials Executed:        3
Reject -> Pivot -> Validate:  2 (67%)  <-- TRUE ADVERSARIAL SWARM INTELLIGENCE
Empty / Unresponsive:         0 (0%)
Average Duration:             105.82s
Verdict:                      DEMO-READY: pivot sequence appears reliably.
============================================================
```

---

## 🛠️ Technology Stack

- **LLM Foundation**: **Google Gemini 3.5 Flash** / **Gemini Flash Lite** via the official **Google GenAI SDK (`google.genai`)**.
- **Backend & Swarm Runtime**: **FastAPI** with async background tasks and Server-Sent Events (SSE) streaming.
- **Enterprise Cloud Infrastructure**:
  - **Google Cloud Run**: Serverless container execution for backend API and agent workers.
  - **Google Cloud Firestore (Native)**: ACID transactional state store and event sourcing.
  - **Google Cloud Storage (GCS)**: Deployment artifacts and large evidence payloads.
- **Frontend Dashboard**: React 18, Vite, Tailwind CSS, Lucide icons.
