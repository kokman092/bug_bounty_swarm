# 🎬 BugBounty Swarm — Master Video Teleprompter & Recording Guide

> **Hackathon**: *All Things Agentic Hackathon* (Google Cloud & Gemini)  
> **Project**: BugBounty Swarm — Autonomous Multi-Agent Security Fleet  
> **Track**: **The Fortified Enterprise Fleet**  
> **Target Video Length**: **3:45 – 4:00 minutes** (Total Spoken Words: ~500 words @ 130 wpm natural pacing)  

---

## 🎛️ Pre-Recording Setup Checklist (Do This Before Recording)

1. **Browser Tab 1**: Open React Dashboard at `http://localhost:3000` (or your live Cloud Run URL). Set browser zoom to 100% or 110% for crisp text.
2. **Browser Tab 2**: Open Google Cloud Console: Cloud Run Services (`bugbounty-swarm`) and Firestore Collections (`investigations`, `findings`, `events`).
3. **Browser Tab 3**: Open GitHub Repository with [`ARCHITECTURE.md`](file:///e:/Ai_bugbounty/ARCHITECTURE.md) and [`README.md`](file:///e:/Ai_bugbounty/README.md).
4. **Terminal / Split View (Optional)**: Have the backend logs or curl terminal open ready to show live HTTP socket execution.
5. **Microphone**: Quiet room, steady natural pace.

---

## ⏱️ Scene-by-Scene Teleprompter & Visual Direction

```
┌───────────────┬─────────────────────────────────────────────────┬───────────┐
│ Time          │ Visual Scene & Screen Action                    │ Target Ws │
├───────────────┼─────────────────────────────────────────────────┼───────────┤
│ 0:00 - 0:40   │ Hook: The Manual Security Crisis & False Alarms │ ~85 words │
│ 0:40 - 1:20   │ Architecture: The Fortified Enterprise Fleet    │ ~90 words │
│ 1:20 - 2:45   │ Live Demo: The Reject -> Pivot Debate Loop      │ ~190 words│
│ 2:45 - 3:25   │ Impact: Interactive Findings & HackerOne Export │ ~80 words │
│ 3:25 - 3:55   │ Production Proof: Cloud Run & Firestore Backing │ ~65 words │
└───────────────┴─────────────────────────────────────────────────┴───────────┘
```

---

### 🎬 Scene 1: The Problem & The Multi-Agent Breakthrough (0:00 – 0:40)

**🖥️ On Screen:**
- Start on a busy API endpoint list or Burp Suite / terminal diff showing endless manual headers and tokens.
- At 0:25, switch cleanly to the **BugBounty Swarm Mission-Control Dashboard** (`http://localhost:3000`).

**🎙️ Spoken Teleprompter (Read Aloud):**
> *"Securing modern enterprise APIs is one of the most critical challenges in software engineering. But today, vulnerability hunting is held back by tedious manual labor.*
>
> *Security teams spend hundreds of hours manually discovering routes, mapping parameters, swapping session tokens, and diffing HTTP responses.*
>
> *Meanwhile, legacy scanners generate massive false-positive noise, and single-shot LLM chatbots hallucinate fake vulnerabilities.*
>
> *We built **BugBounty Swarm** — an autonomous multi-agent AI security fleet on Gemini and Google Cloud that doesn't just chat about security: it actively probes, debates, challenges, and proves real vulnerabilities with zero hallucinations."*

---

### 🎬 Scene 2: Fleet Architecture & Google Cloud Foundation (0:40 – 1:20)

**🖥️ On Screen:**
- Display the clean **Architecture Diagram** from `ARCHITECTURE.md` (or full-screen slide).
- Highlight the 6 specialized agents and the Google Cloud Run / Firestore backing.

**🎙️ Spoken Teleprompter (Read Aloud):**
> *"Entering the **Fortified Enterprise Fleet** track, BugBounty Swarm is built on **Google Gemini 3.5 Flash**, the **Google GenAI SDK**, **FastAPI**, **Google Cloud Firestore**, and **Google Cloud Run**.*
>
> *Rather than a monolithic prompt, our system operates as an institutional fleet of specialized agents:*
> - * **ReconAgent** performs active live web crawling.*
> - * **AttackSurfaceAgent** prioritizes high-risk attack surfaces.*
> - * **HunterAgent** dynamically designs structured multi-step test probes.*
> - * Our deterministic **EvidenceCollector** executes live HTTP socket requests in Python — completely eliminating LLM hallucinations.*
> - * **ReviewAgent** evaluates findings against a 5-Branch Semantic Evidence Graph.*
> - * And **ReportAgent** compiles publication-ready HackerOne reports.*
>
> *All operations are guarded by a 4-layer Scope Guardrail blocking internal SSRF and cloud metadata access."*

---

### 🎬 Scene 3: Live Demo — The Reject-Then-Pivot Debate Loop (1:20 – 2:45)

**🖥️ On Screen:**
- Switch to the live **React Dashboard** (`http://localhost:3000`).
- Enter target `http://localhost:5000` (or authorized URL) and click **"Launch Investigation"**.
- Watch the live **Server-Sent Events (SSE)** transcript stream in real time.
- Zoom in on **Iteration 1 (Rejection)** and then **Iteration 2 (Pivot & Validation)**.

**🎙️ Spoken Teleprompter (Read Aloud):**
> *"Let's launch an active assessment against an authorized enterprise target.*
>
> *As soon as we click **Launch Investigation**, our real-time Server-Sent Events stream springs to life.*
>
> *First, **ReconAgent** crawls the live application, discovering endpoints like user profiles, organizations, and webhooks. **AttackSurfaceAgent** analyzes the attack surface and prioritizes authorization boundaries for testing.*
>
> *Now, watch the finding loop — this is our core differentiator:*
>
> *In Iteration 1, **HunterAgent** proposes a Broken Object Level Authorization hypothesis against a hardened enterprise profile endpoint.*
>
> *Our Evidence Collector dispatches the probe as User 2 (Bob). But look at **ReviewAgent**:*
> *Reviewer challenges the finding — detecting that the server returned Bob's own profile without cross-account data leakage. The finding is **REJECTED** with high confidence!*
>
> *Instead of stopping, Hunter reads the rejection feedback, understands the defense mechanism, and dynamically **pivots** to the organization secrets endpoint.*
>
> *In Iteration 2, Hunter dispatches a cross-tenant probe — and Evidence Collector captures Alice's live production API keys leaked to Bob! Reviewer confirms **Level 4 BOLA** with cryptographic proof.*
>
> *The swarm continues, autonomously validating Server-Side Request Forgery and Privilege Escalation via Mass Assignment."*

---

### 🎬 Scene 4: Interactive Finding Cards & HackerOne Report (2:45 – 3:25)

**🖥️ On Screen:**
- Scroll down the dashboard to reveal the **3 Validated Vulnerability Cards**.
- Expand a card showing the technical severity, reproduction steps, and Evidence Tree.
- Click the **"Raw MD"** toggle to reveal the clean, full Markdown report.

**🎙️ Spoken Teleprompter (Read Aloud):**
> *"In under 25 seconds, the swarm presents 3 confirmed, high-severity vulnerabilities in interactive finding cards:*
> - * Critical BOLA on Organization Secrets*
> - * SSRF on Webhook Integration*
> - * And Privilege Escalation to Admin*
>
> *Notice that rejected hypothesis number 1 was cleanly filtered out — delivering **zero false positives** to triage teams.*
>
> *Each card contains the exact differential evidence and reproduction curl command. With one click, we can view and export the complete HackerOne and Bugcrowd report, fully formatted with root cause analysis and developer remediation guidance."*

---

### 🎬 Scene 5: Google Cloud Deployment Proof & Conclusion (3:25 – 3:55)

**🖥️ On Screen:**
- Switch to the **Google Cloud Console** tab.
- Show **Cloud Run** service `bugbounty-swarm` (with active metrics/green checkmark).
- Show **Cloud Firestore** database showing the `investigations`, `findings`, and `events` collections.
- End on the BugBounty Swarm dashboard with a strong concluding slide.

**🎙️ Spoken Teleprompter (Read Aloud):**
> *"The entire swarm backend runs serverless on **Google Cloud Run**, with durable transactional event logs and investigation history persisted in **Cloud Firestore**.*
>
> *BugBounty Swarm demonstrates the true potential of the **Fortified Enterprise Fleet** — turning hours of exhausting security busywork into a fast, autonomous, and mathematically verified 20-second assessment on Gemini 3.5 Flash and Google Cloud.*
>
> *Thank you, and happy hacking!"*

---

## 💡 Pro-Tips for Recording

1. **Cursor Movement**: Move your mouse deliberately and smoothly. Don't shake or circle the mouse rapidly.
2. **Key Moments to Pause (1–2 seconds)**:
   - When the **REJECTED** badge appears in red on the transcript (pause 1s so judges read it).
   - When the **VALIDATED** badge appears in green on the secrets endpoint (pause 1s).
   - When toggling the **Raw MD** HackerOne report.
3. **Audio Quality**: Speak clearly with enthusiasm; your voice carries the technical authority of the project!
