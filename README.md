# 🛡️ Autonomous Security Operations Platform (ASOP)

**Python (FastAPI) · PostgreSQL · Next.js · Google Gemini AI · Docker**

An AI-enabled security assurance platform that ingests live system logs, classifies threat anomalies (**SQL Injection**, **XSS**, **Brute Force**), calculates automated **0–100 risk scores**, collects **SHA-256 tamper-evident audit evidence**, validates **ISO 27001 / NIST 800-53 / OWASP ASVS security controls** in real time, and generates **LLM compliance and incident summary reports**.

---

## ✨ Key Capabilities

1. **AI Classification & Risk Scoring (`backend/engine.py`)**
   - Ingests live HTTP/auth telemetry (`POST /api/logs/ingest` & `POST /api/logs/simulate`).
   - Hybrid engine: sub-millisecond regex signature pre-filtering for **SQLi (`T1190`)**, **XSS (`T1189`)**, and **Brute Force (`T1110`)** + **Google Gemini AI** contextual reasoning and composite **Risk Score (0–100)** calculation.
2. **Automated Response & Audit Evidence Collection (`backend/models.py`)**
   - Automatically triggers containment workflows (`WAF_BLOCK_IP`, `SANITIZE_PAYLOAD & REVOKE_SESSION`, `LOCK_ACCOUNT_15M`).
   - Records cryptographic **SHA-256 chain-of-custody evidence digests** in PostgreSQL (`audit_evidence` table).
3. **Real-Time Control Validation & Gemini Compliance Reporting**
   - Continuously validates security controls (`ISO-A.8.26`, `OWASP-V5.3`, `NIST-AC-7`, `ISO-A.8.15`).
   - Generates executive Markdown **ISO 27001 / NIST Incident & Compliance Assurance Reports** via Google Gemini (`POST /api/reports/generate`).

---

## 🚀 Instant Setup ($0 Cost)

### Option A: 1-Click Instant Local Mode (Starts in 2 Seconds, No Docker Needed)
```powershell
.\start-instant.bat
```
- Opens the interactive ASOP SOC Dashboard at **http://localhost:8000** (and Swagger API docs at **http://localhost:8000/docs**).
- Pre-seeded with live attack logs, control validations, SHA-256 evidence, and a baseline compliance report.

### Option B: Full Docker Stack (PostgreSQL 16 + FastAPI + Next.js 14)
```powershell
docker compose up --build
```
- **Next.js Dashboard:** http://localhost:3000
- **FastAPI Backend & Docs:** http://localhost:8000/docs
- **PostgreSQL 16:** `localhost:5432` (`asop_db`)
