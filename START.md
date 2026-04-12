# VulnPriority AI — Quick Start

## 1. Start the Backend (one command)

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Backend will be live at: http://localhost:8000

## 2. Open the Frontend

Just double-click `frontend/index.html` in your browser — no build needed.

## 3. Run a Demo

1. Click **"⚡ Load Demo Dataset"** to load 12 real packages
2. System is pre-configured as *payment-gateway* (Critical, PCI-scoped)
3. Optionally upload a VA report PDF to extract CVE IDs automatically
4. Click **"Run Agentic Analysis"**
5. Watch the 9-step live pipeline execute
6. Explore: Vulnerabilities → Exploits & PoC → Dev Tickets → Patch Calendar → Dashboard

## Optional: Add API Keys for Enhanced AI

In Configure page, click **"API Keys"**:
- **Anthropic key** (`sk-ant-...`) → Claude claude-opus-4-5 generates natural language rationale
- **Gemini key** (`AIza...`) → POCme queries for real PoC exploit research

Without keys, the built-in rule-based engine handles everything — fully functional.

## Architecture — 9-Step Agentic Pipeline

```
SBOM / package.json  +  VA Report (PDF/text)
             ↓
   [1] Input Parse   — Extract packages + CVE IDs from VA report
             ↓
   [2] CVE Discovery — NVD CVE API 2.0 SCA scan + VA CVE merge
             ↓
   [3] Deep Research — NVD history + Gemini "Deep Intelligence Gathering"
                       (exact POCme /api/research.js logic)
             ↓
   [4] Exploit Gen   — Gemini "Senior Vulnerability Researcher" PoC
                       (exact POCme /api/exploit.js logic)
             ↓
   [5] AI Evaluation — Claude agent: viability / risk / remediation / verification
             ↓
   [6] Blast Radius  — Dependency graph traversal → affected services
             ↓
   [7] AI Scoring    — Priority = (CVSS × PoC × BlastRadius) ÷ Complexity × Tier × RegFlag
             ↓
   [8] Rationale     — Claude claude-opus-4-5 auditable natural-language explanation
             ↓
   [9] Schedule Assign — Skill-match + sprint capacity → completion date per ticket
             ↓
   Ranked Plan + Exploits & PoC + Dev Tickets + Patch Calendar + Exec Dashboard
```

## API Keys

| Key | Effect |
|-----|--------|
| Anthropic `sk-ant-...` | Claude claude-opus-4-5 rationale + exploit evaluation |
| Gemini `AIza...` | Real-time CVE intelligence + PoC generation via POCme engine |

Without keys: rule-based engine + code stubs — fully functional for demos.
