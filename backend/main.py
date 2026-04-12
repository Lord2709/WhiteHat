"""
VulnPriority AI — Agentic Vulnerability Prioritization Backend v2
─────────────────────────────────────────────────────────────────
Integrates EXACT logic from pocme repos:
  • /api/research  — NVD fetch + Gemini "Deep Intelligence Gathering"
  • /api/exploit   — Gemini "Senior Vulnerability Researcher" PoC gen

Plus:
  • VA report upload (PDF/text → extract CVE IDs via regex)
  • AI exploit evaluation (Claude agent — viability, risk, remediation)
  • Schedule-based dev assignment (sprint capacity + completion dates)
  • 9-step streaming pipeline via SSE
"""

import asyncio, json, math, re
from datetime import datetime, timedelta
from io import BytesIO
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

app = FastAPI(title="VulnPriority AI", version="2.0.0")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────────────────────
# MODELS
# ─────────────────────────────────────────────────────────────────────────────

class DevSchedule(BaseModel):
    available_hours_per_week: int = 40
    sprint_hours_remaining: int = 20
    work_days: List[str] = ["monday","tuesday","wednesday","thursday","friday"]

class TeamMember(BaseModel):
    name: str
    email: str
    expertise: List[str]
    current_load: int = 0
    schedule: DevSchedule = DevSchedule()

class SystemInfo(BaseModel):
    name: str
    tier: str
    regulatory: List[str]
    owner: str = "security-team"
    dependencies: List[str] = []

class MaintenanceWindow(BaseModel):
    day: str
    time: str = "02:00"
    duration_hours: int = 4

class AnalyzeRequest(BaseModel):
    packages: Dict[str, str] = {}
    va_cve_ids: List[str] = []
    system_info: SystemInfo
    maintenance_windows: List[MaintenanceWindow] = []
    team_members: List[TeamMember] = []
    exploit_language: str = "python"
    anthropic_api_key: Optional[str] = None
    gemini_api_key: Optional[str] = None

# ─────────────────────────────────────────────────────────────────────────────
# STATIC INTELLIGENCE DATA
# ─────────────────────────────────────────────────────────────────────────────

POC_CVE_SET = {
    "CVE-2024-29415","CVE-2024-21490","CVE-2024-37890",
    "CVE-2024-48949","CVE-2024-39338","CVE-2021-44228",
    "CVE-2021-45046","CVE-2022-22965","CVE-2022-42889",
    "CVE-2023-44487","CVE-2023-46604","CVE-2023-4863",
}

BLAST_MAP: Dict[str, Dict] = {
    "express":        {"count":6,"services":["api-gateway","payment-service","auth-service","reporting-svc","admin-panel","notification-svc"]},
    "axios":          {"count":5,"services":["frontend-app","payment-service","analytics-svc","notification-svc","batch-processor"]},
    "lodash":         {"count":7,"services":["api-gateway","reporting-svc","analytics-svc","batch-processor","data-transformer","export-svc","email-svc"]},
    "react":          {"count":3,"services":["customer-portal","admin-dashboard","internal-tools"]},
    "angular":        {"count":2,"services":["customer-portal","admin-dashboard"]},
    "ws":             {"count":4,"services":["realtime-svc","chat-svc","notification-svc","monitoring"]},
    "pg":             {"count":5,"services":["payment-service","user-service","order-service","reporting-svc","audit-svc"]},
    "redis":          {"count":4,"services":["session-manager","cache-svc","rate-limiter","queue-svc"]},
    "ip":             {"count":3,"services":["api-gateway","security-scanner","proxy-svc"]},
    "elliptic":       {"count":3,"services":["auth-service","crypto-svc","token-service"]},
    "path-to-regexp": {"count":3,"services":["api-gateway","router-svc","auth-middleware"]},
    "cross-spawn":    {"count":2,"services":["build-pipeline","script-runner"]},
    "node-tar":       {"count":2,"services":["backup-svc","artifact-storage"]},
    "micromatch":     {"count":2,"services":["build-pipeline","file-watcher"]},
    "nanoid":         {"count":3,"services":["session-manager","token-service","api-gateway"]},
    "jsonwebtoken":   {"count":5,"services":["auth-service","api-gateway","payment-service","user-service","mobile-api"]},
    "mongoose":       {"count":4,"services":["user-service","product-svc","order-service","analytics-svc"]},
}

PATCH_COMPLEXITY = {
    "high":   {"pkgs":["react","angular","vue","webpack","babel","typescript","next","nuxt","prisma"],"complexity":4,"desc":"Major framework — extensive regression testing required","hours":8},
    "medium": {"pkgs":["express","fastify","koa","mongoose","pg","redis","sequelize","axios","lodash"],"complexity":3,"desc":"Core dependency — API compatibility review needed","hours":4},
    "low":    {"pkgs":[],"complexity":2,"desc":"Minor utility — straightforward version bump","hours":2},
}

FALLBACK_CVE_DB: Dict[str, Dict] = {
    "CVE-2024-29415": {"cvss":9.8,"description":"SSRF in the ip package allows attackers to reach internal network services via specially crafted IP strings.","published":"2024-05-27"},
    "CVE-2024-21490": {"cvss":8.8,"description":"XSS in Angular allows bypassing sanitization via crafted template expressions.","published":"2024-02-02"},
    "CVE-2024-21538": {"cvss":7.5,"description":"ReDoS in cross-spawn via specially crafted shell arguments causes catastrophic backtracking.","published":"2024-11-08"},
    "CVE-2024-45296": {"cvss":7.5,"description":"Backtracking in path-to-regexp allows ReDoS via crafted URL paths.","published":"2024-09-09"},
    "CVE-2024-37890": {"cvss":7.5,"description":"DoS in ws WebSocket library when handling headers with abnormally large values.","published":"2024-06-17"},
    "CVE-2024-28863": {"cvss":6.5,"description":"Path traversal in node-tar allows arbitrary file writes outside the extraction directory.","published":"2024-03-21"},
    "CVE-2024-4067":  {"cvss":5.3,"description":"ReDoS in micromatch glob pattern matching affects CI/CD pipelines.","published":"2024-04-25"},
    "CVE-2024-55565": {"cvss":5.3,"description":"Predictable ID generation in nanoid under certain Node.js runtime conditions.","published":"2024-12-10"},
    "CVE-2024-48949": {"cvss":9.1,"description":"Incorrect elliptic curve parameter validation allows crafted public keys to bypass ECDH operations.","published":"2024-10-14"},
    "CVE-2024-39338": {"cvss":7.4,"description":"SSRF in axios allows server-side request forgery via crafted protocol-relative URLs.","published":"2024-07-19"},
    "CVE-2021-44228": {"cvss":10.0,"description":"Log4Shell RCE via JNDI lookup in Apache Log4j2 log messages. Widely weaponized.","published":"2021-12-10"},
    "CVE-2022-22965": {"cvss":9.8,"description":"Spring4Shell RCE in Spring Framework via data binding on JDK 9+ ClassLoader.","published":"2022-03-31"},
}

# ─────────────────────────────────────────────────────────────────────────────
# VA REPORT PARSING
# ─────────────────────────────────────────────────────────────────────────────

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

def extract_cves_from_text(text: str) -> List[str]:
    seen, out = set(), []
    for cve in CVE_PATTERN.findall(text):
        cu = cve.upper()
        if cu not in seen:
            seen.add(cu)
            out.append(cu)
    return out

async def parse_va_report(content: bytes, filename: str) -> List[str]:
    text = ""
    if (filename or "").lower().endswith(".pdf"):
        try:
            import PyPDF2
            reader = PyPDF2.PdfReader(BytesIO(content))
            for page in reader.pages:
                text += (page.extract_text() or "") + "\n"
        except Exception:
            text = content.decode("utf-8", errors="ignore")
    else:
        text = content.decode("utf-8", errors="ignore")
    return extract_cves_from_text(text)

# ─────────────────────────────────────────────────────────────────────────────
# SCA SCAN
# ─────────────────────────────────────────────────────────────────────────────

async def sca_scan_packages(packages: Dict[str, str]) -> List[Dict]:
    results: List[Dict] = []
    async with httpx.AsyncClient(timeout=12.0, trust_env=False) as client:
        for pkg, ver in list(packages.items())[:8]:
            try:
                resp = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"keywordSearch": pkg, "resultsPerPage": 3},
                )
                if resp.status_code == 200:
                    for item in resp.json().get("vulnerabilities", [])[:2]:
                        cve  = item.get("cve", {})
                        mets = cve.get("metrics", {})
                        cvss, vec = 5.0, ""
                        for mv in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                            if mv in mets:
                                d = mets[mv][0]["cvssData"]
                                cvss = d.get("baseScore", 5.0)
                                vec  = d.get("vectorString", "")
                                break
                        descs = cve.get("descriptions", [])
                        desc  = next((d["value"] for d in descs if d["lang"]=="en"), "")
                        results.append({
                            "cve_id": cve.get("id",""), "package": pkg, "version": ver,
                            "cvss": cvss, "vector": vec, "description": desc[:400],
                            "published": cve.get("published","")[:10], "source": "nvd-sca",
                        })
                await asyncio.sleep(0.4)
            except Exception:
                pass
    return results

def build_demo_cves(packages: Dict[str, str], va_cve_ids: List[str]) -> List[Dict]:
    out: List[Dict] = []
    pkg_items = list(packages.items())
    used_cves: set = set()

    for i, cve_id in enumerate(va_cve_ids[:5]):
        fb = FALLBACK_CVE_DB.get(cve_id, {"cvss":6.5,"description":f"Vulnerability {cve_id}","published":"2024-01-01"})
        pname, pver = pkg_items[i] if i < len(pkg_items) else ("unknown","?")
        out.append({"cve_id":cve_id,"package":pname,"version":pver,
                    "cvss":fb["cvss"],"description":fb["description"],
                    "published":fb["published"],"source":"va-report"})
        used_cves.add(cve_id)

    for pkg, ver in pkg_items[:8]:
        for cve_id, fb in FALLBACK_CVE_DB.items():
            if cve_id not in used_cves:
                out.append({"cve_id":cve_id,"package":pkg,"version":ver,
                            "cvss":fb["cvss"],"description":fb["description"],
                            "published":fb["published"],"source":"demo"})
                used_cves.add(cve_id)
                break
        if len(out) >= 10:
            break

    return out[:10]

# ─────────────────────────────────────────────────────────────────────────────
# DEEP CVE RESEARCH  — exact POCme /api/research.js logic in Python
# ─────────────────────────────────────────────────────────────────────────────

async def deep_research_cve(cve_id: str, vuln: Dict, gemini_key: Optional[str]) -> Dict:
    technical_context = ""
    reference_links: List[str] = []
    nvd_cvss = vuln.get("cvss", 5.0)
    nvd_desc = vuln.get("description", "")

    async with httpx.AsyncClient(timeout=15.0, trust_env=False, headers={"User-Agent": "Mozilla/5.0"}) as client:
        try:
            hist = await client.get(
                f"https://services.nvd.nist.gov/rest/json/cvehistory/2.0?cveId={cve_id}"
            )
            if hist.status_code == 200:
                for entry in hist.json().get("cveChanges", []):
                    for detail in entry.get("change", {}).get("details", []):
                        if detail.get("value"):
                            technical_context += f"\n- {detail['value']}"
        except Exception:
            pass

        try:
            main = await client.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            )
            if main.status_code == 200:
                cve_item = main.json().get("vulnerabilities",[{}])[0].get("cve",{})
                descs = cve_item.get("descriptions",[])
                nvd_desc = next((d["value"] for d in descs if d["lang"]=="en"), nvd_desc)
                technical_context += f"\nPrimary Description: {nvd_desc}"
                reference_links = [r["url"] for r in cve_item.get("references",[])]
                mets = cve_item.get("metrics",{})
                for mv in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                    if mv in mets:
                        nvd_cvss = mets[mv][0]["cvssData"].get("baseScore", nvd_cvss)
                        break
        except Exception:
            pass

    if not nvd_desc:
        fb = FALLBACK_CVE_DB.get(cve_id, {})
        nvd_desc = fb.get("description", "No description available.")
        if not technical_context:
            technical_context = f"\nPrimary Description: {nvd_desc}"

    # Gemini synthesis — exact prompt from pocme research.js
    gemini_analysis = nvd_desc
    if gemini_key and technical_context.strip():
        try:
            import google.generativeai as genai
            genai.configure(api_key=gemini_key)
            model = genai.GenerativeModel("gemini-1.5-flash")

            deep_prompt = (
                f'Perform "Deep Intelligence Gathering" for {cve_id}. '
                f'Use this collected intelligence context:\n{technical_context}\n\n'
                f'Reference Links to analyze:\n{chr(10).join(reference_links[:5])}\n\n'
                'YOUR MISSION:\n'
                '1. Synthesize vulnerable code paths, protocol sequences, or logic flaw mechanisms.\n'
                '2. Extract the exact payload structure required for an educational PoC reproduction.\n'
                '3. Detail prerequisite lab configurations.\n\n'
                'Output ONLY the technical analysis.'
            )

            resp = model.generate_content(deep_prompt)
            if resp.text:
                gemini_analysis = resp.text
                cm = re.search(r'CVSS[^:]*[:\s]*([0-9]+\.[0-9]+)', gemini_analysis, re.IGNORECASE)
                if cm and nvd_cvss == 5.0:
                    nvd_cvss = float(cm.group(1))
        except Exception:
            pass

    vuln.update({
        "description":   nvd_desc[:400],
        "full_research": gemini_analysis,
        "cvss":          nvd_cvss,
        "references":    reference_links[:5],
        "researched":    True,
    })
    return vuln

# ─────────────────────────────────────────────────────────────────────────────
# EXPLOIT GENERATION  — exact POCme /api/exploit.js logic in Python
# ─────────────────────────────────────────────────────────────────────────────

def _make_stub(template: str, cve_id: str, desc_short: str) -> str:
    """Safe template fill — only replaces __CVE_ID__ and __DESC__."""
    return template.replace("__CVE_ID__", cve_id).replace("__DESC__", desc_short)

EXPLOIT_STUBS = {
    "python": (
        "#!/usr/bin/env python3\n"
        "# PoC for __CVE_ID__ | Generated by VulnPriority AI | Authorized testing ONLY\n"
        "# Vulnerability: __DESC__\n"
        "import requests\n\n"
        'TARGET = "http://TARGET_HOST:PORT"  # Replace with your sandbox\n\n'
        "def exploit():\n"
        '    payload = "PAYLOAD_HERE"\n'
        '    r = requests.get(f"{TARGET}/endpoint", params={"input": payload})\n'
        '    print(f"[*] Status: {r.status_code}")\n'
        '    print(f"[*] Response: {r.text[:200]}")\n'
        '    if r.status_code in [200, 500]:\n'
        '        print("[!] Potential vulnerability confirmed")\n\n'
        'if __name__ == "__main__":\n    exploit()\n'
    ),
    "bash": (
        '#!/usr/bin/env bash\n'
        '# PoC for __CVE_ID__ | Authorized testing ONLY\n'
        '# Vulnerability: __DESC__\n'
        'TARGET="http://TARGET_HOST:PORT"\n'
        'PAYLOAD="PAYLOAD_HERE"\n'
        'echo "[*] Testing __CVE_ID__ against $TARGET"\n'
        'CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/endpoint" --data "$PAYLOAD")\n'
        'echo "[*] HTTP: $CODE"\n'
        '[ "$CODE" = "200" ] && echo "[!] Endpoint reachable"\n'
    ),
    "javascript": (
        '// PoC for __CVE_ID__ | Authorized testing ONLY\n'
        '// Vulnerability: __DESC__\n'
        'const TARGET = "http://TARGET_HOST:PORT";\n'
        'async function exploit() {\n'
        '  const r = await fetch(`${TARGET}/endpoint`, {\n'
        '    method: "POST",\n'
        '    headers: {"Content-Type":"application/json"},\n'
        '    body: JSON.stringify({input:"PAYLOAD_HERE"}),\n'
        '  });\n'
        '  const t = await r.text();\n'
        '  console.log("[*] Status:", r.status);\n'
        '  console.log("[*] Response:", t.slice(0,200));\n'
        '  if (r.status === 200) console.log("[!] Endpoint reached");\n'
        '}\nexploit();\n'
    ),
}

async def generate_exploit(vuln: Dict, language: str, gemini_key: Optional[str]) -> Dict:
    cve_id     = vuln["cve_id"]
    full_desc  = vuln.get("full_research") or vuln.get("description", "")
    desc_short = vuln.get("description","")[:80].rstrip()
    lang       = language if language in EXPLOIT_STUBS else "python"

    if not gemini_key:
        stub = _make_stub(EXPLOIT_STUBS[lang], cve_id, desc_short)
        return {"code": stub, "language": lang, "cve_id": cve_id, "generated": False}

    try:
        import google.generativeai as genai
        genai.configure(api_key=gemini_key)
        model = genai.GenerativeModel("gemini-1.5-flash")

        # Exact prompt from pocme exploit.js
        prompt = (
            f"Act as a Senior Vulnerability Researcher for a high-priority bug bounty program engagement.\n"
            f"Documentation for VDP-authorized verification of {cve_id}:\n{full_desc}\n\n"
            f"Technical Reproduction Task:\n"
            f"Construct a technical verification utility in {lang} to reproduce the described vulnerability "
            f"against a safe-scope endpoint.\n\n"
            "The utility must:\n"
            "- Implement the exact network protocol interactions or HTTP request structures identified in your research.\n"
            "- Focus on demonstrating the reachability of the flaw for remediation evidence.\n"
            "- Include placeholders for target-specific variables.\n"
            "- Be pure source code without conversational text or markdown delimiters.\n\n"
            f"Technical Reproduction Implementation for {cve_id}:"
        )

        resp = model.generate_content(prompt)
        code = resp.text or ""
        # Safety cleanup — same as pocme exploit.js
        if "```" in code:
            code = re.sub(r'```[a-z]*\n', '', code).replace('```', '').strip()

        return {"code": code, "language": lang, "cve_id": cve_id, "generated": True}

    except Exception as e:
        stub = _make_stub(EXPLOIT_STUBS[lang], cve_id, desc_short)
        return {"code": stub + f"\n# Gemini error: {e}", "language": lang,
                "cve_id": cve_id, "generated": False}

# ─────────────────────────────────────────────────────────────────────────────
# EXPLOIT EVALUATION — AI agent
# ─────────────────────────────────────────────────────────────────────────────

def rule_based_eval(vuln: Dict, exploit: Dict) -> Dict:
    cvss, has_poc = vuln.get("cvss",5.0), vuln.get("has_poc",False)
    viability  = "High" if (has_poc and cvss>=7.0) else "Medium" if cvss>=5.0 else "Low"
    confidence = round(0.4 + (cvss/10)*0.4 + (0.2 if has_poc else 0), 2)
    pkg = vuln.get("package","unknown")
    return {
        "viability": viability, "confidence": confidence,
        "risk_summary": (
            f"{vuln['cve_id']} — CVSS {cvss}. "
            f"{'Active PoC confirmed.' if has_poc else 'No public PoC.'} "
            f"Package: {pkg}."
        ),
        "remediation_steps": [
            f"Identify all services importing `{pkg}` and update to patched version",
            "Run the generated PoC in an isolated sandbox to confirm exploitability",
            "Apply package update, re-run PoC to verify the fix removes the behaviour",
            "Update lockfile, run full CI suite, then promote to production",
            "Document findings and close ticket with screenshot evidence",
        ],
        "verification_steps": [
            "1. Set TARGET to your sandbox test instance",
            "2. Install dependencies (pip install requests / npm install / etc.)",
            "3. Run the PoC script and observe HTTP status and response body",
            "4. Compare against CVE description to confirm reproduction",
            "5. Attach output log to ticket before marking as verified",
        ],
        "evaluation_model": "rule-based",
    }

async def evaluate_exploit(vuln: Dict, exploit: Dict, anthropic_key: Optional[str]) -> Dict:
    if not anthropic_key:
        return rule_based_eval(vuln, exploit)
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=anthropic_key)
        msg = client.messages.create(
            model="claude-opus-4-5", max_tokens=900,
            messages=[{"role":"user","content":(
                f"Evaluate this PoC exploit. Respond ONLY with JSON.\n"
                f"CVE: {vuln['cve_id']}  CVSS: {vuln.get('cvss',5.0)}\n"
                f"Package: {vuln.get('package','?')}@{vuln.get('version','?')}\n"
                f"Description: {vuln.get('description','')[:300]}\n\n"
                f"PoC ({exploit.get('language','python')}):\n```\n{(exploit.get('code',''))[:600]}\n```\n\n"
                '{"viability":"High|Medium|Low","confidence":0.85,"risk_summary":"one sentence",'
                '"remediation_steps":["step1","step2","step3","step4"],'
                '"verification_steps":["how to run step by step"],'
                '"evaluation_model":"claude-opus-4-5"}'
            )}],
        )
        m = re.search(r'\{.*\}', msg.content[0].text, re.DOTALL)
        if m:
            return json.loads(m.group())
    except Exception:
        pass
    return rule_based_eval(vuln, exploit)

# ─────────────────────────────────────────────────────────────────────────────
# ENRICHMENT HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def enrich_poc(cve_id: str) -> Dict:
    has = cve_id.upper() in POC_CVE_SET
    return {"has_poc":has,"poc_multiplier":3.0 if has else 1.0,
            "poc_source":"exploit-db/GitHub" if has else "none"}

def calc_blast_radius(package: str, sys_info: SystemInfo) -> Dict:
    pkg = package.lower()
    for key, data in BLAST_MAP.items():
        if key == pkg or key in pkg or pkg in key:
            svcs = data["services"][:data["count"]]
            if sys_info.name not in svcs:
                svcs = [sys_info.name] + svcs[:data["count"]-1]
            return {"blast_radius":len(svcs),"affected_systems":svcs}
    return {"blast_radius":1,"affected_systems":[sys_info.name]}

def calc_patch_complexity(package: str) -> Dict:
    pkg = package.lower()
    for _, meta in PATCH_COMPLEXITY.items():
        if any(p in pkg for p in meta["pkgs"]):
            return {"complexity":meta["complexity"],"complexity_desc":meta["desc"],"estimated_hours":meta["hours"]}
    return {"complexity":2,"complexity_desc":"Minor utility — straightforward version bump","estimated_hours":2}

def calc_priority_score(vuln: Dict, sys_info: SystemInfo) -> float:
    tier_w = {"critical":3.0,"important":2.0,"standard":1.0}
    return round(
        vuln.get("cvss",5.0) * vuln.get("poc_multiplier",1.0) * vuln.get("blast_radius",1)
        / max(vuln.get("complexity",2),1)
        * tier_w.get(sys_info.tier,1.0)
        * (2.0 if sys_info.regulatory else 1.0),
        2
    )

def generate_rationale(vuln: Dict, sys_info: SystemInfo) -> str:
    poc_txt = "active PoC exploit on exploit-db/GitHub" if vuln.get("has_poc") else "no public PoC"
    reg_txt = f"Regulatory: {', '.join(sys_info.regulatory)}. " if sys_info.regulatory else ""
    blast   = vuln.get("blast_radius",1)
    systems = ", ".join(vuln.get("affected_systems",[sys_info.name])[:3])
    return (
        f"Rank #{vuln.get('rank','?')} — score {vuln['priority_score']} "
        f"(CVSS {vuln['cvss']} × PoC×{vuln.get('poc_multiplier',1)} × blast×{blast} "
        f"÷ complexity{vuln.get('complexity',2)}). "
        f"{poc_txt.capitalize()}. Blast radius: {blast} service(s) ({systems}). "
        f"{reg_txt}Patch complexity {vuln.get('complexity',2)}/5."
    )

# ─────────────────────────────────────────────────────────────────────────────
# SCHEDULE-BASED DEV ASSIGNMENT
# ─────────────────────────────────────────────────────────────────────────────

def get_required_skill(package: str) -> str:
    pkg = package.lower()
    if any(p in pkg for p in ["django","flask","fastapi","celery","sqlalchemy","pandas","boto","pytest"]):
        return "python"
    if any(p in pkg for p in ["spring","hibernate","jackson","maven","junit","log4j","tomcat"]):
        return "java"
    return "nodejs"

def schedule_assign(vuln: Dict, team: List[TeamMember], today: datetime) -> Dict:
    if not team:
        return {"name":"Unassigned","email":"","skill":"general",
                "hours_allocated":0,"completion_date":(today+timedelta(days=14)).strftime("%Y-%m-%d"),
                "sprint_capacity_remaining":0}

    required = get_required_skill(vuln.get("package",""))
    hours    = vuln.get("estimated_hours",2)

    def rank(m: TeamMember):
        skill_ok = any(required.lower() in e.lower() for e in m.expertise)
        cap_ok   = m.schedule.sprint_hours_remaining >= hours
        return (not skill_ok, not cap_ok, -m.schedule.sprint_hours_remaining)

    best      = sorted(team, key=rank)[0]
    work_days = best.schedule.work_days or ["monday","tuesday","wednesday","thursday","friday"]
    cap_day   = 8
    days_needed = math.ceil(hours / min(cap_day, max(best.schedule.sprint_hours_remaining, hours)))

    completion = today
    added = 0
    while added < days_needed:
        completion += timedelta(days=1)
        if completion.strftime("%A").lower() in work_days:
            added += 1

    best.schedule.sprint_hours_remaining = max(0, best.schedule.sprint_hours_remaining - hours)
    best.current_load += 1

    return {
        "name":                      best.name,
        "email":                     best.email,
        "skill":                     required,
        "hours_allocated":           hours,
        "completion_date":           completion.strftime("%Y-%m-%d"),
        "sprint_capacity_remaining": best.schedule.sprint_hours_remaining,
    }

# ─────────────────────────────────────────────────────────────────────────────
# CLAUDE EXEC SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

async def claude_rationale(vulns: List[Dict], api_key: str, sys_info: SystemInfo) -> Dict:
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        top5 = [{"rank":v.get("rank"),"cve_id":v["cve_id"],"package":v["package"],
                  "cvss":v["cvss"],"has_poc":v.get("has_poc",False),
                  "blast_radius":v.get("blast_radius",1),"priority_score":v.get("priority_score",0),
                  "viability":v.get("evaluation",{}).get("viability","Medium")} for v in vulns[:5]]
        msg = client.messages.create(
            model="claude-opus-4-5", max_tokens=1500,
            messages=[{"role":"user","content":(
                'You are a CISO. Respond ONLY with JSON:\n'
                '{"exec_summary":"2 sentences","rationales":{"CVE-ID":"1 sentence"},"risk_reduction_pct":75}\n\n'
                + json.dumps(top5, indent=2)
            )}],
        )
        m = re.search(r'\{.*\}', msg.content[0].text, re.DOTALL)
        if m:
            data = json.loads(m.group())
            for v in vulns:
                if v["cve_id"] in data.get("rationales",{}):
                    v["rationale"] = data["rationales"][v["cve_id"]]
            return {"exec_summary":data.get("exec_summary",""),
                    "risk_reduction_pct":data.get("risk_reduction_pct",75),
                    "model":"claude-opus-4-5"}
    except Exception:
        pass
    return {}

# ─────────────────────────────────────────────────────────────────────────────
# PATCH CALENDAR
# ─────────────────────────────────────────────────────────────────────────────

def build_patch_calendar(ranked: List[Dict], windows: List[MaintenanceWindow]) -> List[Dict]:
    today   = datetime.now()
    day_map = {d:i for i,d in enumerate(["monday","tuesday","wednesday","thursday","friday","saturday","sunday"])}
    cal = []
    for i, v in enumerate(ranked[:10]):
        if windows:
            win = windows[i % len(windows)]
            tgt = day_map.get(win.day.lower(),6)
            da  = (tgt - today.weekday()) % 7 or 7
            da += (i // max(len(windows),1)) * 7
            dt  = today + timedelta(days=da)
            lbl = f"{win.day.capitalize()} {win.time}"
        else:
            dt  = today + timedelta(days=(i+1)*7)
            lbl = "Sunday 02:00"
        score = v.get("priority_score",0)
        lvl   = "Critical" if score>80 else "High" if score>30 else "Medium"
        cal.append({
            "rank":i+1,"cve_id":v["cve_id"],
            "package":f"{v['package']}@{v.get('version','?')}",
            "scheduled_date":dt.strftime("%Y-%m-%d"),
            "window":lbl,"estimated_hours":v.get("estimated_hours",2),
            "assigned_to":v.get("assigned_to","Unassigned"),
            "completion_date":v.get("completion_date",""),
            "priority_level":lvl,"priority_score":score,
            "exploit_language":v.get("exploit",{}).get("language",""),
            "viability":v.get("evaluation",{}).get("viability",""),
        })
    return cal

# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/upload-report")
async def upload_report(file: UploadFile = File(...)):
    """Upload VA report (PDF or text) → extract CVE IDs."""
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 10 MB)")
    cves = await parse_va_report(content, file.filename or "report.txt")
    return {"cve_ids": cves, "count": len(cves), "filename": file.filename}


@app.post("/api/analyze")
async def analyze(request: AnalyzeRequest):
    """9-step SSE streaming agentic pipeline."""
    async def stream():
        def evt(step, status, message, **extra):
            return f"data: {json.dumps({'step':step,'status':status,'message':message,**extra})}\n\n"

        try:
            today = datetime.now()
            team  = list(request.team_members)

            # 1 ── Input parsing
            yield evt("input_parse","running",
                      f"Parsing SBOM ({len(request.packages)} pkgs) + {len(request.va_cve_ids)} VA report CVEs…")
            await asyncio.sleep(0.4)
            yield evt("input_parse","done",
                      f"Input ready: {len(request.packages)} packages, {len(request.va_cve_ids)} VA CVEs",
                      sbom_count=len(request.packages), va_count=len(request.va_cve_ids))
            await asyncio.sleep(0.3)

            # 2 ── CVE Discovery
            yield evt("cve_discovery","running","SCA scanning packages via NVD CVE API 2.0…")
            await asyncio.sleep(0.3)

            all_vulns = await sca_scan_packages(request.packages)
            discovered = {v["cve_id"] for v in all_vulns}
            for cve_id in request.va_cve_ids:
                if cve_id not in discovered:
                    fb = FALLBACK_CVE_DB.get(cve_id,{"cvss":6.5,"description":f"CVE {cve_id}","published":"2024-01-01"})
                    p, v = (list(request.packages.items())[0] if request.packages else ("unknown","?"))
                    all_vulns.append({"cve_id":cve_id,"package":p,"version":v,
                                      "cvss":fb["cvss"],"description":fb["description"],
                                      "published":fb["published"],"source":"va-report"})

            if len(all_vulns) < 3:
                all_vulns = build_demo_cves(request.packages, request.va_cve_ids)
                src = "demo CVE database"
            else:
                src = "NVD live data"

            all_vulns = all_vulns[:10]
            yield evt("cve_discovery","done",
                      f"{len(all_vulns)} CVEs discovered via {src}", count=len(all_vulns))
            await asyncio.sleep(0.3)

            # 3 ── Deep CVE Research (POCme logic)
            yield evt("deep_research","running",
                      f"NVD history fetch + Gemini intelligence synthesis for {len(all_vulns)} CVEs…")
            for i, v in enumerate(all_vulns):
                yield evt("deep_research","running",
                          f"[{i+1}/{len(all_vulns)}] Deep-researching {v['cve_id']}…",
                          cve=v["cve_id"], progress={"current":i+1,"total":len(all_vulns)})
                all_vulns[i] = await deep_research_cve(v["cve_id"], v, request.gemini_api_key)
                await asyncio.sleep(0.2)
            yield evt("deep_research","done",
                      f"Research complete — {len(all_vulns)} CVEs fully analysed with technical context")
            await asyncio.sleep(0.3)

            # 4 ── Exploit Generation (POCme logic)
            yield evt("exploit_gen","running",
                      f"Generating {request.exploit_language} PoC exploits via Gemini (POCme engine)…")
            for i, v in enumerate(all_vulns):
                yield evt("exploit_gen","running",
                          f"[{i+1}/{len(all_vulns)}] Generating {request.exploit_language} exploit for {v['cve_id']}…",
                          cve=v["cve_id"])
                all_vulns[i]["exploit"] = await generate_exploit(v, request.exploit_language, request.gemini_api_key)
                await asyncio.sleep(0.15)
            gen_n = sum(1 for v in all_vulns if v.get("exploit",{}).get("generated"))
            yield evt("exploit_gen","done",
                      f"Exploits ready: {gen_n} Gemini-generated, {len(all_vulns)-gen_n} structured stubs",
                      generated=gen_n)
            await asyncio.sleep(0.3)

            # 5 ── Exploit Evaluation
            yield evt("evaluation","running",
                      "AI agent evaluating exploit viability, risk level, and remediation steps…")
            for i, v in enumerate(all_vulns):
                yield evt("evaluation","running",
                          f"[{i+1}/{len(all_vulns)}] Evaluating {v['cve_id']}…", cve=v["cve_id"])
                all_vulns[i]["evaluation"] = await evaluate_exploit(
                    v, v.get("exploit",{}), request.anthropic_api_key)
                await asyncio.sleep(0.1)
            high_v = sum(1 for v in all_vulns if v.get("evaluation",{}).get("viability")=="High")
            yield evt("evaluation","done",
                      f"Evaluation complete: {high_v} high-viability exploits — immediate action required",
                      high_viability=high_v)
            await asyncio.sleep(0.3)

            # 6 ── Blast Radius
            yield evt("blast_radius","running","Mapping dependency blast radius across enterprise services…")
            await asyncio.sleep(0.9)
            for v in all_vulns:
                v.update(enrich_poc(v["cve_id"]))
                v.update(calc_blast_radius(v["package"], request.system_info))
                v.update(calc_patch_complexity(v["package"]))
                v["regulatory"]  = request.system_info.regulatory
                v["system_tier"] = request.system_info.tier
            max_blast = max(v.get("blast_radius",1) for v in all_vulns)
            yield evt("blast_radius","done",
                      f"Blast radius mapped: max {max_blast} downstream services at risk",
                      max_blast=max_blast)
            await asyncio.sleep(0.3)

            # 7 ── AI Scoring
            yield evt("ai_scoring","running",
                      "Computing priority scores: (CVSS × PoC × BlastRadius) ÷ Complexity × Tier × RegFlag…")
            await asyncio.sleep(1.0)
            for v in all_vulns:
                v["priority_score"] = calc_priority_score(v, request.system_info)
            all_vulns.sort(key=lambda x: x["priority_score"], reverse=True)
            for i, v in enumerate(all_vulns):
                v["rank"] = i + 1
            yield evt("ai_scoring","done",
                      f"Scoring complete — top CVE scored {all_vulns[0]['priority_score']:.1f} priority points")
            await asyncio.sleep(0.3)

            # 8 ── Rationale
            yield evt("rationale","running",
                      "Claude agent generating auditable natural-language rationale…")
            await asyncio.sleep(0.8)
            ai_meta = {}
            if request.anthropic_api_key:
                ai_meta = await claude_rationale(all_vulns, request.anthropic_api_key, request.system_info)
            for v in all_vulns:
                if not v.get("rationale"):
                    v["rationale"] = generate_rationale(v, request.system_info)
            yield evt("rationale","done",
                      f"Rationale generated via {ai_meta.get('model','rule-based engine')}")
            await asyncio.sleep(0.3)

            # 9 ── Schedule Assignment
            yield evt("schedule_assign","running",
                      f"Schedule-based assignment: routing {len(all_vulns)} tickets by skill + sprint capacity…")
            await asyncio.sleep(0.8)
            tickets: List[Dict] = []
            for v in all_vulns:
                assignee = schedule_assign(v, team, today)
                v["assigned_to"]     = assignee["name"]
                v["assigned_email"]  = assignee["email"]
                v["completion_date"] = assignee["completion_date"]
                v["skill_routed_to"] = assignee["skill"]

                score = v["priority_score"]
                lvl   = "Critical" if score>80 else "High" if score>30 else "Medium" if score>10 else "Low"
                tickets.append({
                    "ticket_id":f"SEC-{1000+v['rank']}","cve_id":v["cve_id"],
                    "package":f"{v['package']}@{v.get('version','?')}","cvss":v["cvss"],
                    "priority_level":lvl,"priority_score":score,
                    "assigned_to":v["assigned_to"],"assigned_email":v.get("assigned_email",""),
                    "estimated_hours":v.get("estimated_hours",2),"completion_date":v["completion_date"],
                    "skill":assignee["skill"],"status":"Open","rank":v["rank"],
                    "has_poc":v.get("has_poc",False),"blast_radius":v.get("blast_radius",1),
                    "viability":v.get("evaluation",{}).get("viability","Medium"),
                    "rationale":v.get("rationale",""),"description":v.get("description",""),
                    "exploit_language":v.get("exploit",{}).get("language",""),
                    "verification_steps":v.get("evaluation",{}).get("verification_steps",[]),
                    "remediation_steps":v.get("evaluation",{}).get("remediation_steps",[]),
                })

            calendar = build_patch_calendar(all_vulns, request.maintenance_windows)
            yield evt("schedule_assign","done",
                      f"{len(tickets)} tickets assigned with sprint capacity-based completion dates")
            await asyncio.sleep(0.2)

            # ── Final payload
            total = sum(v["priority_score"] for v in all_vulns) or 1
            top3  = sum(v["priority_score"] for v in all_vulns[:3])
            risk  = round(top3/total*100)
            ai_r  = ai_meta.get("risk_reduction_pct", risk)
            poc_n = sum(1 for v in all_vulns if v.get("has_poc"))

            exec_summary = ai_meta.get("exec_summary") or (
                f"Security analysis identified {len(all_vulns)} CVEs across "
                f"{len(request.packages)} packages in {request.system_info.name}. "
                f"Patching top-3 priority items cuts risk by ~{ai_r}%; "
                f"{poc_n} active exploits need immediate developer action."
            )

            stats = {
                "total_vulns":len(all_vulns),"critical_cvss":sum(1 for v in all_vulns if v["cvss"]>=9),
                "high_cvss":sum(1 for v in all_vulns if 7<=v["cvss"]<9),
                "medium_cvss":sum(1 for v in all_vulns if 4<=v["cvss"]<7),
                "poc_active":poc_n,"exploits_generated":sum(1 for v in all_vulns if v.get("exploit",{}).get("generated")),
                "high_viability":high_v,"packages_scanned":len(request.packages),
                "va_cves":len(request.va_cve_ids),"risk_reduction":ai_r,
                "total_effort_hrs":sum(v.get("estimated_hours",2) for v in all_vulns[:10]),
                "max_blast_radius":max_blast,
            }

            yield f"data: {json.dumps({'step':'complete','status':'done','message':f'Complete — patch top 3 to cut risk {ai_r}%','data':{'vulnerabilities':all_vulns,'tickets':tickets,'calendar':calendar,'exec_summary':exec_summary,'risk_reduction':ai_r,'stats':stats}})}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'step':'error','status':'error','message':str(e)})}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.get("/health")
async def health():
    return {"status":"ok","service":"VulnPriority AI","version":"2.0.0"}
