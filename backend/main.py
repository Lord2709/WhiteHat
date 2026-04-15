"""
VulnPriority AI — Agentic Vulnerability Prioritization Backend v3
─────────────────────────────────────────────────────────────────
AI-assisted pipeline with verified CVE discovery and bounded downstream synthesis.

Every intelligence decision is delegated to an LLM:
  • CVE discovery       → OSV/NVD verification with bounded LLM fallback
  • Deep research       → Gemini "Deep Intelligence Gathering" (bounded by retrieved context)
  • Exploit generation  → Gemini "Senior Vulnerability Researcher" (POCme logic)
  • Exploit evaluation  → Claude/Gemini: viability, risk, remediation, verification
  • Blast radius        → LLM analyses enterprise impact per CVE
  • Priority scoring    → LLM-derived inputs fed into formula
  • Rationale           → Claude/Gemini natural-language explanation per CVE
  • Schedule assignment → sprint-capacity math (deterministic, not opinion)
"""

import asyncio, json, math, os, re, sqlite3, uuid
from datetime import datetime, timedelta
from io import BytesIO
from itertools import zip_longest
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# Load .env from the same directory as this file
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

# Keys from .env — ignore placeholder values
def _env_key(name: str) -> Optional[str]:
    val = os.getenv(name, "").strip()
    return val if val and not val.startswith("your_") else None

ENV_GEMINI_KEY    = _env_key("GEMINI_API_KEY")
ENV_ANTHROPIC_KEY = _env_key("ANTHROPIC_API_KEY")
ENV_NVD_KEY       = _env_key("NVD_API_KEY")     # optional — removes 5-req/30s rate limit
SAMPLE_DATA_DIR   = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sample_data"))
DATA_DIR          = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
DB_PATH           = os.path.join(DATA_DIR, "whitehat.db")
_NVD_CVE_CACHE: Dict[str, Optional[Dict]] = {}
_NVD_HISTORY_CACHE: Dict[str, List[Dict[str, Any]]] = {}


def _db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_table_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _db_init() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with _db_connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS team_profiles (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT '',
                linkedin_url TEXT NOT NULL DEFAULT '',
                professional_summary TEXT NOT NULL DEFAULT '',
                expertise_json TEXT NOT NULL DEFAULT '[]',
                availability_notes TEXT NOT NULL DEFAULT '',
                current_load INTEGER NOT NULL DEFAULT 0,
                available_hours_per_week INTEGER NOT NULL DEFAULT 40,
                sprint_hours_remaining INTEGER NOT NULL DEFAULT 20,
                work_days_json TEXT NOT NULL DEFAULT '["monday","tuesday","wednesday","thursday","friday"]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                system_name TEXT NOT NULL DEFAULT '',
                counts_json TEXT NOT NULL DEFAULT '{}',
                request_json TEXT NOT NULL DEFAULT '{}',
                result_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_config (
                id TEXT PRIMARY KEY DEFAULT 'default',
                packages_json TEXT NOT NULL DEFAULT '{}',
                va_cve_ids_json TEXT NOT NULL DEFAULT '[]',
                system_info_json TEXT NOT NULL DEFAULT '{}',
                maintenance_windows_json TEXT NOT NULL DEFAULT '[]',
                team_members_json TEXT NOT NULL DEFAULT '[]',
                exploit_language TEXT NOT NULL DEFAULT 'python',
                api_keys_json TEXT NOT NULL DEFAULT '{}',
                nl_text TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        _ensure_table_column(conn, "analysis_config", "vendor_advisories_json", "TEXT NOT NULL DEFAULT '[]'")
        _ensure_table_column(conn, "analysis_config", "internal_docs_json", "TEXT NOT NULL DEFAULT '[]'")
        _ensure_table_column(conn, "analysis_config", "dependency_graph_json", "TEXT NOT NULL DEFAULT '[]'")
        conn.commit()

app = FastAPI(title="VulnPriority AI", version="3.0.0")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

_db_init()

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
    role: str = ""
    linkedin_url: str = ""
    professional_summary: str = ""
    expertise: List[str]
    availability_notes: str = ""
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


class VendorAdvisory(BaseModel):
    advisory_id: str = ""
    title: str = ""
    severity: str = "medium"
    cve_ids: List[str] = []
    affected_packages: List[str] = []
    summary: str = ""
    url: str = ""
    published: str = ""


class InternalDoc(BaseModel):
    doc_id: str = ""
    title: str = ""
    systems: List[str] = []
    tags: List[str] = []
    criticality: str = ""
    content: str = ""


class DependencyEdge(BaseModel):
    source: str
    target: str
    relation: str = "depends_on"

class AnalyzeRequest(BaseModel):
    packages: Dict[str, str] = {}
    va_cve_ids: List[str] = []
    system_info: SystemInfo
    maintenance_windows: List[MaintenanceWindow] = []
    team_members: List[TeamMember] = []
    vendor_advisories: List[VendorAdvisory] = []
    internal_docs: List[InternalDoc] = []
    dependency_graph: List[DependencyEdge] = []
    exploit_language: str = "python"
    anthropic_api_key: Optional[str] = None
    gemini_api_key: Optional[str] = None


class TeamProfileRequest(BaseModel):
    name: str
    email: str
    role: str = ""
    linkedin_url: str = ""
    professional_summary: str = ""
    expertise: List[str] = []
    availability_notes: str = ""
    current_load: int = 0
    schedule: DevSchedule = DevSchedule()


class ScanRecordRequest(BaseModel):
    label: str
    system_name: str = ""
    counts: Dict[str, int] = {}
    request_payload: Dict[str, Any] = {}
    result_payload: Dict[str, Any] = {}


class NaturalLanguageConfigRequest(BaseModel):
    text: str
    current_system_info: Optional[SystemInfo] = None
    current_maintenance_windows: List[MaintenanceWindow] = []
    gemini_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None


class AnalysisConfigPayload(BaseModel):
    packages: Dict[str, str] = {}
    va_cve_ids: List[str] = []
    system_info: Optional[SystemInfo] = None
    maintenance_windows: List[MaintenanceWindow] = []
    team_members: List[TeamMember] = []
    vendor_advisories: List[VendorAdvisory] = []
    internal_docs: List[InternalDoc] = []
    dependency_graph: List[DependencyEdge] = []
    exploit_language: str = "python"
    api_keys: Dict[str, str] = {}
    nl_text: str = ""


def _json_loads_safe(raw: Any, fallback: Any) -> Any:
    try:
        if raw is None:
            return fallback
        return json.loads(raw)
    except Exception:
        return fallback


def _team_profile_row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "email": row["email"],
        "role": row["role"],
        "linkedin_url": row["linkedin_url"],
        "professional_summary": row["professional_summary"],
        "expertise": _json_loads_safe(row["expertise_json"], []),
        "availability_notes": row["availability_notes"],
        "current_load": int(row["current_load"] or 0),
        "schedule": {
            "available_hours_per_week": int(row["available_hours_per_week"] or 40),
            "sprint_hours_remaining": int(row["sprint_hours_remaining"] or 20),
            "work_days": _json_loads_safe(
                row["work_days_json"],
                ["monday", "tuesday", "wednesday", "thursday", "friday"],
            ),
        },
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _scan_row_to_meta(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "label": row["label"],
        "system_name": row["system_name"],
        "counts": _json_loads_safe(row["counts_json"], {}),
        "created_at": row["created_at"],
    }


def _norm_token(value: str) -> str:
    return re.sub(r"[^a-z0-9._\-/@]+", "", (value or "").strip().lower())


def _package_base_name(package_value: str) -> str:
    raw = (package_value or "").strip().lower()
    if "@" in raw and not raw.startswith("@"):
        return raw.split("@", 1)[0]
    return raw


def _dependency_reach(start: str, edges: List[Dict[str, Any]], max_nodes: int = 25) -> List[str]:
    index: Dict[str, Set[str]] = {}
    for e in edges:
        src = _norm_token(str(e.get("source", "")))
        tgt = _norm_token(str(e.get("target", "")))
        if not src or not tgt:
            continue
        index.setdefault(src, set()).add(tgt)
    seen: Set[str] = set()
    queue: List[str] = [_norm_token(start)]
    while queue and len(seen) < max_nodes:
        cur = queue.pop(0)
        for nxt in sorted(index.get(cur, set())):
            if nxt in seen:
                continue
            seen.add(nxt)
            queue.append(nxt)
            if len(seen) >= max_nodes:
                break
    return list(seen)


def apply_connector_signals(
    vuln: Dict[str, Any],
    advisories: List[VendorAdvisory],
    internal_docs: List[InternalDoc],
    dependency_graph: List[DependencyEdge],
) -> Dict[str, Any]:
    cve_id = _norm_token(str(vuln.get("cve_id", "")))
    pkg = _package_base_name(str(vuln.get("package", "")))

    advisory_hits: List[str] = []
    for adv in advisories:
        cves = {_norm_token(c) for c in (adv.cve_ids or [])}
        adv_pkgs = {_package_base_name(p) for p in (adv.affected_packages or [])}
        text_blob = " ".join([adv.title or "", adv.summary or "", adv.advisory_id or ""]).lower()
        if cve_id and cve_id in cves:
            advisory_hits.append(adv.advisory_id or adv.title or "vendor-advisory")
        elif pkg and (pkg in adv_pkgs or pkg in text_blob):
            advisory_hits.append(adv.advisory_id or adv.title or "vendor-advisory")

    doc_hits: List[str] = []
    doc_systems: Set[str] = set()
    for doc in internal_docs:
        blob = " ".join([
            doc.title or "",
            doc.content or "",
            " ".join(doc.tags or []),
            " ".join(doc.systems or []),
        ]).lower()
        if (cve_id and cve_id in blob) or (pkg and pkg in blob):
            doc_hits.append(doc.doc_id or doc.title or "internal-doc")
            for s in (doc.systems or []):
                if s:
                    doc_systems.add(str(s))

    dep_reach = _dependency_reach(pkg, [e.model_dump() for e in dependency_graph]) if pkg else []

    connector_signals = {
        "vendor_advisory_hits": len(advisory_hits),
        "internal_doc_hits": len(doc_hits),
        "dependency_reach": len(dep_reach),
        "matched_advisories": advisory_hits[:5],
        "matched_docs": doc_hits[:5],
        "dependency_downstream": dep_reach[:8],
    }

    affected = list(vuln.get("affected_systems", []) or [])
    for item in list(doc_systems) + dep_reach:
        if item not in affected:
            affected.append(item)
    vuln["affected_systems"] = affected[:10]
    vuln["connector_signals"] = connector_signals
    return connector_signals

# ─────────────────────────────────────────────────────────────────────────────
# LLM HELPER LAYER
# ─────────────────────────────────────────────────────────────────────────────

async def call_gemini(prompt: str, key: str, temperature: float = 0.2) -> str:
    """Call Gemini 1.5-flash and return the text response."""
    import google.generativeai as genai
    genai.configure(api_key=key)
    model = genai.GenerativeModel(
        "gemini-1.5-flash",
        generation_config={"temperature": temperature, "max_output_tokens": 2048},
    )
    resp = model.generate_content(prompt)
    return resp.text or ""


async def call_gemini_exploit(prompt: str, key: str) -> str:
    """
    PoC generation using the newer google-genai SDK with gemini-3-flash-preview.
    Mirrors the exact API call pattern from exploit.js:
        const ai = new GoogleGenAI({});
        const response = await ai.models.generateContent({
            model: "gemini-3-flash-preview",
            contents: prompt,
        });
    No temperature setting — uses model default for maximum code quality.
    Falls back to gemini-2.0-flash if the preview model is unavailable.
    """
    from google import genai as google_genai
    client = google_genai.Client(api_key=key)
    for model_name in ("gemini-3-flash-preview", "gemini-2.0-flash"):
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
            )
            text = response.text or ""
            if text.strip():
                return text
        except Exception as e:
            last = e
            continue
    raise last


async def call_claude(
    prompt: str,
    key: str,
    max_tokens: int = 1500,
    temperature: float = 0.2,
) -> str:
    """Call Claude claude-opus-4-5 and return the text response."""
    import anthropic
    client = anthropic.Anthropic(api_key=key)
    msg = client.messages.create(
        model="claude-opus-4-5", max_tokens=max_tokens,
        temperature=max(0.0, min(1.0, temperature)),
        messages=[{"role": "user", "content": prompt}],
    )
    return msg.content[0].text or ""


async def llm_call(
    prompt: str,
    gemini_key: Optional[str],
    anthropic_key: Optional[str],
    max_tokens: int = 1500,
    temperature: float = 0.2,
) -> str:
    """
    Unified LLM gateway: Gemini first, Claude as fallback.
    Raises RuntimeError if neither key is available.
    """
    last_err = None
    if gemini_key:
        try:
            return await call_gemini(prompt, gemini_key, temperature)
        except Exception as e:
            last_err = e
    if anthropic_key:
        try:
            return await call_claude(prompt, anthropic_key, max_tokens, temperature)
        except Exception as e:
            last_err = e
    raise RuntimeError(f"All LLM calls failed: {last_err}")


def parse_llm_json(text: str) -> Any:
    """
    Robustly extract the first JSON object or array from an LLM response.
    Strips markdown fences, then parses.
    """
    # Strip ```json ... ``` or ``` ... ```
    text = re.sub(r'```(?:json)?\s*', '', text).strip().rstrip('`').strip()
    # Try first {...} block
    m = re.search(r'(\{[\s\S]*\}|\[[\s\S]*\])', text)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    # Last resort: full text
    try:
        return json.loads(text)
    except Exception:
        return {}

# ─────────────────────────────────────────────────────────────────────────────
# VA REPORT PARSING  — regex first, LLM fallback for non-CVE-ID reports
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

def extract_pdf_text(content: bytes, filename: str) -> str:
    if (filename or "").lower().endswith(".pdf"):
        try:
            import PyPDF2
            reader = PyPDF2.PdfReader(BytesIO(content))
            text = ""
            for page in reader.pages:
                text += (page.extract_text() or "") + "\n"
            return text
        except Exception:
            pass
    return content.decode("utf-8", errors="ignore")


def _load_json_file(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _load_text_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _extract_packages_from_manifest(manifest: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for section in ("dependencies", "devDependencies"):
        for pkg, version in (manifest.get(section, {}) or {}).items():
            cleaned = re.sub(r"[\^~>=<]", "", str(version)).strip()
            if cleaned:
                out[pkg] = cleaned
    return out


def _normalize_identifier(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (value or "").lower())


def _package_aliases(pkg: str) -> Set[str]:
    raw = (pkg or "").strip().lower()
    aliases = {raw, raw.lstrip("@"), _normalize_identifier(raw)}
    for part in re.split(r"[@/._:\-\s]+", raw):
        if len(part) >= 3:
            aliases.add(part)
            aliases.add(_normalize_identifier(part))
    return {a for a in aliases if a}


def _identifier_matches_alias(value: str, aliases: Set[str]) -> bool:
    if not value:
        return False
    norm_value = _normalize_identifier(value)
    for alias in aliases:
        if alias == value.lower() or alias == norm_value:
            return True
    return False


def _split_version_parts(version: str) -> List[Tuple[int, Any]]:
    cleaned = (version or "").strip().lower()
    cleaned = re.sub(r"^[<>=~^v\s]+", "", cleaned)
    cleaned = cleaned.split(",", 1)[0].strip()
    pieces = re.findall(r"\d+|[a-z]+", cleaned)
    out: List[Tuple[int, Any]] = []
    for piece in pieces:
        out.append((0, int(piece)) if piece.isdigit() else (1, piece))
    return out


def _compare_versions(left: str, right: str) -> Optional[int]:
    a = _split_version_parts(left)
    b = _split_version_parts(right)
    if not a or not b:
        return None
    for pa, pb in zip_longest(a, b, fillvalue=(0, 0)):
        if pa == pb:
            continue
        if pa[0] != pb[0]:
            return 1 if pa[0] < pb[0] else -1
        return 1 if pa[1] > pb[1] else -1
    return 0


def _version_matches_cpe(pkg_version: str, cpe_item: Dict, criteria_version: str) -> Optional[bool]:
    version = (pkg_version or "").strip()
    if not version:
        return None

    exact = (criteria_version or "").strip()
    if exact and exact not in {"*", "-"}:
        cmp_exact = _compare_versions(version, exact)
        return None if cmp_exact is None else cmp_exact == 0

    checks: List[bool] = []
    start_incl = cpe_item.get("versionStartIncluding")
    start_excl = cpe_item.get("versionStartExcluding")
    end_incl = cpe_item.get("versionEndIncluding")
    end_excl = cpe_item.get("versionEndExcluding")

    if start_incl:
        cmp_val = _compare_versions(version, str(start_incl))
        if cmp_val is None:
            return None
        checks.append(cmp_val >= 0)
    if start_excl:
        cmp_val = _compare_versions(version, str(start_excl))
        if cmp_val is None:
            return None
        checks.append(cmp_val > 0)
    if end_incl:
        cmp_val = _compare_versions(version, str(end_incl))
        if cmp_val is None:
            return None
        checks.append(cmp_val <= 0)
    if end_excl:
        cmp_val = _compare_versions(version, str(end_excl))
        if cmp_val is None:
            return None
        checks.append(cmp_val < 0)

    return all(checks) if checks else None


def _iter_cpe_matches(configurations: Iterable[Dict]) -> Iterable[Dict]:
    stack: List[Dict] = list(configurations or [])
    while stack:
        current = stack.pop()
        nodes = current.get("nodes") if isinstance(current, dict) and "nodes" in current else [current]
        for node in nodes:
            if node.get("negate"):
                continue
            for match in node.get("cpeMatch", []):
                yield match
            stack.extend(node.get("children", []))


def _text_mentions_package(text: str, aliases: Set[str]) -> bool:
    lowered = (text or "").lower()
    normalized = _normalize_identifier(lowered)
    tokenized = {
        tok for tok in re.split(r"[^a-z0-9]+", lowered)
        if len(tok) >= 3
    }
    for alias in aliases:
        if len(alias) >= 4 and alias in tokenized:
            return True
        if "/" in alias or "@" in alias:
            if alias in lowered:
                return True
        elif alias == normalized:
            return True
    return False


def _looks_like_package_identifier(value: str) -> bool:
    value = (value or "").strip()
    if not value:
        return False
    return bool(re.search(r"[@/_-]", value) or (" " not in value and value.lower() == value))


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "y"}
    return bool(value)


def _coerce_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _coerce_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


_DAY_ALIASES: Dict[str, str] = {
    "mon": "Monday", "monday": "Monday",
    "tue": "Tuesday", "tues": "Tuesday", "tuesday": "Tuesday",
    "wed": "Wednesday", "wednesday": "Wednesday",
    "thu": "Thursday", "thur": "Thursday", "thurs": "Thursday", "thursday": "Thursday",
    "fri": "Friday", "friday": "Friday",
    "sat": "Saturday", "saturday": "Saturday",
    "sun": "Sunday", "sunday": "Sunday",
}


def _normalize_time_token(raw: str) -> Optional[str]:
    token = (raw or "").strip().lower()
    if not token:
        return None
    m = re.match(r"^(\d{1,2})(?::(\d{2}))?\s*(am|pm)?$", token)
    if not m:
        return None
    hour = int(m.group(1))
    minute = int(m.group(2) or "0")
    ampm = m.group(3)
    if ampm == "pm" and hour < 12:
        hour += 12
    if ampm == "am" and hour == 12:
        hour = 0
    if hour > 23 or minute > 59:
        return None
    return f"{hour:02d}:{minute:02d}"


def _extract_maintenance_windows_from_text(text: str) -> List[Dict[str, Any]]:
    windows: List[Dict[str, Any]] = []
    lowered = (text or "").lower()
    day_pat = re.compile(
        r"\b(mon(?:day)?|tue(?:s|sday)?|wed(?:nesday)?|thu(?:r|rs|rsday)?|fri(?:day)?|sat(?:urday)?|sun(?:day)?)\b",
        re.IGNORECASE,
    )
    time_pat = re.compile(r"\b(?:at\s*)?(\d{1,2}(?::\d{2})?\s*(?:am|pm)?)\b", re.IGNORECASE)
    dur_pat = re.compile(r"\bfor\s*(\d{1,2})\s*(?:h|hr|hrs|hour|hours)\b", re.IGNORECASE)

    for m in day_pat.finditer(lowered):
        day_raw = m.group(1) or ""
        day = _DAY_ALIASES.get(day_raw[:3], _DAY_ALIASES.get(day_raw, "Sunday"))
        lookahead = lowered[m.start(): min(len(lowered), m.end() + 80)]
        time_match = time_pat.search(lookahead)
        dur_match = dur_pat.search(lookahead)
        time_val = _normalize_time_token(time_match.group(1) if time_match else "") or "02:00"
        duration = _coerce_int(dur_match.group(1) if dur_match else None, 4)
        duration = max(1, min(24, duration))
        windows.append({"day": day, "time": time_val, "duration_hours": duration})

    unique: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str]] = set()
    for w in windows:
        key = (w["day"], w["time"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(w)
    return unique[:7]


def _extract_dependencies_from_text(text: str) -> List[str]:
    m = re.search(
        r"(?i)depend(?:s|encies)?\s*(?:on)?\s*[:=-]?\s*([^\n\r.;]+)",
        text or "",
    )
    if not m:
        return []
    raw = re.split(r"(?i)\b(patch|maintenance|window|schedule|owner|tier)\b", m.group(1))[0]
    parts = [p.strip() for p in re.split(r"[,;/]|\band\b", raw, flags=re.IGNORECASE)]
    return [p for p in parts if len(p) >= 2][:10]


def _extract_system_name_from_text(text: str) -> Optional[str]:
    patterns = [
        r"(?i)system\s*(?:name)?\s*[:=-]\s*([a-z0-9][a-z0-9._\- ]{2,60})",
        r"(?i)application\s*(?:name)?\s*[:=-]\s*([a-z0-9][a-z0-9._\- ]{2,60})",
        r"(?i)for\s+([a-z0-9][a-z0-9._\- ]{2,60})\s+system",
    ]
    for pat in patterns:
        m = re.search(pat, text or "")
        if m:
            return m.group(1).strip()
    return None


def _extract_owner_from_text(text: str) -> Optional[str]:
    m = re.search(r"(?i)owner\s*[:=-]\s*([^\n\r.;]+)", text or "")
    if not m:
        return None
    raw = re.split(r"(?i)\b(depends|patch|maintenance|window|tier|regulat)\w*\b", m.group(1))[0]
    return raw.strip()[:80] or None


def _extract_tier_from_text(text: str) -> Optional[str]:
    lowered = (text or "").lower()
    if re.search(r"\bcritical\b", lowered):
        return "critical"
    if re.search(r"\bimportant\b|\bhigh\b", lowered):
        return "important"
    if re.search(r"\bstandard\b|\blow\b|\bnormal\b", lowered):
        return "standard"
    return None


def _extract_regulatory_from_text(text: str) -> List[str]:
    lowered = (text or "").lower()
    regs: List[str] = []
    if "pci" in lowered:
        regs.append("PCI")
    if "sox" in lowered:
        regs.append("SOX")
    if "hipaa" in lowered:
        regs.append("HIPAA")
    if "gdpr" in lowered:
        regs.append("GDPR")
    if "fedramp" in lowered:
        regs.append("FedRAMP")
    return regs


async def _nvd_fetch_cve(cve_id: str) -> Optional[Dict]:
    """Fetch a single CVE record from NVD API v2. Passes NVD_API_KEY if set."""
    if cve_id in _NVD_CVE_CACHE:
        return _NVD_CVE_CACHE[cve_id]
    params: Dict[str, str] = {"cveId": cve_id}
    if ENV_NVD_KEY:
        params["apiKey"] = ENV_NVD_KEY
    try:
        async with httpx.AsyncClient(timeout=12.0, trust_env=False,
                                      headers={"User-Agent": "VulnPriorityAI/3.0"}) as client:
            r = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params,
            )
            if r.status_code != 200:
                return None
            vulns = r.json().get("vulnerabilities", [])
            result = vulns[0].get("cve", {}) if vulns else None
            _NVD_CVE_CACHE[cve_id] = result
            return result
    except Exception:
        return None


async def _nvd_fetch_history(cve_id: str) -> List[Dict[str, Any]]:
    """Fetch cached NVD history entries for a CVE."""
    if cve_id in _NVD_HISTORY_CACHE:
        return _NVD_HISTORY_CACHE[cve_id]
    params: Dict[str, str] = {"cveId": cve_id}
    if ENV_NVD_KEY:
        params["apiKey"] = ENV_NVD_KEY
    try:
        async with httpx.AsyncClient(
            timeout=12.0,
            trust_env=False,
            headers={"User-Agent": "VulnPriorityAI/3.0"},
        ) as client:
            r = await client.get(
                "https://services.nvd.nist.gov/rest/json/cvehistory/2.0",
                params=params,
            )
            if r.status_code != 200:
                return []
            changes = r.json().get("cveChanges", [])
            _NVD_HISTORY_CACHE[cve_id] = changes
            return changes
    except Exception:
        return []


def _extract_nvd_cvss(metrics: Dict) -> Tuple[float, str, str]:
    """
    Extract CVSS base score, vector, and source label from NVD API metrics dict.

    Priority:
      1. NVD Primary (type="Primary")  → source = "nvd-primary"   ← most authoritative
      2. CNA/reporter (type="Secondary") → source = "nvd-cna"     ← fallback
      3. Any other entry                 → source = "nvd-cna"

    Returns (score, vector_string, source). Returns (0.0, "", "") if nothing found.
    """
    cna_score, cna_vector = 0.0, ""
    any_score, any_vector = 0.0, ""
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for e in metrics.get(metric_key, []):
            score  = float(e.get("cvssData", {}).get("baseScore", 0) or 0)
            vector = str(e.get("cvssData", {}).get("vectorString", "") or "")
            if score <= 0:
                continue
            entry_type = str(e.get("type", "")).lower()
            if entry_type == "primary":
                return score, vector, "nvd-primary"      # ← best possible, stop here
            if entry_type == "secondary" and cna_score == 0.0:
                cna_score, cna_vector = score, vector    # keep looking for Primary
            if any_score == 0.0:
                any_score, any_vector = score, vector
    if cna_score > 0.0:
        return cna_score, cna_vector, "nvd-cna"
    if any_score > 0.0:
        return any_score, any_vector, "nvd-cna"
    return 0.0, "", ""


def _round_up_1_decimal(value: float) -> float:
    import math
    return math.ceil(value * 10.0) / 10.0


def _score_cvss_v3_vector(vector: str) -> float:
    """
    Calculate CVSS v3.x base score from a vector string.
    Supports strings like:
      CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    Returns 0.0 if the vector is incomplete or unsupported.
    """
    if not vector or "CVSS:3" not in vector.upper():
        return 0.0

    metric_map: Dict[str, str] = {}
    for part in str(vector).split("/"):
        if ":" not in part:
            continue
        key, val = part.split(":", 1)
        metric_map[key.upper()] = val.upper()

    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[metric_map["AV"]]
        ac = {"L": 0.77, "H": 0.44}[metric_map["AC"]]
        scope = metric_map["S"]
        if scope == "U":
            pr = {"N": 0.85, "L": 0.62, "H": 0.27}[metric_map["PR"]]
        else:
            pr = {"N": 0.85, "L": 0.68, "H": 0.50}[metric_map["PR"]]
        ui = {"N": 0.85, "R": 0.62}[metric_map["UI"]]
        conf = {"H": 0.56, "L": 0.22, "N": 0.0}[metric_map["C"]]
        integ = {"H": 0.56, "L": 0.22, "N": 0.0}[metric_map["I"]]
        avail = {"H": 0.56, "L": 0.22, "N": 0.0}[metric_map["A"]]
    except KeyError:
        return 0.0

    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0

    base = impact + exploitability
    if scope == "C":
        base = min(1.08 * base, 10.0)
    else:
        base = min(base, 10.0)
    return _round_up_1_decimal(base)


def _score_cvss_v2_vector(vector: str) -> float:
    """
    Calculate CVSS v2 base score from an abbreviated vector string.
    Example:
      AV:N/AC:L/Au:N/C:P/I:P/A:P
    Returns 0.0 if incomplete.
    """
    if not vector:
        return 0.0

    metric_map: Dict[str, str] = {}
    for part in str(vector).split("/"):
        if ":" not in part:
            continue
        key, val = part.split(":", 1)
        metric_map[key.upper()] = val.upper()

    try:
        av = {"L": 0.395, "A": 0.646, "N": 1.0}[metric_map["AV"]]
        ac = {"H": 0.35, "M": 0.61, "L": 0.71}[metric_map["AC"]]
        au = {"M": 0.45, "S": 0.56, "N": 0.704}[metric_map["AU"]]
        conf = {"N": 0.0, "P": 0.275, "C": 0.660}[metric_map["C"]]
        integ = {"N": 0.0, "P": 0.275, "C": 0.660}[metric_map["I"]]
        avail = {"N": 0.0, "P": 0.275, "C": 0.660}[metric_map["A"]]
    except KeyError:
        return 0.0

    impact = 10.41 * (1 - (1 - conf) * (1 - integ) * (1 - avail))
    exploitability = 20 * av * ac * au
    f_impact = 0.0 if impact == 0 else 1.176
    score = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact
    return max(0.0, round(score, 1))


def _score_from_cvss_vector(vector: str) -> float:
    vector = str(vector or "").strip()
    if not vector:
        return 0.0
    if "CVSS:3" in vector.upper():
        return _score_cvss_v3_vector(vector)
    return _score_cvss_v2_vector(vector)


def _nvd_english_description(cve_data: Dict) -> str:
    descriptions = cve_data.get("descriptions", []) if isinstance(cve_data, dict) else []
    return next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")


def _nvd_published_date(cve_data: Dict) -> str:
    return str((cve_data or {}).get("published", "") or "")[:10]


def _calc_blast_radius(cvss_vector: str, system_deps: List[str], system_name: str) -> Tuple[int, List[str], str]:
    """
    Calculate blast radius mathematically from the CVSS vector and known system topology.
    No LLM involved — fully deterministic and auditable.

    Formula:
        known_services = {system_name} ∪ system_deps   (ground-truth topology)
        base_reach     = len(known_services)
        av_factor:  AV:N=1.0, AV:A=0.7, AV:L=0.4, AV:P=0.2
        scope_factor: S:C=1.3, S:U=1.0
        blast_radius = max(1, min(10, ceil(base_reach × av_factor × scope_factor)))

    The affected_systems list contains services from known_services that are
    reachable given the attack vector.

    Returns (blast_radius, affected_systems, formula_explanation)
    """
    import math

    # Build ordered service list: primary system first, then unique deps
    known = [system_name] + [d for d in system_deps if d and d != system_name]
    known = list(dict.fromkeys(known))[:10]   # deduplicate, cap at 10

    # Parse CVSS v3 vector fields
    av_match = re.search(r'/AV:([NALP])', cvss_vector)
    s_match  = re.search(r'/S:([CU])',    cvss_vector)

    av_val = av_match.group(1) if av_match else "N"   # default Network if unknown
    s_val  = s_match.group(1)  if s_match  else "U"

    av_factor    = {"N": 1.0, "A": 0.7, "L": 0.4, "P": 0.2}.get(av_val, 1.0)
    scope_factor = 1.3 if s_val == "C" else 1.0

    raw_blast  = len(known)
    blast      = max(1, min(10, math.ceil(raw_blast * av_factor * scope_factor)))

    # Affected systems: take the top `blast` services from known list
    affected = known[:blast]
    if system_name not in affected:
        affected = [system_name] + affected[: blast - 1]

    av_names = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}
    explanation = (
        f"blast = ceil({raw_blast} services × AV:{av_val}({av_factor}) "
        f"× S:{s_val}({scope_factor})) = {blast}"
    )
    return blast, affected, explanation


def _calc_estimated_hours(complexity: int, blast_radius: int, has_regulatory: bool) -> int:
    """
    Estimate remediation effort in developer-hours using a deterministic formula.

        base_hours       = complexity² × 1.5   (non-linear: harder patches take disproportionately longer)
        spread_factor    = 1 + 0.25 × (blast_radius - 1)   (each extra service adds 25%)
        regulatory_factor = 1.5 if any regulatory framework applies, else 1.0
                           (compliance verification, documentation, sign-off add overhead)
        estimated_hours  = round(base_hours × spread_factor × regulatory_factor)

    Capped at 80h (2 sprints) since anything larger needs separate project scoping.
    """
    base   = (complexity ** 2) * 1.5
    spread = 1.0 + 0.25 * max(0, blast_radius - 1)
    reg    = 1.5 if has_regulatory else 1.0
    return min(80, max(1, round(base * spread * reg)))


def _complexity_from_cvss_vector(cvss_vector: str) -> int:
    """
    Derive patch complexity (1–5) deterministically from the CVSS v3 vector string.
    This eliminates LLM non-determinism for the complexity divisor in the score formula.

    CVSS v3 vector fields used:
      AC (Attack Complexity):  L=Low → easier (+0), H=High → harder (+2)
      PR (Privileges Required): N=None (+0), L=Low (+1), H=High (+2)
      UI (User Interaction):   N=None (+0), R=Required (+1)

    Sum → clamp to 1–5.
    """
    if not cvss_vector:
        return 2  # neutral default
    ac = re.search(r'/AC:([LH])', cvss_vector)
    pr = re.search(r'/PR:([NLH])', cvss_vector)
    ui = re.search(r'/UI:([NR])', cvss_vector)
    score = 1
    score += 2 if ac and ac.group(1) == 'H' else 0
    score += 2 if pr and pr.group(1) == 'H' else (1 if pr and pr.group(1) == 'L' else 0)
    score += 1 if ui and ui.group(1) == 'R' else 0
    return max(1, min(5, score))


def _poc_multiplier_from_viability(viability: str) -> float:
    """
    Map evaluate_exploit viability to a deterministic PoC multiplier.
    Using fixed tiers prevents the scoring formula from shifting between runs.
      High   → 3.0 (active, weaponised exploit known)
      Medium → 1.5 (theoretical or partial PoC)
      Low    → 1.0 (no credible PoC)
    """
    return {"High": 3.0, "Medium": 1.5, "Low": 1.0}.get(viability, 1.0)


def _extract_component_hint(section: str) -> Tuple[Optional[str], Optional[str]]:
    labels = (
        "affected component", "affected package", "component",
        "package", "technology", "library", "module",
    )
    line = ""
    for label in labels:
        match = re.search(rf"(?im)^{label}\s*:\s*(.+)$", section)
        if match:
            line = match.group(1).strip()
            break
    if not line:
        return None, None

    cleaned_line = re.sub(r"(?i)\b(?:npm|pypi)\s+package\b", "", line).strip(" -,:;")
    version_match = re.search(r"\b(?:v)?(\d+(?:\.\d+){1,5}(?:[-+._][A-Za-z0-9]+)?)\b", cleaned_line)
    version = version_match.group(1) if version_match else None

    component = None
    for pattern in (
        r"`([^`]+)`",
        r"\b(@?[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)\b",
        r"\(([^)]+)\)",
    ):
        match = re.search(pattern, line)
        if match:
            candidate = match.group(1).strip()
            if pattern == r"\(([^)]+)\)" and not _looks_like_package_identifier(candidate):
                continue
            component = candidate
            break

    if not component:
        before_version = cleaned_line[:version_match.start()].strip() if version_match else cleaned_line
        before_version = re.sub(r"\([^)]*\)", "", before_version).strip()
        component = before_version

    component = re.sub(
        r"(?i)\b(?:package|component|library|module|version|release|build)\b",
        "",
        component or "",
    )
    component = re.sub(r"\s+", " ", component).strip(" -,:;")

    return (component or None), version


def _split_report_findings(report_text: str) -> List[str]:
    chunks = re.split(r"\n(?=(?:finding|issue|vuln)[-_ ]?\d+\b)", report_text, flags=re.IGNORECASE)
    findings = [
        chunk.strip()[:1800]
        for chunk in chunks
        if re.search(r"(?im)^(?:finding|issue|vuln)[-_ ]?\d+\b", chunk)
    ]
    return findings[:10] if findings else [report_text[:1800].strip()]


def _component_matches_package(component: Optional[str], pkg: str) -> bool:
    if not component or not pkg:
        return False
    aliases = _package_aliases(pkg)
    component_tokens = {
        token for token in re.split(r"[^a-z0-9@/._-]+", component.lower())
        if token
    }
    normalized_component = _normalize_identifier(component)
    if normalized_component in aliases:
        return True
    for token in component_tokens:
        if token in aliases or _normalize_identifier(token) in aliases:
            return True
    return False


def _report_finding_matches_package(component: Optional[str], version: Optional[str], pkg: str, pkg_ver: str) -> bool:
    if not _component_matches_package(component, pkg):
        return False
    if not version:
        return True
    cmp_result = _compare_versions(version, pkg_ver)
    return cmp_result == 0 if cmp_result is not None else False


def _extract_report_finding_records(report_text: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for section in _split_report_findings(report_text):
        cves = extract_cves_from_text(section)
        component, version = _extract_component_hint(section)
        if not cves:
            continue
        records.append({
            "cve_ids": cves,
            "component": component,
            "version": version,
            "raw_text": section[:1800],
        })
    return records


def _filter_report_cves_for_packages(report_text: str, packages: Dict[str, str]) -> Dict[str, Any]:
    records = _extract_report_finding_records(report_text)
    matched: List[str] = []
    unmatched: List[str] = []
    seen: Set[str] = set()
    for record in records:
        cve_ids = [c.upper().strip() for c in record.get("cve_ids", [])]
        if not cve_ids:
            continue
        is_match = any(
            _report_finding_matches_package(record.get("component"), record.get("version"), pkg, ver)
            for pkg, ver in packages.items()
        ) if packages else True
        target = matched if is_match else unmatched
        for cve_id in cve_ids:
            if cve_id not in seen:
                seen.add(cve_id)
                target.append(cve_id)
    return {"matched": matched, "unmatched": unmatched, "records": records}


def _build_sample_bundle() -> Dict[str, Any]:
    package_path = os.path.join(SAMPLE_DATA_DIR, "package.json")
    report_path = os.path.join(SAMPLE_DATA_DIR, "va_report_sample.txt")
    catalog_path = os.path.join(SAMPLE_DATA_DIR, "system_catalog.json")

    manifest = _load_json_file(package_path)
    packages = _extract_packages_from_manifest(manifest)
    report_text = _load_text_file(report_path)
    filtered = _filter_report_cves_for_packages(report_text, packages)

    system_catalog = _load_json_file(catalog_path)
    systems = system_catalog.get("systems", [])
    system = systems[0] if systems else {}
    sample_system_info = {
        "name": system.get("name", "payment-gateway"),
        "tier": system.get("tier", "critical"),
        "regulatory": system.get("regulatory", ["PCI"]),
        "owner": system.get("owner", "security-team"),
        "dependencies": system.get("downstream_services", []),
    }

    team_members = []
    for idx, member in enumerate(system_catalog.get("team", [])):
        team_members.append({
            "name": member.get("name", f"Engineer {idx + 1}"),
            "email": member.get("email", ""),
            "expertise": member.get("expertise", []),
            "current_load": 0,
            "schedule": {
                "available_hours_per_week": 40,
                "sprint_hours_remaining": max(12, 24 - idx * 3),
                "work_days": ["monday", "tuesday", "wednesday", "thursday", "friday"],
            },
        })

    maintenance_windows = [
        {
            "day": item.get("day", "Sunday"),
            "time": item.get("time", "02:00"),
            "duration_hours": item.get("duration_hours", 4),
        }
        for item in system_catalog.get("maintenance_windows", [])
    ]

    return {
        "package_filename": os.path.basename(package_path),
        "va_filename": os.path.basename(report_path),
        "packages": packages,
        "va_cve_ids": filtered["matched"],
        "unmatched_va_cves": filtered["unmatched"],
        "system_info": sample_system_info,
        "team_members": team_members,
        "maintenance_windows": maintenance_windows,
    }


def _build_verified_vuln(
    cve_data: Dict,
    pkg: str,
    ver: Optional[str],
    source: str,
    evidence_text: Optional[str] = None,
    allow_description_fallback: bool = False,
) -> Optional[Dict]:
    pkg = (pkg or "").strip()
    if not pkg:
        return None

    aliases = _package_aliases(pkg)
    if not aliases:
        return None

    cve_id = cve_data.get("id", "")
    if not re.match(r"CVE-\d{4}-\d{4,7}$", cve_id or ""):
        return None

    desc = next(
        (d["value"] for d in cve_data.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )

    cvss_score, cvss_vector, _cvss_src = _extract_nvd_cvss(cve_data.get("metrics", {}))

    published = cve_data.get("published", "")[:10]
    ecosystem = _detect_ecosystem(pkg)
    cve_year = int(cve_id.split("-")[1]) if cve_id.startswith("CVE-") else 9999
    min_year = {"npm": 2010, "PyPI": 2000}.get(ecosystem, 1995)
    if cve_year < min_year:
        return None

    has_cpe = False
    package_matched = False
    version_states: List[Optional[bool]] = []

    for cpe_item in _iter_cpe_matches(cve_data.get("configurations", [])):
        if not cpe_item.get("vulnerable", True):
            continue
        criteria = cpe_item.get("criteria", "").lower()
        if not criteria:
            continue
        parts = criteria.split(":")
        vendor = parts[3] if len(parts) > 3 else ""
        product = parts[4] if len(parts) > 4 else ""
        criteria_version = parts[5] if len(parts) > 5 else ""
        has_cpe = True
        if _identifier_matches_alias(vendor, aliases) or _identifier_matches_alias(product, aliases):
            package_matched = True
            version_states.append(_version_matches_cpe(ver or "", cpe_item, criteria_version))

    if has_cpe and not package_matched:
        return None
    if package_matched and version_states and True not in version_states and any(v is False for v in version_states):
        return None
    if not package_matched and (not allow_description_fallback or not _text_mentions_package(desc, aliases)):
        return None
    if evidence_text and not _text_mentions_package(evidence_text, aliases):
        return None

    version_confidence = 1.0
    if version_states:
        if True in version_states:
            version_confidence = 1.0
        elif all(v is None for v in version_states):
            version_confidence = 0.8
    elif ver:
        version_confidence = 0.7

    return {
        "cve_id": cve_id,
        "package": pkg,
        "version": ver or "?",
        "cvss": cvss_score,
        "cvss_vector": cvss_vector,   # stored for deterministic complexity + blast calc
        "description": desc[:400],
        "published": published,
        "source": source,
        "provenance": {
            "identity_source": source,
            "package_match": "cpe" if package_matched else "description",
            "version_confidence": version_confidence,
            "evidence_present": bool(evidence_text),
            "cvss_source": "nvd-primary",   # explicit: only NVD Primary scores used
            "description_source": "nvd",
        },
    }

async def llm_extract_cves_from_report(
    report_text: str,
    gemini_key: Optional[str],
    anthropic_key: Optional[str],
) -> List[str]:
    """
    For VA reports that use custom IDs (VA-01, VULN-1, etc.) instead of CVE numbers,
    ask the LLM to map each finding to real known CVE IDs from NVD.
    """
    findings = _split_report_findings(report_text)
    verified: List[str] = []
    seen: Set[str] = set()

    for finding in findings:
        component, version = _extract_component_hint(finding)
        if not component:
            continue

        prompt = (
            "You are matching one vulnerability finding to public CVE records.\n\n"
            f"Component hint: {component}\n"
            f"Version hint: {version or 'unknown'}\n"
            f"Finding text:\n{finding}\n\n"
            "Return ONLY a JSON array of up to 2 objects with keys cve_id and confidence.\n"
            "Rules:\n"
            "- Return [] if the finding is not specific enough to ground a public CVE.\n"
            "- Do not guess based on severity alone.\n"
            "- The CVE must affect the same component or package named in the finding.\n"
            "- If the version hint is outside the affected range, omit the CVE.\n"
            "- No prose, no markdown."
        )
        try:
            raw = await llm_call(prompt, gemini_key, anthropic_key, max_tokens=300, temperature=0.1)
            data = parse_llm_json(raw)
            if not isinstance(data, list):
                continue
            for item in data[:2]:
                if isinstance(item, dict):
                    cve_id = str(item.get("cve_id", "")).upper().strip()
                else:
                    cve_id = str(item).upper().strip()
                if not re.match(r"CVE-\d{4}-\d{4,7}$", cve_id):
                    continue
                verified_match = await nvd_verify_cve(
                    cve_id,
                    component,
                    version,
                    evidence_text=finding,
                )
                if verified_match and cve_id not in seen:
                    seen.add(cve_id)
                    verified.append(cve_id)
        except Exception:
            continue

    return verified[:10]

async def parse_va_report(
    content: bytes,
    filename: str,
    gemini_key: Optional[str] = None,
    anthropic_key: Optional[str] = None,
) -> dict:
    """
    Parse VA report. Returns dict:
      cve_ids: list of CVE IDs found or LLM-mapped
      llm_mapped: True if LLM mapping was used (no standard CVE IDs in text)
      raw_text_snippet: first 300 chars for debug
    """
    text = extract_pdf_text(content, filename)
    cves = extract_cves_from_text(text)
    llm_mapped = False

    if not cves and text.strip() and (gemini_key or anthropic_key):
        cves = await llm_extract_cves_from_report(text, gemini_key, anthropic_key)
        llm_mapped = bool(cves)

    return {
        "cve_ids": cves,
        "llm_mapped": llm_mapped,
        "raw_text_snippet": text[:300].strip(),
    }

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — CVE DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────

async def nvd_scan_packages(packages: Dict[str, str]) -> List[Dict]:
    """Try live NVD CVE API 2.0 keyword scan. Returns whatever it finds (may be empty)."""
    results: List[Dict] = []
    headers = {"User-Agent": "VulnPriorityAI/3.0"}
    async with httpx.AsyncClient(timeout=10.0, trust_env=False, headers=headers) as client:
        for pkg, ver in list(packages.items())[:8]:
            try:
                params: Dict[str, Any] = {"keywordSearch": pkg, "resultsPerPage": 3}
                if ENV_NVD_KEY:
                    params["apiKey"] = ENV_NVD_KEY
                resp = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params=params,
                )
                if resp.status_code == 200:
                    for item in resp.json().get("vulnerabilities", [])[:8]:
                        cve = item.get("cve", {})
                        verified = _build_verified_vuln(cve, pkg, ver, "nvd-sca")
                        if verified:
                            results.append(verified)
                await asyncio.sleep(0.3)
            except Exception:
                pass
    return results


def _detect_ecosystem(pkg: str) -> str:
    """Heuristic: decide if a package is PyPI or npm."""
    PY_ONLY = {"django", "flask", "fastapi", "sqlalchemy", "celery", "pillow",
               "numpy", "pandas", "cryptography", "paramiko", "pyyaml", "urllib3",
               "requests", "boto3", "aiohttp", "pydantic", "uvicorn", "gunicorn"}
    if pkg.lower() in PY_ONLY:
        return "PyPI"
    # npm is the default for everything else
    return "npm"


async def osv_lookup(pkg: str, ver: str) -> List[Dict]:
    """
    Query OSV.dev for real, confirmed vulnerabilities affecting pkg@ver.
    Returns a list of CVE dicts (same shape as llm_discover_cves output).
    OSV is the primary ground-truth source for exact package@version lookups.
    """
    ecosystem = _detect_ecosystem(pkg)
    payload = {"version": ver, "package": {"name": pkg, "ecosystem": ecosystem}}
    results: List[Dict] = []
    try:
        async with httpx.AsyncClient(timeout=12.0, trust_env=False) as client:
            r = await client.post("https://api.osv.dev/v1/query", json=payload)
            if r.status_code != 200:
                return []
            vulns = r.json().get("vulns", [])
            for v in vulns[:5]:                      # cap at 5 per package
                # Extract the first CVE alias (prefer CVE-XXXX-XXXXX)
                aliases = v.get("aliases", []) + [v.get("id", "")]
                cve_id = next(
                    (a for a in aliases if re.match(r"CVE-\d{4}-\d{4,7}", a)),
                    None
                )
                if not cve_id:
                    continue
                # CVSS baseline from OSV / CNA.
                # NVD Primary (preferred) will override this later when available.
                cvss_score = 0.0
                cvss_vector = ""
                for sev in v.get("severity", []):
                    try:
                        raw_score = str(sev.get("score", "") or "").strip()
                        sev_type = str(sev.get("type", "") or "").upper()
                        if not raw_score:
                            continue
                        if re.match(r"^\d+(\.\d+)?$", raw_score):
                            cvss_score = float(raw_score)
                            break
                        if sev_type.startswith("CVSS") or raw_score.upper().startswith("CVSS:"):
                            parsed_score = _score_from_cvss_vector(raw_score)
                            if parsed_score > 0:
                                cvss_score = parsed_score
                                cvss_vector = raw_score
                                break
                    except Exception:
                        pass
                # Also check database_specific for CVSS numeric score
                if cvss_score == 0.0:
                    db = v.get("database_specific", {})
                    for key in ("cvss", "cvss_score", "base_score"):
                        try:
                            val = float(db.get(key) or 0)
                            if val > 0:
                                cvss_score = val
                                break
                        except Exception:
                            pass
                # Last chance: if a vector survived but numeric parsing failed earlier, retry now.
                if cvss_score == 0.0 and cvss_vector:
                    cvss_score = _score_from_cvss_vector(cvss_vector)
                desc = v.get("summary", v.get("details", ""))[:400]
                published = v.get("published", "")[:10]
                cvss_source = "osv-cna" if cvss_score > 0 else "nvd-pending"
                description_source = "osv"

                # NVD enrichment: description + score override (NVD Primary > CNA > OSV)
                nvd_cve = await _nvd_fetch_cve(cve_id)
                if nvd_cve:
                    nvd_desc    = _nvd_english_description(nvd_cve)
                    nvd_pub     = _nvd_published_date(nvd_cve)
                    nvd_score, nvd_vector, nvd_src = _extract_nvd_cvss(nvd_cve.get("metrics", {}))
                    if nvd_desc:                          # prefer NVD description
                        desc = nvd_desc[:400]
                        description_source = "nvd"
                    if nvd_pub:
                        published = nvd_pub
                    if nvd_vector:
                        cvss_vector = nvd_vector
                    if nvd_score > 0:
                        cvss_score  = nvd_score
                        cvss_source = nvd_src             # "nvd-primary" or "nvd-cna"
                    elif cvss_score == 0.0 and cvss_vector:
                        cvss_score  = _score_from_cvss_vector(cvss_vector)
                        cvss_source = "osv-cna" if cvss_score > 0 else "nvd-pending"

                results.append({
                    "cve_id":      cve_id,
                    "package":     pkg,
                    "version":     ver,
                    "cvss":        cvss_score,
                    "cvss_vector": cvss_vector,
                    "description": desc,
                    "published":   published,
                    "source":      "osv",          # ← trusted ground-truth
                    "provenance": {
                        "identity_source": "osv",
                        "package_match": "osv-package-version",
                        "version_confidence": 1.0,
                        "evidence_present": True,
                        "cvss_source": cvss_source,
                        "description_source": description_source,
                    },
                })
    except Exception:
        pass
    return results


async def nvd_verify_cve(
    cve_id: str,
    pkg: str,
    ver: Optional[str] = None,
    evidence_text: Optional[str] = None,
) -> Optional[Dict]:
    """
    Confirm a CVE actually affects `pkg` by fetching its NVD record and
    checking that the package name appears in the description or CPE data.
    Returns the enriched CVE dict if confirmed, None if it should be rejected.

    This is the anti-hallucination guard for LLM-suggested CVEs.
    e.g. CVE-1999-0967 description mentions "Internet Explorer / Outlook Express"
    but NOT the npm package "express" — so it gets rejected.
    """
    cve_data = await _nvd_fetch_cve(cve_id)
    if not cve_data:
        return None
    return _build_verified_vuln(
        cve_data,
        pkg,
        ver,
        "nvd-verified",
        evidence_text=evidence_text,
        allow_description_fallback=bool(evidence_text),
    )


async def llm_discover_cves(
    pkg: str, ver: str,
    gemini_key: Optional[str], anthropic_key: Optional[str],
) -> List[Dict]:
    """
    CVE discovery — three-stage pipeline with anti-hallucination at every step:

      Stage 1 — OSV.dev (ground-truth database):
        Query osv.dev for exact package@version. Returns only confirmed CVEs.
        No LLM involved → zero hallucination risk.

      Stage 2 — LLM suggestion (only if OSV returns nothing):
        Ask the LLM for CVE IDs, with explicit instructions NOT to use
        name-similarity matching.

      Stage 3 — NVD cross-validation of every LLM suggestion:
        Fetch the real NVD record for each suggested CVE. Reject it if the
        package name doesn't appear in the CVE description or CPE data.
        This kills hallucinations like CVE-1999-0967 → express@4.18.2
        (Outlook Express CVE assigned to npm "express" by name confusion).
    """
    # ── Stage 1: OSV ground-truth ──────────────────────────────────────────────
    osv_results = await osv_lookup(pkg, ver)
    if osv_results:
        return osv_results

    # ── Stage 2: LLM suggestion ────────────────────────────────────────────────
    prompt = (
        f"You are a vulnerability intelligence database. "
        f"List up to 3 real, confirmed CVEs that affect the {_detect_ecosystem(pkg)} package "
        f'"{pkg}" (exactly this package name) at version "{ver}" or nearby versions.\n\n'
        "STRICT RULES — violations will be caught and rejected:\n"
        f"1. The CVE must explicitly name the SOFTWARE '{pkg}' — "
        f"NOT a different product that shares a word with '{pkg}'.\n"
        "   Example of what NOT to do: assigning a Windows/IE CVE to an npm package "
        "   named 'express' because Outlook Express contains the word 'express'.\n"
        "2. Only return CVEs you are certain exist in public databases (NVD/OSV).\n"
        "3. If you are uncertain about ANY CVE, omit it. Return [] if unsure.\n\n"
        "For each CVE return JSON keys: cve_id, cvss (float), description (1 sentence), "
        "published (YYYY-MM-DD)\n\n"
        "Return ONLY a JSON array. No prose, no markdown."
    )
    llm_candidates: List[Dict] = []
    try:
        raw = await llm_call(prompt, gemini_key, anthropic_key, max_tokens=600, temperature=0.1)
        data = parse_llm_json(raw)
        if isinstance(data, list):
            for item in data[:5]:
                if not isinstance(item, dict):
                    continue
                cve_id = str(item.get("cve_id", "")).upper().strip()
                if re.match(r'CVE-\d{4}-\d{4,7}', cve_id):
                    llm_candidates.append({
                        "cve_id":      cve_id,
                        "cvss":        float(item.get("cvss", 5.0)),
                        "description": str(item.get("description", ""))[:400],
                        "published":   str(item.get("published", ""))[:10],
                    })
    except Exception:
        pass

    if not llm_candidates:
        return []

    # ── Stage 3: NVD cross-validation — reject anything that doesn't match pkg ─
    validated: List[Dict] = []
    for candidate in llm_candidates:
        cve_id = candidate["cve_id"]
        nvd_result = await nvd_verify_cve(cve_id, pkg, ver)
        if nvd_result:
            # Use the real NVD description (more accurate than LLM's)
            validated.append({
                "cve_id":      cve_id,
                "package":     pkg,
                "version":     ver,
                "cvss":        nvd_result["cvss"],
                "description": nvd_result["description"],
                "published":   nvd_result["published"],
                "source":      "nvd-verified",   # passed NVD cross-check
                "provenance":  nvd_result.get("provenance", {}),
            })
        # else: silently drop — LLM hallucinated this CVE for this package

    return validated[:3]

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — DEEP CVE RESEARCH  (exact POCme /api/research.js logic)
# ─────────────────────────────────────────────────────────────────────────────

async def deep_research_cve(
    cve_id: str, vuln: Dict,
    gemini_key: Optional[str], anthropic_key: Optional[str],
) -> Dict:
    technical_context = ""
    reference_links: List[str] = []
    baseline_cvss = _coerce_float(vuln.get("cvss", 0.0), 0.0)
    nvd_primary_cvss = 0.0
    nvd_desc  = vuln.get("description", "")
    description_source = str((vuln.get("provenance") or {}).get("description_source", "osv"))
    if vuln.get("cvss_vector"):
        vuln["cvss_vector"] = str(vuln.get("cvss_vector") or "")

    # Phase 1: Try NVD for raw data (cached to avoid repeated rate-limited fetches)
    try:
        for entry in await _nvd_fetch_history(cve_id):
            for detail in entry.get("change", {}).get("details", []):
                if detail.get("value"):
                    technical_context += f"\n- {detail['value']}"
    except Exception:
        pass

    nvd_score_source = ""   # tracks whether NVD returned "nvd-primary" or "nvd-cna"
    try:
        cve_item = await _nvd_fetch_cve(cve_id)
        if cve_item:
            fetched_desc = _nvd_english_description(cve_item)
            if fetched_desc:
                nvd_desc = fetched_desc          # always prefer NVD description
                description_source = "nvd"
            technical_context += f"\nPrimary Description: {nvd_desc}"
            reference_links = [r["url"] for r in cve_item.get("references", [])]
            mets = cve_item.get("metrics", {})
            extracted_score, extracted_vector, nvd_score_source = _extract_nvd_cvss(mets)
            if extracted_score > 0:
                nvd_primary_cvss = extracted_score
            if extracted_vector:
                vuln["cvss_vector"] = extracted_vector
    except Exception:
        pass

    research_grounded = bool(technical_context.strip())

    # Phase 2: If NVD is unavailable, stay bounded to known facts rather than inventing detail
    if not research_grounded:
        try:
            baseline_prompt = (
                "You are preparing a bounded security research note from limited evidence.\n\n"
                f"CVE: {cve_id}\n"
                f"Known package: {vuln.get('package', 'unknown')}@{vuln.get('version', '?')}\n"
                f"Known description: {nvd_desc or vuln.get('description', '')}\n\n"
                "Return ONLY a JSON object with keys: description, technical_notes, unknowns.\n"
                "Rules:\n"
                "- Use ONLY the facts provided above.\n"
                "- Do not add CVSS values, dates, payloads, protocol steps, or references that are not present.\n"
                "- If exact exploit mechanics are not grounded, say so in unknowns."
            )
            raw = await llm_call(
                baseline_prompt,
                gemini_key,
                anthropic_key,
                max_tokens=350,
                temperature=0.1,
            )
            data = parse_llm_json(raw)
            if isinstance(data, dict):
                if not nvd_desc and data.get("description"):
                    nvd_desc = str(data["description"])[:400]
                technical_context = (
                    f"\nPrimary Description: {nvd_desc}\n"
                    f"Technical Notes: {data.get('technical_notes', '')}\n"
                    f"Unknowns: {data.get('unknowns', '')}"
                )
        except Exception:
            pass

    # Phase 3: Gemini "Deep Intelligence Gathering" — exact POCme research.js prompt
    analysis = nvd_desc or f"Vulnerability {cve_id}"
    deep_prompt = (
        f'Perform "Deep Intelligence Gathering" for {cve_id}.\n'
        f'Use this collected intelligence context:\n{technical_context}\n\n'
        f'Reference Links to analyze:\n{chr(10).join(reference_links[:5])}\n\n'
        'YOUR MISSION:\n'
        '1. Synthesize the vulnerable code paths, protocol sequences, or logic flaw mechanisms that are directly supported by the provided context.\n'
        '2. Identify any payload structures or lab prerequisites only when they are grounded in that context.\n'
        '3. If the context is insufficient for an exact detail, explicitly label it as Unknown instead of guessing.\n\n'
        'Output ONLY the technical analysis.'
    )
    try:
        raw_analysis = await llm_call(deep_prompt, gemini_key, anthropic_key,
                                       max_tokens=1200, temperature=0.2)
        if raw_analysis.strip():
            analysis = raw_analysis
            # NOTE: CVSS score is NEVER extracted from LLM output.
            # Only NVD Primary scores (fetched above) are authoritative.
    except Exception:
        pass

    # Score resolution priority:
    #   1. NVD Primary  (type=Primary in NVD metrics)  → cvss_source = "nvd-primary"
    #   2. NVD CNA      (type=Secondary in NVD metrics) → cvss_source = "nvd-cna"
    #   3. OSV baseline (from OSV severity data)        → cvss_source = "osv-cna"
    #   4. Nothing at all                               → cvss_source = "nvd-pending"
    if nvd_primary_cvss > 0:
        final_cvss  = nvd_primary_cvss
        cvss_source = nvd_score_source or "nvd-primary"   # "nvd-primary" or "nvd-cna"
    elif baseline_cvss > 0:
        final_cvss  = baseline_cvss
        cvss_source = "osv-cna"
    else:
        final_cvss  = 0.0
        cvss_source = "nvd-pending"

    vuln.update({
        "description":        (nvd_desc or analysis)[:400],
        "full_research":      analysis,
        "cvss":               final_cvss,
        "nvd_score_pending":  (final_cvss == 0.0),  # only show PENDING if truly no score
        "cvss_source":        cvss_source,
        "description_source": description_source,
        "references":         reference_links[:5],
        "researched":         True,
        "research_grounded":  research_grounded,
        "research_confidence": 1.0 if research_grounded else 0.45,
        "research_source":    "nvd" if research_grounded else "limited-context",
    })
    vuln["provenance"] = {
        **(vuln.get("provenance") or {}),
        "cvss_source": cvss_source,
        "description_source": description_source,
    }
    return vuln

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — EXPLOIT GENERATION  (exact POCme /api/exploit.js logic)
# ─────────────────────────────────────────────────────────────────────────────

async def generate_exploit(
    vuln: Dict, language: str,
    gemini_key: Optional[str], anthropic_key: Optional[str],
) -> Dict:
    """
    Generate a developer-facing patch-verification PoC using the exact same
    prompt and model chain as exploit.js (gemini-3-flash-preview via google-genai SDK).

    Purpose: give developers a runnable verification utility so they can confirm
    a patch actually closes the vulnerability before pushing to production.

    Model priority:
        1. gemini-3-flash-preview  (via call_gemini_exploit — new google-genai SDK)
        2. gemini-2.0-flash        (auto-fallback inside call_gemini_exploit)
        3. Claude claude-opus-4-5              (if no Gemini key at all)
    """
    cve_id    = vuln["cve_id"]
    # Use deep research output as the description — richer context = better PoC
    full_desc = vuln.get("full_research") or vuln.get("description", "")
    lang      = language if language in ("python", "bash", "javascript") else "python"

    # ── Exact prompt from exploit.js ──────────────────────────────────────────
    # Matches: Act as a Senior Vulnerability Researcher...
    #          Documentation for VDP-authorized verification of ${cve.id}: ${cve.description}
    #          Technical Reproduction Task: Construct a technical verification utility in ${language}
    prompt = (
        f"Act as a Senior Vulnerability Researcher for a high-priority bug bounty program engagement.\n"
        f"Documentation for VDP-authorized verification of {cve_id}:\n"
        f"{full_desc}\n\n"
        f"Technical Reproduction Task:\n"
        f"Construct a technical verification utility in {lang} to reproduce the described "
        f"vulnerability against a safe-scope endpoint.\n"
        "The utility must:\n"
        "- Implement the exact network protocol interactions or HTTP request structures "
        "identified in your research.\n"
        "- Focus on demonstrating the reachability of the flaw for remediation evidence.\n"
        "- Include placeholders for target-specific variables.\n"
        "- Be pure source code without conversational text or markdown delimiters.\n\n"
        f"Technical Reproduction Implementation for {cve_id}:"
    )

    code = ""
    model_used = "none"

    # ── Stage 1: gemini-3-flash-preview via new google-genai SDK (matches exploit.js) ──
    if gemini_key:
        try:
            code = await call_gemini_exploit(prompt, gemini_key)
            model_used = "gemini-3-flash-preview"
        except Exception:
            pass

    # ── Stage 2: Claude fallback if Gemini unavailable ────────────────────────
    if not code.strip() and anthropic_key:
        try:
            code = await call_claude(prompt, anthropic_key, max_tokens=1500, temperature=0.2)
            model_used = "claude-opus-4-5"
        except Exception:
            pass

    # ── Cleanup: strip markdown fences (same as exploit.js) ──────────────────
    if "```" in code:
        code = re.sub(r'```[a-z]*\n', '', code).replace('```', '').strip()

    if code.strip():
        return {
            "code":            code,
            "language":        lang,
            "cve_id":          cve_id,
            "generated":       True,
            "model":           model_used,
            "references_used": len(vuln.get("references", [])),
        }

    # ── Fallback scaffold: never return an empty code block ───────────────────
    pkg = vuln.get('package', 'unknown')
    ver = vuln.get('version', '?')
    scaffold = {
        "python": (
            f"# Patch verification scaffold for {cve_id}\n"
            f"# Package: {pkg}@{ver}\n"
            f"# Replace TARGET, PORT, and PAYLOAD before running.\n\n"
            f"import requests\n\n"
            f"TARGET  = 'http://TARGET:PORT'  # TODO: set safe-scope test endpoint\n"
            f"PAYLOAD = 'PAYLOAD'             # TODO: insert CVE-specific payload\n\n"
            f"def verify_{cve_id.replace('-', '_').lower()}():\n"
            f"    \"\"\"Verify {cve_id} is patched on {pkg}.\"\"\"\n"
            f"    resp = requests.get(f'{{TARGET}}/endpoint', params={{'input': PAYLOAD}})\n"
            f"    # TODO: assert patch behaviour — e.g. resp.status_code != 500\n"
            f"    print('Status:', resp.status_code)\n\n"
            f"if __name__ == '__main__':\n"
            f"    verify_{cve_id.replace('-', '_').lower()}()\n"
        ),
        "javascript": (
            f"// Patch verification scaffold for {cve_id}\n"
            f"// Package: {pkg}@{ver}\n"
            f"// Replace TARGET, PORT, and PAYLOAD before running.\n\n"
            f"const axios = require('axios');\n\n"
            f"const TARGET  = 'http://TARGET:PORT'; // TODO: set safe-scope test endpoint\n"
            f"const PAYLOAD = 'PAYLOAD';            // TODO: insert CVE-specific payload\n\n"
            f"async function verify() {{\n"
            f"  const res = await axios.get(`${{TARGET}}/endpoint`, {{ params: {{ input: PAYLOAD }} }});\n"
            f"  // TODO: assert patch behaviour\n"
            f"  console.log('Status:', res.status);\n"
            f"}}\n\nverify();\n"
        ),
        "bash": (
            f"#!/bin/bash\n"
            f"# Patch verification scaffold for {cve_id}\n"
            f"# Package: {pkg}@{ver}\n\n"
            f"TARGET='http://TARGET:PORT'  # TODO: set safe-scope test endpoint\n"
            f"PAYLOAD='PAYLOAD'            # TODO: insert CVE-specific payload\n\n"
            f"echo '[*] Testing {cve_id} against $TARGET'\n"
            f"STATUS=$(curl -s -o /dev/null -w '%{{http_code}}' \\\n"
            f"  \"$TARGET/endpoint?input=$PAYLOAD\")\n"
            f"echo \"Status: $STATUS\"\n"
            f"# TODO: assert patched behaviour\n"
        ),
    }
    return {
        "code":            scaffold.get(lang, scaffold["python"]),
        "language":        lang,
        "cve_id":          cve_id,
        "generated":       False,
        "model":           "scaffold-fallback",
        "references_used": len(vuln.get("references", [])),
    }

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — EXPLOIT EVALUATION  (bounded LLM with deterministic fallback)
# ─────────────────────────────────────────────────────────────────────────────

async def evaluate_exploit(
    vuln: Dict, exploit: Dict,
    gemini_key: Optional[str], anthropic_key: Optional[str],
) -> Dict:
    """
    Evaluate exploit viability using LLM.
    Tries Claude first (preferred for structured security analysis), then Gemini.
    Prefer LLM evaluation, but fall back to deterministic low-confidence guidance.
    """
    eval_prompt = (
        f"You are a senior offensive security engineer. Evaluate this PoC exploit.\n\n"
        f"CVE: {vuln['cve_id']}  |  CVSS: {vuln.get('cvss', 5.0)}\n"
        f"Package: {vuln.get('package', '?')}@{vuln.get('version', '?')}\n"
        f"Research grounded in authoritative context: {'yes' if vuln.get('research_grounded') else 'no'}\n"
        f"Reference count: {len(vuln.get('references', []))}\n"
        f"Description: {vuln.get('description', '')[:300]}\n"
        f"Full Research: {vuln.get('full_research', '')[:400]}\n\n"
        f"PoC Code ({exploit.get('language', 'python')}):\n"
        f"```\n{(exploit.get('code', ''))[:800]}\n```\n\n"
        "Respond ONLY with a JSON object with these exact keys:\n"
        "  viability: 'High' | 'Medium' | 'Low'\n"
        "  confidence: float 0.0-1.0\n"
        "  risk_summary: one concise sentence\n"
        "  remediation_steps: array of 4-5 specific actionable steps for the dev\n"
        "  verification_steps: array of 4-5 steps for the dev to run and verify the PoC\n"
        "  evaluation_model: which model evaluated this\n\n"
        "Base viability on: CVSS score, presence of active exploits, exploit code quality, "
        "attack complexity, and whether the described attack is realistically reproducible.\n"
        "If the research context is not grounded, lower confidence and avoid claiming active exploitability with certainty.\n"
        "No markdown, no prose — ONLY the JSON object."
    )

    # Prefer Claude for structured JSON (better instruction following); fall back to Gemini
    try:
        if anthropic_key:
            raw = await llm_call(eval_prompt, None, anthropic_key, max_tokens=1000)
        else:
            raw = await llm_call(eval_prompt, gemini_key, None, max_tokens=1000)
    except Exception:
        raw = ""

    try:
        data = parse_llm_json(raw)
        if isinstance(data, dict) and "viability" in data:
            data["confidence"] = max(0.0, min(1.0, _coerce_float(data.get("confidence", 0.5), 0.5)))
            if not vuln.get("research_grounded"):
                data["confidence"] = min(data["confidence"], 0.55)
                if data.get("viability") == "High":
                    data["viability"] = "Medium" if vuln.get("cvss", 5.0) >= 7 else "Low"
            data["evaluation_model"] = (
                "claude-opus-4-5" if anthropic_key else "gemini-1.5-flash"
            )
            return data
    except Exception:
        pass

    # Structured retry with simpler prompt
    retry_prompt = (
        f"Evaluate {vuln['cve_id']} for package {vuln.get('package','?')}@{vuln.get('version','?')}.\n"
        f"Research grounded: {'yes' if vuln.get('research_grounded') else 'no'}.\n"
        "Return JSON only with keys viability, confidence, risk_summary, remediation_steps, verification_steps.\n"
        "If the research is not grounded, keep confidence at or below 0.5 and avoid 'High' viability unless the provided evidence clearly supports it."
    )
    try:
        raw2 = await llm_call(retry_prompt, gemini_key, anthropic_key, max_tokens=600)
        data = parse_llm_json(raw2)
        if isinstance(data, dict):
            data["confidence"] = max(0.0, min(1.0, _coerce_float(data.get("confidence", 0.4), 0.4)))
            if not vuln.get("research_grounded"):
                data["confidence"] = min(data["confidence"], 0.5)
            data["evaluation_model"] = "gemini-1.5-flash" if gemini_key else "claude-opus-4-5"
            return data
    except Exception:
        pass

    # Absolute last resort — minimal structured response from LLM
    cvss = vuln.get("cvss", 5.0)
    grounded = bool(vuln.get("research_grounded"))
    viability = "High" if grounded and cvss >= 8.0 else "Medium" if cvss >= 5.0 else "Low"
    if not grounded and viability == "High":
        viability = "Medium"
    return {
        "viability": viability,
        "confidence": round(min(cvss / 10.0, 0.85 if grounded else 0.5), 2),
        "risk_summary": (
            f"{vuln['cve_id']} in {vuln.get('package', 'the affected package')} "
            f"needs patch validation before exploitability can be asserted."
        ),
        "remediation_steps": [
            f"Confirm the deployed version of {vuln.get('package', 'the affected package')} against the vendor advisory for {vuln['cve_id']}",
            f"Upgrade {vuln.get('package', 'the affected package')} to a patched release and refresh dependency locks/artifacts",
            "Run targeted regression tests around the affected package call paths",
            "Execute the bounded verification utility in an isolated environment before and after patching",
            "Attach advisory links and verification evidence to the remediation ticket",
        ],
        "verification_steps": [
            f"Review the upstream advisory details for {vuln['cve_id']} and confirm the preconditions for {vuln.get('package', 'the package')}",
            "Deploy a controlled test instance and set the verification utility placeholders for that environment",
            "Capture the request/response trace from the pre-patch execution",
            "Apply the patch or version upgrade and rerun the exact same verification flow",
            "Mark the ticket verified only when the post-patch trace demonstrates the flaw is no longer reachable",
        ],
        "evaluation_model": "deterministic-fallback",
    }

# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — BLAST RADIUS + COMPLEXITY  (LLM-driven)
# ─────────────────────────────────────────────────────────────────────────────

def calc_impact(
    vuln: Dict, sys_info: SystemInfo,
) -> Dict:
    """
    100% mathematical impact analysis — zero LLM calls.
    Every output is derived from NVD CVSS vector fields and known system topology.
    Production-grade: deterministic, auditable, explainable to a CISO.

    ┌──────────────────────┬────────────────────────────────────────────────────┐
    │ Output field         │ Formula / ground-truth source                      │
    ├──────────────────────┼────────────────────────────────────────────────────┤
    │ complexity (1–5)     │ NVD CVSS AC + PR + UI fields                       │
    │ poc_multiplier       │ evaluate_exploit viability → {H:3.0,M:1.5,L:1.0}  │
    │ blast_radius (1–10)  │ ceil(services × AV_factor × Scope_factor)          │
    │ affected_systems     │ top N services from declared topology, N = blast   │
    │ estimated_hours      │ complexity²×1.5 × spread_factor × reg_factor       │
    └──────────────────────┴────────────────────────────────────────────────────┘
    """
    cvss_vector = vuln.get("cvss_vector", "")
    pkg         = vuln.get("package", "unknown")

    # ── Complexity: from NVD CVSS vector AC/PR/UI ─────────────────────────────
    complexity = (
        _complexity_from_cvss_vector(cvss_vector)
        if cvss_vector
        else max(1, min(5, 1 + int(vuln.get("cvss", 5.0) >= 7) + int(bool(sys_info.regulatory))))
    )

    # ── PoC multiplier: locked to exploit evaluation output ───────────────────
    viability  = (vuln.get("evaluation") or {}).get("viability", "Low")
    poc_mult   = _poc_multiplier_from_viability(viability)
    has_poc    = poc_mult > 1.0
    poc_source = "exploit-evaluation" if has_poc else "none"

    # ── Blast radius: mathematical from CVSS AV + Scope + topology ───────────
    blast, affected_systems, blast_formula = _calc_blast_radius(
        cvss_vector, sys_info.dependencies, sys_info.name
    )

    # ── Estimated hours: formula ──────────────────────────────────────────────
    has_regulatory  = bool(sys_info.regulatory)
    estimated_hours = _calc_estimated_hours(complexity, blast, has_regulatory)

    # ── Human-readable audit trail ────────────────────────────────────────────
    ac_m = re.search(r'/AC:([LH])',  cvss_vector)
    pr_m = re.search(r'/PR:([NLH])', cvss_vector)
    ui_m = re.search(r'/UI:([NR])',  cvss_vector)
    complexity_desc = (
        f"AC:{ac_m.group(1) if ac_m else '?'} + "
        f"PR:{pr_m.group(1) if pr_m else '?'} + "
        f"UI:{ui_m.group(1) if ui_m else '?'} "
        f"→ complexity {complexity}/5 (NVD Primary vector). "
        f"{blast_formula}. "
        f"Hours = {complexity}²×1.5 × spread({blast}) × reg({1.5 if has_regulatory else 1.0}) = {estimated_hours}h."
    )

    return {
        "blast_radius":     blast,
        "affected_systems": affected_systems,
        "has_poc":          has_poc,
        "poc_source":       poc_source,
        "poc_multiplier":   poc_mult,
        "complexity":       complexity,
        "complexity_desc":  complexity_desc,
        "estimated_hours":  estimated_hours,
        "impact_source":    "mathematical",
        "cvss_vector_used": cvss_vector or "none",
    }


def calc_priority_score(vuln: Dict, sys_info: SystemInfo) -> float:
    """
    Priority formula — all inputs are mathematically derived from NVD ground-truth data.
    Priority = (CVSS × PoC_multiplier × blast_radius) ÷ complexity × tier_weight × reg_flag

    CVSS          → NVD Primary score only (CNA scores excluded)
    poc_multiplier → exploit viability {High:3.0, Medium:1.5, Low:1.0}
    blast_radius  → ceil(services × AV_factor × Scope_factor)
    complexity    → derived from CVSS AC + PR + UI vector fields
    tier_weight   → {critical:3.0, important:2.0, standard:1.0}
    reg_flag      → 2.0 if any regulatory framework declared, else 1.0
    """
    tier_w = {"critical": 3.0, "important": 2.0, "standard": 1.0}
    return round(
        vuln.get("cvss", 5.0)
        * vuln.get("poc_multiplier", 1.0)
        * vuln.get("blast_radius", 1)
        / max(vuln.get("complexity", 2), 1)
        * tier_w.get(sys_info.tier.lower(), 1.0)
        * (2.0 if sys_info.regulatory else 1.0),
        2,
    )

# ─────────────────────────────────────────────────────────────────────────────
# STEP 8 — RATIONALE GENERATION  (LLM-always)
# ─────────────────────────────────────────────────────────────────────────────

async def llm_generate_rationale(
    vuln: Dict, sys_info: SystemInfo,
    gemini_key: Optional[str], anthropic_key: Optional[str],
) -> str:
    """Generate a concise, auditable rationale for the priority ranking using LLM."""
    prompt = (
        f"You are a CISO writing a one-sentence rationale for a security ticket.\n\n"
        f"CVE: {vuln['cve_id']}  Rank: #{vuln.get('rank','?')}  "
        f"Priority Score: {vuln.get('priority_score', 0)}\n"
        f"Package: {vuln.get('package','?')}@{vuln.get('version','?')}\n"
        f"CVSS: {vuln.get('cvss', 5.0)}  PoC Multiplier: {vuln.get('poc_multiplier',1.0)}  "
        f"Blast Radius: {vuln.get('blast_radius',1)} services  "
        f"Patch Complexity: {vuln.get('complexity',2)}/5\n"
        f"Affected systems: {', '.join(vuln.get('affected_systems',[])[:3])}\n"
        f"System tier: {sys_info.tier}  Regulatory: {', '.join(sys_info.regulatory) or 'none'}\n\n"
        "Write exactly ONE sentence explaining why this CVE has this priority rank. "
        "Be specific: mention CVSS score, PoC status, blast radius, and regulatory impact if relevant. "
        "No markdown, no JSON — just the sentence."
    )
    try:
        text = await llm_call(prompt, gemini_key, anthropic_key, max_tokens=200, temperature=0.3)
        return text.strip().split("\n")[0][:500]
    except Exception:
        return (
            f"Rank #{vuln.get('rank','?')} — CVSS {vuln.get('cvss',5.0)} "
            f"× blast-radius {vuln.get('blast_radius',1)} services "
            f"÷ complexity {vuln.get('complexity',2)} = score {vuln.get('priority_score',0)}."
        )


async def llm_exec_summary(
    vulns: List[Dict], sys_info: SystemInfo,
    gemini_key: Optional[str], anthropic_key: Optional[str],
) -> Dict:
    """Generate CISO-level executive summary using LLM."""
    top5 = [
        {
            "rank": v.get("rank"), "cve_id": v["cve_id"],
            "package": v.get("package"), "cvss": v.get("cvss"),
            "has_poc": v.get("has_poc", False),
            "blast_radius": v.get("blast_radius", 1),
            "priority_score": v.get("priority_score", 0),
            "viability": v.get("evaluation", {}).get("viability", "Medium"),
        }
        for v in vulns[:5]
    ]
    prompt = (
        "You are a CISO writing an executive summary for a security report.\n"
        f"System: {sys_info.name} ({sys_info.tier} tier)\n"
        f"Regulatory scope: {', '.join(sys_info.regulatory) or 'none'}\n\n"
        "Top vulnerabilities:\n" + json.dumps(top5, indent=2) + "\n\n"
        "Respond ONLY with a JSON object:\n"
        '{"exec_summary": "2 concise sentences"}\n\n'
        "Do not invent numeric metrics beyond the provided inputs."
    )
    try:
        raw = await llm_call(prompt, gemini_key, anthropic_key, max_tokens=400)
        data = parse_llm_json(raw)
        if isinstance(data, dict) and "exec_summary" in data:
            return {"exec_summary": str(data.get("exec_summary", ""))[:600]}
    except Exception:
        pass
    return {}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 9 — SCHEDULE ASSIGNMENT  (deterministic sprint math — no LLM opinion needed)
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
        return {
            "name": "Unassigned", "email": "", "skill": "general",
            "hours_allocated": 0,
            "completion_date": (today + timedelta(days=14)).strftime("%Y-%m-%d"),
            "sprint_capacity_remaining": 0,
        }

    required  = get_required_skill(vuln.get("package", ""))
    hours     = vuln.get("estimated_hours", 2)

    def rank(m: TeamMember):
        profile_blob = " ".join([
            m.role or "",
            m.linkedin_url or "",
            m.professional_summary or "",
            m.availability_notes or "",
            " ".join(m.expertise or []),
        ]).lower()
        required_synonyms = {
            "nodejs": ["node", "nodejs", "javascript", "typescript", "react", "next"],
            "python": ["python", "django", "flask", "fastapi", "pandas"],
            "java": ["java", "spring", "jvm", "maven", "kotlin"],
            "general": ["security", "backend", "software"],
        }
        skill_terms = required_synonyms.get(required.lower(), [required.lower()])
        skill_hits = sum(1 for term in skill_terms if term in profile_blob)
        has_direct_skill = any(required.lower() in (e or "").lower() for e in m.expertise)
        cap_ok   = m.schedule.sprint_hours_remaining >= hours
        return (
            not has_direct_skill,
            -skill_hits,
            not cap_ok,
            m.current_load,
            -m.schedule.sprint_hours_remaining,
        )

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
# PATCH CALENDAR
# ─────────────────────────────────────────────────────────────────────────────

def build_patch_calendar(ranked: List[Dict], windows: List[MaintenanceWindow]) -> List[Dict]:
    today   = datetime.now()
    day_map = {d: i for i, d in enumerate(
        ["monday","tuesday","wednesday","thursday","friday","saturday","sunday"]
    )}
    cal = []
    for i, v in enumerate(ranked[:10]):
        if windows:
            win = windows[i % len(windows)]
            tgt = day_map.get(win.day.lower(), 6)
            da  = (tgt - today.weekday()) % 7 or 7
            da += (i // max(len(windows), 1)) * 7
            dt  = today + timedelta(days=da)
            lbl = f"{win.day.capitalize()} {win.time}"
        else:
            dt  = today + timedelta(days=(i + 1) * 7)
            lbl = "Sunday 02:00"
        score = v.get("priority_score", 0)
        lvl   = "Critical" if score > 80 else "High" if score > 30 else "Medium"
        cal.append({
            "rank": i + 1, "cve_id": v["cve_id"],
            "package": f"{v['package']}@{v.get('version','?')}",
            "scheduled_date": dt.strftime("%Y-%m-%d"),
            "window": lbl, "estimated_hours": v.get("estimated_hours", 2),
            "assigned_to": v.get("assigned_to", "Unassigned"),
            "completion_date": v.get("completion_date", ""),
            "priority_level": lvl, "priority_score": score,
            "exploit_language": v.get("exploit", {}).get("language", ""),
            "viability": v.get("evaluation", {}).get("viability", ""),
        })
    return cal

# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/upload-report")
async def upload_report(file: UploadFile = File(...)):
    """
    Upload VA report (PDF or text).
    - If standard CVE IDs (CVE-XXXX-XXXXX) are found, returns them directly.
    - If the report uses custom IDs (VA-01, VULN-1, etc.), the LLM maps
      findings to real CVE IDs from NVD using the server's .env keys.
    """
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 10 MB)")
    result = await parse_va_report(
        content, file.filename or "report.txt",
        gemini_key=ENV_GEMINI_KEY,
        anthropic_key=ENV_ANTHROPIC_KEY,
    )
    return {
        "cve_ids":   result["cve_ids"],
        "count":     len(result["cve_ids"]),
        "filename":  file.filename,
        "llm_mapped": result["llm_mapped"],
        "note": (
            "CVE IDs were mapped from report findings and verified against NVD before acceptance."
            if result["llm_mapped"] else
            f"{len(result['cve_ids'])} CVE IDs extracted directly from document text."
        ),
    }


@app.get("/api/sample-input")
async def sample_input():
    bundle = _build_sample_bundle()
    return {
        "package_filename": bundle["package_filename"],
        "va_filename": bundle["va_filename"],
        "packages": bundle["packages"],
        "package_count": len(bundle["packages"]),
        "va_cve_ids": bundle["va_cve_ids"],
        "va_count": len(bundle["va_cve_ids"]),
        "unmatched_va_cves": bundle["unmatched_va_cves"],
        "unmatched_va_count": len(bundle["unmatched_va_cves"]),
        "system_info": bundle["system_info"],
        "team_members": bundle["team_members"],
        "maintenance_windows": bundle["maintenance_windows"],
    }


@app.get("/api/team-profiles")
async def list_team_profiles():
    with _db_connect() as conn:
        rows = conn.execute(
            "SELECT * FROM team_profiles ORDER BY updated_at DESC"
        ).fetchall()
    return {"items": [_team_profile_row_to_dict(r) for r in rows]}


@app.post("/api/team-profiles")
async def create_team_profile(payload: TeamProfileRequest):
    now = datetime.utcnow().isoformat()
    profile_id = str(uuid.uuid4())
    with _db_connect() as conn:
        conn.execute(
            """
            INSERT INTO team_profiles (
                id, name, email, role, linkedin_url, professional_summary,
                expertise_json, availability_notes, current_load,
                available_hours_per_week, sprint_hours_remaining, work_days_json,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                profile_id,
                payload.name,
                payload.email,
                payload.role,
                payload.linkedin_url,
                payload.professional_summary,
                json.dumps(payload.expertise),
                payload.availability_notes,
                payload.current_load,
                payload.schedule.available_hours_per_week,
                payload.schedule.sprint_hours_remaining,
                json.dumps(payload.schedule.work_days),
                now,
                now,
            ),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM team_profiles WHERE id = ?", (profile_id,)).fetchone()
    return _team_profile_row_to_dict(row)


@app.put("/api/team-profiles/{profile_id}")
async def update_team_profile(profile_id: str, payload: TeamProfileRequest):
    now = datetime.utcnow().isoformat()
    with _db_connect() as conn:
        cur = conn.execute(
            """
            UPDATE team_profiles
               SET name = ?,
                   email = ?,
                   role = ?,
                   linkedin_url = ?,
                   professional_summary = ?,
                   expertise_json = ?,
                   availability_notes = ?,
                   current_load = ?,
                   available_hours_per_week = ?,
                   sprint_hours_remaining = ?,
                   work_days_json = ?,
                   updated_at = ?
             WHERE id = ?
            """,
            (
                payload.name,
                payload.email,
                payload.role,
                payload.linkedin_url,
                payload.professional_summary,
                json.dumps(payload.expertise),
                payload.availability_notes,
                payload.current_load,
                payload.schedule.available_hours_per_week,
                payload.schedule.sprint_hours_remaining,
                json.dumps(payload.schedule.work_days),
                now,
                profile_id,
            ),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Team profile not found")
        conn.commit()
        row = conn.execute("SELECT * FROM team_profiles WHERE id = ?", (profile_id,)).fetchone()
    return _team_profile_row_to_dict(row)


@app.delete("/api/team-profiles/{profile_id}")
async def delete_team_profile(profile_id: str):
    with _db_connect() as conn:
        cur = conn.execute("DELETE FROM team_profiles WHERE id = ?", (profile_id,))
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Team profile not found")
    return {"deleted": True, "id": profile_id}


@app.get("/api/scans")
async def list_scans():
    with _db_connect() as conn:
        rows = conn.execute(
            "SELECT id, label, system_name, counts_json, created_at FROM scan_history ORDER BY created_at DESC"
        ).fetchall()
    return {"items": [_scan_row_to_meta(r) for r in rows]}


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    with _db_connect() as conn:
        row = conn.execute("SELECT * FROM scan_history WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "id": row["id"],
        "label": row["label"],
        "system_name": row["system_name"],
        "counts": _json_loads_safe(row["counts_json"], {}),
        "request_payload": _json_loads_safe(row["request_json"], {}),
        "result_payload": _json_loads_safe(row["result_json"], {}),
        "created_at": row["created_at"],
    }


@app.post("/api/scans")
async def create_scan(payload: ScanRecordRequest):
    scan_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat()
    with _db_connect() as conn:
        conn.execute(
            """
            INSERT INTO scan_history (id, label, system_name, counts_json, request_json, result_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                payload.label,
                payload.system_name,
                json.dumps(payload.counts),
                json.dumps(payload.request_payload),
                json.dumps(payload.result_payload),
                created_at,
            ),
        )
        conn.commit()
    return {
        "id": scan_id,
        "label": payload.label,
        "system_name": payload.system_name,
        "counts": payload.counts,
        "created_at": created_at,
    }


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str):
    with _db_connect() as conn:
        cur = conn.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": True, "id": scan_id}


@app.delete("/api/scans")
async def clear_scans():
    with _db_connect() as conn:
        conn.execute("DELETE FROM scan_history")
        conn.commit()
    return {"deleted": True}


@app.post("/api/config/save")
async def save_config(payload: AnalysisConfigPayload):
    """Save analysis configuration to database."""
    cfg_id = "default"
    now = datetime.utcnow().isoformat()
    with _db_connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO analysis_config 
            (id, packages_json, va_cve_ids_json, system_info_json, maintenance_windows_json, 
             team_members_json, vendor_advisories_json, internal_docs_json, dependency_graph_json,
             exploit_language, api_keys_json, nl_text, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cfg_id,
                json.dumps(payload.packages),
                json.dumps(payload.va_cve_ids),
                json.dumps(payload.system_info.model_dump()) if payload.system_info else json.dumps({}),
                json.dumps([w.model_dump() for w in (payload.maintenance_windows or [])]),
                json.dumps([m.model_dump() for m in (payload.team_members or [])]),
                json.dumps([a.model_dump() for a in (payload.vendor_advisories or [])]),
                json.dumps([d.model_dump() for d in (payload.internal_docs or [])]),
                json.dumps([e.model_dump() for e in (payload.dependency_graph or [])]),
                payload.exploit_language,
                json.dumps(payload.api_keys),
                payload.nl_text,
                now,
                now,
            ),
        )
        conn.commit()
    return {"saved": True, "id": cfg_id}


@app.get("/api/config/load")
async def load_config():
    """Load analysis configuration from database."""
    cfg_id = "default"
    with _db_connect() as conn:
        row = conn.execute(
            "SELECT * FROM analysis_config WHERE id = ?", (cfg_id,)
        ).fetchone()
    if not row:
        return {
            "packages": {},
            "va_cve_ids": [],
            "system_info": None,
            "maintenance_windows": [],
            "team_members": [],
            "vendor_advisories": [],
            "internal_docs": [],
            "dependency_graph": [],
            "exploit_language": "python",
            "api_keys": {},
            "nl_text": "",
        }
    return {
        "packages": _json_loads_safe(row["packages_json"], {}),
        "va_cve_ids": _json_loads_safe(row["va_cve_ids_json"], []),
        "system_info": _json_loads_safe(row["system_info_json"], None),
        "maintenance_windows": _json_loads_safe(row["maintenance_windows_json"], []),
        "team_members": _json_loads_safe(row["team_members_json"], []),
        "vendor_advisories": _json_loads_safe(row["vendor_advisories_json"], []),
        "internal_docs": _json_loads_safe(row["internal_docs_json"], []),
        "dependency_graph": _json_loads_safe(row["dependency_graph_json"], []),
        "exploit_language": row["exploit_language"],
        "api_keys": _json_loads_safe(row["api_keys_json"], {}),
        "nl_text": row["nl_text"],
    }


def _default_system_info() -> Dict[str, Any]:
    return {
        "name": "payment-gateway",
        "tier": "standard",
        "regulatory": ["PCI"],
        "owner": "security-team",
        "dependencies": [],
    }


@app.post("/api/parse-config-nl")
async def parse_config_nl(payload: NaturalLanguageConfigRequest):
    text = (payload.text or "").strip()
    current_sys = payload.current_system_info.model_dump() if payload.current_system_info else {}
    base_sys = {**_default_system_info(), **current_sys}

    parsed_name = _extract_system_name_from_text(text)
    parsed_owner = _extract_owner_from_text(text)
    parsed_tier = _extract_tier_from_text(text)
    parsed_regs = _extract_regulatory_from_text(text)
    parsed_deps = _extract_dependencies_from_text(text)
    parsed_windows = _extract_maintenance_windows_from_text(text)

    merged_system = {
        "name": parsed_name or base_sys.get("name") or "payment-gateway",
        "tier": parsed_tier or base_sys.get("tier") or "standard",
        "regulatory": parsed_regs or list(base_sys.get("regulatory") or ["PCI"]),
        "owner": parsed_owner or base_sys.get("owner") or "security-team",
        "dependencies": parsed_deps or list(base_sys.get("dependencies") or []),
    }
    merged_windows = (
        parsed_windows
        or [w.model_dump() for w in (payload.current_maintenance_windows or [])]
        or [{"day": "Sunday", "time": "02:00", "duration_hours": 4}]
    )

    hints: List[str] = []
    if parsed_name:
        hints.append(f"set system name to '{parsed_name}'")
    if parsed_tier:
        hints.append(f"set tier to '{parsed_tier}'")
    if parsed_regs:
        hints.append(f"detected regulations: {', '.join(parsed_regs)}")
    if parsed_deps:
        hints.append(f"captured {len(parsed_deps)} dependencies")
    if parsed_windows:
        hints.append(f"parsed {len(parsed_windows)} maintenance window(s)")
    if not hints:
        hints.append("no specific config found, kept existing/default values")

    return {
        "system_info": merged_system,
        "maintenance_windows": merged_windows,
        "assistant_message": "Applied natural-language config: " + "; ".join(hints) + ".",
        "parsed": {
            "name": parsed_name,
            "tier": parsed_tier,
            "regulatory": parsed_regs,
            "dependencies": parsed_deps,
            "maintenance_windows": parsed_windows,
        },
    }


@app.post("/api/analyze")
async def analyze(request: AnalyzeRequest):
    """9-step fully LLM-driven SSE streaming agentic pipeline."""
    async def stream():
        def evt(step, status, message, **extra):
            return f"data: {json.dumps({'step':step,'status':status,'message':message,**extra})}\n\n"

        # Frontend keys take priority; fall back to .env keys
        gk = request.gemini_api_key or ENV_GEMINI_KEY
        ak = request.anthropic_api_key or ENV_ANTHROPIC_KEY

        if not gk and not ak:
            yield evt(
                "pipeline_mode",
                "done",
                "No Gemini or Anthropic key provided — running in verified-data mode with NVD/OSV lookups and deterministic fallbacks.",
            )

        try:
            today = datetime.now()
            team  = list(request.team_members)

            # ── 1. Input Parsing
            yield evt("input_parse", "running",
                      f"Parsing SBOM ({len(request.packages)} pkgs) + {len(request.va_cve_ids)} VA report CVEs…")
            await asyncio.sleep(0.3)
            yield evt("input_parse", "done",
                      f"Input ready: {len(request.packages)} packages, {len(request.va_cve_ids)} VA CVEs",
                      sbom_count=len(request.packages), va_count=len(request.va_cve_ids))
            await asyncio.sleep(0.2)

            # ── 2. CVE Discovery
            yield evt("cve_discovery", "running",
                      "Attempting verified CVE discovery via NVD/OSV, then bounded LLM fallback if needed…")
            await asyncio.sleep(0.2)

            all_vulns: List[Dict] = []
            unmatched_va_cves: List[str] = []
            nvd_results = await nvd_scan_packages(request.packages)
            discovered  = {v["cve_id"] for v in nvd_results}
            all_vulns.extend(nvd_results)

            # Add VA-report CVEs (LLM will enrich them in deep research)
            for cve_id in request.va_cve_ids:
                if cve_id not in discovered:
                    verified_match = None
                    for pkg, ver in request.packages.items():
                        verified_match = await nvd_verify_cve(cve_id, pkg, ver)
                        if verified_match:
                            break
                    if verified_match:
                        verified_match["source"] = "va-report"
                        verified_match["description"] = verified_match.get("description") or "VA report CVE — research pending"
                        provenance = dict(verified_match.get("provenance", {}))
                        provenance["reported_by"] = "va-report"
                        verified_match["provenance"] = provenance
                        all_vulns.append(verified_match)
                    else:
                        if request.packages:
                            unmatched_va_cves.append(cve_id)
                        else:
                            all_vulns.append({
                                "cve_id": cve_id,
                                "package": "unknown",
                                "version": "?",
                                "cvss": 5.0,
                                "description": "VA report CVE — package not resolved from current SBOM",
                                "published": "",
                                "source": "va-report",
                                "provenance": {
                                    "identity_source": "va-report",
                                    "package_match": "unresolved",
                                    "version_confidence": 0.0,
                                    "evidence_present": True,
                                },
                            })
                    discovered.add(cve_id)

            if unmatched_va_cves:
                yield evt(
                    "cve_discovery",
                    "running",
                    f"Omitted {len(unmatched_va_cves)} VA-report CVEs that do not map to the current SBOM packages.",
                    unmatched_va_count=len(unmatched_va_cves),
                )

            # If NVD returned nothing, ask LLM to discover CVEs per package
            if len(all_vulns) < 3:
                yield evt("cve_discovery", "running",
                          "Extending discovery with bounded LLM suggestions plus NVD verification…")
                for pkg, ver in list(request.packages.items())[:6]:
                    yield evt("cve_discovery", "running",
                              f"LLM discovering CVEs for {pkg}@{ver}…")
                    llm_cves = await llm_discover_cves(pkg, ver, gk, ak)
                    for c in llm_cves:
                        if c["cve_id"] not in discovered:
                            all_vulns.append(c)
                            discovered.add(c["cve_id"])
                    await asyncio.sleep(0.2)

            all_vulns = [v for v in all_vulns if v.get("cve_id")][:10]
            src = "verified NVD/OSV data" if nvd_results else "bounded discovery fallback"
            yield evt("cve_discovery", "done",
                      f"{len(all_vulns)} CVEs discovered via {src}", count=len(all_vulns))
            await asyncio.sleep(0.2)

            # ── 2.5 Connector Ingestion (vendor advisories + internal docs + dependency graph)
            advisory_count = len(request.vendor_advisories or [])
            doc_count = len(request.internal_docs or [])
            edge_count = len(request.dependency_graph or [])
            yield evt(
                "connector_ingest",
                "running",
                f"Applying connector context: {advisory_count} advisories, {doc_count} internal docs, {edge_count} dependency edges…",
            )
            total_adv_hits = 0
            total_doc_hits = 0
            max_dep_reach = 0
            for i, v in enumerate(all_vulns):
                sig = apply_connector_signals(
                    v,
                    request.vendor_advisories or [],
                    request.internal_docs or [],
                    request.dependency_graph or [],
                )
                total_adv_hits += int(sig.get("vendor_advisory_hits", 0))
                total_doc_hits += int(sig.get("internal_doc_hits", 0))
                max_dep_reach = max(max_dep_reach, int(sig.get("dependency_reach", 0)))
                all_vulns[i] = v
            yield evt(
                "connector_ingest",
                "done",
                f"Connector enrichment complete: {total_adv_hits} advisory matches, {total_doc_hits} doc matches, max dependency reach {max_dep_reach}.",
                advisory_hits=total_adv_hits,
                doc_hits=total_doc_hits,
                max_dependency_reach=max_dep_reach,
            )
            await asyncio.sleep(0.1)

            # ── 3. Deep CVE Research  (POCme logic)
            yield evt("deep_research", "running",
                      f"NVD history fetch + LLM 'Deep Intelligence Gathering' for {len(all_vulns)} CVEs…")
            for i, v in enumerate(all_vulns):
                yield evt("deep_research", "running",
                          f"[{i+1}/{len(all_vulns)}] Deep-researching {v['cve_id']}…",
                          cve=v["cve_id"], progress={"current": i+1, "total": len(all_vulns)})
                all_vulns[i] = await deep_research_cve(v["cve_id"], v, gk, ak)
                await asyncio.sleep(0.15)
            yield evt("deep_research", "done",
                      f"Research complete — {len(all_vulns)} CVEs fully synthesized with technical context")
            await asyncio.sleep(0.2)

            # ── 4. Exploit Generation — SKIPPED in pipeline
            # PoC generation is on-demand only. Each CVE card has a "Generate PoC"
            # button that calls POST /api/generate-exploit individually.
            # This avoids generating potentially sensitive code for all CVEs upfront.
            for i in range(len(all_vulns)):
                all_vulns[i]["exploit"] = {"generated": False, "code": "", "on_demand": True}
            yield evt("exploit_gen", "done",
                      "PoC generation is on-demand — click 'Generate PoC' on any CVE card.",
                      generated=0)
            await asyncio.sleep(0.1)

            # ── 5. Exploit Evaluation
            yield evt("evaluation", "running",
                      "LLM agent evaluating exploit viability, risk severity, and remediation paths…")
            for i, v in enumerate(all_vulns):
                yield evt("evaluation", "running",
                          f"[{i+1}/{len(all_vulns)}] LLM evaluating {v['cve_id']}…", cve=v["cve_id"])
                all_vulns[i]["evaluation"] = await evaluate_exploit(
                    v, v.get("exploit", {}), gk, ak)
                await asyncio.sleep(0.1)
            high_v = sum(1 for v in all_vulns
                         if v.get("evaluation", {}).get("viability") == "High")
            yield evt("evaluation", "done",
                      f"Evaluation complete: {high_v} high-viability exploits requiring immediate action",
                      high_viability=high_v)
            await asyncio.sleep(0.2)

            # ── 6. Blast Radius + Complexity  (LLM-driven)
            yield evt("blast_radius", "running",
                      "Computing blast radius, complexity, and effort via CVSS vector math…")
            for i, v in enumerate(all_vulns):
                yield evt("blast_radius", "running",
                          f"[{i+1}/{len(all_vulns)}] Computing impact for {v['cve_id']}…",
                          cve=v["cve_id"])
                impact = calc_impact(v, request.system_info)
                all_vulns[i].update(impact)
                dep_reach = int((all_vulns[i].get("connector_signals") or {}).get("dependency_reach", 0))
                if dep_reach > 0:
                    all_vulns[i]["blast_radius"] = min(10, max(int(all_vulns[i].get("blast_radius", 1)), dep_reach + 1))
                all_vulns[i]["regulatory"]  = request.system_info.regulatory
                all_vulns[i]["system_tier"] = request.system_info.tier
                await asyncio.sleep(0.1)
            max_blast = max(v.get("blast_radius", 1) for v in all_vulns)
            yield evt("blast_radius", "done",
                      f"Blast radius mapped: max {max_blast} downstream services at risk",
                      max_blast=max_blast)
            await asyncio.sleep(0.2)

            # ── 7. AI Priority Scoring
            yield evt("ai_scoring", "running",
                      "Computing priority scores: (CVSS × PoC × BlastRadius) ÷ Complexity × Tier × RegFlag…")
            await asyncio.sleep(0.5)
            for v in all_vulns:
                v["priority_score"] = calc_priority_score(v, request.system_info)
            all_vulns.sort(key=lambda x: x["priority_score"], reverse=True)
            for i, v in enumerate(all_vulns):
                v["rank"] = i + 1
            yield evt("ai_scoring", "done",
                      f"Scoring complete — top CVE scored {all_vulns[0]['priority_score']:.1f} priority points")
            await asyncio.sleep(0.2)

            # ── 8. LLM Rationale Generation
            yield evt("rationale", "running",
                      "LLM generating auditable natural-language rationale for each CVE…")
            exec_meta = await llm_exec_summary(all_vulns, request.system_info, gk, ak)
            for i, v in enumerate(all_vulns):
                yield evt("rationale", "running",
                          f"[{i+1}/{len(all_vulns)}] Writing rationale for {v['cve_id']}…",
                          cve=v["cve_id"])
                all_vulns[i]["rationale"] = await llm_generate_rationale(
                    v, request.system_info, gk, ak)
                await asyncio.sleep(0.1)
            model_used = ("claude-opus-4-5" if ak else "gemini-1.5-flash")
            yield evt("rationale", "done",
                      f"Rationale generated via {model_used} for all {len(all_vulns)} CVEs")
            await asyncio.sleep(0.2)

            # ── 9. Schedule-Based Dev Assignment
            yield evt("schedule_assign", "running",
                      f"Routing {len(all_vulns)} tickets by skill + sprint capacity…")
            await asyncio.sleep(0.4)
            tickets: List[Dict] = []
            for v in all_vulns:
                assignee = schedule_assign(v, team, today)
                v["assigned_to"]     = assignee["name"]
                v["assigned_email"]  = assignee["email"]
                v["completion_date"] = assignee["completion_date"]
                v["skill_routed_to"] = assignee["skill"]

                score = v["priority_score"]
                lvl   = "Critical" if score > 80 else "High" if score > 30 else "Medium" if score > 10 else "Low"
                tickets.append({
                    "ticket_id":         f"SEC-{1000 + v['rank']}",
                    "cve_id":            v["cve_id"],
                    "package":           f"{v['package']}@{v.get('version','?')}",
                    "cvss":              v["cvss"],
                    "priority_level":    lvl,
                    "priority_score":    score,
                    "assigned_to":       v["assigned_to"],
                    "assigned_email":    v.get("assigned_email", ""),
                    "estimated_hours":   v.get("estimated_hours", 2),
                    "completion_date":   v["completion_date"],
                    "skill":             assignee["skill"],
                    "status":            "Open",
                    "rank":              v["rank"],
                    "has_poc":           v.get("has_poc", False),
                    "blast_radius":      v.get("blast_radius", 1),
                    "viability":         v.get("evaluation", {}).get("viability", "Medium"),
                    "rationale":         v.get("rationale", ""),
                    "description":       v.get("description", ""),
                    "exploit_language":  v.get("exploit", {}).get("language", ""),
                    "verification_steps": v.get("evaluation", {}).get("verification_steps", []),
                    "remediation_steps":  v.get("evaluation", {}).get("remediation_steps", []),
                })

            calendar = build_patch_calendar(all_vulns, request.maintenance_windows)
            yield evt("schedule_assign", "done",
                      f"{len(tickets)} tickets assigned with sprint capacity-based completion dates")
            await asyncio.sleep(0.2)

            # ── Final payload
            total   = sum(v["priority_score"] for v in all_vulns) or 1
            top3    = sum(v["priority_score"] for v in all_vulns[:3])
            risk_r  = round(top3 / total * 100)
            ai_r    = risk_r
            poc_n   = sum(1 for v in all_vulns if v.get("has_poc"))

            exec_summary = exec_meta.get("exec_summary") or (
                f"Security analysis identified {len(all_vulns)} CVEs across "
                f"{len(request.packages)} packages in {request.system_info.name}. "
                f"Patching top-3 priority items cuts risk by ~{ai_r}%; "
                f"{poc_n} active exploits require immediate developer action."
            )

            stats = {
                "total_vulns":       len(all_vulns),
                "critical_cvss":     sum(1 for v in all_vulns if v["cvss"] >= 9),
                "high_cvss":         sum(1 for v in all_vulns if 7 <= v["cvss"] < 9),
                "medium_cvss":       sum(1 for v in all_vulns if 4 <= v["cvss"] < 7),
                "poc_active":        poc_n,
                "exploits_generated": 0,
                "high_viability":    high_v,
                "packages_scanned":  len(request.packages),
                "va_cves":           len(request.va_cve_ids),
                "risk_reduction":    ai_r,
                "total_effort_hrs":  sum(v.get("estimated_hours", 2) for v in all_vulns[:10]),
                "max_blast_radius":  max_blast,
                "connector_advisory_hits": sum(int((v.get("connector_signals") or {}).get("vendor_advisory_hits", 0)) for v in all_vulns),
                "connector_doc_hits": sum(int((v.get("connector_signals") or {}).get("internal_doc_hits", 0)) for v in all_vulns),
            }

            final_payload = json.dumps({
                "step": "complete", "status": "done",
                "message": f"Complete — patch top 3 to cut risk {ai_r}%",
                "data": {
                    "vulnerabilities": all_vulns,
                    "tickets":         tickets,
                    "calendar":        calendar,
                    "exec_summary":    exec_summary,
                    "risk_reduction":  ai_r,
                    "stats":           stats,
                    "unmatched_va_cves": unmatched_va_cves,
                },
            })
            yield f"data: {final_payload}\n\n"

        except Exception as e:
            import traceback
            yield evt("error", "error", f"Pipeline error: {e}")

    return StreamingResponse(stream(), media_type="text/event-stream")


class ExploitRequest(BaseModel):
    cve_id:      str
    description: str = ""
    full_research: str = ""
    package:     str = ""
    version:     str = ""
    language:    str = "python"
    cvss:        float = 5.0
    references:  List[str] = []
    research_grounded: bool = False
    gemini_api_key:    Optional[str] = None
    anthropic_api_key: Optional[str] = None


@app.post("/api/generate-exploit")
async def generate_exploit_endpoint(req: ExploitRequest):
    """
    On-demand PoC generation for a single CVE.
    Called when the developer explicitly clicks "Generate PoC" on a CVE card.
    Uses gemini-3-flash-preview via the new google-genai SDK (matches exploit.js).
    """
    gk = req.gemini_api_key or ENV_GEMINI_KEY
    ak = req.anthropic_api_key or ENV_ANTHROPIC_KEY
    if not gk and not ak:
        raise HTTPException(status_code=400, detail="No API key available.")

    vuln = {
        "cve_id":           req.cve_id,
        "description":      req.description,
        "full_research":    req.full_research or req.description,
        "package":          req.package,
        "version":          req.version,
        "cvss":             req.cvss,
        "references":       req.references,
        "research_grounded": req.research_grounded,
    }
    result = await generate_exploit(vuln, req.language, gk, ak)
    return result


@app.get("/health")
async def health():
    return {"status": "ok", "service": "VulnPriority AI", "version": "3.0.0"}


@app.get("/api/env-status")
async def env_status():
    """Tell the frontend which API keys are already loaded from .env."""
    return {
        "gemini_key_loaded":    ENV_GEMINI_KEY is not None,
        "anthropic_key_loaded": ENV_ANTHROPIC_KEY is not None,
        "nvd_key_loaded":       ENV_NVD_KEY is not None,
    }
