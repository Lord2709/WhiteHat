const { useState, useEffect, useRef, useCallback } = React;
// In production (Render), frontend is served by the same FastAPI server,
// so API calls are same-origin (empty string). Locally, backend runs on 8000.
const API_URL = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
  ? 'http://localhost:8000'
  : '';

const STORAGE_KEYS = {
  page: 'whitehat-ui-page-v1',
  config: 'whitehat-ui-config-v1',
  results: 'whitehat-ui-latest-results-v1',
  history: 'whitehat-ui-scan-history-v1',
  exploitLang: 'whitehat-ui-exploit-lang-v1',
  pocState: 'whitehat-ui-poc-state-v1',
  lastRequest: 'whitehat-ui-last-request-v1',
};

function readStoredJSON(key, fallback) {
  try {
    const raw = window.localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

function writeStoredJSON(key, value) {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    return;
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────
const cvssClass  = (s,p) => p||s===0?'cvss-pending':s>=9?'cvss-critical':s>=7?'cvss-high':s>=4?'cvss-medium':'cvss-low';
const cvssLabel  = (s,p,src) => {
  if (p||s===0) return 'NVD PENDING';
  const sev = s>=9?'CRITICAL':s>=7?'HIGH':s>=4?'MEDIUM':'LOW';
  if (src==='nvd-primary') return sev;           // NVD assigned — no suffix
  if (src==='nvd-cna')     return sev+' (CNA)';  // NVD has it but not yet scored by NIST
  if (src==='osv-cna')     return sev+' (CNA)';  // OSV-only fallback
  return sev;
};
const sourceDetailLabel = s => s==='nvd-primary'?'NVD/NIST':s==='osv-cna'?'CNA / OSV fallback':s==='nvd'?'NVD/NIST':s==='osv'?'OSV summary':'—';
const scoreClass = s => s>80?'high':s>30?'med':'';
const pClass     = p => `p-${(p||'medium').toLowerCase()}`;
const vClass     = v => v==='High'?'v-high':v==='Low'?'v-low':'v-medium';
const langClass  = l => `lang-${(l||'python').toLowerCase()}`;
const now        = () => new Date().toLocaleTimeString('en-US',{hour12:false});
const initials   = n => (n||'?').split(' ').map(w=>w[0]).join('').toUpperCase().slice(0,2);
const avatarClr  = n => {const h=[...n].reduce((a,c)=>a+c.charCodeAt(0),0);return ['#7c3aed','#3b82f6','#10b981','#f59e0b','#ef4444','#ec4899'][h%6];};
const sourceBadge = s => s==='va-report'?'source-va':s==='nvd-sca'||s==='nvd'||s==='nvd-verified'?'source-nvd':s==='osv'?'source-osv':s==='llm-fallback'?'source-llm-fallback':'source-demo';
const sourceLabel = s => s==='va-report'?'VA':s==='nvd-sca'||s==='nvd'?'NVD':s==='nvd-verified'?'NVD ✓':s==='osv'?'OSV ✓':s==='llm-fallback'?'LLM?':'DEMO';

const teamProfileToMember = p => ({
  name: p?.name || 'Engineer',
  email: p?.email || '',
  role: p?.role || '',
  linkedin_url: p?.linkedin_url || '',
  professional_summary: p?.professional_summary || '',
  expertise: Array.isArray(p?.expertise) ? p.expertise : [],
  availability_notes: p?.availability_notes || '',
  current_load: Number.isFinite(p?.current_load) ? p.current_load : 0,
  schedule: {
    available_hours_per_week: p?.schedule?.available_hours_per_week ?? 40,
    sprint_hours_remaining: p?.schedule?.sprint_hours_remaining ?? 20,
    work_days: Array.isArray(p?.schedule?.work_days)
      ? p.schedule.work_days
      : ['monday','tuesday','wednesday','thursday','friday'],
  },
});

const normalizeScanMeta = item => ({
  id: item?.id,
  label: item?.label || 'Scan result',
  timestamp: item?.created_at || '',
  systemName: item?.system_name || 'system',
  counts: item?.counts || {},
});

// ─── Pipeline Steps (9) ─────────────────────────────────────────────────────
const STEPS = [
  {key:'input_parse',    label:'Input Parsing',         icon:'📄',desc:'SBOM + VA report parsing'},
  {key:'cve_discovery',  label:'CVE Discovery',         icon:'🔍',desc:'OSV/NVD verification → bounded LLM fallback'},
  {key:'deep_research',  label:'Deep CVE Research',     icon:'🧬',desc:'NVD history + LLM Deep Intelligence Gathering (POCme)'},
  {key:'exploit_gen',    label:'Exploit Generation',    icon:'💣',desc:'LLM PoC synthesis — Senior Vulnerability Researcher (POCme)'},
  {key:'evaluation',     label:'Exploit Evaluation',    icon:'⚖️',desc:'Claude/Gemini viability, risk & remediation analysis'},
  {key:'blast_radius',   label:'Blast Radius Mapping',  icon:'🌐',desc:'LLM enterprise impact & PoC status analysis'},
  {key:'ai_scoring',     label:'Priority Scoring',      icon:'⚡',desc:'CVSS × PoC × Blast ÷ Complexity'},
  {key:'rationale',      label:'Rationale Generation',  icon:'🧠',desc:'LLM auditable natural-language rationale per CVE'},
  {key:'schedule_assign',label:'Schedule Assignment',   icon:'📅',desc:'Sprint capacity + completion date'},
];

// ─── Icon components ─────────────────────────────────────────────────────────
const Play = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>;
const Plus = () => <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>;
const X    = () => <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>;
const Chev = ({open}) => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" style={{transform:open?'rotate(90deg)':'none',transition:'transform .2s'}}><polyline points="9 18 15 12 9 6"/></svg>;
const Term = () => <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>;
const Key  = () => <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="8" cy="15" r="5"/><line x1="17.657" y1="6.343" x2="12.929" y2="11.071"/><line x1="17.657" y1="6.343" x2="21" y2="9.686"/><line x1="22" y1="6" x2="20" y2="8"/></svg>;
const Copy = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>;

// ─── Exploit code block with highlight.js ────────────────────────────────────
function CodeBlock({code, language}) {
  const ref = useRef(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (ref.current && window.hljs) {
      ref.current.removeAttribute('data-highlighted');
      window.hljs.highlightElement(ref.current);
    }
  }, [code]);

  const handleCopy = () => {
    navigator.clipboard.writeText(code||'').then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div className="exploit-code-wrap">
      <button className="copy-btn" onClick={handleCopy}><Copy/> {copied?'Copied!':'Copy'}</button>
      <pre><code ref={ref} className={`language-${language||'python'}`}>{code||'# No code generated'}</code></pre>
    </div>
  );
}

// ─── Configure Page ──────────────────────────────────────────────────────────
