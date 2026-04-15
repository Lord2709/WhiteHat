function ConfigurePage({onRun, exploitLang, setExploitLang, onGoTeamPage}) {
  const [packages,   setPackages]   = useState({});
  const [fileName,   setFileName]   = useState('');
  const [vaCves,     setVaCves]     = useState([]);
  const [vaLlmNote,  setVaLlmNote]  = useState('');
  const [vaFile,     setVaFile]     = useState('');
  const [vaUploading,setVaUploading]= useState(false);
  const [vaDragging, setVaDragging] = useState(false);
  const [dragging,   setDragging]   = useState(false);
  const [sysInfo, setSysInfo] = useState(() => ({name:'payment-gateway',tier:'critical',regulatory:['PCI'],owner:'security-team',dependencies:[]}));
  const [windows, setWindows] = useState(() => [{day:'Sunday',time:'02:00',duration_hours:4}]);
  const [team, setTeam] = useState(() => [
    {name:'Alex Chen',   email:'alex@co.com',  expertise:['nodejs','security'], current_load:0, schedule:{available_hours_per_week:40,sprint_hours_remaining:20,work_days:['monday','tuesday','wednesday','thursday','friday']}},
    {name:'Priya Sharma',email:'priya@co.com', expertise:['python','devops'],   current_load:0, schedule:{available_hours_per_week:40,sprint_hours_remaining:15,work_days:['monday','tuesday','wednesday','thursday','friday']}},
    {name:'Marcus Webb', email:'marcus@co.com',expertise:['nodejs','react'],    current_load:0, schedule:{available_hours_per_week:40,sprint_hours_remaining:24,work_days:['monday','tuesday','wednesday','thursday','friday']}},
  ]);
  const [newMember, setNewMember] = useState({name:'',email:'',expertiseStr:'',sprintHours:20});
  const [apiKeys,  setApiKeys]   = useState({anthropic:'',gemini:''});
  const [nlText, setNlText] = useState('');
  const [vendorAdvisoriesText, setVendorAdvisoriesText] = useState('[]');
  const [vendorLinesText, setVendorLinesText] = useState('');
  const [internalDocsText, setInternalDocsText] = useState('[]');
  const [internalLinesText, setInternalLinesText] = useState('');
  const [dependencyGraphText, setDependencyGraphText] = useState('[]');
  const [graphLinesText, setGraphLinesText] = useState('');
  const [connectorMsg, setConnectorMsg] = useState('');
  const [nlBusy, setNlBusy] = useState(false);
  const [nlMsg, setNlMsg] = useState('');
  const [teamSyncNote, setTeamSyncNote] = useState('');
  const [envKeys,  setEnvKeys]   = useState({gemini:false,anthropic:false,nvd:false});
  const [showApiModal, setShowApiModal] = useState(false);

  const normalizeSystemInfo = raw => ({
    name: raw?.name || 'payment-gateway',
    tier: raw?.tier || 'critical',
    regulatory: Array.isArray(raw?.regulatory) ? raw.regulatory : [],
    owner: raw?.owner || 'security-team',
    dependencies: Array.isArray(raw?.dependencies) ? raw.dependencies : [],
  });

  const normalizeTeamMember = m => ({
    name: m?.name || 'Engineer',
    email: m?.email || '',
    role: m?.role || '',
    linkedin_url: m?.linkedin_url || '',
    professional_summary: m?.professional_summary || '',
    expertise: Array.isArray(m?.expertise) ? m.expertise : [],
    availability_notes: m?.availability_notes || '',
    current_load: m?.current_load || 0,
    schedule: {
      available_hours_per_week: m?.schedule?.available_hours_per_week || 40,
      sprint_hours_remaining: m?.schedule?.sprint_hours_remaining || 20,
      work_days: Array.isArray(m?.schedule?.work_days) ? m.schedule.work_days : ['monday','tuesday','wednesday','thursday','friday'],
    },
  });

  const edgesToLines = edges => {
    if (!Array.isArray(edges)) return '';
    return edges
      .map(e => `${e?.source || ''} -> ${e?.target || ''}`)
      .filter(line => !line.startsWith(' ->'))
      .join('\n');
  };

  const parseGraphLines = raw => {
    const lines = (raw || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    const out = [];
    for (const line of lines) {
      const chain = line.split(/\s*->\s*/).map(s => s.trim()).filter(Boolean);
      if (chain.length < 2) continue;
      for (let i = 0; i < chain.length - 1; i += 1) {
        out.push({source: chain[i], target: chain[i + 1], relation: 'depends_on'});
      }
    }
    const uniq = [];
    const seen = new Set();
    for (const e of out) {
      const k = `${(e.source || '').toLowerCase()}|${(e.target || '').toLowerCase()}|${(e.relation || '').toLowerCase()}`;
      if (seen.has(k)) continue;
      seen.add(k);
      uniq.push(e);
    }
    return uniq;
  };

  const advisoriesToLines = advisories => {
    if (!Array.isArray(advisories)) return '';
    return advisories.map(a => [
      a?.advisory_id || '',
      a?.severity || 'medium',
      Array.isArray(a?.cve_ids) ? a.cve_ids.join(',') : '',
      Array.isArray(a?.affected_packages) ? a.affected_packages.join(',') : '',
      a?.title || '',
    ].join(' | ')).join('\n');
  };

  const parseAdvisoryLines = raw => {
    const lines = (raw || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    const advisories = [];
    for (const line of lines) {
      const [advisoryId, severity, cvesRaw, pkgsRaw, title] = line.split('|').map(s => s.trim());
      advisories.push({
        advisory_id: advisoryId || `ADV-${advisories.length + 1}`,
        title: title || advisoryId || 'Vendor advisory',
        severity: (severity || 'medium').toLowerCase(),
        cve_ids: (cvesRaw || '').split(',').map(s => s.trim()).filter(Boolean),
        affected_packages: (pkgsRaw || '').split(',').map(s => s.trim()).filter(Boolean),
        summary: '',
        url: '',
        published: '',
      });
    }
    return advisories;
  };

  const docsToLines = docs => {
    if (!Array.isArray(docs)) return '';
    return docs.map(d => [
      d?.doc_id || '',
      d?.title || '',
      Array.isArray(d?.systems) ? d.systems.join(',') : '',
      Array.isArray(d?.tags) ? d.tags.join(',') : '',
      d?.content || '',
    ].join(' | ')).join('\n');
  };

  const parseDocLines = raw => {
    const lines = (raw || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    const docs = [];
    for (const line of lines) {
      const [docId, title, systemsRaw, tagsRaw, content] = line.split('|').map(s => s.trim());
      docs.push({
        doc_id: docId || `DOC-${docs.length + 1}`,
        title: title || docId || 'Internal note',
        systems: (systemsRaw || '').split(',').map(s => s.trim()).filter(Boolean),
        tags: (tagsRaw || '').split(',').map(s => s.trim()).filter(Boolean),
        criticality: '',
        content: content || '',
      });
    }
    return docs;
  };

  const regulatoryList = Array.isArray(sysInfo?.regulatory) ? sysInfo.regulatory : [];
  useEffect(()=>{
    fetch(`${API_URL}/api/env-status`).then(r=>r.json()).then(d=>{
      setEnvKeys({gemini:!!d.gemini_key_loaded, anthropic:!!d.anthropic_key_loaded, nvd:!!d.nvd_key_loaded});
    }).catch(()=>{});
    // Load config from DB on mount
    fetch(`${API_URL}/api/config/load`).then(r=>r.ok?r.json():null).then(cfg=>{
      if (cfg) {
        if (cfg.packages && Object.keys(cfg.packages).length > 0) setPackages(cfg.packages);
        if (cfg.va_cve_ids && cfg.va_cve_ids.length > 0) setVaCves(cfg.va_cve_ids);
        if (cfg.system_info) setSysInfo(normalizeSystemInfo(cfg.system_info));
        if (cfg.maintenance_windows && cfg.maintenance_windows.length > 0) setWindows(cfg.maintenance_windows);
        if (cfg.team_members && cfg.team_members.length > 0) {
          setTeam(cfg.team_members.map(normalizeTeamMember));
        }
        if (cfg.api_keys) setApiKeys(cfg.api_keys);
        if (cfg.nl_text) setNlText(cfg.nl_text);
        if (Array.isArray(cfg.vendor_advisories)) {
          setVendorAdvisoriesText(JSON.stringify(cfg.vendor_advisories, null, 2));
          setVendorLinesText(advisoriesToLines(cfg.vendor_advisories));
        }
        if (Array.isArray(cfg.internal_docs)) {
          setInternalDocsText(JSON.stringify(cfg.internal_docs, null, 2));
          setInternalLinesText(docsToLines(cfg.internal_docs));
        }
        if (Array.isArray(cfg.dependency_graph)) {
          setDependencyGraphText(JSON.stringify(cfg.dependency_graph, null, 2));
          setGraphLinesText(edgesToLines(cfg.dependency_graph));
        }
      }
    }).catch(()=>{});
    // Auto-load team profiles from DB on mount
    fetch(`${API_URL}/api/team-profiles`).then(r=>r.ok?r.json():{items:[]}).then(d=>{
      if (Array.isArray(d.items) && d.items.length > 0) {
        const imported = d.items.map(teamProfileToMember);
        setTeam(imported);
        setTeamSyncNote(`Auto-loaded ${imported.length} team profile(s) from database.`);
      }
    }).catch(()=>{});
  }, []);
  const fileRef = useRef(null);
  const vaRef   = useRef(null);
  const sampleRef = useRef(null);

  const parsePackageJson = txt => {
    try {
      const j = JSON.parse(txt);
      const deps = {...(j.dependencies||{}), ...(j.devDependencies||{})};
      const out = {};
      for (const [k,v] of Object.entries(deps).slice(0,30))
        out[k] = v.replace(/[\^~>=<]/g,'').trim();
      return out;
    } catch { return {}; }
  };

  const handleFile = f => {
    if (!f) return;
    setFileName(f.name);
    const r = new FileReader();
    r.onload = e => setPackages(parsePackageJson(e.target.result));
    r.readAsText(f);
  };

  const handleVaFile = async f => {
    if (!f) return;
    setVaFile(f.name);
    setVaUploading(true);
    try {
      const fd = new FormData();
      fd.append('file', f);
      const resp = await fetch(`${API_URL}/api/upload-report`, {method:'POST', body:fd});
      const data = await resp.json();
      setVaCves(data.cve_ids || []);
      if (data.llm_mapped) setVaLlmNote(`🤖 LLM mapped ${data.count} CVEs from report findings (no standard CVE IDs found)`);
      else if (data.count > 0) setVaLlmNote(`✓ ${data.count} CVE IDs extracted directly from document`);
      else setVaLlmNote('⚠ No CVEs found — add packages in SBOM or use LLM discovery');
    } catch {
      // Fallback: parse as text client-side
      const r = new FileReader();
      r.onload = e => {
        const found = (e.target.result.match(/CVE-\d{4}-\d{4,7}/gi)||[]).filter((v,i,a)=>a.indexOf(v)===i);
        setVaCves(found.map(c=>c.toUpperCase()));
        setVaLlmNote(found.length > 0 ? `✓ ${found.length} CVEs found (client-side parse)` : '⚠ No CVEs found in text');
      };
      r.readAsText(f);
    }
    setVaUploading(false);
  };

  const fetchSampleBundle = async () => {
    if (sampleRef.current) return sampleRef.current;
    const resp = await fetch(`${API_URL}/api/sample-input`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
    const data = await resp.json();
    sampleRef.current = data;
    return data;
  };

  const applySampleSystem = data => {
    if (data.system_info) setSysInfo(normalizeSystemInfo(data.system_info));
    if (Array.isArray(data.team_members) && data.team_members.length) setTeam(data.team_members.map(normalizeTeamMember));
    if (Array.isArray(data.maintenance_windows) && data.maintenance_windows.length) setWindows(data.maintenance_windows);
  };

  const loadSample = async () => {
    try {
      const data = await fetchSampleBundle();
      setPackages(data.packages || {});
      setFileName(`${data.package_filename || 'sample_package.json'} (${data.package_count || Object.keys(data.packages||{}).length} packages)`);
      applySampleSystem(data);
    } catch (e) {
      setVaLlmNote(`⚠ Unable to load demo sample data: ${e.message}`);
    }
  };

  const loadSampleVa = async () => {
    try {
      const data = await fetchSampleBundle();
      setVaCves(data.va_cve_ids || []);
      setVaFile(`${data.va_filename || 'va_report_sample.txt'} (${data.va_count || (data.va_cve_ids||[]).length} matched CVEs)`);
      if ((data.unmatched_va_count||0) > 0) {
        setVaLlmNote(`✓ Loaded ${data.va_count} SBOM-matched CVEs from sample VA report; omitted ${data.unmatched_va_count} unrelated findings`);
      } else {
        setVaLlmNote(`✓ Loaded ${data.va_count || (data.va_cve_ids||[]).length} SBOM-matched CVEs from sample VA report`);
      }
    } catch (e) {
      setVaLlmNote(`⚠ Unable to load demo VA report: ${e.message}`);
    }
  };

  const toggleReg = r => setSysInfo(s=>{
    const regs = Array.isArray(s.regulatory) ? s.regulatory : [];
    return {...s,regulatory:regs.includes(r)?regs.filter(x=>x!==r):[...regs,r]};
  });

  const addMember = () => {
    const {name,email,expertiseStr,sprintHours} = newMember;
    if (!name||!email) return;
    setTeam(t=>[...t,{name,email,expertise:expertiseStr.split(',').map(s=>s.trim()).filter(Boolean),current_load:0,schedule:{available_hours_per_week:40,sprint_hours_remaining:parseInt(sprintHours)||20,work_days:['monday','tuesday','wednesday','thursday','friday']}}]);
    setNewMember({name:'',email:'',expertiseStr:'',sprintHours:20});
  };
  const removeMember = i => setTeam(t=>t.filter((_,j)=>j!==i));
  const updateSprintHours = (i,h) => setTeam(t=>t.map((m,j)=>j===i?{...m,schedule:{...m.schedule,sprint_hours_remaining:parseInt(h)||0}}:m));

  const importTeamProfiles = async () => {
    try {
      const resp = await fetch(`${API_URL}/api/team-profiles`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      const imported = (Array.isArray(data.items) ? data.items : []).map(teamProfileToMember);
      if (!imported.length) {
        setTeamSyncNote('No saved team profiles found in database.');
        return;
      }
      setTeam(imported);
      setTeamSyncNote(`Imported ${imported.length} team profiles from database.`);
    } catch (err) {
      setTeamSyncNote(`Unable to import team profiles: ${err.message}`);
    }
  };

  const parseConnectorJson = (raw, label) => {
    const txt = (raw || '').trim();
    if (!txt) return [];
    let parsed = null;
    try {
      parsed = JSON.parse(txt);
    } catch {
      throw new Error(`${label} must be valid JSON array`);
    }
    if (!Array.isArray(parsed)) throw new Error(`${label} must be a JSON array`);
    return parsed;
  };

  const parseConnectorJsonNoThrow = raw => {
    try {
      const parsed = JSON.parse((raw || '').trim() || '[]');
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  };

  const buildGraphFromLines = () => {
    const edges = parseGraphLines(graphLinesText);
    setDependencyGraphText(JSON.stringify(edges, null, 2));
    setConnectorMsg(edges.length ? `Built ${edges.length} dependency edge(s) from simple input.` : 'No valid graph lines found. Use format: source -> target');
  };

  const buildAdvisoriesFromLines = () => {
    const advisories = parseAdvisoryLines(vendorLinesText);
    setVendorAdvisoriesText(JSON.stringify(advisories, null, 2));
    setConnectorMsg(advisories.length ? `Built ${advisories.length} vendor advisory record(s) from simple input.` : 'No valid advisory lines found.');
  };

  const buildDocsFromLines = () => {
    const docs = parseDocLines(internalLinesText);
    setInternalDocsText(JSON.stringify(docs, null, 2));
    setConnectorMsg(docs.length ? `Built ${docs.length} internal doc record(s) from simple input.` : 'No valid internal-doc lines found.');
  };

  const syncDependenciesFromGraph = () => {
    const edges = parseConnectorJsonNoThrow(dependencyGraphText);
    const deps = Array.from(new Set(edges.map(e => (e?.target || '').trim()).filter(Boolean)));
    setSysInfo(s => ({...s, dependencies: deps}));
    setConnectorMsg(deps.length ? `Synced ${deps.length} downstream dependencies from graph.` : 'No dependency targets found to sync.');
  };

  useEffect(() => {
    // Auto-save config to DB (debounced: only save changes, not on every keystroke)
    const saveTimer = setTimeout(() => {
      fetch(`${API_URL}/api/config/save`, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({
          packages,
          va_cve_ids: vaCves,
          system_info: sysInfo,
          maintenance_windows: windows,
          team_members: team,
          vendor_advisories: parseConnectorJsonNoThrow(vendorAdvisoriesText),
          internal_docs: parseConnectorJsonNoThrow(internalDocsText),
          dependency_graph: parseConnectorJsonNoThrow(dependencyGraphText),
          exploit_language: exploitLang,
          api_keys: apiKeys,
          nl_text: nlText,
        }),
      }).catch(()=>{});
    }, 1000);
    return () => clearTimeout(saveTimer);
  }, [packages, vaCves, sysInfo, windows, team, exploitLang, apiKeys, nlText, vendorAdvisoriesText, internalDocsText, dependencyGraphText]);

  const hasApiKey = !!(apiKeys.anthropic || apiKeys.gemini || envKeys.gemini || envKeys.anthropic);
  const canRun = Object.keys(packages).length > 0 || vaCves.length > 0;

  const handleRun = () => {
    let vendorAdvisories = [];
    let internalDocs = [];
    let dependencyGraph = [];
    try {
      vendorAdvisories = parseConnectorJson(vendorAdvisoriesText, 'Vendor advisories');
      internalDocs = parseConnectorJson(internalDocsText, 'Internal docs');
      dependencyGraph = parseConnectorJson(dependencyGraphText, 'Dependency graph');
      setConnectorMsg('');
    } catch (err) {
      setConnectorMsg(err.message);
      return;
    }
    onRun({packages, va_cve_ids:vaCves, system_info:sysInfo, maintenance_windows:windows,
           team_members:team, vendor_advisories:vendorAdvisories, internal_docs:internalDocs, dependency_graph:dependencyGraph,
           exploit_language:exploitLang,
           anthropic_api_key:apiKeys.anthropic||null, gemini_api_key:apiKeys.gemini||null});
  };

  const applyNaturalLanguageConfig = async () => {
    if (!nlText.trim()) {
      setNlMsg('Type a short description first, for example: "Critical payment system, PCI + SOX, patch Sunday 1am for 3 hours".');
      return;
    }
    setNlBusy(true);
    setNlMsg('');
    try {
      const resp = await fetch(`${API_URL}/api/parse-config-nl`, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({
          text: nlText,
          current_system_info: sysInfo,
          current_maintenance_windows: windows,
          anthropic_api_key: apiKeys.anthropic || null,
          gemini_api_key: apiKeys.gemini || null,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
      if (data.system_info) setSysInfo(normalizeSystemInfo(data.system_info));
      if (Array.isArray(data.maintenance_windows) && data.maintenance_windows.length) setWindows(data.maintenance_windows);
      setNlMsg(data.assistant_message || 'Configuration updated from natural-language input.');
    } catch (err) {
      setNlMsg(`Unable to parse natural-language config: ${err.message}`);
    }
    setNlBusy(false);
  };

  return (
    <div className="page">
      <div style={{display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:26,flexWrap:'wrap',gap:12}}>
        <div>
          <div className="page-title">Configure Analysis</div>
          <div className="page-sub">Upload SBOM + VA report, define your system, set team schedule</div>
        </div>
        <div style={{display:'flex',flexDirection:'column',alignItems:'flex-end',gap:8}}>
          {!hasApiKey&&<div style={{background:'rgba(251,191,36,.08)',border:'1px solid rgba(251,191,36,.3)',borderRadius:8,padding:'6px 12px',fontSize:12,color:'#fcd34d',display:'flex',alignItems:'center',gap:6}}>
            ⚠ No Gemini or Anthropic key loaded — verified-data mode will still run NVD/OSV lookups and deterministic fallbacks
          </div>}
          {(envKeys.gemini||envKeys.anthropic)&&<div style={{background:'rgba(16,185,129,.1)',border:'1px solid rgba(16,185,129,.3)',borderRadius:8,padding:'6px 12px',fontSize:12,color:'#6ee7b7',display:'flex',alignItems:'center',gap:6}}>
            ✓ Server .env: {envKeys.gemini&&'Gemini'}{envKeys.gemini&&envKeys.anthropic&&' + '}{envKeys.anthropic&&'Anthropic'} key loaded{envKeys.nvd&&' + NVD'}
          </div>}
          {!envKeys.nvd&&(envKeys.gemini||envKeys.anthropic)&&<div style={{background:'rgba(251,191,36,.08)',border:'1px solid rgba(251,191,36,.3)',borderRadius:8,padding:'6px 12px',fontSize:12,color:'#fcd34d',display:'flex',alignItems:'center',gap:6}}>
            ⚠ No NVD_API_KEY — CVSS fetch limited to 5 req/30s. Add key to .env to prevent NVD PENDING on multi-CVE scans.
          </div>}
          <div style={{display:'flex',gap:10}}>
            <button className="btn btn-outline btn-sm" onClick={()=>setShowApiModal(true)}><Key/> {(envKeys.gemini||envKeys.anthropic)?'✓ .env Keys Active':'API Keys Optional'}</button>
            <button className="btn btn-primary" disabled={!canRun} onClick={handleRun} title={!hasApiKey?'Runs in verified-data mode without Gemini/Anthropic; add a key for LLM research and PoCs.':undefined}><Play/> Run Agentic Analysis</button>
          </div>
        </div>
      </div>

      <div className="card" style={{marginBottom:18}}>
        <div className="card-header"><span>💬</span><span className="card-title">Config Chat</span></div>
        <div className="card-body" style={{display:'grid',gap:10}}>
          <div className="section-label">Describe system, regulations, and maintenance in plain English</div>
          <textarea
            value={nlText}
            onChange={e=>setNlText(e.target.value)}
            placeholder="Example: Payment API for checkout, owner platform-security, critical tier, PCI + GDPR, depends on stripe and redis, patch on Sunday at 01:00 for 3 hours"
            style={{minHeight:90,resize:'vertical',background:'#0b1224',color:'#e5e7eb',border:'1px solid #334155',borderRadius:10,padding:'10px 12px'}}
          />
          <div style={{display:'flex',gap:10,flexWrap:'wrap'}}>
            <button className="btn btn-primary btn-sm" onClick={applyNaturalLanguageConfig} disabled={nlBusy}>{nlBusy?'Parsing...':'Apply from Chat'}</button>
            <button className="btn btn-outline btn-sm" onClick={()=>setNlText('')}>Clear</button>
          </div>
          {nlMsg&&<div style={{fontSize:12,color:'var(--text2)'}}>{nlMsg}</div>}
        </div>
      </div>

      <div className="card" style={{marginBottom:18}}>
        <div className="card-header"><span>🔌</span><span className="card-title">Connector Inputs (Phase 2)</span></div>
        <div className="card-body" style={{display:'grid',gap:10}}>
          <div className="section-label">Vendor advisories JSON array</div>
          <textarea
            value={vendorAdvisoriesText}
            onChange={e=>setVendorAdvisoriesText(e.target.value)}
            placeholder='[{"advisory_id":"ADV-2026-001","cve_ids":["CVE-2026-1234"],"affected_packages":["axios"],"severity":"high","title":"Vendor patch note"}]'
            style={{minHeight:90,resize:'vertical',background:'#0b1224',color:'#e5e7eb',border:'1px solid #334155',borderRadius:10,padding:'10px 12px'}}
          />
          <div className="section-label">Simple advisories input (advisory_id | severity | cves | packages | title)</div>
          <textarea
            value={vendorLinesText}
            onChange={e=>setVendorLinesText(e.target.value)}
            placeholder={'ADV-2026-001 | high | CVE-2026-1234,CVE-2026-5678 | axios,express | Vendor patch note'}
            style={{minHeight:74,resize:'vertical',background:'#0b1224',color:'#e5e7eb',border:'1px solid #334155',borderRadius:10,padding:'10px 12px'}}
          />
          <div style={{display:'flex',gap:10,flexWrap:'wrap'}}>
            <button className="btn btn-outline btn-sm" onClick={buildAdvisoriesFromLines}>Build Advisory JSON</button>
            <button className="btn btn-outline btn-sm" onClick={()=>setVendorLinesText('ADV-2026-001 | high | CVE-2026-1234 | axios | Axios security fix')}>Load Advisory Example</button>
          </div>
          <div className="section-label">Internal docs JSON array</div>
          <textarea
            value={internalDocsText}
            onChange={e=>setInternalDocsText(e.target.value)}
            placeholder='[{"doc_id":"DOC-SEC-01","title":"Payment Service Threat Notes","systems":["payment-api","reporting"],"tags":["pci"],"content":"axios path used in checkout flow"}]'
            style={{minHeight:90,resize:'vertical',background:'#0b1224',color:'#e5e7eb',border:'1px solid #334155',borderRadius:10,padding:'10px 12px'}}
          />
          <div className="section-label">Simple internal-doc input (doc_id | title | systems | tags | content)</div>
          <textarea
            value={internalLinesText}
            onChange={e=>setInternalLinesText(e.target.value)}
            placeholder={'DOC-SEC-01 | Payment Threat Notes | payment-api,reporting | pci,checkout | axios used in checkout flow'}
            style={{minHeight:74,resize:'vertical',background:'#0b1224',color:'#e5e7eb',border:'1px solid #334155',borderRadius:10,padding:'10px 12px'}}
          />
          <div style={{display:'flex',gap:10,flexWrap:'wrap'}}>
            <button className="btn btn-outline btn-sm" onClick={buildDocsFromLines}>Build Internal Docs JSON</button>
            <button className="btn btn-outline btn-sm" onClick={()=>setInternalLinesText('DOC-SEC-01 | Payment Threat Notes | payment-api,reporting | pci | axios used in checkout flow')}>Load Docs Example</button>
          </div>
          <div className="section-label">Dependency graph JSON array</div>
          <textarea
            value={dependencyGraphText}
            onChange={e=>setDependencyGraphText(e.target.value)}
            placeholder='[{"source":"axios","target":"payment-api","relation":"depends_on"},{"source":"payment-api","target":"reporting","relation":"calls"}]'
            style={{minHeight:90,resize:'vertical',background:'#0b1224',color:'#e5e7eb',border:'1px solid #334155',borderRadius:10,padding:'10px 12px'}}
          />
          <div className="section-label">Simple graph input (one chain per line)</div>
          <textarea
            value={graphLinesText}
            onChange={e=>setGraphLinesText(e.target.value)}
            placeholder={'axios -> payment-api -> reporting\nexpress -> web-gateway -> auth-service'}
            style={{minHeight:80,resize:'vertical',background:'#0b1224',color:'#e5e7eb',border:'1px solid #334155',borderRadius:10,padding:'10px 12px'}}
          />
          <div style={{display:'flex',gap:10,flexWrap:'wrap'}}>
            <button className="btn btn-outline btn-sm" onClick={buildGraphFromLines}>Build JSON from Lines</button>
            <button className="btn btn-outline btn-sm" onClick={syncDependenciesFromGraph}>Sync Dependencies from Graph</button>
            <button className="btn btn-outline btn-sm" onClick={()=>setGraphLinesText('axios -> payment-api -> reporting\njsonwebtoken -> auth-service')}>Load Example</button>
          </div>
          <div style={{fontSize:12,color:'var(--text2)'}}>These connector inputs are stored in DB and used to enrich CVE matching and dependency impact.</div>
          {connectorMsg&&<div style={{fontSize:12,color:'#fca5a5'}}>{connectorMsg}</div>}
        </div>
      </div>

      <div className="config-grid">
        {/* LEFT */}
        <div style={{display:'flex',flexDirection:'column',gap:18}}>

          {/* SBOM */}
          <div className="card">
            <div className="card-header"><span>📦</span><span className="card-title">SBOM / Package Input</span></div>
            <div className="card-body">
              <div className="section-label">Upload package.json or SBOM</div>
              <div className={`drop-zone${dragging?' drag-over':''}`}
                onDragOver={e=>{e.preventDefault();setDragging(true)}}
                onDragLeave={()=>setDragging(false)}
                onDrop={e=>{e.preventDefault();setDragging(false);handleFile(e.dataTransfer.files[0])}}
                onClick={()=>fileRef.current.click()}>
                <div className="drop-zone-icon">📂</div>
                <div className="drop-zone-title">{fileName||'Drop package.json / SBOM here'}</div>
                <div className="drop-zone-sub">{fileName?`${Object.keys(packages).length} packages loaded`:'or click to browse'}</div>
                <input ref={fileRef} type="file" accept=".json" style={{display:'none'}} onChange={e=>handleFile(e.target.files[0])}/>
              </div>
              <div style={{textAlign:'center',margin:'10px 0',color:'var(--text3)',fontSize:11}}>— or —</div>
              <button className="btn btn-outline" style={{width:'100%'}} onClick={loadSample}>⚡ Load Demo SBOM</button>
              {Object.keys(packages).length>0 && (
                <div style={{marginTop:12}}>
                  <div className="section-label">Packages ({Object.keys(packages).length})</div>
                  <div className="packages-preview">{Object.entries(packages).map(([k,v])=><div key={k} className="pkg-row"><span className="pkg-name">{k}</span><span className="pkg-ver">{v}</span></div>)}</div>
                </div>
              )}
            </div>
          </div>

          {/* VA Report */}
          <div className="card">
            <div className="card-header"><span>📋</span><span className="card-title">Vulnerability Assessment Report</span><span style={{fontSize:11,color:'#a78bfa',marginLeft:'auto'}}>optional</span></div>
            <div className="card-body">
              <div className="section-label">Upload VA/Pentest Report — CVE IDs extracted automatically</div>
              <div className={`va-drop-zone${vaDragging?' drag-over':''}`}
                onDragOver={e=>{e.preventDefault();setVaDragging(true)}}
                onDragLeave={()=>setVaDragging(false)}
                onDrop={e=>{e.preventDefault();setVaDragging(false);handleVaFile(e.dataTransfer.files[0])}}
                onClick={()=>vaRef.current.click()}>
                {vaUploading ? (
                  <div style={{display:'flex',flexDirection:'column',alignItems:'center',gap:8}}>
                    <div className="spinner" style={{width:24,height:24}}/>
                    <div style={{fontSize:12,color:'var(--text2)'}}>Extracting CVE IDs…</div>
                  </div>
                ) : (
                  <>
                    <div style={{fontSize:28,marginBottom:8}}>📄</div>
                    <div style={{fontSize:13,fontWeight:600,color:'var(--text0)',marginBottom:3}}>{vaFile||'Drop VA Report here (PDF or .txt)'}</div>
                    <div style={{fontSize:11,color:'var(--text2)'}}>{vaFile?`${vaCves.length} CVE IDs extracted`:'CVE IDs parsed automatically — supports VA-01/VULN-1 style via LLM'}</div>
                  </>
                )}
                <input ref={vaRef} type="file" accept=".pdf,.txt,.csv,.html,.xml" style={{display:'none'}} onChange={e=>handleVaFile(e.target.files[0])}/>
              </div>
              {vaLlmNote&&<div style={{marginTop:8,padding:'6px 10px',borderRadius:6,fontSize:11,background:vaLlmNote.startsWith('🤖')?'rgba(124,58,237,.12)':vaLlmNote.startsWith('⚠')?'rgba(245,158,11,.1)':'rgba(16,185,129,.1)',color:vaLlmNote.startsWith('🤖')?'#a78bfa':vaLlmNote.startsWith('⚠')?'#fbbf24':'#6ee7b7',border:`1px solid ${vaLlmNote.startsWith('🤖')?'rgba(124,58,237,.3)':vaLlmNote.startsWith('⚠')?'rgba(245,158,11,.25)':'rgba(16,185,129,.25)'}`}}>{vaLlmNote}</div>}
              <div style={{textAlign:'center',margin:'10px 0',color:'var(--text3)',fontSize:11}}>— or —</div>
              <button className="btn btn-purple btn-sm" style={{width:'100%'}} onClick={loadSampleVa}>📋 Load Demo VA Report</button>
              {vaCves.length>0 && (
                <div style={{marginTop:12}}>
                  <div className="section-label">Extracted CVE IDs ({vaCves.length})</div>
                  <div style={{display:'flex',gap:6,flexWrap:'wrap',marginTop:6}}>
                    {vaCves.map(c=><span key={c} className="cve-pill">{c}</span>)}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Exploit Language */}
          <div className="card">
            <div className="card-header"><span>💣</span><span className="card-title">Exploit Generation Settings</span></div>
            <div className="card-body">
              <div className="section-label">PoC Language (Gemini generates in this language)</div>
              <div style={{display:'flex',gap:8,marginTop:6}}>
                {['python','bash','javascript'].map(l=>(
                  <label key={l} className={`checkbox-item${exploitLang===l?' checked':''}`} style={{flex:1,justifyContent:'center'}}>
                    <input type="radio" checked={exploitLang===l} onChange={()=>setExploitLang(l)} style={{display:'none'}}/>
                    <span className={`lang-badge ${langClass(l)}`}>{l}</span>
                  </label>
                ))}
              </div>
              <div style={{marginTop:10,fontSize:11,color:'var(--text3)',lineHeight:1.6}}>
                Exploits use the exact POCme prompt: <em>"Senior Vulnerability Researcher for VDP-authorized verification"</em>
              </div>
            </div>
          </div>

          {/* Team */}
          <div className="card">
            <div className="card-header"><span>👥</span><span className="card-title">Dev Team & Sprint Schedule</span></div>
            <div className="card-body">
              <div className="section-label">Members, Skills & Sprint Capacity</div>
              <div style={{display:'flex',gap:8,marginBottom:10,flexWrap:'wrap'}}>
                <button className="btn btn-outline btn-sm" onClick={importTeamProfiles}>Import Saved Team Profiles</button>
                <button className="btn btn-outline btn-sm" onClick={onGoTeamPage}>Manage Team Profiles</button>
              </div>
              {teamSyncNote && (
                <div style={{marginBottom:10,fontSize:11,color:'var(--text2)'}}>{teamSyncNote}</div>
              )}
              <div style={{display:'flex',flexDirection:'column',gap:7,marginBottom:12}}>
                {team.map((m,i)=>(
                  <div key={i} className="team-member-item">
                    <div style={{flex:1,minWidth:0}}>
                      <div className="member-name">{m.name} <span style={{fontSize:10,color:'var(--text3)'}}>— {m.email}</span></div>
                      {!!m.role && <div style={{fontSize:10,color:'var(--text3)',marginTop:2}}>Role: {m.role}</div>}
                      <div className="member-skills">{m.expertise.map(e=><span key={e} className="skill-tag">{e}</span>)}</div>
                    </div>
                    <div style={{display:'flex',alignItems:'center',gap:8,marginLeft:8,flexShrink:0}}>
                      <div style={{textAlign:'center'}}>
                        <div style={{fontSize:9,color:'var(--text3)',marginBottom:2}}>SPRINT HRS</div>
                        <input className="sprint-input" type="number" min="0" max="80"
                          value={m.schedule.sprint_hours_remaining}
                          onChange={e=>updateSprintHours(i,e.target.value)}/>
                      </div>
                      <button className="btn btn-ghost" onClick={()=>removeMember(i)}><X/></button>
                    </div>
                  </div>
                ))}
              </div>
              <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:8}}>
                <div className="field"><label>Name</label><input value={newMember.name} onChange={e=>setNewMember(m=>({...m,name:e.target.value}))} placeholder="Jane Doe"/></div>
                <div className="field"><label>Email</label><input value={newMember.email} onChange={e=>setNewMember(m=>({...m,email:e.target.value}))} placeholder="jane@co.com"/></div>
              </div>
              <div style={{display:'grid',gridTemplateColumns:'2fr 1fr',gap:8,marginTop:8}}>
                <div className="field"><label>Skills (comma-separated)</label><input value={newMember.expertiseStr} onChange={e=>setNewMember(m=>({...m,expertiseStr:e.target.value}))} placeholder="nodejs, python, security"/></div>
                <div className="field"><label>Sprint Hrs</label><input type="number" min="0" max="80" value={newMember.sprintHours} onChange={e=>setNewMember(m=>({...m,sprintHours:e.target.value}))} placeholder="20"/></div>
              </div>
              <button className="btn btn-outline btn-sm" style={{width:'100%',marginTop:10}} onClick={addMember}><Plus/> Add Team Member</button>
            </div>
          </div>
        </div>

        {/* RIGHT */}
        <div style={{display:'flex',flexDirection:'column',gap:18}}>

          {/* System Info */}
          <div className="card">
            <div className="card-header"><span>🏢</span><span className="card-title">System Configuration</span></div>
            <div className="card-body">
              <div className="field-group">
                <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12}}>
                  <div className="field"><label>System Name</label><input value={sysInfo.name} onChange={e=>setSysInfo(s=>({...s,name:e.target.value}))} placeholder="payment-gateway"/></div>
                  <div className="field"><label>Criticality Tier</label>
                    <select value={sysInfo.tier} onChange={e=>setSysInfo(s=>({...s,tier:e.target.value}))}>
                      <option value="critical">Critical (×3.0)</option>
                      <option value="important">Important (×2.0)</option>
                      <option value="standard">Standard (×1.0)</option>
                    </select>
                  </div>
                </div>
                <div className="field"><label>Owner</label><input value={sysInfo.owner} onChange={e=>setSysInfo(s=>({...s,owner:e.target.value}))} placeholder="security-team"/></div>
                <div className="field">
                  <label>Regulatory Exposure (×2.0 multiplier)</label>
                  <div className="checkbox-group" style={{marginTop:4}}>
                    {['PCI','SOX','HIPAA','GDPR','FedRAMP'].map(r=>(
                      <label key={r} className={`checkbox-item${regulatoryList.includes(r)?' checked':''}`}>
                        <input type="checkbox" checked={regulatoryList.includes(r)} onChange={()=>toggleReg(r)} style={{display:'none'}}/>{r}
                      </label>
                    ))}
                  </div>
                </div>
                <div className="field"><label>Known Downstream Dependencies</label><input value={sysInfo.dependencies.join(', ')} onChange={e=>setSysInfo(s=>({...s,dependencies:e.target.value.split(',').map(x=>x.trim()).filter(Boolean)}))} placeholder="auth-service, reporting-service"/></div>
              </div>
            </div>
          </div>

          {/* Maintenance Windows */}
          <div className="card">
            <div className="card-header"><span>🕐</span><span className="card-title">Maintenance Windows</span></div>
            <div className="card-body">
              <div className="section-label">Scheduled Downtime for Patching</div>
              <div style={{display:'flex',flexDirection:'column',gap:8,marginBottom:10}}>
                {windows.map((w,i)=>(
                  <div key={i} className="window-item">
                    <span>🗓️</span>
                    <select value={w.day} onChange={e=>{const ww=[...windows];ww[i]={...ww[i],day:e.target.value};setWindows(ww)}} style={{background:'var(--bg2)',border:'1px solid var(--border2)',color:'var(--text0)',padding:'5px 10px',borderRadius:6,fontSize:12,flex:1}}>
                      {['Sunday','Saturday','Monday','Tuesday','Wednesday','Thursday','Friday'].map(d=><option key={d}>{d}</option>)}
                    </select>
                    <input type="time" value={w.time} onChange={e=>{const ww=[...windows];ww[i]={...ww[i],time:e.target.value};setWindows(ww)}} style={{background:'var(--bg2)',border:'1px solid var(--border2)',color:'var(--text0)',padding:'5px 8px',borderRadius:6,fontSize:12,width:90}}/>
                    <button className="btn btn-ghost" onClick={()=>setWindows(ww=>ww.filter((_,j)=>j!==i))}><X/></button>
                  </div>
                ))}
              </div>
              <button className="btn btn-outline btn-sm" style={{width:'100%'}} onClick={()=>setWindows(w=>[...w,{day:'Saturday',time:'03:00',duration_hours:4}])}><Plus/> Add Window</button>
            </div>
          </div>

          {/* Formula */}
          <div style={{background:'linear-gradient(135deg,rgba(0,212,170,.05),rgba(124,58,237,.05))',border:'1px solid var(--border)',borderRadius:'var(--radius)',padding:'16px 20px'}}>
            <div style={{fontSize:10,fontWeight:700,letterSpacing:1,textTransform:'uppercase',color:'var(--primary)',marginBottom:10}}>⚡ Scoring Formula</div>
            <div style={{fontFamily:'var(--mono)',fontSize:12,color:'var(--text1)',lineHeight:1.9}}>
              Priority = <span style={{color:'var(--primary)'}}>CVSS</span> × <span style={{color:'#f472b6'}}>PoC_mul</span> × <span style={{color:'#a78bfa'}}>BlastRadius</span><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;÷ <span style={{color:'var(--warning)'}}>PatchComplexity</span><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;× <span style={{color:'#60a5fa'}}>TierWeight</span> × <span style={{color:'var(--success)'}}>RegFlag</span>
            </div>
            <div style={{fontSize:11,color:'var(--text2)',marginTop:10,lineHeight:1.7}}>
              PoC: ×3.0 active | ×1.0 none &nbsp;·&nbsp; Tier: Critical ×3, Important ×2<br/>
              Regulatory: ×2.0 &nbsp;·&nbsp; Exploit: LLM (POCme engine) &nbsp;·&nbsp; Blast Radius: LLM
            </div>
          </div>
        </div>
      </div>

      {showApiModal && (
        <div className="modal-overlay" onClick={e=>{if(e.target===e.currentTarget)setShowApiModal(false)}}>
          <div className="modal-box">
            <div className="modal-title">🔑 API Keys</div>
            <div className="modal-sub">
              <strong style={{color:'var(--warning)'}}>Verified-data mode works without keys</strong> — NVD/OSV lookups and deterministic scoring still run, but deep research, rationale, and PoC generation are richer with model keys.<br/><br/>
              <strong style={{color:'var(--success)'}}>Gemini</strong> → POCme CVE research, exploit generation, blast radius analysis, rationale.<br/>
              <strong style={{color:'var(--primary)'}}>Anthropic</strong> → Claude claude-opus-4-5 for evaluation &amp; rationale (preferred for structured output).<br/>
              Both keys = full dual-model pipeline with best-of-breed results.
            </div>
            <div className="field" style={{marginBottom:12}}>
              <label>Anthropic API Key (Claude claude-opus-4-5 — rationale + evaluation)</label>
              <input type="password" value={apiKeys.anthropic} onChange={e=>setApiKeys(k=>({...k,anthropic:e.target.value}))} placeholder="sk-ant-..."/>
            </div>
            <div className="field" style={{marginBottom:20}}>
              <label>Gemini API Key (POCme engine — deep research + exploit gen)</label>
              <input type="password" value={apiKeys.gemini} onChange={e=>setApiKeys(k=>({...k,gemini:e.target.value}))} placeholder="AIza..."/>
            </div>
            <div style={{display:'flex',gap:10,justifyContent:'flex-end'}}>
              <button className="btn btn-outline" onClick={()=>setShowApiModal(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={()=>setShowApiModal(false)}>Save Keys</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Pipeline Page ────────────────────────────────────────────────────────────
