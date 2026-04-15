function ConfigurePage({onRun, exploitLang, setExploitLang, onGoTeamPage}) {
  const [packages,   setPackages]   = useState({});
  const [fileName,   setFileName]   = useState('');
  const [vaCves,     setVaCves]     = useState([]);
  const [vaLlmNote,  setVaLlmNote]  = useState('');
  const [vaFile,     setVaFile]     = useState('');
  const [vaUploading,setVaUploading]= useState(false);
  const [vaDragging, setVaDragging] = useState(false);
  const [dragging,   setDragging]   = useState(false);
  const [sysInfo, setSysInfo] = useState(() => ({name:'payment-api',tier:'critical',regulatory:['PCI','GDPR','SOX'],owner:'platform-security',dependencies:['auth-service','settlement-worker','fraud-scoring','merchant-portal','reporting-service']}));
  const [windows, setWindows] = useState(() => [{day:'Sunday',time:'01:30',duration_hours:4},{day:'Wednesday',time:'23:00',duration_hours:2}]);
  const [team, setTeam] = useState(() => [
    {name:'Ariana Patel', email:'ariana.patel@northstar.example', role:'Staff AppSec Engineer', expertise:['security','nodejs','jwt'], current_load:1, schedule:{available_hours_per_week:36,sprint_hours_remaining:20,work_days:['monday','tuesday','wednesday','thursday','friday']}},
    {name:'Devon Kim',    email:'devon.kim@northstar.example',    role:'Senior Backend Engineer', expertise:['nodejs','express','postgres','redis'], current_load:2, schedule:{available_hours_per_week:40,sprint_hours_remaining:18,work_days:['monday','tuesday','wednesday','thursday','friday']}},
    {name:'Mina Ortega',  email:'mina.ortega@northstar.example',  role:'SRE Engineer', expertise:['devops','kubernetes','monitoring'], current_load:1, schedule:{available_hours_per_week:40,sprint_hours_remaining:24,work_days:['monday','tuesday','wednesday','thursday','friday']}},
  ]);
  const [newMember, setNewMember] = useState({name:'',email:'',expertiseStr:'',sprintHours:20});
  const [apiKeys,  setApiKeys]   = useState({anthropic:'',gemini:''});
  const [vendorAdvisories, setVendorAdvisories] = useState([]);
  const [internalDocs,     setInternalDocs]     = useState([]);
  const [dependencyGraph,  setDependencyGraph]  = useState([]);
  const [connectorStatus, setConnectorStatus] = useState({vendor:'',internal:'',graph:''});
  const [sysInfoStatus,   setSysInfoStatus]   = useState('');
  const [windowsStatus,   setWindowsStatus]   = useState('');
  const [teamStatus,      setTeamStatus]      = useState('');
  const [envKeys,  setEnvKeys]   = useState({gemini:false,anthropic:false,nvd:false});
  const [showApiModal, setShowApiModal] = useState(false);

  const normalizeSystemInfo = raw => ({
    name: raw?.name || 'payment-api',
    tier: raw?.tier || 'critical',
    regulatory: Array.isArray(raw?.regulatory) ? raw.regulatory : [],
    owner: raw?.owner || 'platform-security',
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

  const regulatoryList = Array.isArray(sysInfo?.regulatory) ? sysInfo.regulatory : [];

  useEffect(()=>{
    fetch(`${API_URL}/api/env-status`).then(r=>r.json()).then(d=>{
      setEnvKeys({gemini:!!d.gemini_key_loaded, anthropic:!!d.anthropic_key_loaded, nvd:!!d.nvd_key_loaded});
    }).catch(()=>{});
    fetch(`${API_URL}/api/config/load`).then(r=>r.ok?r.json():null).then(cfg=>{
      if (!cfg) return;
      if (cfg.packages && Object.keys(cfg.packages).length > 0) setPackages(cfg.packages);
      if (cfg.va_cve_ids && cfg.va_cve_ids.length > 0) setVaCves(cfg.va_cve_ids);
      if (cfg.system_info) setSysInfo(normalizeSystemInfo(cfg.system_info));
      if (cfg.maintenance_windows && cfg.maintenance_windows.length > 0) setWindows(cfg.maintenance_windows);
      if (cfg.team_members && cfg.team_members.length > 0) setTeam(cfg.team_members.map(normalizeTeamMember));
      if (cfg.api_keys) setApiKeys(cfg.api_keys);
      if (Array.isArray(cfg.vendor_advisories) && cfg.vendor_advisories.length) setVendorAdvisories(cfg.vendor_advisories);
      if (Array.isArray(cfg.internal_docs) && cfg.internal_docs.length) setInternalDocs(cfg.internal_docs);
      if (Array.isArray(cfg.dependency_graph) && cfg.dependency_graph.length) setDependencyGraph(cfg.dependency_graph);
    }).catch(()=>{});
    fetch(`${API_URL}/api/team-profiles`).then(r=>r.ok?r.json():{items:[]}).then(d=>{
      if (Array.isArray(d.items) && d.items.length > 0) {
        setTeam(d.items.map(teamProfileToMember));
        setTeamStatus(`Auto-loaded ${d.items.length} team profiles from database.`);
      }
    }).catch(()=>{});
  }, []);

  const fileRef    = useRef(null);
  const vaRef      = useRef(null);
  const sysRef     = useRef(null);
  const winRef     = useRef(null);
  const teamRef    = useRef(null);
  const vendorRef  = useRef(null);
  const internalRef= useRef(null);
  const graphRef   = useRef(null);

  // ── File parsers ─────────────────────────────────────────────────────────────

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

  const readJsonFile = (file, onParsed, onError) => {
    const r = new FileReader();
    r.onload = e => {
      try {
        const parsed = JSON.parse(e.target.result);
        onParsed(parsed);
      } catch {
        onError && onError('Invalid JSON — check the file format.');
      }
    };
    r.readAsText(file);
  };

  const handleSbomFile = f => {
    if (!f) return;
    setFileName(f.name);
    const r = new FileReader();
    r.onload = e => {
      const pkgs = parsePackageJson(e.target.result);
      setPackages(pkgs);
    };
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
      if (data.llm_mapped) setVaLlmNote(`🤖 LLM mapped ${data.count} CVEs from report findings`);
      else if (data.count > 0) setVaLlmNote(`✓ ${data.count} CVE IDs extracted from report`);
      else setVaLlmNote('⚠ No CVEs found — ensure SBOM packages are loaded too');
    } catch {
      const r = new FileReader();
      r.onload = e => {
        const found = (e.target.result.match(/CVE-\d{4}-\d{4,7}/gi)||[]).filter((v,i,a)=>a.indexOf(v)===i);
        setVaCves(found.map(c=>c.toUpperCase()));
        setVaLlmNote(found.length > 0 ? `✓ ${found.length} CVEs found` : '⚠ No CVEs found in file');
      };
      r.readAsText(f);
    }
    setVaUploading(false);
  };

  const handleSysInfoFile = f => {
    if (!f) return;
    readJsonFile(f,
      parsed => { setSysInfo(normalizeSystemInfo(parsed)); setSysInfoStatus(`✓ Loaded from ${f.name}`); },
      err    => setSysInfoStatus(`⚠ ${err}`)
    );
  };

  const handleWindowsFile = f => {
    if (!f) return;
    readJsonFile(f,
      parsed => {
        if (!Array.isArray(parsed)) { setWindowsStatus('⚠ Expected a JSON array of maintenance windows.'); return; }
        setWindows(parsed);
        setWindowsStatus(`✓ Loaded ${parsed.length} maintenance window(s) from ${f.name}`);
      },
      err => setWindowsStatus(`⚠ ${err}`)
    );
  };

  const handleTeamFile = f => {
    if (!f) return;
    readJsonFile(f,
      parsed => {
        const arr = Array.isArray(parsed) ? parsed : parsed?.team || [];
        if (!arr.length) { setTeamStatus('⚠ No team members found in file.'); return; }
        setTeam(arr.map(normalizeTeamMember));
        setTeamStatus(`✓ Loaded ${arr.length} team members from ${f.name}`);
      },
      err => setTeamStatus(`⚠ ${err}`)
    );
  };

  const handleVendorFile = f => {
    if (!f) return;
    readJsonFile(f,
      parsed => {
        const arr = Array.isArray(parsed) ? parsed : [];
        setVendorAdvisories(arr);
        setConnectorStatus(s=>({...s, vendor:`✓ Loaded ${arr.length} vendor advisories from ${f.name}`}));
      },
      err => setConnectorStatus(s=>({...s, vendor:`⚠ ${err}`}))
    );
  };

  const handleInternalFile = f => {
    if (!f) return;
    readJsonFile(f,
      parsed => {
        const arr = Array.isArray(parsed) ? parsed : [];
        setInternalDocs(arr);
        setConnectorStatus(s=>({...s, internal:`✓ Loaded ${arr.length} internal docs from ${f.name}`}));
      },
      err => setConnectorStatus(s=>({...s, internal:`⚠ ${err}`}))
    );
  };

  const handleGraphFile = f => {
    if (!f) return;
    readJsonFile(f,
      parsed => {
        const arr = Array.isArray(parsed) ? parsed : [];
        setDependencyGraph(arr);
        const deps = Array.from(new Set(arr.map(e=>(e?.target||'').trim()).filter(Boolean)));
        setSysInfo(s=>({...s, dependencies: deps.length ? deps : s.dependencies}));
        setConnectorStatus(s=>({...s, graph:`✓ Loaded ${arr.length} edges from ${f.name} — synced ${deps.length} dependencies`}));
      },
      err => setConnectorStatus(s=>({...s, graph:`⚠ ${err}`}))
    );
  };

  // ── Team helpers ──────────────────────────────────────────────────────────────
  const toggleReg = r => setSysInfo(s=>{
    const regs = Array.isArray(s.regulatory) ? s.regulatory : [];
    return {...s, regulatory: regs.includes(r) ? regs.filter(x=>x!==r) : [...regs,r]};
  });

  const addMember = () => {
    const {name,email,expertiseStr,sprintHours} = newMember;
    if (!name||!email) return;
    setTeam(t=>[...t,{name,email,expertise:expertiseStr.split(',').map(s=>s.trim()).filter(Boolean),current_load:0,schedule:{available_hours_per_week:40,sprint_hours_remaining:parseInt(sprintHours)||20,work_days:['monday','tuesday','wednesday','thursday','friday']}}]);
    setNewMember({name:'',email:'',expertiseStr:'',sprintHours:20});
  };
  const removeMember    = i => setTeam(t=>t.filter((_,j)=>j!==i));
  const updateSprintHours = (i,h) => setTeam(t=>t.map((m,j)=>j===i?{...m,schedule:{...m.schedule,sprint_hours_remaining:parseInt(h)||0}}:m));

  // ── Auto-save ─────────────────────────────────────────────────────────────────
  useEffect(() => {
    const t = setTimeout(() => {
      fetch(`${API_URL}/api/config/save`, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({
          packages, va_cve_ids: vaCves, system_info: sysInfo, maintenance_windows: windows,
          team_members: team, vendor_advisories: vendorAdvisories, internal_docs: internalDocs,
          dependency_graph: dependencyGraph, exploit_language: exploitLang, api_keys: apiKeys,
        }),
      }).catch(()=>{});
    }, 1200);
    return () => clearTimeout(t);
  }, [packages, vaCves, sysInfo, windows, team, exploitLang, apiKeys, vendorAdvisories, internalDocs, dependencyGraph]);

  const hasApiKey = !!(apiKeys.anthropic || apiKeys.gemini || envKeys.gemini || envKeys.anthropic);
  const canRun    = Object.keys(packages).length > 0 || vaCves.length > 0;

  const handleRun = () => {
    onRun({
      packages, va_cve_ids: vaCves, system_info: sysInfo, maintenance_windows: windows,
      team_members: team, vendor_advisories: vendorAdvisories, internal_docs: internalDocs,
      dependency_graph: dependencyGraph, exploit_language: exploitLang,
      anthropic_api_key: apiKeys.anthropic||null, gemini_api_key: apiKeys.gemini||null,
    });
  };

  // ── Reusable file upload zone ─────────────────────────────────────────────────
  const FileUploadZone = ({label, hint, accept, inputRef, onFile, status, icon, variant}) => {
    // variant: 'primary' (teal) or 'secondary' (purple). Defaults to primary.
    const [drag, setDrag] = useState(false);
    const isPurple = variant === 'secondary';
    const rgb      = isPurple ? '124,58,237' : '0,212,170';
    const borderColor = drag ? `rgba(${rgb},.7)` : `rgba(${rgb},.25)`;
    return (
      <div>
        <div
          onDragOver={e=>{e.preventDefault();setDrag(true)}}
          onDragLeave={()=>setDrag(false)}
          onDrop={e=>{e.preventDefault();setDrag(false);onFile(e.dataTransfer.files[0])}}
          onClick={()=>inputRef.current.click()}
          style={{
            border:`2px dashed ${borderColor}`,
            borderRadius:'var(--radius)',
            padding:'18px 16px',
            textAlign:'center',
            cursor:'pointer',
            transition:'all .2s',
            background: drag ? `rgba(${rgb},.1)` : 'rgba(255,255,255,.02)',
          }}>
          <div style={{fontSize:24,marginBottom:6}}>{icon||'📂'}</div>
          <div style={{fontSize:13,fontWeight:600,color:'var(--text0)',marginBottom:3}}>{label}</div>
          <div style={{fontSize:11,color:'var(--text2)'}}>{hint}</div>
          <input ref={inputRef} type="file" accept={accept||'.json'} style={{display:'none'}} onChange={e=>onFile(e.target.files[0])}/>
        </div>
        {status && (
          <div style={{
            marginTop:7, padding:'5px 10px', borderRadius:6, fontSize:11,
            background: status.startsWith('✓') ? 'rgba(16,185,129,.1)' : 'rgba(245,158,11,.1)',
            color:       status.startsWith('✓') ? '#6ee7b7' : '#fbbf24',
            border:`1px solid ${status.startsWith('✓') ? 'rgba(16,185,129,.25)' : 'rgba(245,158,11,.25)'}`,
          }}>{status}</div>
        )}
      </div>
    );
  };

  return (
    <div className="page">

      {/* ── Header ── */}
      <div style={{display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:26,flexWrap:'wrap',gap:12}}>
        <div>
          <div className="page-title">Configure Analysis</div>
          <div className="page-sub">Upload dataset files to configure the agentic pipeline</div>
        </div>
        <div style={{display:'flex',flexDirection:'column',alignItems:'flex-end',gap:8}}>
          {(envKeys.gemini||envKeys.anthropic) && (
            <div style={{background:'rgba(16,185,129,.1)',border:'1px solid rgba(16,185,129,.3)',borderRadius:8,padding:'6px 12px',fontSize:12,color:'#6ee7b7',display:'flex',alignItems:'center',gap:6}}>
              ✓ Server .env: {envKeys.gemini&&'Gemini'}{envKeys.gemini&&envKeys.anthropic&&' + '}{envKeys.anthropic&&'Anthropic'} key loaded{envKeys.nvd&&' + NVD'}
            </div>
          )}
          {!envKeys.nvd && (envKeys.gemini||envKeys.anthropic) && (
            <div style={{background:'rgba(251,191,36,.08)',border:'1px solid rgba(251,191,36,.3)',borderRadius:8,padding:'6px 12px',fontSize:12,color:'#fcd34d',display:'flex',alignItems:'center',gap:6}}>
              ⚠ No NVD_API_KEY — add to .env to prevent NVD PENDING on multi-CVE scans
            </div>
          )}
          <div style={{display:'flex',gap:10}}>
            <button className="btn btn-outline btn-sm" onClick={()=>setShowApiModal(true)}>
              <Key/> {(envKeys.gemini||envKeys.anthropic)?'✓ .env Keys Active':'API Keys'}
            </button>
            <button className="btn btn-primary" disabled={!canRun} onClick={handleRun}>
              <Play/> Run Agentic Analysis
            </button>
          </div>
        </div>
      </div>

      <div className="config-grid">
        {/* ══ LEFT COLUMN ══ */}
        <div style={{display:'flex',flexDirection:'column',gap:18}}>

          {/* SBOM */}
          <div className="card">
            <div className="card-header"><span>📦</span><span className="card-title">SBOM / Package Input</span></div>
            <div className="card-body" style={{display:'flex',flexDirection:'column',gap:12}}>
              <div
                onDragOver={e=>{e.preventDefault();setDragging(true)}}
                onDragLeave={()=>setDragging(false)}
                onDrop={e=>{e.preventDefault();setDragging(false);handleSbomFile(e.dataTransfer.files[0])}}
                onClick={()=>fileRef.current.click()}
                className={`drop-zone${dragging?' drag-over':''}`}>
                <div className="drop-zone-icon">📂</div>
                <div className="drop-zone-title">{fileName||'Upload package.json'}</div>
                <div className="drop-zone-sub">
                  {fileName ? `${Object.keys(packages).length} packages loaded` : 'Drop file or click to browse — test_dataset_enterprise_2026/package.json'}
                </div>
                <input ref={fileRef} type="file" accept=".json" style={{display:'none'}} onChange={e=>handleSbomFile(e.target.files[0])}/>
              </div>
              {Object.keys(packages).length > 0 && (
                <div>
                  <div className="section-label">Packages ({Object.keys(packages).length})</div>
                  <div className="packages-preview">
                    {Object.entries(packages).map(([k,v])=>(
                      <div key={k} className="pkg-row"><span className="pkg-name">{k}</span><span className="pkg-ver">{v}</span></div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* VA Report */}
          <div className="card">
            <div className="card-header">
              <span>📋</span><span className="card-title">Vulnerability Assessment Report</span>
              <span style={{fontSize:11,color:'#a78bfa',marginLeft:'auto'}}>optional</span>
            </div>
            <div className="card-body" style={{display:'flex',flexDirection:'column',gap:10}}>
              <div
                onDragOver={e=>{e.preventDefault();setVaDragging(true)}}
                onDragLeave={()=>setVaDragging(false)}
                onDrop={e=>{e.preventDefault();setVaDragging(false);handleVaFile(e.dataTransfer.files[0])}}
                onClick={()=>vaRef.current.click()}
                className={`va-drop-zone${vaDragging?' drag-over':''}`}>
                {vaUploading ? (
                  <div style={{display:'flex',flexDirection:'column',alignItems:'center',gap:8}}>
                    <div className="spinner" style={{width:24,height:24}}/>
                    <div style={{fontSize:12,color:'var(--text2)'}}>Extracting CVE IDs…</div>
                  </div>
                ) : (
                  <>
                    <div style={{fontSize:28,marginBottom:8}}>📄</div>
                    <div style={{fontSize:13,fontWeight:600,color:'var(--text0)',marginBottom:3}}>
                      {vaFile||'Upload VA Report (.txt / .pdf)'}
                    </div>
                    <div style={{fontSize:11,color:'var(--text2)'}}>
                      {vaFile ? `${vaCves.length} CVE IDs extracted` : 'test_dataset_enterprise_2026/va_report_q2_2026.txt'}
                    </div>
                  </>
                )}
                <input ref={vaRef} type="file" accept=".pdf,.txt,.csv,.html,.xml" style={{display:'none'}} onChange={e=>handleVaFile(e.target.files[0])}/>
              </div>
              {vaLlmNote && (
                <div style={{padding:'6px 10px',borderRadius:6,fontSize:11,
                  background: vaLlmNote.startsWith('🤖')?'rgba(124,58,237,.12)':vaLlmNote.startsWith('⚠')?'rgba(245,158,11,.1)':'rgba(16,185,129,.1)',
                  color:       vaLlmNote.startsWith('🤖')?'#a78bfa':vaLlmNote.startsWith('⚠')?'#fbbf24':'#6ee7b7',
                  border:`1px solid ${vaLlmNote.startsWith('🤖')?'rgba(124,58,237,.3)':vaLlmNote.startsWith('⚠')?'rgba(245,158,11,.25)':'rgba(16,185,129,.25)'}`
                }}>{vaLlmNote}</div>
              )}
              {vaCves.length > 0 && (
                <div>
                  <div className="section-label">Extracted CVE IDs ({vaCves.length})</div>
                  <div style={{display:'flex',gap:6,flexWrap:'wrap',marginTop:6}}>
                    {vaCves.map(c=><span key={c} className="cve-pill">{c}</span>)}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Team Profiles */}
          <div className="card">
            <div className="card-header"><span>👥</span><span className="card-title">Dev Team & Sprint Schedule</span></div>
            <div className="card-body" style={{display:'flex',flexDirection:'column',gap:12}}>
              <FileUploadZone
                label="Upload team_profiles.json"
                hint="test_dataset_enterprise_2026/team_profiles.json — bulk-imports all members"
                icon="👤"
                accept=".json"
                inputRef={teamRef}
                onFile={handleTeamFile}
                status={teamStatus}
              />
              {team.length > 0 && (
                <div style={{display:'flex',flexDirection:'column',gap:7}}>
                  {team.map((m,i)=>(
                    <div key={i} className="team-member-item">
                      <div style={{flex:1,minWidth:0}}>
                        <div className="member-name">{m.name} <span style={{fontSize:10,color:'var(--text3)'}}>— {m.email}</span></div>
                        {!!m.role && <div style={{fontSize:10,color:'var(--text3)',marginTop:2}}>{m.role}</div>}
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
              )}
              {/* Manual add */}
              <div style={{borderTop:'1px solid var(--border2)',paddingTop:12}}>
                <div style={{fontSize:11,fontWeight:600,color:'var(--text3)',textTransform:'uppercase',letterSpacing:.8,marginBottom:8}}>Add Member Manually</div>
                <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:8}}>
                  <div className="field"><label>Name</label><input value={newMember.name} onChange={e=>setNewMember(m=>({...m,name:e.target.value}))} placeholder="Jane Doe"/></div>
                  <div className="field"><label>Email</label><input value={newMember.email} onChange={e=>setNewMember(m=>({...m,email:e.target.value}))} placeholder="jane@co.com"/></div>
                </div>
                <div style={{display:'grid',gridTemplateColumns:'2fr 1fr',gap:8,marginTop:8}}>
                  <div className="field"><label>Skills (comma-separated)</label><input value={newMember.expertiseStr} onChange={e=>setNewMember(m=>({...m,expertiseStr:e.target.value}))} placeholder="nodejs, python, security"/></div>
                  <div className="field"><label>Sprint Hrs</label><input type="number" min="0" max="80" value={newMember.sprintHours} onChange={e=>setNewMember(m=>({...m,sprintHours:e.target.value}))} placeholder="20"/></div>
                </div>
                <button className="btn btn-outline btn-sm" style={{width:'100%',marginTop:10}} onClick={addMember}><Plus/> Add Member</button>
              </div>
              <div style={{display:'flex',gap:8}}>
                <button className="btn btn-outline btn-sm" style={{flex:1}} onClick={onGoTeamPage}>Manage Profiles DB</button>
              </div>
            </div>
          </div>

          {/* Exploit Language */}
          <div className="card">
            <div className="card-header"><span>💣</span><span className="card-title">PoC Generation Language</span></div>
            <div className="card-body">
              <div className="section-label">Gemini generates PoC in this language (on-demand per CVE)</div>
              <div style={{display:'flex',gap:8,marginTop:8}}>
                {['python','bash','javascript'].map(l=>(
                  <label key={l} className={`checkbox-item${exploitLang===l?' checked':''}`} style={{flex:1,justifyContent:'center'}}>
                    <input type="radio" checked={exploitLang===l} onChange={()=>setExploitLang(l)} style={{display:'none'}}/>
                    <span className={`lang-badge ${langClass(l)}`}>{l}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>

        </div>

        {/* ══ RIGHT COLUMN ══ */}
        <div style={{display:'flex',flexDirection:'column',gap:18}}>

          {/* System Configuration */}
          <div className="card">
            <div className="card-header"><span>🏢</span><span className="card-title">System Configuration</span></div>
            <div className="card-body" style={{display:'flex',flexDirection:'column',gap:12}}>
              <FileUploadZone
                label="Upload system_info.json"
                hint="test_dataset_enterprise_2026/system_info.json — auto-fills all fields below"
                icon="🏢"
                accept=".json"
                inputRef={sysRef}
                onFile={handleSysInfoFile}
                status={sysInfoStatus}
              />
              <div className="field-group">
                <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12}}>
                  <div className="field"><label>System Name</label>
                    <input value={sysInfo.name} onChange={e=>setSysInfo(s=>({...s,name:e.target.value}))} placeholder="payment-api"/>
                  </div>
                  <div className="field"><label>Criticality Tier</label>
                    <select value={sysInfo.tier} onChange={e=>setSysInfo(s=>({...s,tier:e.target.value}))}>
                      <option value="critical">Critical (×3.0)</option>
                      <option value="important">Important (×2.0)</option>
                      <option value="standard">Standard (×1.0)</option>
                    </select>
                  </div>
                </div>
                <div className="field"><label>Owner</label>
                  <input value={sysInfo.owner} onChange={e=>setSysInfo(s=>({...s,owner:e.target.value}))} placeholder="security-team"/>
                </div>
                <div className="field">
                  <label>Regulatory Exposure (×2.0 score multiplier)</label>
                  <div className="checkbox-group" style={{marginTop:4}}>
                    {['PCI','SOX','HIPAA','GDPR','FedRAMP'].map(r=>(
                      <label key={r} className={`checkbox-item${regulatoryList.includes(r)?' checked':''}`}>
                        <input type="checkbox" checked={regulatoryList.includes(r)} onChange={()=>toggleReg(r)} style={{display:'none'}}/>{r}
                      </label>
                    ))}
                  </div>
                </div>
                <div className="field"><label>Downstream Dependencies</label>
                  <input value={sysInfo.dependencies.join(', ')} onChange={e=>setSysInfo(s=>({...s,dependencies:e.target.value.split(',').map(x=>x.trim()).filter(Boolean)}))} placeholder="auth-service, reporting-service"/>
                </div>
              </div>
            </div>
          </div>

          {/* Maintenance Windows */}
          <div className="card">
            <div className="card-header"><span>🕐</span><span className="card-title">Maintenance Windows</span></div>
            <div className="card-body" style={{display:'flex',flexDirection:'column',gap:12}}>
              <FileUploadZone
                label="Upload maintenance_windows.json"
                hint="test_dataset_enterprise_2026/maintenance_windows.json"
                icon="🗓️"
                accept=".json"
                inputRef={winRef}
                onFile={handleWindowsFile}
                status={windowsStatus}
              />
              <div style={{display:'flex',flexDirection:'column',gap:8}}>
                {windows.map((w,i)=>(
                  <div key={i} className="window-item">
                    <span>🗓️</span>
                    <select value={w.day} onChange={e=>{const ww=[...windows];ww[i]={...ww[i],day:e.target.value};setWindows(ww)}}
                      style={{background:'var(--bg2)',border:'1px solid var(--border2)',color:'var(--text0)',padding:'5px 10px',borderRadius:6,fontSize:12,flex:1}}>
                      {['Sunday','Saturday','Monday','Tuesday','Wednesday','Thursday','Friday'].map(d=><option key={d}>{d}</option>)}
                    </select>
                    <input type="time" value={w.time} onChange={e=>{const ww=[...windows];ww[i]={...ww[i],time:e.target.value};setWindows(ww)}}
                      style={{background:'var(--bg2)',border:'1px solid var(--border2)',color:'var(--text0)',padding:'5px 8px',borderRadius:6,fontSize:12,width:90}}/>
                    <button className="btn btn-ghost" onClick={()=>setWindows(ww=>ww.filter((_,j)=>j!==i))}><X/></button>
                  </div>
                ))}
              </div>
              <button className="btn btn-outline btn-sm" style={{width:'100%'}} onClick={()=>setWindows(w=>[...w,{day:'Saturday',time:'03:00',duration_hours:4}])}>
                <Plus/> Add Window
              </button>
            </div>
          </div>

          {/* Connector Inputs */}
          <div className="card">
            <div className="card-header"><span>🔌</span><span className="card-title">Connector Inputs</span></div>
            <div className="card-body" style={{display:'flex',flexDirection:'column',gap:14}}>
              <div style={{fontSize:12,color:'var(--text2)',lineHeight:1.6}}>
                Upload the three connector JSON files from <code style={{color:'var(--primary)',fontSize:11}}>test_dataset_enterprise_2026/</code> to enrich CVE matching and dependency impact analysis.
              </div>

              <div>
                <div className="section-label">Vendor Advisories</div>
                <FileUploadZone
                  label="Upload vendor_advisories.json"
                  hint={vendorAdvisories.length ? `${vendorAdvisories.length} advisories loaded` : 'test_dataset_enterprise_2026/vendor_advisories.json'}
                  icon="📡"
                  accept=".json"
                  inputRef={vendorRef}
                  onFile={handleVendorFile}
                  status={connectorStatus.vendor}
                  variant="secondary"
                />
              </div>

              <div>
                <div className="section-label">Internal Docs</div>
                <FileUploadZone
                  label="Upload internal_docs.json"
                  hint={internalDocs.length ? `${internalDocs.length} docs loaded` : 'test_dataset_enterprise_2026/internal_docs.json'}
                  icon="📁"
                  accept=".json"
                  inputRef={internalRef}
                  onFile={handleInternalFile}
                  status={connectorStatus.internal}
                  variant="secondary"
                />
              </div>

              <div>
                <div className="section-label">Dependency Graph</div>
                <FileUploadZone
                  label="Upload dependency_graph.json"
                  hint={dependencyGraph.length ? `${dependencyGraph.length} edges loaded — dependencies auto-synced` : 'test_dataset_enterprise_2026/dependency_graph.json'}
                  icon="🕸️"
                  accept=".json"
                  inputRef={graphRef}
                  onFile={handleGraphFile}
                  status={connectorStatus.graph}
                  variant="secondary"
                />
              </div>

              {/* Loaded summary */}
              {(vendorAdvisories.length > 0 || internalDocs.length > 0 || dependencyGraph.length > 0) && (
                <div style={{display:'flex',gap:8,flexWrap:'wrap',marginTop:4}}>
                  {vendorAdvisories.length > 0 && <span style={{fontSize:10,fontFamily:'var(--mono)',padding:'3px 8px',borderRadius:5,background:'var(--sec-dim)',color:'#a78bfa',border:'1px solid rgba(124,58,237,.25)'}}>{vendorAdvisories.length} advisories</span>}
                  {internalDocs.length > 0 &&     <span style={{fontSize:10,fontFamily:'var(--mono)',padding:'3px 8px',borderRadius:5,background:'var(--blue-dim)',color:'#60a5fa',border:'1px solid rgba(59,130,246,.25)'}}>{internalDocs.length} docs</span>}
                  {dependencyGraph.length > 0 &&  <span style={{fontSize:10,fontFamily:'var(--mono)',padding:'3px 8px',borderRadius:5,background:'rgba(16,185,129,.12)',color:'#34d399',border:'1px solid rgba(16,185,129,.25)'}}>{dependencyGraph.length} edges</span>}
                </div>
              )}
            </div>
          </div>

          {/* Scoring Formula */}
          <div style={{background:'linear-gradient(135deg,rgba(0,212,170,.05),rgba(124,58,237,.05))',border:'1px solid var(--border)',borderRadius:'var(--radius)',padding:'16px 20px'}}>
            <div style={{fontSize:10,fontWeight:700,letterSpacing:1,textTransform:'uppercase',color:'var(--primary)',marginBottom:10}}>⚡ Scoring Formula</div>
            <div style={{fontFamily:'var(--mono)',fontSize:12,color:'var(--text1)',lineHeight:1.9}}>
              Priority = <span style={{color:'var(--primary)'}}>CVSS</span> × <span style={{color:'#f472b6'}}>PoC_mul</span> × <span style={{color:'#a78bfa'}}>BlastRadius</span><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;÷ <span style={{color:'var(--warning)'}}>PatchComplexity</span><br/>
              &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;× <span style={{color:'#60a5fa'}}>TierWeight</span> × <span style={{color:'var(--success)'}}>RegFlag</span>
            </div>
            <div style={{fontSize:11,color:'var(--text2)',marginTop:10,lineHeight:1.7}}>
              CVSS: NVD Primary only &nbsp;·&nbsp; PoC: ×3.0 active | ×1.0 none<br/>
              Tier: Critical ×3 | Important ×2 &nbsp;·&nbsp; Regulatory: ×2.0
            </div>
          </div>

        </div>
      </div>

      {/* API Keys Modal */}
      {showApiModal && (
        <div className="modal-overlay" onClick={e=>{if(e.target===e.currentTarget)setShowApiModal(false)}}>
          <div className="modal-box">
            <div className="modal-title">🔑 API Keys</div>
            <div className="modal-sub">
              <strong style={{color:'var(--warning)'}}>Verified-data mode works without keys</strong> — NVD/OSV lookups and deterministic scoring still run, but deep research and PoC generation require model keys.<br/><br/>
              <strong style={{color:'var(--success)'}}>Gemini</strong> — CVE research, exploit generation, rationale.<br/>
              <strong style={{color:'var(--primary)'}}>Anthropic</strong> — Claude for evaluation &amp; structured output.
            </div>
            <div className="field" style={{marginBottom:12}}>
              <label>Anthropic API Key</label>
              <input type="password" value={apiKeys.anthropic} onChange={e=>setApiKeys(k=>({...k,anthropic:e.target.value}))} placeholder="sk-ant-..."/>
            </div>
            <div className="field" style={{marginBottom:20}}>
              <label>Gemini API Key</label>
              <input type="password" value={apiKeys.gemini} onChange={e=>setApiKeys(k=>({...k,gemini:e.target.value}))} placeholder="AIza..."/>
            </div>
            <div style={{display:'flex',gap:10,justifyContent:'flex-end'}}>
              <button className="btn btn-outline" onClick={()=>setShowApiModal(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={()=>setShowApiModal(false)}>Save</button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

// ─── Pipeline Page ────────────────────────────────────────────────────────────
