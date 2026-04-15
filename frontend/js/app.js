function App() {
  const [page,       setPage]       = useState(() => readStoredJSON(STORAGE_KEYS.page, 'configure'));
  const [stepStates, setStepStates] = useState({});
  const [logs,       setLogs]       = useState([]);
  const [progress,   setProgress]   = useState(0);
  const [results,    setResults]    = useState(() => readStoredJSON(STORAGE_KEYS.results, null));
  const [error,      setError]      = useState('');
  const [backendOk,  setBackendOk]  = useState(null);
  const [exploitLang, setExploitLang] = useState(() => readStoredJSON(STORAGE_KEYS.exploitLang, 'python'));
  const [pocState, setPocState] = useState(() => readStoredJSON(STORAGE_KEYS.pocState, {}));
  const [lastRequest, setLastRequest] = useState(() => readStoredJSON(STORAGE_KEYS.lastRequest, null));
  const [scanHistory, setScanHistory] = useState(() => readStoredJSON(STORAGE_KEYS.history, []));

  useEffect(()=>{
    fetch(`${API_URL}/health`).then(r=>r.json()).then(()=>setBackendOk(true)).catch(()=>setBackendOk(false));
  },[]);

  const refreshScanHistory = useCallback(async () => {
    try {
      const resp = await fetch(`${API_URL}/api/scans`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      const items = (Array.isArray(data.items) ? data.items : []).map(normalizeScanMeta);
      setScanHistory(items);
      writeStoredJSON(STORAGE_KEYS.history, items);
    } catch {
      // Keep local fallback when backend DB is unavailable.
    }
  }, []);

  useEffect(() => {
    refreshScanHistory();
  }, [refreshScanHistory]);

  useEffect(() => {
    writeStoredJSON(STORAGE_KEYS.page, page);
  }, [page]);

  useEffect(() => {
    writeStoredJSON(STORAGE_KEYS.results, results);
  }, [results]);

  useEffect(() => {
    writeStoredJSON(STORAGE_KEYS.exploitLang, exploitLang);
  }, [exploitLang]);

  useEffect(() => {
    writeStoredJSON(STORAGE_KEYS.pocState, pocState);
  }, [pocState]);

  useEffect(() => {
    writeStoredJSON(STORAGE_KEYS.lastRequest, lastRequest);
  }, [lastRequest]);

  useEffect(() => {
    writeStoredJSON(STORAGE_KEYS.history, scanHistory);
  }, [scanHistory]);

  const addLog = (text, type='') => setLogs(l=>[...l,{time:now(),text,type}]);

  const STEP_ORDER = STEPS.map(s=>s.key);

  const handleGeneratePoC = async (vuln, lang) => {
    const cveId = vuln.cve_id;
    setPocState(prev => ({...prev, [cveId]: {loading: true, code: '', error: null}}));
    try {
      const body = {
        cve_id:           cveId,
        description:      vuln.description || '',
        full_research:    vuln.full_research || vuln.description || '',
        package:          vuln.package || '',
        version:          vuln.version || '',
        language:         lang || exploitLang,
        cvss:             vuln.cvss || 5.0,
        references:       vuln.references || [],
        research_grounded: !!vuln.research_grounded,
        gemini_api_key:   lastRequest?.gemini_api_key || null,
        anthropic_api_key: lastRequest?.anthropic_api_key || null,
      };
      const res = await fetch(`${API_URL}/api/generate-exploit`, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Generation failed');
      setPocState(prev => ({...prev, [cveId]: {
        loading: false,
        code:     data.code || '',
        language: data.language || lang,
        model:    data.model || 'unknown',
        generated: data.generated,
        error:    null,
      }}));
    } catch (err) {
      setPocState(prev => ({...prev, [cveId]: {loading: false, code: '', error: err.message}}));
    }
  };

  const handleRun = async request => {
    setLastRequest(request);
    setPage('pipeline');
    setStepStates({});
    setLogs([]);
    setProgress(0);
    setError('');
    addLog('VulnPriority AI v3 — verified + AI-assisted pipeline initializing…','success');
    addLog(`System: ${request.system_info.name} [${request.system_info.tier}] | ${Object.keys(request.packages).length} SBOM pkgs | ${request.va_cve_ids.length} VA CVEs | exploit lang: ${request.exploit_language}`,'info');
    if (request.gemini_api_key && request.anthropic_api_key) addLog('✓ Dual-model: Gemini (POCme research + exploits) + Claude (evaluation + rationale)','success');
    else if (request.gemini_api_key) addLog('✓ Gemini key — CVE discovery, research, exploits, blast radius, evaluation, rationale all via Gemini','success');
    else if (request.anthropic_api_key) addLog('✓ Anthropic key — all LLM pipeline steps via Claude claude-opus-4-5','success');

    try {
      const resp = await fetch(`${API_URL}/api/analyze`,{
        method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify(request),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);

      const reader  = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const {done, value} = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, {stream:true});
        const lines = buffer.split('\n');
        buffer = lines.pop();

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          try {
            const data = JSON.parse(line.slice(6));

            if (data.step==='complete') {
              setProgress(100);
              addLog('━━ Pipeline complete! Loading results…','success');
              setResults(data.data);
              try {
                const counts = {
                  vulnerabilities: Array.isArray(data.data?.vulnerabilities) ? data.data.vulnerabilities.length : 0,
                  tickets: Array.isArray(data.data?.tickets) ? data.data.tickets.length : 0,
                  calendar: Array.isArray(data.data?.calendar) ? data.data.calendar.length : 0,
                };
                await fetch(`${API_URL}/api/scans`, {
                  method: 'POST',
                  headers: {'Content-Type':'application/json'},
                  body: JSON.stringify({
                    label: request.system_info?.name ? `${request.system_info.name} scan` : 'Scan result',
                    system_name: request.system_info?.name || 'system',
                    counts,
                    request_payload: request,
                    result_payload: data.data,
                  }),
                });
                refreshScanHistory();
              } catch {
                // Non-blocking: analysis results are still shown even if history persistence fails.
              }
              setTimeout(()=>setPage('results'),500);
              return;
            }
            if (data.step==='error') {
              addLog(`ERROR: ${data.message}`,'error');
              setError(data.message);
              return;
            }

            setStepStates(prev=>({...prev,[data.step]:data.status,[`${data.step}_msg`]:data.message}));

            const idx = STEP_ORDER.indexOf(data.step);
            if (idx>=0 && data.status==='done') setProgress(Math.round(((idx+1)/STEP_ORDER.length)*95));

            const pref = data.status==='done'?'✓':data.status==='running'?'▶':'!';
            const type = data.status==='done'?'success':data.status==='error'?'error':'';
            addLog(`${pref} [${data.step.toUpperCase()}] ${data.message}`, type);

            if (data.count!=null)       addLog(`  └─ CVEs: ${data.count}`,'');
            if (data.unmatched_va_count!=null) addLog(`  └─ Omitted VA CVEs not found in current SBOM: ${data.unmatched_va_count}`,'warn');
            if (data.poc_count!=null)   addLog(`  └─ Active PoC exploits: ${data.poc_count}`,data.poc_count>0?'warn':'');
            if (data.max_blast!=null)   addLog(`  └─ Max blast radius: ${data.max_blast} services`,'');
            if (data.generated!=null)   addLog(`  └─ Exploits generated: ${data.generated}`,'');
            if (data.high_viability!=null) addLog(`  └─ High-viability exploits: ${data.high_viability}`,data.high_viability>0?'warn':'');
            if (data.cve!=null)         addLog(`     ↳ ${data.cve}`,'info');
          } catch (_) {}
        }
      }
    } catch(e) {
      addLog(`Pipeline error: ${e.message}`,'error');
      setError(e.message);
    }
  };

  const navSt = pg => {
    if (pg === 'configure') return page === 'configure' ? 'active' : 'done';
    if (pg === 'team') return page === 'team' ? 'active' : (page === 'pipeline' || page === 'results' || page === 'history' ? 'done' : '');
    if (pg === 'pipeline') return page === 'pipeline' ? 'active' : (page === 'results' || page === 'history' ? 'done' : '');
    if (pg === 'results') return page === 'results' ? 'active' : (page === 'history' ? 'done' : '');
    if (pg === 'history') return page === 'history' ? 'active' : '';
    return '';
  };
  const navItems = [
    ['configure', '1', 'Configure'],
    ['team', '2', 'Team'],
    ['pipeline', '3', 'Pipeline'],
    ['results', '4', 'Results'],
    ['history', '5', 'History'],
  ];

  const canNavigateTo = pg => {
    if (pg === 'pipeline') return false;
    if (pg === 'results') return !!results;
    if (pg === 'history') return true;
    if (pg === 'team') return true;
    return true;
  };

  const openSavedScan = async scan => {
    if (!scan?.id) return;
    try {
      const resp = await fetch(`${API_URL}/api/scans/${scan.id}`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      setResults(data.result_payload || null);
      if (data.request_payload) setLastRequest(data.request_payload);
      setPage('results');
    } catch (err) {
      addLog(`Unable to open saved scan: ${err.message}`, 'error');
    }
  };

  const clearHistory = async () => {
    try {
      await fetch(`${API_URL}/api/scans`, {method:'DELETE'});
    } catch {
      // keep local cleanup fallback
    }
    setScanHistory([]);
    writeStoredJSON(STORAGE_KEYS.history, []);
  };

  return (
    <div className="app-shell">
      <div className="grid-bg"/>
      {page==='pipeline'&&<div className="scanning-overlay"/>}
      <div className="content-wrap">
        <div className="topbar">
          <div className="logo">
            <svg width="30" height="30" viewBox="0 0 32 32" fill="none">
              <path d="M16 2 L28 8 L28 18 C28 25 22 29.5 16 31 C10 29.5 4 25 4 18 L4 8 Z" fill="rgba(0,212,170,.1)" stroke="var(--primary)" strokeWidth="1.5"/>
              <path d="M12 16 L15 19 L20 13" stroke="var(--primary)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              <circle cx="16" cy="11" r="2" fill="var(--primary)" opacity=".5"/>
            </svg>
            <span className="logo-text">Vuln<span>Priority</span> AI</span>
          </div>
          <div className="page-nav">
            {navItems.map(([pg,n,l])=>(
              <div
                key={pg}
                className={`nav-step ${navSt(pg)}`}
                onClick={() => { if (canNavigateTo(pg)) setPage(pg); }}
                style={{opacity: canNavigateTo(pg) ? 1 : 0.55}}
              >
                <div className="nav-num">{navSt(pg)==='done'?'✓':n}</div>{l}
              </div>
            ))}
          </div>
          <div className="topbar-right">
            {backendOk===true&&<><div className="status-dot green"/><span style={{fontSize:11,color:'var(--text2)'}}>Backend Online</span></>}
            {backendOk===false&&<><div className="status-dot orange"/><span style={{fontSize:11,color:'var(--warning)'}}>Backend Offline</span></>}
            {backendOk===null&&<><div className="spinner"/><span style={{fontSize:11,color:'var(--text2)'}}>Connecting…</span></>}
          </div>
        </div>

        {backendOk===false&&(
          <div style={{background:'rgba(245,158,11,.08)',borderBottom:'1px solid rgba(245,158,11,.2)',padding:'8px 28px',fontSize:12,color:'var(--warning)',display:'flex',gap:8,alignItems:'center',flexWrap:'wrap'}}>
            ⚠️ Backend offline.
            <code style={{fontFamily:'var(--mono)',background:'rgba(0,0,0,.3)',padding:'1px 8px',borderRadius:4}}>
              cd backend && pip install -r requirements.txt && uvicorn main:app --reload --port 8000
            </code>
          </div>
        )}

        {page==='configure'&&<ConfigurePage onRun={handleRun} exploitLang={exploitLang} setExploitLang={setExploitLang} onGoTeamPage={()=>setPage('team')}/>}
        {page==='team'     &&<TeamProfilesPage/>}
        {page==='pipeline' &&<PipelinePage stepStates={stepStates} logs={logs} progress={progress}/>}
        {page==='results'  &&results&&<ResultsPage results={results} pocState={pocState} setPocState={setPocState} handleGeneratePoC={handleGeneratePoC} exploitLang={exploitLang}/>}
        {page==='history'  &&<HistoryPage history={scanHistory} onOpenScan={openSavedScan} onClearHistory={clearHistory}/>}

        {error&&page==='pipeline'&&(
          <div style={{padding:'24px 28px'}}>
            <div style={{background:'var(--danger-dim)',border:'1px solid rgba(255,71,87,.25)',borderRadius:'var(--radius)',padding:'20px 24px'}}>
              <div style={{fontSize:14,fontWeight:700,color:'var(--danger)',marginBottom:8}}>Pipeline Error</div>
              <div style={{fontFamily:'var(--mono)',fontSize:12,color:'var(--text1)',marginBottom:14}}>{error}</div>
              <button className="btn btn-outline btn-sm" onClick={()=>{setPage('configure');setError('');}}>← Back</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
