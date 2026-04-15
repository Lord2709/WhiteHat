function ResultsPage({results, pocState, setPocState, handleGeneratePoC, exploitLang}) {
  const [tab, setTab] = useState('vulns');
  const vulnerabilities = Array.isArray(results?.vulnerabilities) ? results.vulnerabilities.filter(Boolean) : [];
  const tickets = Array.isArray(results?.tickets) ? results.tickets.filter(Boolean) : [];
  const calendar = Array.isArray(results?.calendar) ? results.calendar.filter(Boolean) : [];
  const exec_summary = results?.exec_summary || '';
  const risk_reduction = results?.risk_reduction || 0;
  const stats = results?.stats || {};
  const tabs = [
    {key:'vulns',    label:'Vulnerabilities', icon:'🔍',count:vulnerabilities.length},
    {key:'exploits', label:'Exploits & PoC',  icon:'💣',count:vulnerabilities.length},
    {key:'tickets',  label:'Dev Tickets',     icon:'🎫',count:tickets.length},
    {key:'calendar', label:'Patch Calendar',  icon:'📅',count:calendar.length},
    {key:'dashboard',label:'Dashboard',       icon:'📊',count:null},
  ];

  return (
    <div className="page">
      <div style={{marginBottom:22}}>
        <div className="page-title">Analysis Results</div>
      </div>
      <div className="tab-bar">
        {tabs.map(t=>(
          <button key={t.key} className={`tab-btn${tab===t.key?' active':''}`} onClick={()=>setTab(t.key)}>
            {t.icon} {t.label}{t.count!==null&&<span className="tab-count">{t.count}</span>}
          </button>
        ))}
      </div>
      {tab==='vulns'    &&<VulnerabilitiesTab vulns={vulnerabilities} execSummary={exec_summary} riskReduction={risk_reduction}/>}
      {tab==='exploits' &&<ExploitsTab vulns={vulnerabilities} pocState={pocState} setPocState={setPocState} handleGeneratePoC={handleGeneratePoC} exploitLang={exploitLang}/>}
      {tab==='tickets'  &&<TicketsTab tickets={tickets}/>}
      {tab==='calendar' &&<CalendarTab calendar={calendar}/>}
      {tab==='dashboard'&&<DashboardTab stats={stats} vulns={vulnerabilities} execSummary={exec_summary} riskReduction={risk_reduction}/>}
    </div>
  );
}

// ─── History Page ────────────────────────────────────────────────────────────
function HistoryPage({history, onOpenScan, onClearHistory}) {
  const scans = Array.isArray(history) ? history : [];

  return (
    <div className="page">
      <div style={{marginBottom:22,display:'flex',alignItems:'center',justifyContent:'space-between',gap:12,flexWrap:'wrap'}}>
        <div>
          <div className="page-title">Saved Scans</div>
          <div className="page-sub">Previously completed analyses stored in the backend database</div>
        </div>
        <button className="btn btn-outline btn-sm" onClick={onClearHistory} disabled={!scans.length}>Clear History</button>
      </div>

      <div className="card">
        <div className="card-body">
          {scans.length === 0 ? (
            <div style={{textAlign:'center',padding:'50px 20px',color:'var(--text3)'}}>
              No saved scans yet. Run an analysis and the full result set will be stored here.
            </div>
          ) : (
            <div style={{display:'grid',gap:14}}>
              {scans.map(scan => (
                <div key={scan.id} style={{background:'var(--bg3)',border:'1px solid var(--border2)',borderRadius:12,padding:16,display:'flex',justifyContent:'space-between',gap:14,flexWrap:'wrap'}}>
                  <div>
                    <div style={{fontSize:14,fontWeight:700,color:'var(--text0)'}}>{scan.label}</div>
                    <div style={{fontSize:11,color:'var(--text2)',marginTop:4,fontFamily:'var(--mono)'}}>{scan.timestamp ? new Date(scan.timestamp).toLocaleString() : ''}</div>
                    <div style={{fontSize:12,color:'var(--text2)',marginTop:8}}>
                      {scan.counts?.vulnerabilities || 0} CVEs · {scan.counts?.tickets || 0} tickets · {scan.counts?.calendar || 0} scheduled patches
                    </div>
                  </div>
                  <div style={{display:'flex',gap:10,alignItems:'center',flexWrap:'wrap'}}>
                    <button className="btn btn-outline btn-sm" onClick={()=>onOpenScan(scan)}>Open</button>
                    <span className="source-badge source-demo">{scan.systemName || 'scan'}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Team Profiles Page ─────────────────────────────────────────────────────
