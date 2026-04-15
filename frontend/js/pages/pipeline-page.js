function PipelinePage({stepStates, logs, progress}) {
  const logRef = useRef(null);
  useEffect(()=>{ if(logRef.current) logRef.current.scrollTop=logRef.current.scrollHeight; },[logs]);

  return (
    <div className="page">
      <div style={{marginBottom:20}}>
        <div className="page-title">🤖 Agentic Pipeline Running</div>
        <div className="page-sub">9-step verified + AI-assisted pipeline — grounded CVE discovery · bounded research · LLM evaluation</div>
      </div>
      <div className="progress-bar-wrap"><div className="progress-bar-fill" style={{width:`${progress}%`}}/></div>
      <div className="pipeline-container">
        <div className="card" style={{padding:'6px 0'}}>
          <div className="step-list">
            {STEPS.map((s,idx)=>{
              const st = stepStates[s.key]||'pending';
              return (
                <div key={s.key} className={`step-item${st==='running'?' active':''}${st==='done'?' done':''}`} style={{position:'relative'}}>
                  {idx<STEPS.length-1 && <div className={`step-connector${st==='done'?' done':''}`}/>}
                  <div className={`step-icon-wrap ${st}`}>{st==='done'?'✓':st==='running'?<div className="spinner"/>:s.icon}</div>
                  <div className="step-info">
                    <div className="step-name">
                      {s.label}
                      <span className={`step-badge ${st}`}>{st==='running'?'ACTIVE':st==='done'?'DONE':st==='error'?'ERR':'WAIT'}</span>
                    </div>
                    <div className="step-msg">{stepStates[s.key+'_msg']||s.desc}</div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
        <div className="log-panel">
          <div className="log-header"><Term/> Live Agent Log <span style={{marginLeft:'auto',fontSize:10,color:'var(--text3)'}}>{logs.length} events</span></div>
          <div className="log-body" ref={logRef}>
            {logs.length===0 && <div style={{color:'var(--text3)'}}>Waiting for agent…</div>}
            {logs.map((l,i)=><div key={i} className="log-line"><span className="log-time">{l.time}</span><span className={`log-text ${l.type||''}`}>{l.text}</span></div>)}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Vulnerabilities Tab ─────────────────────────────────────────────────────
function VulnerabilitiesTab({vulns, execSummary, riskReduction}) {
  const [expanded, setExpanded] = useState(null);
  const [filterPoC, setFilterPoC] = useState(false);
  const safeVulns = Array.isArray(vulns) ? vulns.filter(Boolean) : [];
  const filtered = safeVulns.filter(v=>filterPoC?v.has_poc:true);

  return (
    <div>
      <div className="exec-box">
        <div className="exec-label">🤖 AI Executive Summary</div>
        <div className="exec-text">{execSummary}</div>
      </div>
      <div className="card" style={{marginBottom:22}}>
        <div className="card-header"><span>📊</span><span className="card-title">Risk Reduction</span></div>
        <div className="card-body">
          <div className="risk-delta-wrap">
            <div style={{flex:1}}>
              <div style={{fontSize:11,color:'var(--text2)',marginBottom:5}}>Before patching</div>
              <div className="risk-bar-bg"><div className="risk-bar-fill risk-before" style={{width:'100%'}}>100%</div></div>
              <div style={{fontSize:11,color:'var(--text2)',margin:'10px 0 5px'}}>After patching top 3</div>
              <div className="risk-bar-bg"><div className="risk-bar-fill risk-after" style={{width:`${100-riskReduction}%`}}>{100-riskReduction}%</div></div>
            </div>
            <div style={{textAlign:'center',flexShrink:0}}>
              <div style={{fontSize:44,fontWeight:800,fontFamily:'var(--mono)',color:'var(--success)',lineHeight:1}}>↓{riskReduction}%</div>
              <div style={{fontSize:11,color:'var(--text2)',marginTop:4}}>risk reduction</div>
            </div>
          </div>
        </div>
      </div>
      <div style={{display:'flex',alignItems:'center',gap:12,marginBottom:14}}>
        <div style={{fontSize:13,fontWeight:600,color:'var(--text0)',flex:1}}>{filtered.length} Vulnerabilities — Ranked by Priority Score</div>
        <label className={`checkbox-item${filterPoC?' checked':''}`} style={{cursor:'pointer'}}>
          <input type="checkbox" checked={filterPoC} onChange={e=>setFilterPoC(e.target.checked)} style={{display:'none'}}/>
          💥 Active PoC only
        </label>
      </div>
      <div className="card" style={{overflow:'auto'}}>
        <table className="vuln-table">
          <thead><tr><th>RANK</th><th>CVE ID</th><th>PACKAGE</th><th>CVSS</th><th>PoC</th><th>EXPLOIT VIABILITY</th><th>BLAST</th><th>SCORE</th><th>ASSIGNED</th><th>DUE</th><th>SRC</th><th></th></tr></thead>
          <tbody>
            {filtered.map((v,i)=>(
              <React.Fragment key={v.cve_id}>
                <tr className={`vuln-row${expanded===i?' expanded':''}`} onClick={()=>setExpanded(expanded===i?null:i)}>
                  <td><div className={`rank-badge${v.rank===1?' rank1':v.rank<=3?' top3':''}`}>#{v.rank}</div></td>
                  <td><span className="cve-id">{v.cve_id}</span></td>
                  <td><span className="pkg-chip">{v.package}@{v.version||'?'}</span></td>
                  <td><span className={`cvss-badge ${cvssClass(v.cvss,v.nvd_score_pending)}`}>{v.nvd_score_pending?'—':v.cvss} {cvssLabel(v.cvss,v.nvd_score_pending,v.cvss_source)}</span></td>
                  <td><span className={`poc-badge ${v.has_poc?'poc-yes':'poc-no'}`}>{v.has_poc?'⚡ ACTIVE':'None'}</span></td>
                  <td><span className={`viability-badge ${vClass(v.evaluation?.viability||'Medium')}`}>{v.evaluation?.viability||'—'}</span></td>
                  <td><span className="blast-num">×{v.blast_radius}</span></td>
                  <td><span className={`score-pill ${scoreClass(v.priority_score)}`}>{v.priority_score}</span></td>
                  <td>{v.assigned_to&&<div style={{display:'flex',alignItems:'center',gap:6}}><div className="avatar" style={{background:avatarClr(v.assigned_to)}}>{initials(v.assigned_to)}</div><span style={{fontSize:11}}>{v.assigned_to.split(' ')[0]}</span></div>}</td>
                  <td><span style={{fontFamily:'var(--mono)',fontSize:10,color:'var(--text3)'}}>{v.completion_date||'—'}</span></td>
                  <td><span className={`source-badge ${sourceBadge(v.source||'demo')}`}>{sourceLabel(v.source||'demo')}</span></td>
                  <td><Chev open={expanded===i}/></td>
                </tr>
                {expanded===i&&(
                  <tr className="vuln-expand"><td colSpan={12}>
                    <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:20}}>
                      <div>
                        <div style={{fontSize:10,fontWeight:700,letterSpacing:1,textTransform:'uppercase',color:'var(--primary)',marginBottom:8}}>AI Rationale</div>
                        <div className="rationale-box">{v.rationale}</div>
                        <div style={{fontSize:10,fontWeight:700,letterSpacing:1,textTransform:'uppercase',color:'var(--text3)',marginBottom:6}}>CVE Description</div>
                        <div style={{fontSize:12,color:'var(--text2)',lineHeight:1.6,marginBottom:12}}>{v.description}</div>
                        {v.evaluation?.risk_summary&&<>
                          <div style={{fontSize:10,fontWeight:700,letterSpacing:1,textTransform:'uppercase',color:'var(--warning)',marginBottom:6}}>Risk Assessment</div>
                          <div style={{fontSize:12,color:'var(--text1)',background:'var(--warn-dim)',padding:'8px 12px',borderRadius:8,border:'1px solid rgba(245,158,11,.2)'}}>{v.evaluation.risk_summary}</div>
                        </>}
                      </div>
                      <div>
                        <div style={{fontSize:10,fontWeight:700,letterSpacing:1,textTransform:'uppercase',color:'#a78bfa',marginBottom:8}}>Blast Radius ({v.blast_radius})</div>
                        <div className="systems-list">{(v.affected_systems||[]).map(s=><span key={s} className="system-chip">{s}</span>)}</div>
                        <div style={{marginTop:14,display:'grid',gridTemplateColumns:'1fr 1fr',gap:8}}>
                          {[['Complexity',`${v.complexity}/5`],['Est. Effort',`${v.estimated_hours}h`],['Tier',v.system_tier],['Regulatory',(v.regulatory||[]).join(',')||'None'],['Published',v.published||'—'],['CVSS Source',sourceDetailLabel(v.cvss_source)],['Description Source',sourceDetailLabel(v.description_source||v.provenance?.description_source)],['Viability',v.evaluation?.viability||'—'],['Confidence',v.evaluation?.confidence||'—'],['PoC Source',v.poc_source||'N/A']].map(([l,val])=>(
                            <div key={l} style={{background:'var(--bg2)',borderRadius:6,padding:'7px 10px',border:'1px solid var(--border2)'}}>
                              <div style={{fontSize:9,letterSpacing:1,textTransform:'uppercase',color:'var(--text3)',marginBottom:2}}>{l}</div>
                              <div style={{fontSize:11,fontFamily:'var(--mono)',fontWeight:600,color:'var(--text0)'}}>{val}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </td></tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Exploits Tab (NEW) ──────────────────────────────────────────────────────
function ExploitsTab({vulns, pocState, setPocState, handleGeneratePoC, exploitLang}) {
  const [filter, setFilter] = useState('all');

  const safeVulns = Array.isArray(vulns) ? vulns.filter(Boolean) : [];
  const filtered = safeVulns.filter(v=>{
    if (filter==='generated') return !!pocState?.[v.cve_id]?.code;
    if (filter==='high')      return v.evaluation?.viability==='High';
    if (filter==='poc')       return v.has_poc;
    return true;
  });

  return (
    <div>
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:18,flexWrap:'wrap',gap:10}}>
        <div>
          <div style={{fontSize:16,fontWeight:700,color:'var(--text0)'}}>On-Demand PoC Exploits</div>
          <div style={{fontSize:12,color:'var(--text2)',marginTop:3}}>
            Click <strong style={{color:'var(--danger)'}}>💣 Generate PoC</strong> per CVE — Gemini "Senior Vulnerability Researcher" prompt — for <strong style={{color:'var(--warning)'}}>authorized testing only</strong>
          </div>
        </div>
        <div style={{display:'flex',gap:6}}>
          {[['all','All'],['generated','Generated'],['high','High Viability'],['poc','Active PoC']].map(([v,l])=>(
            <button key={v} className={`btn btn-sm ${filter===v?'btn-primary':'btn-outline'}`} onClick={()=>setFilter(v)}>{l}</button>
          ))}
        </div>
      </div>

      {filtered.map(v=>(
        <div key={v.cve_id} className="exploit-card">
          <div className="exploit-card-header">
            <div className="exploit-meta">
              <span className="cve-id" style={{fontSize:14,fontWeight:700}}>{v.cve_id}</span>
              <span className="pkg-chip">{v.package}@{v.version||'?'}</span>
              <span className={`cvss-badge ${cvssClass(v.cvss,v.nvd_score_pending)}`}>{v.nvd_score_pending?'—':v.cvss} {cvssLabel(v.cvss,v.nvd_score_pending,v.cvss_source)}</span>
              {v.has_poc && <span className="poc-badge poc-yes">⚡ ACTIVE PoC</span>}
              <span className={`viability-badge ${vClass(v.evaluation?.viability||'Medium')}`}>Viability: {v.evaluation?.viability||'?'}</span>
            </div>
            <div style={{display:'flex',gap:8,alignItems:'center'}}>
              <span className={`lang-badge ${langClass(pocState?.[v.cve_id]?.language||exploitLang)}`}>
                {pocState?.[v.cve_id]?.language||exploitLang}
              </span>
              <span className={`gen-badge ${pocState?.[v.cve_id]?.code?'gen-yes':'gen-no'}`}>
                {pocState?.[v.cve_id]?.code ? `✦ ${pocState[v.cve_id].model||'Gemini-Gen'}` : '⏳ On-Demand'}
              </span>
            </div>
          </div>

          {!pocState?.[v.cve_id]?.code ? (
            <div className="poc-generate-zone">
              <div className="poc-lang-selector">
                {['python','javascript','bash'].map(l => (
                  <button key={l}
                    className={`poc-lang-btn${(pocState?.[v.cve_id]?.language||exploitLang)===l?' active':''}`}
                    onClick={()=>setPocState(p=>({...p,[v.cve_id]:{...p[v.cve_id],language:l}}))}>
                    {l}
                  </button>
                ))}
              </div>
              <button className="poc-generate-btn"
                disabled={pocState?.[v.cve_id]?.loading}
                onClick={()=>handleGeneratePoC(v, pocState?.[v.cve_id]?.language||exploitLang)}>
                {pocState?.[v.cve_id]?.loading ? '⟳ Generating...' : '💣 Generate PoC'}
              </button>
              {pocState?.[v.cve_id]?.error && (
                <div style={{color:'var(--danger)',fontSize:12,marginTop:8}}>{pocState[v.cve_id].error}</div>
              )}
              <div className="poc-warning">⚠ For authorized patch verification only. Use in isolated environment.</div>
            </div>
          ) : (
            <div>
              <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:6}}>
                <span style={{fontSize:11,color:'var(--text3)',fontFamily:'var(--mono)'}}>
                  {pocState[v.cve_id]?.model ? `✦ ${pocState[v.cve_id].model}` : '✦ Generated'}
                </span>
                <button className="btn btn-sm btn-outline" style={{fontSize:10,padding:'2px 8px'}}
                  onClick={()=>setPocState(p=>({...p,[v.cve_id]:{...p[v.cve_id],code:''}}))}>
                  ↺ Regenerate
                </button>
              </div>
              <CodeBlock code={pocState[v.cve_id].code} language={pocState[v.cve_id].language||'python'}/>
            </div>
          )}

          <div className="exploit-eval">
            <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:14}}>
              <div style={{fontFamily:'var(--mono)',fontSize:12,color:'var(--text1)',flex:1,background:'var(--bg3)',padding:'8px 12px',borderRadius:8,border:'1px solid var(--border2)'}}>
                <strong style={{color:'var(--warning)'}}>Risk:</strong> {v.evaluation?.risk_summary||'—'}
              </div>
              <div style={{flexShrink:0,textAlign:'center',background:'var(--bg3)',border:'1px solid var(--border2)',borderRadius:8,padding:'8px 14px'}}>
                <div style={{fontFamily:'var(--mono)',fontSize:18,fontWeight:800,color:v.evaluation?.viability==='High'?'var(--danger)':v.evaluation?.viability==='Low'?'var(--success)':'var(--warning)'}}>{v.evaluation?.viability||'?'}</div>
                <div style={{fontSize:9,color:'var(--text3)',letterSpacing:1}}>VIABILITY</div>
                <div style={{fontFamily:'var(--mono)',fontSize:11,color:'var(--text2)',marginTop:2}}>{Math.round((v.evaluation?.confidence||0)*100)}% conf</div>
              </div>
            </div>
            <div className="eval-grid">
              <div>
                <div className="eval-section-title">🔧 Remediation Steps</div>
                <div className="eval-steps">
                  {(v.evaluation?.remediation_steps||[]).map((s,i)=><div key={i} className="eval-step remediation">{s}</div>)}
                </div>
              </div>
              <div>
                <div className="eval-section-title">✅ Verification Steps (for Dev)</div>
                <div className="eval-steps">
                  {(v.evaluation?.verification_steps||[]).map((s,i)=><div key={i} className="eval-step verification">{s}</div>)}
                </div>
              </div>
            </div>
          </div>
        </div>
      ))}
      {filtered.length===0&&<div style={{textAlign:'center',padding:'60px 20px',color:'var(--text3)'}}>No exploits match the current filter.</div>}
    </div>
  );
}

// ─── Tickets Tab ─────────────────────────────────────────────────────────────
function TicketsTab({tickets}) {
  const [list, setList] = useState(Array.isArray(tickets) ? tickets.filter(Boolean) : []);
  const [selected, setSelected] = useState(null);
  useEffect(()=>setList(Array.isArray(tickets) ? tickets.filter(Boolean) : []),[tickets]);

  const cols = [
    {status:'Open',       label:'Open',       dot:'var(--warning)'},
    {status:'In Progress',label:'In Progress',dot:'var(--primary)'},
    {status:'Done',       label:'Done',       dot:'var(--success)'},
  ];
  const next = s=>s==='Open'?'In Progress':s==='In Progress'?'Done':'Open';
  const move = (id,st)=>setList(l=>l.map(t=>t.ticket_id===id?{...t,status:st}:t));

  return (
    <div>
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:18,flexWrap:'wrap',gap:10}}>
        <div>
          <div style={{fontSize:16,fontWeight:700,color:'var(--text0)'}}>Security Tickets</div>
          <div style={{fontSize:12,color:'var(--text2)',marginTop:3}}>Schedule-based assignment — completion dates from sprint capacity</div>
        </div>
        <div style={{display:'flex',gap:10}}>
          {[{l:'Total',v:list.length,c:'var(--text0)'},{l:'Critical',v:list.filter(t=>t.priority_level==='Critical').length,c:'var(--danger)'},{l:'High Viability',v:list.filter(t=>t.viability==='High').length,c:'#f472b6'}].map(s=>(
            <div key={s.l} style={{textAlign:'center',background:'var(--bg2)',border:'1px solid var(--border2)',borderRadius:8,padding:'7px 14px'}}>
              <div style={{fontSize:20,fontWeight:800,fontFamily:'var(--mono)',color:s.c}}>{s.v}</div>
              <div style={{fontSize:10,color:'var(--text3)'}}>{s.l}</div>
            </div>
          ))}
        </div>
      </div>
      <div className="kanban">
        {cols.map(col=>(
          <div key={col.status} className="kanban-col">
            <div className="kanban-col-header">
              <div className="kanban-col-title"><div className="col-dot" style={{background:col.dot}}/>{col.label}</div>
              <span style={{fontFamily:'var(--mono)',fontSize:11,color:'var(--text3)'}}>{list.filter(t=>t.status===col.status).length}</span>
            </div>
            <div className="kanban-cards">
              {list.filter(t=>t.status===col.status).map(t=>(
                <div key={t.ticket_id} className="ticket-card" onClick={()=>setSelected(selected?.ticket_id===t.ticket_id?null:t)}>
                  <div className="ticket-top">
                    <span className="ticket-id">{t.ticket_id}</span>
                    <span className={`priority-badge ${pClass(t.priority_level)}`}>{t.priority_level}</span>
                  </div>
                  <div className="ticket-cve">{t.cve_id}</div>
                  <div className="ticket-pkg">{t.package}</div>
                  {t.has_poc&&<div style={{fontSize:10,color:'#f472b6',marginBottom:5}}>⚡ Active exploit — {t.viability} viability</div>}
                  <div className="ticket-footer">
                    <div className="ticket-assignee">
                      <div className="avatar" style={{background:avatarClr(t.assigned_to||'?')}}>{initials(t.assigned_to||'?')}</div>
                      <div>
                        <div>{t.assigned_to}</div>
                        <div style={{fontSize:9,color:'var(--text3)'}}>{t.skill} specialist</div>
                      </div>
                    </div>
                    <div style={{textAlign:'right'}}>
                      <div className="ticket-date">📅 {t.completion_date||'TBD'}</div>
                      <div style={{fontSize:9,color:'var(--text3)',marginTop:1}}>{t.estimated_hours}h est.</div>
                    </div>
                  </div>
                  <div style={{marginTop:8,textAlign:'right'}}>
                    <button className="btn btn-outline btn-sm" style={{fontSize:10,padding:'3px 8px'}}
                      onClick={e=>{e.stopPropagation();move(t.ticket_id,next(t.status))}}>
                      → {next(t.status)}
                    </button>
                  </div>
                </div>
              ))}
              {list.filter(t=>t.status===col.status).length===0&&<div style={{fontSize:11,color:'var(--text3)',textAlign:'center',padding:'16px 0'}}>Empty</div>}
            </div>
          </div>
        ))}
      </div>
      {selected&&(
        <div style={{marginTop:20}} className="card">
          <div className="card-header" style={{justifyContent:'space-between'}}>
            <div style={{display:'flex',alignItems:'center',gap:10}}><span className="cve-id">{selected.ticket_id}</span><span className={`priority-badge ${pClass(selected.priority_level)}`}>{selected.priority_level}</span></div>
            <button className="btn btn-ghost" onClick={()=>setSelected(null)}><X/></button>
          </div>
          <div className="card-body">
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:20}}>
              <div>
                {[['CVE ID',selected.cve_id],['Package',selected.package],['CVSS',selected.cvss],['Priority Score',selected.priority_score],['Viability',selected.viability],['Blast Radius',`${selected.blast_radius} services`],['Skill Routed',selected.skill],['Assigned To',selected.assigned_to],['Email',selected.assigned_email],['Est. Hours',`${selected.estimated_hours}h`],['Completion Date',selected.completion_date],['Status',selected.status]].map(([l,v])=>(
                  <div key={l} style={{display:'flex',justifyContent:'space-between',padding:'7px 0',borderBottom:'1px solid var(--border2)'}}>
                    <span style={{fontSize:11,color:'var(--text2)'}}>{l}</span>
                    <span style={{fontSize:11,fontFamily:'var(--mono)',fontWeight:600,color:'var(--text0)'}}>{v}</span>
                  </div>
                ))}
              </div>
              <div>
                <div style={{fontSize:10,fontWeight:700,letterSpacing:1,textTransform:'uppercase',color:'var(--primary)',marginBottom:8}}>AI Rationale</div>
                <div className="rationale-box">{selected.rationale}</div>
                <div style={{fontSize:10,fontWeight:700,letterSpacing:1,textTransform:'uppercase',color:'var(--success)',marginBottom:8,marginTop:14}}>Verification Steps</div>
                <div className="eval-steps">{(selected.verification_steps||[]).map((s,i)=><div key={i} className="eval-step verification">{s}</div>)}</div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Calendar Tab ─────────────────────────────────────────────────────────────
function CalendarTab({calendar}) {
  const safeCalendar = Array.isArray(calendar) ? calendar.filter(Boolean) : [];
  return (
    <div>
      <div style={{marginBottom:18}}>
        <div style={{fontSize:16,fontWeight:700,color:'var(--text0)'}}>Patch Calendar</div>
        <div style={{fontSize:12,color:'var(--text2)',marginTop:3}}>Patches scheduled within maintenance windows, ordered by priority. Completion dates based on dev sprint capacity.</div>
      </div>
      <div className="card" style={{overflow:'auto'}}>
        <table className="cal-table">
          <thead><tr><th>RANK</th><th>PATCH DATE</th><th>WINDOW</th><th>CVE / PACKAGE</th><th>PRIORITY</th><th>SCORE</th><th>EXPLOIT</th><th>VIABILITY</th><th>ASSIGNED</th><th>DUE DATE</th><th>HRS</th></tr></thead>
          <tbody>
            {safeCalendar.map(c=>(
              <tr key={c.cve_id}>
                <td><div className={`rank-badge${c.rank===1?' rank1':c.rank<=3?' top3':''}`}>#{c.rank}</div></td>
                <td><span className="date-chip">📅 {c.scheduled_date}</span></td>
                <td><span className="window-chip">🕐 {c.window}</span></td>
                <td><div className="cve-id">{c.cve_id}</div><div style={{fontSize:11,color:'var(--text3)',marginTop:2}}>{c.package}</div></td>
                <td><span className={`priority-badge ${pClass(c.priority_level)}`}>{c.priority_level}</span></td>
                <td><span className={`score-pill ${scoreClass(c.priority_score)}`}>{c.priority_score}</span></td>
                <td>{c.exploit_language&&<span className={`lang-badge ${langClass(c.exploit_language)}`}>{c.exploit_language}</span>}</td>
                <td>{c.viability&&<span className={`viability-badge ${vClass(c.viability)}`}>{c.viability}</span>}</td>
                <td>{c.assigned_to&&<div style={{display:'flex',alignItems:'center',gap:6}}><div className="avatar" style={{background:avatarClr(c.assigned_to),width:18,height:18,fontSize:8}}>{initials(c.assigned_to)}</div><span style={{fontSize:11}}>{c.assigned_to}</span></div>}</td>
                <td><span style={{fontFamily:'var(--mono)',fontSize:11,color:'var(--text1)'}}>{c.completion_date||'—'}</span></td>
                <td><span style={{fontFamily:'var(--mono)',fontSize:11,color:'var(--text2)'}}>{c.estimated_hours}h</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Dashboard Tab ────────────────────────────────────────────────────────────
function DashboardTab({stats, vulns, execSummary, riskReduction}) {
  const s = stats||{};
  const safeVulns = Array.isArray(vulns) ? vulns.filter(Boolean) : [];
  const top3 = safeVulns.slice(0,3);
  const chartData = safeVulns.slice(0,8).map(v=>({l:v.package,v:v.priority_score,max:(safeVulns[0]||{}).priority_score||1}));
  const barClr = (v,m)=>{const p=v/m; return p>.7?'linear-gradient(90deg,#ff4757,#ff6b6b)':p>.4?'linear-gradient(90deg,#f59e0b,#fbbf24)':'linear-gradient(90deg,#3b82f6,#60a5fa)';};

  return (
    <div>
      <div style={{marginBottom:18}}>
        <div style={{fontSize:16,fontWeight:700,color:'var(--text0)'}}>Executive Dashboard</div>
        <div style={{fontSize:12,color:'var(--text2)',marginTop:3}}>Risk metrics, exploit intelligence, and dev schedule overview</div>
      </div>
      <div className="stats-grid">
        {[
          {val:s.total_vulns||0,     label:'Total CVEs',          sub:'discovered',          accent:'var(--primary)'},
          {val:s.critical_cvss||0,   label:'Critical CVSS≥9',     sub:'emergency patch',     accent:'var(--danger)'},
          {val:s.poc_active||0,      label:'Active Exploits',      sub:'weaponized',          accent:'#f472b6'},
          {val:s.exploits_generated||0,label:'Exploits Generated', sub:'by Gemini/POCme',     accent:'var(--secondary)'},
          {val:s.high_viability||0,  label:'High Viability',       sub:'exploit confirmed',   accent:'var(--danger)'},
          {val:`${s.risk_reduction||riskReduction}%`,label:'Risk Reduction',sub:'patch top 3',accent:'var(--success)'},
          {val:`${s.total_effort_hrs||0}h`,label:'Total Effort',   sub:'top 10 patches',      accent:'var(--blue)'},
          {val:s.va_cves||0,         label:'VA Report CVEs',        sub:'from report',         accent:'#a78bfa'},
        ].map(({val,label,sub,accent})=>(
          <div key={label} className="stat-card" style={{'--accent':accent}}>
            <div className="stat-val" style={{color:accent}}>{val}</div>
            <div className="stat-label">{label}</div>
            <div className="stat-sub">{sub}</div>
          </div>
        ))}
      </div>
      <div className="dashboard-grid">
        <div className="card">
          <div className="card-header"><span>📊</span><span className="card-title">Priority Score by Package</span></div>
          <div className="card-body">
            {chartData.map(r=>(
              <div key={r.l} className="risk-chart-row">
                <div className="risk-chart-label">{r.l}</div>
                <div className="risk-chart-bar"><div className="risk-chart-fill" style={{width:`${Math.max(8,(r.v/r.max)*100)}%`,background:barClr(r.v,r.max)}}>{r.v>r.max*.3?r.v:''}</div></div>
                <div style={{width:36,textAlign:'right',fontFamily:'var(--mono)',fontSize:9,color:'var(--text3)'}}>{r.v}</div>
              </div>
            ))}
          </div>
        </div>
        <div className="card">
          <div className="card-header"><span>⚡</span><span className="card-title">Top 3 Immediate Actions</span></div>
          <div className="card-body">
            {top3.map((v,i)=>(
              <div key={v.cve_id} className="action-item">
                <div className="action-num">{i+1}</div>
                <div className="action-text">
                  <strong style={{color:'var(--primary)'}}>{v.cve_id}</strong> — patch{' '}
                  <span style={{fontFamily:'var(--mono)',color:'var(--text0)'}}>{v.package}</span>.{' '}
                  {v.has_poc&&<span style={{color:'#f472b6'}}>⚡ Active exploit! </span>}
                  <span className={`viability-badge ${vClass(v.evaluation?.viability||'Medium')}`} style={{fontSize:9}}>{v.evaluation?.viability} viability</span>{' '}
                  Assign to <strong style={{color:'var(--text0)'}}>{v.assigned_to}</strong> — due <span style={{fontFamily:'var(--mono)',color:'var(--primary)'}}>{v.completion_date}</span>.
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="card" style={{gridColumn:'span 2'}}>
          <div className="card-header"><span>🧠</span><span className="card-title">AI Executive Summary</span></div>
          <div className="card-body">
            <div style={{fontSize:14,lineHeight:1.8,color:'var(--text0)',marginBottom:16}}>{execSummary}</div>
            <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(200px,1fr))',gap:10}}>
              {[
                {icon:'🛡️',txt:`${s.critical_cvss||0} critical-severity CVEs need emergency patching`},
                {icon:'💣',txt:`${s.exploits_generated||0} PoC exploits generated via Gemini/POCme`},
                {icon:'💥',txt:`${s.high_viability||0} high-viability exploits confirmed — immediate action`},
                {icon:'📅',txt:`${s.total_effort_hrs||0}h total engineering effort across top-10 CVEs`},
              ].map(({icon,txt})=>(
                <div key={txt} style={{display:'flex',gap:7,alignItems:'flex-start',background:'var(--bg3)',borderRadius:8,padding:'8px 12px',border:'1px solid var(--border2)'}}>
                  <span>{icon}</span><span style={{fontSize:11,color:'var(--text1)',lineHeight:1.5}}>{txt}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Results Page ─────────────────────────────────────────────────────────────
