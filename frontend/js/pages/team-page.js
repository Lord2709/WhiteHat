function TeamProfilesPage() {
  const EMPTY_FORM = {
    id: null,
    name: '',
    email: '',
    role: '',
    linkedin_url: '',
    professional_summary: '',
    expertise_str: '',
    availability_notes: '',
    current_load: 0,
    available_hours_per_week: 40,
    sprint_hours_remaining: 20,
    work_days: ['monday','tuesday','wednesday','thursday','friday'],
  };
  const [profiles, setProfiles] = useState([]);
  const [form, setForm] = useState(EMPTY_FORM);
  const [statusMsg, setStatusMsg] = useState('');

  const loadProfiles = async () => {
    try {
      const resp = await fetch(`${API_URL}/api/team-profiles`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      setProfiles(Array.isArray(data.items) ? data.items : []);
    } catch (err) {
      setStatusMsg(`Unable to load team profiles: ${err.message}`);
    }
  };

  useEffect(() => {
    loadProfiles();
  }, []);

  const saveProfile = async () => {
    if (!form.name.trim() || !form.email.trim()) {
      setStatusMsg('Name and email are required.');
      return;
    }
    const payload = {
      name: form.name.trim(),
      email: form.email.trim(),
      role: form.role.trim(),
      linkedin_url: form.linkedin_url.trim(),
      professional_summary: form.professional_summary.trim(),
      expertise: form.expertise_str.split(',').map(s => s.trim()).filter(Boolean),
      availability_notes: form.availability_notes.trim(),
      current_load: parseInt(form.current_load || 0, 10) || 0,
      schedule: {
        available_hours_per_week: parseInt(form.available_hours_per_week || 40, 10) || 40,
        sprint_hours_remaining: parseInt(form.sprint_hours_remaining || 20, 10) || 20,
        work_days: form.work_days,
      },
    };
    const isUpdate = !!form.id;
    const url = isUpdate
      ? `${API_URL}/api/team-profiles/${form.id}`
      : `${API_URL}/api/team-profiles`;
    const method = isUpdate ? 'PUT' : 'POST';
    try {
      const resp = await fetch(url, {
        method,
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify(payload),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      await loadProfiles();
      setForm(EMPTY_FORM);
      setStatusMsg(isUpdate ? 'Team profile updated.' : 'Team profile added.');
    } catch (err) {
      setStatusMsg(`Failed to save profile: ${err.message}`);
    }
  };

  const editProfile = p => {
    setForm({
      id: p.id,
      name: p.name || '',
      email: p.email || '',
      role: p.role || '',
      linkedin_url: p.linkedin_url || '',
      professional_summary: p.professional_summary || '',
      expertise_str: Array.isArray(p.expertise) ? p.expertise.join(', ') : '',
      availability_notes: p.availability_notes || '',
      current_load: p.current_load ?? 0,
      available_hours_per_week: p.schedule?.available_hours_per_week ?? 40,
      sprint_hours_remaining: p.schedule?.sprint_hours_remaining ?? 20,
      work_days: Array.isArray(p.schedule?.work_days) ? p.schedule.work_days : ['monday','tuesday','wednesday','thursday','friday'],
    });
  };

  const deleteProfile = async id => {
    try {
      const resp = await fetch(`${API_URL}/api/team-profiles/${id}`, {method:'DELETE'});
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      await loadProfiles();
      setStatusMsg('Team profile deleted.');
    } catch (err) {
      setStatusMsg(`Failed to delete profile: ${err.message}`);
    }
  };

  const toggleWorkDay = day => {
    setForm(prev => ({
      ...prev,
      work_days: prev.work_days.includes(day)
        ? prev.work_days.filter(d => d !== day)
        : [...prev.work_days, day],
    }));
  };

  return (
    <div className="page">
      <div style={{marginBottom:22}}>
        <div className="page-title">Team Profiles</div>
        <div className="page-sub">Persisted team roles, LinkedIn, professional summaries, skills, and availability for smarter assignment</div>
      </div>
      <div className="config-grid">
        <div className="card">
          <div className="card-header"><span>🧾</span><span className="card-title">Profile Editor</span></div>
          <div className="card-body" style={{display:'grid',gap:10}}>
            <div className="field"><label>Name</label><input value={form.name} onChange={e=>setForm(f=>({...f,name:e.target.value}))} placeholder="Jane Doe"/></div>
            <div className="field"><label>Email</label><input value={form.email} onChange={e=>setForm(f=>({...f,email:e.target.value}))} placeholder="jane@company.com"/></div>
            <div className="field"><label>Role</label><input value={form.role} onChange={e=>setForm(f=>({...f,role:e.target.value}))} placeholder="Senior Backend Engineer"/></div>
            <div className="field"><label>LinkedIn URL (optional)</label><input value={form.linkedin_url} onChange={e=>setForm(f=>({...f,linkedin_url:e.target.value}))} placeholder="https://linkedin.com/in/..."/></div>
            <div className="field"><label>Skills (comma-separated)</label><input value={form.expertise_str} onChange={e=>setForm(f=>({...f,expertise_str:e.target.value}))} placeholder="python, nodejs, security"/></div>
            <div className="field"><label>Professional Summary</label><textarea rows="3" value={form.professional_summary} onChange={e=>setForm(f=>({...f,professional_summary:e.target.value}))} placeholder="Key experience, systems owned, strengths"/></div>
            <div className="field"><label>Availability Notes</label><textarea rows="2" value={form.availability_notes} onChange={e=>setForm(f=>({...f,availability_notes:e.target.value}))} placeholder="Time zone, on-call, planned leave"/></div>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr 1fr',gap:8}}>
              <div className="field"><label>Current Load</label><input type="number" value={form.current_load} onChange={e=>setForm(f=>({...f,current_load:e.target.value}))}/></div>
              <div className="field"><label>Hours / Week</label><input type="number" value={form.available_hours_per_week} onChange={e=>setForm(f=>({...f,available_hours_per_week:e.target.value}))}/></div>
              <div className="field"><label>Sprint Hours Free</label><input type="number" value={form.sprint_hours_remaining} onChange={e=>setForm(f=>({...f,sprint_hours_remaining:e.target.value}))}/></div>
            </div>
            <div className="field">
              <label>Work Days</label>
              <div className="checkbox-group">
                {['monday','tuesday','wednesday','thursday','friday','saturday','sunday'].map(day => (
                  <label key={day} className={`checkbox-item${form.work_days.includes(day)?' checked':''}`}>
                    <input type="checkbox" checked={form.work_days.includes(day)} onChange={()=>toggleWorkDay(day)} />
                    {day.slice(0,3).toUpperCase()}
                  </label>
                ))}
              </div>
            </div>
            <div style={{display:'flex',gap:8,flexWrap:'wrap'}}>
              <button className="btn btn-primary" onClick={saveProfile}>{form.id ? 'Update Profile' : 'Save Profile'}</button>
              <button className="btn btn-outline" onClick={()=>setForm(EMPTY_FORM)}>Reset</button>
            </div>
            {statusMsg && <div style={{fontSize:11,color:'var(--text2)'}}>{statusMsg}</div>}
          </div>
        </div>
        <div className="card">
          <div className="card-header"><span>👥</span><span className="card-title">Saved Profiles</span></div>
          <div className="card-body" style={{display:'grid',gap:10}}>
            {!profiles.length && <div style={{fontSize:12,color:'var(--text3)'}}>No profiles saved yet.</div>}
            {profiles.map(p => (
              <div key={p.id} style={{background:'var(--bg3)',border:'1px solid var(--border2)',borderRadius:10,padding:12}}>
                <div style={{fontSize:13,fontWeight:700,color:'var(--text0)'}}>{p.name}</div>
                <div style={{fontSize:11,color:'var(--text2)',marginTop:3}}>{p.role || 'Role not set'} · {p.email}</div>
                <div style={{display:'flex',gap:6,flexWrap:'wrap',marginTop:8}}>
                  {(Array.isArray(p.expertise) ? p.expertise : []).map(skill => <span key={skill} className="skill-tag">{skill}</span>)}
                </div>
                <div style={{display:'flex',gap:8,marginTop:10}}>
                  <button className="btn btn-outline btn-sm" onClick={()=>editProfile(p)}>Edit</button>
                  <button className="btn btn-outline btn-sm" onClick={()=>deleteProfile(p.id)}>Delete</button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Root App ─────────────────────────────────────────────────────────────────
