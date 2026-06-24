async function renderDashboard() {
  if (!state.user) { navigate('/login'); return; }

  const app = document.getElementById('app');
  app.innerHTML += `
<div class="page fade-in">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:32px;">
    <div>
      <div class="label" style="margin-bottom:6px;">SOC Dashboard</div>
      <h1 style="font-size:1.6rem;font-weight:700;">Overview</h1>
    </div>
    <button class="btn btn-primary" onclick="navigate('/scan')"> New Scan</button>
  </div>
  <div id="dashStats" class="grid-4" style="margin-bottom:24px;">
    ${[1,2,3,4].map(() => `<div class="card stat-card"><div class="spinner"></div></div>`).join('')}
  </div>
  <div class="grid-2">
    <div class="card" style="padding:24px;" id="recentScans">
      <div class="label" style="margin-bottom:16px;">Recent Activity</div>
      <div class="spinner"></div>
    </div>
    <div class="card" style="padding:24px;" id="verdictBreakdown">
      <div class="label" style="margin-bottom:16px;">Verdict Breakdown</div>
      <div class="spinner"></div>
    </div>
  </div>
</div>`;

  await loadDashboard();
}

async function loadDashboard() {
  try {
    const res = await apiFetch('/history/?limit=100');
    if (!res || !res.ok) return;
    const scans = await res.json();

    const total = scans.length;
    const malicious = scans.filter(s => s.verdict === 'Malicious').length;
    const suspicious = scans.filter(s => s.verdict === 'Suspicious').length;
    const avgScore = total ? Math.round(scans.reduce((a, b) => a + (b.risk_score || 0), 0) / total) : 0;

    document.getElementById('dashStats').innerHTML = `
      <div class="card stat-card"><div class="stat-value">${total}</div><div class="stat-label">Total Scans</div></div>
      <div class="card stat-card"><div class="stat-value" style="color:var(--red);">${malicious}</div><div class="stat-label">Malicious</div></div>
      <div class="card stat-card"><div class="stat-value" style="color:var(--yellow);">${suspicious}</div><div class="stat-label">Suspicious</div></div>
      <div class="card stat-card"><div class="stat-value">${avgScore}</div><div class="stat-label">Avg Risk Score</div></div>`;

    const recent = scans.slice(0, 8);
    document.getElementById('recentScans').innerHTML = `
      <div class="label" style="margin-bottom:16px;">Recent Activity</div>
      ${recent.map(s => `
        <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--surface2);cursor:pointer;" onclick="viewScan(${s.id})">
          <div style="display:flex;align-items:center;gap:10px;">
            <span class="tag">${s.scan_type}</span>
            <span style="font-size:0.82rem;color:var(--muted);">${new Date(s.created_at).toLocaleString()}</span>
          </div>
          <span class="badge badge-${(s.verdict||'unknown').toLowerCase()}">${s.verdict || 'Unknown'}</span>
        </div>`).join('')}
      ${!recent.length ? '<div style="color:var(--muted);font-size:0.875rem;">No scans yet.</div>' : ''}`;

    const verdictCounts = { Clear: 0, Suspicious: 0, Malicious: 0, Unknown: 0 };
    scans.forEach(s => { if (verdictCounts[s.verdict] !== undefined) verdictCounts[s.verdict]++; });

    document.getElementById('verdictBreakdown').innerHTML = `
      <div class="label" style="margin-bottom:16px;">Verdict Breakdown</div>
      ${Object.entries(verdictCounts).map(([verdict, count]) => {
        const pct = total ? Math.round((count / total) * 100) : 0;
        return `
        <div style="margin-bottom:14px;">
          <div style="display:flex;justify-content:space-between;margin-bottom:6px;">
            <span class="badge badge-${verdict.toLowerCase()}">${verdict}</span>
            <span style="font-size:0.85rem;color:var(--muted);">${count} (${pct}%)</span>
          </div>
          <div class="score-bar"><div style="height:100%;width:${pct}%;background:${getVerdictColor(verdict)};border-radius:4px;transition:width 0.6s;"></div></div>
        </div>`;
      }).join('')}`;

  } catch { toast('Failed to load dashboard', 'error'); }
}