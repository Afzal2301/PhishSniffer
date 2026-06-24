async function renderHistory() {
  if (!state.user) { navigate('/login'); return; }

  const app = document.getElementById('app');
  app.innerHTML += `
<div class="page fade-in">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:28px;">
    <div>
      <div class="label" style="margin-bottom:6px;">Analyst View</div>
      <h1 style="font-size:1.6rem;font-weight:700;">Scan History</h1>
    </div>
    <div style="display:flex;gap:8px;align-items:center;">
      <select class="input" id="filterVerdict" style="width:140px;" onchange="loadHistory()">
        <option value="">All Verdicts</option>
        <option value="Clear">Clear</option>
        <option value="Suspicious">Suspicious</option>
        <option value="Malicious">Malicious</option>
        <option value="Unknown">Unknown</option>
      </select>
      <select class="input" id="filterType" style="width:130px;" onchange="loadHistory()">
        <option value="">All Types</option>
        <option value="email">Email</option>
        <option value="url">URL</option>
      </select>
      <button class="btn btn-primary btn-sm" onclick="navigate('/scan')">New Scan</button>
    </div>
  </div>
  <div class="card" id="historyTable" style="overflow:hidden;">
    <div style="padding:40px;text-align:center;"><div class="spinner"></div></div>
  </div>
</div>`;

  await loadHistory();
}

async function loadHistory() {
  const verdict = document.getElementById('filterVerdict')?.value || '';
  const type = document.getElementById('filterType')?.value || '';
  let url = '/history/?limit=50';
  if (verdict) url += `&verdict=${verdict}`;
  if (type) url += `&scan_type=${type}`;

  const container = document.getElementById('historyTable');
  if (!container) return;

  try {
    const res = await apiFetch(url);
    if (!res || !res.ok) { container.innerHTML = `<div style="padding:32px;text-align:center;color:var(--muted);">Failed to load history.</div>`; return; }
    const data = await res.json();

    if (!data.length) {
      container.innerHTML = `<div style="padding:48px;text-align:center;color:var(--muted);">No scans found. <a href="/" onclick="navigate('/');return false;" style="color:var(--blue);">Run your first scan.</a></div>`;
      return;
    }

 container.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>Name</th>
          <th>Type</th>
          <th>Score</th>
          <th>Verdict</th>
          <th>Date</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        ${data.map(scan => `
        <tr>
          <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
            <span style="font-weight:500;color:var(--text);">${scan.scan_name || '—'}</span>
          </td>
          <td><span class="tag">${scan.scan_type}</span></td>
          <td style="font-weight:600;color:${getVerdictColor(scan.verdict)};">${scan.risk_score ?? '—'}</td>
          <td><span class="badge badge-${(scan.verdict||'unknown').toLowerCase()}">${scan.verdict || 'Unknown'}</span></td>
          <td style="color:var(--muted);font-size:0.82rem;">${new Date(scan.created_at).toLocaleString()}</td>
          <td>
            <div style="display:flex;gap:6px;">
              <button class="btn btn-secondary btn-sm" onclick="viewScan(${scan.id})">View</button>
              <button class="btn btn-danger btn-sm" onclick="deleteScan(${scan.id})">Delete</button>
            </div>
          </td>
        </tr>`).join('')}
      </tbody>
    </table>`;
  } catch {
    container.innerHTML = `<div style="padding:32px;text-align:center;color:var(--muted);">Error loading history.</div>`;
  }
}

async function viewScan(scanId) {
  window._lastScanResult = null;
  navigate(`/results/${scanId}`);
}

async function deleteScan(scanId) {
  if (!confirm('Delete this scan permanently?')) return;
  const res = await apiFetch(`/history/${scanId}`, { method: 'DELETE' });
  if (res && res.ok) { toast('Scan deleted', 'success'); await loadHistory(); }
  else toast('Delete failed', 'error');
}