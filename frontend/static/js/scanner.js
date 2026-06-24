const CYBER_FACTS = [
  "Phishing accounts for over 90% of all data breaches globally.",
  "The average time to detect a phishing breach is 197 days.",
  "Business Email Compromise attacks cost organizations over $2.7 billion in 2022.",
  "Over 3.4 billion phishing emails are sent every single day.",
  "A new phishing site is created every 20 seconds on average.",
  "96% of phishing attacks arrive via email.",
  "Spear phishing targets specific individuals and has an 80% success rate.",
  "The financial sector is the most targeted industry for phishing attacks.",
  "Mobile phishing attacks increased by 161% in a single year.",
  "DNS hijacking is used in 46% of advanced phishing campaigns.",
  "The average cost of a phishing attack on a mid-size company is $1.6 million.",
  "Human error is responsible for 95% of all cybersecurity breaches.",
  "Whaling attacks target C-suite executives and have a 70% success rate.",
  "Vishing — voice phishing — increased by 550% in 2022 alone.",
  "One in every 99 emails is a phishing attack.",
  "It takes an average employee just 16 seconds to click a phishing link.",
  "Smishing — SMS phishing — grew by 328% in a single year.",
  "Credential phishing is used in 73% of all cyberattacks.",
  "Over 75% of organizations worldwide experienced a phishing attack in 2023.",
  "Attackers can set up a convincing phishing site in under 10 minutes.",
  "Clone phishing replicates legitimate emails and replaces links with malicious ones.",
  "QR code phishing — quishing — bypasses most email security filters completely.",
  "AI-generated phishing emails have a 60% higher click-through rate than manual ones.",
  "The healthcare industry is the most expensive sector for phishing breach costs.",
  "Over 65% of cybercriminal groups used spear phishing as their primary attack vector.",
  "Supply chain phishing targets vendors to gain access to larger organizations.",
  "Zero-day phishing exploits vulnerabilities before patches are even available.",
  "DMARC adoption could block an estimated 90% of phishing emails — only 30% of domains use it.",
  "Attackers register lookalike domains hours before launching a phishing campaign.",
  "Thread hijacking attacks insert malicious replies into legitimate email chains."
];

let factInterval = null;
let currentFact = 0;

function showLoadingOverlay() {
  currentFact = 0;
  const el = document.createElement('div');
  el.className = 'loading-overlay fade-in';
  el.id = 'loadingOverlay';
  el.innerHTML = `
    <div style="display:flex;flex-direction:column;align-items:center;gap:20px;">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px;">
        <img src="/static/img/logo.png" alt="PhishSniffer" style="height:1.5rem;width:auto;">
        <span style="font-size:1.1rem;font-weight:600;color:var(--text);">PhishSniffer</span>
      </div>
      <div class="loading-spinner-lg"></div>
      <div class="progress-bar"><div class="progress-fill"></div></div>
      <div class="fact-text" id="factText">${CYBER_FACTS[0]}</div>
      <div style="color:var(--muted);font-size:0.78rem;letter-spacing:0.08em;text-transform:uppercase;">Analyzing — parallel intelligence gathering</div>
    </div>`;
  document.body.appendChild(el);
  factInterval = setInterval(() => {
    currentFact = (currentFact + 1) % CYBER_FACTS.length;
    const ft = document.getElementById('factText');
    if (ft) {
      ft.style.opacity = '0';
      setTimeout(() => {
        ft.textContent = CYBER_FACTS[currentFact];
        ft.style.opacity = '1';
        ft.style.transition = 'opacity 0.5s';
      }, 300);
    }
  },6000);
}

function hideLoadingOverlay() {
  clearInterval(factInterval);
  const el = document.getElementById('loadingOverlay');
  if (el) el.remove();
}

async function renderHome() {
  const app = document.getElementById('app');
  const isLoggedIn = !!state.user;

  app.innerHTML += `
<div style="text-align:center;">

  <!-- HERO -->
  <div style="padding:100px 24px 80px;background:linear-gradient(180deg,rgba(59,130,246,0.06) 0%,transparent 100%);position:relative;">
    <div style="max-width:760px;margin:0 auto;">
      <div style="display:flex;align-items:center;justify-content:center;gap:10px;margin-bottom:20px;">
        <img src="/static/img/logo.png" alt="PhishSniffer" style="height:clamp(2.4rem,5vw,3.2rem);width:auto;">
        <h1 style="font-size:clamp(2.4rem,5vw,3.2rem);font-weight:800;letter-spacing:-0.04em;color:var(--blue);line-height:1;">PhishSniffer</h1>
      </div>
      <p style="font-size:clamp(1.4rem,3vw,2rem);font-weight:700;color:var(--text);margin-bottom:16px;line-height:1.3;">Phishing Ends Here.</p>
      <p style="color:var(--muted);font-size:1rem;max-width:540px;margin:0 auto 36px;line-height:1.75;">An advanced phishing analysis platform that helps security teams triage, dissect, and resolve threats — quickly, accurately, and at scale.</p>
      <div style="display:flex;align-items:center;justify-content:center;gap:12px;flex-wrap:wrap;">
        <button class="btn btn-primary btn-lg" onclick="navigate('/scan')">Start Investigating</button>
        <button class="btn btn-secondary btn-lg" onclick="document.getElementById('how-it-works').scrollIntoView({behavior:'smooth'})">How it Works</button>
      </div>
      ${isLoggedIn ? `<div style="margin-top:20px;font-size:0.85rem;color:var(--muted);">Welcome back, <span style="color:var(--blue);font-weight:500;">${state.user.username}</span></div>` : ''}
    </div>
  </div>

  <!-- WHY PHISHSNIFFER -->
  <div style="padding:80px 24px;max-width:1100px;margin:0 auto;">
    <div class="label" style="margin-bottom:12px;">Why PhishSniffer</div>
    <h2 style="font-size:clamp(1.6rem,3vw,2.2rem);font-weight:700;margin-bottom:16px;letter-spacing:-0.02em;">Built for analysts, not just admins</h2>
    <p style="color:var(--muted);max-width:560px;margin:0 auto 48px;line-height:1.75;font-size:0.95rem;">Most security tools give you data. PhishSniffer gives you answers. Every scan produces an analyst-grade verdict with reasoning — not just a score.</p>
    <div class="grid-3" style="text-align:left;">
      <div class="card card-hover" style="padding:28px;">
        <div style="font-size:1.8rem;margin-bottom:14px;">⚡</div>
        <div style="font-weight:600;font-size:1rem;margin-bottom:8px;">Parallel Intelligence</div>
        <div style="color:var(--muted);font-size:0.875rem;line-height:1.7;">Queries VirusTotal, AbuseIPDB, Google Safe Browsing, and URLScan simultaneously — results in under 15 seconds.</div>
      </div>
      <div class="card card-hover" style="padding:28px;">
        <div style="font-size:1.8rem;margin-bottom:14px;">🧠</div>
        <div style="font-weight:600;font-size:1rem;margin-bottom:8px;">AI-Driven Verdicts</div>
        <div style="color:var(--muted);font-size:0.875rem;line-height:1.7;">An AI engine reasons through every signal and writes a handoff-ready analyst narrative — not just a number.</div>
      </div>
      <div class="card card-hover" style="padding:28px;">
        <div style="font-size:1.8rem;margin-bottom:14px;">🔬</div>
        <div style="font-weight:600;font-size:1rem;margin-bottom:8px;">Deep Email Forensics</div>
        <div style="color:var(--muted);font-size:0.875rem;line-height:1.7;">SPF, DKIM, DMARC validation from trusted receivers. Domain mismatch, hop analysis, and IOC extraction built in.</div>
      </div>
      <div class="card card-hover" style="padding:28px;">
        <div style="font-size:1.8rem;margin-bottom:14px;">🎯</div>
        <div style="font-weight:600;font-size:1rem;margin-bottom:8px;">Typosquat Detection</div>
        <div style="color:var(--muted);font-size:0.875rem;line-height:1.7;">Number substitution, letter swaps, and edit distance checks across 400+ known brands — catches what humans miss.</div>
      </div>
      <div class="card card-hover" style="padding:28px;">
        <div style="font-size:1.8rem;margin-bottom:14px;">📊</div>
        <div style="font-weight:600;font-size:1rem;margin-bottom:8px;">SOC Dashboard</div>
        <div style="color:var(--muted);font-size:0.875rem;line-height:1.7;">Full scan history, verdict breakdown charts, and live threat pulse — everything a tier-1 analyst needs at a glance.</div>
      </div>
      <div class="card card-hover" style="padding:28px;">
        <div style="font-size:1.8rem;margin-bottom:14px;">📁</div>
        <div style="font-weight:600;font-size:1rem;margin-bottom:8px;">Export Ready</div>
        <div style="color:var(--muted);font-size:0.875rem;line-height:1.7;">Download every report as PDF, JSON, or HTML. Attach directly to tickets or share with your team instantly.</div>
      </div>
    </div>
  </div>

  <!-- HOW IT WORKS -->
  <div id="how-it-works" style="padding:80px 24px;background:var(--surface);border-top:1px solid var(--surface2);border-bottom:1px solid var(--surface2);">
    <div style="max-width:860px;margin:0 auto;">
      <div class="label" style="margin-bottom:12px;">How it Works</div>
      <h2 style="font-size:clamp(1.6rem,3vw,2.2rem);font-weight:700;margin-bottom:48px;letter-spacing:-0.02em;">Three steps to a verdict</h2>
      <div class="grid-3" style="text-align:left;">
        <div style="padding:0 16px;">
          <div style="width:40px;height:40px;background:var(--blue-bg);border:1px solid var(--blue-border);border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:700;color:var(--blue);font-size:1.1rem;margin-bottom:16px;">1</div>
          <div style="font-weight:600;margin-bottom:8px;">Submit</div>
          <div style="color:var(--muted);font-size:0.875rem;line-height:1.7;">Drop a .eml file or paste a suspicious URL. No configuration needed — just submit and go.</div>
        </div>
        <div style="padding:0 16px;">
          <div style="width:40px;height:40px;background:var(--blue-bg);border:1px solid var(--blue-border);border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:700;color:var(--blue);font-size:1.1rem;margin-bottom:16px;">2</div>
          <div style="font-weight:600;margin-bottom:8px;">Analyse</div>
          <div style="color:var(--muted);font-size:0.875rem;line-height:1.7;">Five threat intelligence engines run in parallel — authentication, reputation, structure, IOCs, and AI reasoning.</div>
        </div>
        <div style="padding:0 16px;">
          <div style="width:40px;height:40px;background:var(--blue-bg);border:1px solid var(--blue-border);border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:700;color:var(--blue);font-size:1.1rem;margin-bottom:16px;">3</div>
          <div style="font-weight:600;margin-bottom:8px;">Act</div>
          <div style="color:var(--muted);font-size:0.875rem;line-height:1.7;">Get a Clear, Suspicious, or Malicious verdict with a full analyst narrative and exportable report — ready for your ticket.</div>
        </div>
      </div>
    </div>
  </div>


  <!-- FOOTER -->
  <div style="padding:32px 24px;border-top:1px solid var(--surface2);text-align:center;">
    <div style="display:flex;align-items:center;justify-content:center;gap:8px;margin-bottom:12px;">
      <img src="/static/img/logo.png" alt="PhishSniffer" style="height:1.2rem;width:auto;">
      <span style="font-weight:700;color:var(--blue);font-size:0.9rem;">PhishSniffer</span>
      <span class="tag" style="font-size:0.6rem;">v2.0</span>
    </div>
    <div style="color:var(--muted);font-size:0.78rem;">Built for SOC analysts. Powered by parallel threat intelligence and AI.</div>
  </div>

</div>`;

  window._activeTab = 'unified';
  window._emlFile = null;

  if (isLoggedIn) loadRecentScansHome();
}
async function loadRecentScansHome() {
  const container = document.getElementById('recentScansHome');
  if (!container) return;
  try {
    const res = await apiFetch('/history/?limit=3');
    if (!res || !res.ok) { container.innerHTML = '<div style="color:var(--muted);font-size:0.8rem;">Could not load recent scans.</div>'; return; }
    const scans = await res.json();
    if (!scans.length) { container.innerHTML = '<div style="color:var(--muted);font-size:0.8rem;">No scans yet.</div>'; return; }
    container.innerHTML = scans.map(s => `
      <div style="display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--surface2);cursor:pointer;" onclick="viewScan(${s.id})">
        <div style="display:flex;align-items:center;gap:10px;">
          <span class="tag">${s.scan_type}</span>
          <span style="font-size:0.8rem;color:var(--muted);">${new Date(s.created_at).toLocaleString()}</span>
        </div>
        <span class="badge badge-${(s.verdict||'unknown').toLowerCase()}">${s.verdict || 'Unknown'}</span>
      </div>`).join('');
  } catch {
    container.innerHTML = '<div style="color:var(--muted);font-size:0.8rem;">Could not load recent scans.</div>';
  }
}
function renderScan() {
  const app = document.getElementById('app');
  app.innerHTML += `
<div style="max-width:860px;margin:0 auto;padding:60px 24px 80px;text-align:center;">

  <div style="margin-bottom:32px;">
    <div class="label" style="margin-bottom:8px;">Threat Analysis</div>
    <h1 style="font-size:1.8rem;font-weight:700;letter-spacing:-0.02em;">Submit a threat for analysis</h1>
  </div>

  <div style="background:var(--surface);border:1px solid var(--surface2);border-radius:16px;overflow:hidden;">
    <div style="display:flex;border-bottom:1px solid var(--surface2);">
      <button class="scan-tab active" data-tab="unified"
        style="flex:1;padding:20px 12px;background:none;color:var(--text);font-size:0.8rem;font-weight:700;border-right:1px solid var(--surface2);letter-spacing:0.08em;transition:all 0.2s;"
        onclick="switchTab('unified')">ONE-CLICK TRIAGE</button>
      <button class="scan-tab" data-tab="url"
        style="flex:1;padding:20px 12px;background:none;color:var(--muted);font-size:0.8rem;font-weight:700;letter-spacing:0.08em;transition:all 0.2s;"
        onclick="switchTab('url')">URL SCAN</button>
    </div>

    <div style="padding:32px;">
      <div id="tab-unified">
        <div id="eml-dropzone"
          style="border:2px dashed var(--border);border-radius:12px;padding:40px 24px;cursor:pointer;transition:all 0.25s;background:var(--bg);text-align:center;"
          onclick="document.getElementById('emlFileInput').click()"
          ondragover="event.preventDefault();this.style.borderColor='var(--blue)';this.style.background='var(--blue-bg)';this.style.boxShadow='0 0 0 4px var(--blue-bg)';"
          ondragleave="this.style.borderColor='var(--border)';this.style.background='var(--bg)';this.style.boxShadow='none';"
          ondrop="handleEmlDrop(event)">
          <div style="font-size:2.5rem;margin-bottom:12px;">📧</div>
          <div style="font-weight:600;font-size:1rem;color:var(--text);margin-bottom:6px;">Drop .eml file here</div>
          <div style="color:var(--muted);font-size:0.85rem;">or click to browse — supports .eml files</div>
          <input type="file" id="emlFileInput" accept=".eml" style="display:none;" onchange="handleEmlSelect(event)">
        </div>

        <div id="eml-selected"
          style="display:none;margin-top:16px;padding:16px 20px;background:var(--bg);border:1px solid var(--blue-border);border-radius:12px;align-items:center;justify-content:space-between;">
          <div style="display:flex;align-items:center;gap:12px;">
            <span style="font-size:1.5rem;">📄</span>
            <div>
              <div style="font-weight:600;font-size:0.9rem;" id="emlFileName"></div>
              <div style="color:var(--muted);font-size:0.8rem;" id="emlFileSize"></div>
            </div>
          </div>
          <button class="btn btn-secondary btn-sm" onclick="clearEmlFile()">Remove</button>
        </div>

        <button class="btn btn-primary" style="width:100%;margin-top:20px;padding:16px;font-size:1rem;font-weight:700;background:linear-gradient(135deg,var(--blue),#1a73e8);box-shadow:0 4px 20px rgba(26,115,232,0.3);border:none;border-radius:10px;transition:all 0.25s;justify-content:center;"
          onmouseover="this.style.boxShadow='0 6px 28px rgba(26,115,232,0.5)';this.style.transform='translateY(-1px)';"
          onmouseout="this.style.boxShadow='0 4px 20px rgba(26,115,232,0.3)';this.style.transform='translateY(0)';"
          onclick="runUnifiedScan()">⚡ Analyse Now</button>
      </div>

      <div id="tab-url" style="display:none;">
        <div style="display:flex;gap:10px;">
          <input class="input" id="urlInput" type="url" placeholder="https://suspicious-domain.com/path" style="font-size:0.95rem;padding:13px 14px;flex:1;" onkeydown="if(event.key==='Enter')runUrlScan()">
          <button class="btn btn-primary" style="padding:0 28px;font-size:0.875rem;white-space:nowrap;" onclick="runUrlScan()">Analyse</button>
        </div>
      </div>
    </div>

    <div style="border-top:1px solid var(--surface2);padding:16px 32px;display:flex;align-items:center;justify-content:center;gap:28px;flex-wrap:wrap;">
      <span style="font-size:0.78rem;color:var(--muted);display:flex;align-items:center;gap:6px;"><span style="width:5px;height:5px;background:var(--green);border-radius:50%;display:inline-block;"></span>VirusTotal</span>
      <span style="font-size:0.78rem;color:var(--muted);display:flex;align-items:center;gap:6px;"><span style="width:5px;height:5px;background:var(--green);border-radius:50%;display:inline-block;"></span>AbuseIPDB</span>
      <span style="font-size:0.78rem;color:var(--muted);display:flex;align-items:center;gap:6px;"><span style="width:5px;height:5px;background:var(--green);border-radius:50%;display:inline-block;"></span>Google Safe Browsing</span>
      <span style="font-size:0.78rem;color:var(--muted);display:flex;align-items:center;gap:6px;"><span style="width:5px;height:5px;background:var(--green);border-radius:50%;display:inline-block;"></span>URLScan.io</span>
      <span style="font-size:0.78rem;color:var(--muted);display:flex;align-items:center;gap:6px;"><span style="width:5px;height:5px;background:var(--green);border-radius:50%;display:inline-block;"></span>AI Narrative</span>
    </div>
  </div>

  <div style="margin-top:14px;font-size:0.78rem;color:var(--muted);">
    No account needed. <a href="/register" onclick="navigate('/register');return false;" style="color:var(--blue);">Sign in</a> to save scan history.
  </div>

</div>`;

  window._activeTab = 'unified';
  window._emlFile = null;
}
function switchTab(tab) {
  document.querySelectorAll('.scan-tab').forEach(t => {
    t.style.color = 'var(--muted)';
    t.style.fontWeight = '400';
  });
  const active = document.querySelector(`[data-tab="${tab}"]`);
  if (active) { active.style.color = 'var(--text)'; active.style.fontWeight = '500'; }

  ['unified', 'email', 'url'].forEach(t => {
    const el = document.getElementById(`tab-${t}`);
    if (el) el.style.display = t === tab ? 'block' : 'none';
  });
  window._activeTab = tab;
}

function handleEmlDrop(event) {
  event.preventDefault();
  const dropzone = document.getElementById('eml-dropzone');
  dropzone.style.borderColor = 'var(--border)';
  dropzone.style.background = 'var(--bg)';
  const file = event.dataTransfer.files[0];
  if (!file) return;
  if (!file.name.endsWith('.eml')) { toast('Only .eml files are accepted', 'error'); return; }
  setEmlFile(file);
}

function handleEmlSelect(event) {
  const file = event.target.files[0];
  if (!file) return;
  setEmlFile(file);
}

function setEmlFile(file) {
  window._emlFile = file;
  const dropzone = document.getElementById('eml-dropzone');
  const selected = document.getElementById('eml-selected');
  if (dropzone) dropzone.style.display = 'none';
  if (selected) { selected.style.display = 'flex'; }
  const nameEl = document.getElementById('emlFileName');
  const sizeEl = document.getElementById('emlFileSize');
  if (nameEl) nameEl.textContent = file.name;
  if (sizeEl) sizeEl.textContent = (file.size / 1024).toFixed(1) + ' KB';
  toast(`${file.name} ready to scan`, 'success');
}

function clearEmlFile() {
  window._emlFile = null;
  const dropzone = document.getElementById('eml-dropzone');
  const selected = document.getElementById('eml-selected');
  if (dropzone) dropzone.style.display = 'block';
  if (selected) selected.style.display = 'none';
  const input = document.getElementById('emlFileInput');
  if (input) input.value = '';
}

async function runUnifiedScan() {
  const rawEmail = document.getElementById('unifiedEmail')?.value.trim() || null;
  const rawUrls = document.getElementById('unifiedUrls')?.value.trim();
  const urls = rawUrls ? rawUrls.split('\n').map(u => u.trim()).filter(Boolean) : [];

  if (!window._emlFile && !rawEmail && !urls.length) {
    toast('Upload a .eml file, paste email content, or enter URLs to analyze', 'error');
    return;
  }

  showLoadingOverlay();

  try {
    let data;

    if (window._emlFile) {
      const formData = new FormData();
      formData.append('file', window._emlFile);
      const headers = {};
      if (state.token) headers['Authorization'] = `Bearer ${state.token}`;
      const res = await fetch('/scan/upload-eml', { method: 'POST', headers, body: formData });
      if (!res.ok) { hideLoadingOverlay(); toast('Scan failed', 'error'); return; }
      data = await res.json();
    } else {
      const res = await apiFetch('/scan/unified', {
        method: 'POST',
        body: JSON.stringify({ raw_email: rawEmail, urls })
      });
      if (!res || !res.ok) { hideLoadingOverlay(); toast('Scan failed', 'error'); return; }
      data = await res.json();
    }

    hideLoadingOverlay();
    window._lastScanResult = data;
    navigate(`/results/${data.scan_id || 'latest'}`);
  } catch (e) {
    hideLoadingOverlay();
    toast('Network error during scan', 'error');
  }
}
async function runEmailScan() {
  const raw = document.getElementById('emailInput')?.value.trim();
  if (!raw) { toast('Paste an email to analyze', 'error'); return; }
  showLoadingOverlay();
  try {
    const res = await apiFetch('/scan/email', { method: 'POST', body: JSON.stringify({ raw_email: raw }) });
    hideLoadingOverlay();
    if (!res || !res.ok) { toast('Email scan failed', 'error'); return; }
    const data = await res.json();
    window._lastScanResult = data;
    navigate(`/results/${data.scan_id || 'latest'}`);
  } catch (e) {
    hideLoadingOverlay();
    toast('Network error', 'error');
  }
}

async function runUrlScan() {
  const url = document.getElementById('urlInput')?.value.trim();
  if (!url) { toast('Enter a URL to analyze', 'error'); return; }
  showLoadingOverlay();
  try {
    const res = await apiFetch('/scan/url', { method: 'POST', body: JSON.stringify({ url }) });
    hideLoadingOverlay();
    if (!res || !res.ok) { toast('URL scan failed', 'error'); return; }
    const data = await res.json();
    window._lastScanResult = data;
    navigate(`/results/${data.scan_id || 'latest'}`);
  } catch (e) {
    hideLoadingOverlay();
    toast('Network error', 'error');
  }
}

async function renderResults(scanId) {
  const app = document.getElementById('app');
  app.innerHTML = renderNav();

  let data = window._lastScanResult;
  if (!data && scanId !== 'latest' && state.token) {
    const res = await apiFetch(`/history/${scanId}`);
    if (res && res.ok) {
      const raw = await res.json();
      data = {
        scan_id: raw.id,
        scan_type: raw.scan_type,
        risk_score: raw.risk_score,
        verdict: raw.verdict,
        narrative: raw.narrative,
        iocs: JSON.parse(raw.iocs || '[]'),
        details: JSON.parse(raw.raw_results || '{}')
      };
    }
  }

  if (!data) {
    app.innerHTML += `<div class="page" style="text-align:center;padding-top:80px;">
      <div style="color:var(--muted);margin-bottom:16px;">Result not found.</div>
      <button class="btn btn-secondary btn-sm" onclick="navigate('/scan')">New Scan</button>
    </div>`;
    return;
  }

  const verdictColor = getVerdictColor(data.verdict);
  const scoreWidth = Math.min(100, data.risk_score || 0);
  const iocs = data.iocs || [];
  const details = data.details || {};

  app.innerHTML += `
<div class="page fade-in">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:28px;flex-wrap:wrap;gap:12px;">
    <div>
      <div class="label" style="margin-bottom:6px;">Analysis Complete</div>
      <h1 style="font-size:1.6rem;font-weight:700;">Threat Report</h1>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;">
      <button class="btn btn-secondary btn-sm" onclick="navigate('/scan')">New Scan</button>
      ${state.user && data.scan_id ? `
        <button class="btn btn-secondary btn-sm" onclick="exportReport(${data.scan_id},'json')">Export JSON</button>
        <button class="btn btn-secondary btn-sm" onclick="exportReport(${data.scan_id},'pdf')">Export PDF</button>
        <button class="btn btn-secondary btn-sm" onclick="exportReport(${data.scan_id},'html')">Export HTML</button>
      ` : ''}
    </div>
  </div>

  <div class="grid-2" style="margin-bottom:16px;">
    <div class="card" style="padding:28px;">
      <div style="font-size:0.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:0.1em;margin-bottom:12px;">Risk Score</div>
      <div style="font-size:3.5rem;font-weight:700;color:${verdictColor};line-height:1;margin-bottom:14px;">${data.risk_score ?? 0}</div>
      <div class="score-bar" style="margin-bottom:14px;"><div class="score-bar-fill" style="width:${scoreWidth}%"></div></div>
      <span class="badge badge-${(data.verdict || 'unknown').toLowerCase()}" style="font-size:0.85rem;padding:5px 16px;">${data.verdict || 'Unknown'}</span>
    </div>
    <div class="card" style="padding:28px;">
      <div style="font-size:0.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:0.1em;margin-bottom:12px;">Analyst Narrative</div>
      <p style="line-height:1.8;color:var(--text);font-size:0.9rem;">${data.narrative || 'No narrative available.'}</p>
    </div>
  </div>

  ${iocs.length ? `
  <div class="card" style="padding:24px;margin-bottom:16px;">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
      <div class="label">Indicators of Compromise</div>
      <span class="tag">${iocs.length} extracted</span>
    </div>
    <div style="max-height:320px;overflow-y:auto;display:flex;flex-direction:column;gap:6px;">
      ${iocs.map(ioc => `
        <div class="ioc-row">
          <span class="tag" style="min-width:64px;text-align:center;">${ioc.type || 'ioc'}</span>
          <span class="ioc-value">${ioc.value || ''}</span>
          <button class="copy-btn" title="Copy" onclick="copyToClipboard('${(ioc.value || '').replace(/'/g, "\\'")}')">⧉</button>
        </div>`).join('')}
    </div>
  </div>` : ''}

  ${renderIntelScores(data.intel_scores || {})}
  ${renderDetailsSection(details, data.scan_type)}

  <div style="margin-top:28px;text-align:center;">
    <button class="btn btn-primary btn-lg" onclick="navigate('/scan')">Run Another Scan</button>
  </div>
</div>`;
}
function renderIntelScores(intel) {
  if (!intel || !Object.keys(intel).length) return '';

  const vt = intel.virustotal;
  const gsb = intel.google_safe_browsing;
  const abuse = intel.abuseipdb;

  let cards = '';

  if (vt && !vt.error) {
    const rate = vt.detection_rate ?? 0;
    const color = rate === 0 ? 'var(--green)' : rate < 20 ? 'var(--yellow)' : 'var(--red)';
    cards += `
    <div style="background:var(--bg);border:1px solid var(--surface2);border-radius:10px;padding:18px 20px;">
      <div style="font-size:0.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:0.1em;margin-bottom:10px;">VirusTotal</div>
      <div style="font-size:1.8rem;font-weight:700;color:${color};line-height:1;margin-bottom:6px;">${rate}%</div>
      <div style="font-size:0.75rem;color:var(--muted);">detection rate</div>
      <div style="margin-top:10px;display:flex;gap:10px;flex-wrap:wrap;">
        <span style="font-size:0.75rem;color:var(--red);">🔴 ${vt.malicious} malicious</span>
        <span style="font-size:0.75rem;color:var(--yellow);">🟡 ${vt.suspicious} suspicious</span>
        <span style="font-size:0.75rem;color:var(--green);">🟢 ${vt.harmless} harmless</span>
      </div>
    </div>`;
  }

  if (gsb) {
    const threats = gsb.threats_found ?? 0;
    const color = threats === 0 ? 'var(--green)' : 'var(--red)';
    cards += `
    <div style="background:var(--bg);border:1px solid var(--surface2);border-radius:10px;padding:18px 20px;">
      <div style="font-size:0.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:0.1em;margin-bottom:10px;">Google Safe Browsing</div>
      <div style="font-size:1.8rem;font-weight:700;color:${color};line-height:1;margin-bottom:6px;">${threats}</div>
      <div style="font-size:0.75rem;color:var(--muted);">threats found</div>
      ${gsb.threat_types && gsb.threat_types.length ? `<div style="margin-top:10px;font-size:0.75rem;color:var(--red);">${gsb.threat_types.join(', ')}</div>` : `<div style="margin-top:10px;font-size:0.75rem;color:var(--green);">No threats detected</div>`}
    </div>`;
  }

  if (abuse && Array.isArray(abuse) && abuse.length) {
    const maxScore = Math.max(...abuse.map(a => a.abuse_score || 0));
    const color = maxScore === 0 ? 'var(--green)' : maxScore < 50 ? 'var(--yellow)' : 'var(--red)';
    cards += `
    <div style="background:var(--bg);border:1px solid var(--surface2);border-radius:10px;padding:18px 20px;">
      <div style="font-size:0.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:0.1em;margin-bottom:10px;">AbuseIPDB</div>
      <div style="font-size:1.8rem;font-weight:700;color:${color};line-height:1;margin-bottom:6px;">${maxScore}</div>
      <div style="font-size:0.75rem;color:var(--muted);">max abuse score / 100</div>
      <div style="margin-top:10px;display:flex;flex-direction:column;gap:4px;">
        ${abuse.slice(0, 3).map(a => `
          <div style="display:flex;justify-content:space-between;font-size:0.73rem;">
            <span class="mono" style="color:var(--muted);">${a.ip || ''}</span>
            <span style="color:${(a.abuse_score || 0) > 50 ? 'var(--red)' : 'var(--muted)'};">Score: ${a.abuse_score ?? 0}</span>
          </div>`).join('')}
      </div>
    </div>`;
  }

  if (!cards) return '';

  return `
  <div class="card" style="padding:24px;margin-bottom:16px;">
    <div class="label" style="margin-bottom:16px;">Threat Intelligence Scores</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;">
      ${cards}
    </div>
  </div>`;
}

function renderDetailsSection(details, scanType) {
  const email = details.email;
  const urlAnalysis = details.url_analysis;
  const pulse = details.threat_pulse || [];
  let html = '';

  if (email) {
    const spf = email.spf || {};
    const dkim = email.dkim || {};
    const dmarc = email.dmarc || {};
    const mismatch = email.domain_mismatch || {};
    html += `
    <div class="card" style="padding:24px;margin-bottom:16px;">
      <div class="label" style="margin-bottom:16px;">Email Header Analysis</div>
      <div class="grid-3" style="margin-bottom:16px;">
        <div style="text-align:center;padding:16px;background:var(--bg);border-radius:var(--radius-sm);">
          <div style="font-size:0.7rem;color:var(--muted);text-transform:uppercase;margin-bottom:6px;">SPF</div>
          <div style="font-weight:600;color:${spf.pass ? 'var(--green)' : 'var(--red)'};">${spf.pass ? 'Pass' : 'Fail'}</div>
        </div>
        <div style="text-align:center;padding:16px;background:var(--bg);border-radius:var(--radius-sm);">
          <div style="font-size:0.7rem;color:var(--muted);text-transform:uppercase;margin-bottom:6px;">DKIM</div>
          <div style="font-weight:600;color:${dkim.pass ? 'var(--green)' : 'var(--red)'};">${dkim.pass ? 'Pass' : 'Fail'}</div>
        </div>
        <div style="text-align:center;padding:16px;background:var(--bg);border-radius:var(--radius-sm);">
          <div style="font-size:0.7rem;color:var(--muted);text-transform:uppercase;margin-bottom:6px;">DMARC</div>
          <div style="font-weight:600;color:${dmarc.pass ? 'var(--green)' : 'var(--red)'};">${dmarc.pass ? 'Pass' : 'Fail'}</div>
        </div>
      </div>
      ${mismatch.mismatch ? `<div style="padding:10px 14px;background:var(--red-bg);border:1px solid var(--red-border);border-radius:var(--radius-sm);font-size:0.85rem;color:var(--red);">Domain mismatch: From <strong>${mismatch.from_domain}</strong> vs Reply-To <strong>${mismatch.reply_to_domain}</strong></div>` : ''}
    </div>`;
  }

  if (urlAnalysis) {
    const typo = urlAnalysis.typosquatting || {};
    const redirects = urlAnalysis.redirects || {};
    html += `
    <div class="card" style="padding:24px;margin-bottom:16px;">
      <div class="label" style="margin-bottom:16px;">URL Analysis</div>
      <div class="grid-2" style="gap:16px;">
        <div><div style="font-size:0.8rem;color:var(--muted);margin-bottom:6px;">Domain</div><div class="mono" style="font-size:0.9rem;">${urlAnalysis.domain || 'N/A'}</div></div>
        <div><div style="font-size:0.8rem;color:var(--muted);margin-bottom:6px;">Scheme</div><div class="mono" style="font-size:0.9rem;color:${urlAnalysis.scheme === 'https' ? 'var(--green)' : 'var(--red)'};">${urlAnalysis.scheme || 'N/A'}</div></div>
        <div><div style="font-size:0.8rem;color:var(--muted);margin-bottom:6px;">Typosquatting</div><div style="font-size:0.875rem;color:${typo.detected ? 'var(--red)' : 'var(--green)'};">${typo.detected ? (typo.findings || []).join(', ') : 'None detected'}</div></div>
        <div><div style="font-size:0.8rem;color:var(--muted);margin-bottom:6px;">Redirects</div><div style="font-size:0.875rem;">${redirects.redirect_count || 0} hop(s)</div></div>
      </div>
      ${urlAnalysis.suspicious_tld ? `<div style="margin-top:14px;padding:10px 14px;background:var(--yellow-bg);border:1px solid var(--yellow-border);border-radius:var(--radius-sm);font-size:0.85rem;color:var(--yellow);">Suspicious TLD detected</div>` : ''}
    </div>`;
  }

  if (pulse.length) {
    html += `
    <div class="card" style="padding:24px;margin-bottom:16px;">
      <div class="label" style="margin-bottom:16px;">Live Threat Pulse</div>
      ${pulse.slice(0, 8).map(p => `
        <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--surface2);">
          <div style="display:flex;align-items:center;gap:10px;">
            <span class="tag">${p.type}</span>
            <span class="mono" style="font-size:0.8rem;">${p.value}</span>
          </div>
          <span style="font-size:0.78rem;color:${p.pulse && p.pulse.is_novel ? 'var(--yellow)' : 'var(--muted)'};">${p.pulse ? p.pulse.label : ''}</span>
        </div>`).join('')}
    </div>`;
  }

  return html;
}

async function exportReport(scanId, format) {
  toast(`Generating ${format.toUpperCase()}...`, 'info');
  try {
    const res = await apiFetch(`/export/${scanId}/${format}`);
    if (!res || !res.ok) { toast('Export failed', 'error'); return; }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishsniffer-${scanId}.${format}`;
    a.click();
    URL.revokeObjectURL(url);
    toast('Downloaded', 'success');
  } catch { toast('Export failed', 'error'); }
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => toast('Copied', 'success'));
}