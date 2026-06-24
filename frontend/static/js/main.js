const state = { user: null, token: sessionStorage.getItem('token') || null };

async function apiFetch(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...options.headers };
  if (state.token) headers['Authorization'] = `Bearer ${state.token}`;
  const res = await fetch(path, { ...options, headers });
  if (res.status === 401) { logout(); return null; }
  return res;
}

function toast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

function logout() {
  state.token = null;
  state.user = null;
  sessionStorage.removeItem('token');
  navigate('/');
}

async function loadUser() {
  if (!state.token) return;
  try {
    const res = await fetch('routers/auth/me', {
      headers: { 'Authorization': `Bearer ${state.token}`, 'Content-Type': 'application/json' }
    });
    if (res.ok) {
      state.user = await res.json();
    } else {
      state.token = null;
      sessionStorage.removeItem('token');
    }
  } catch {
    state.token = null;
  }
}

function navigate(path) {
  history.pushState({}, '', path);
  render();
}

function getVerdictColor(verdict) {
  const map = { Clear: 'var(--blue)', Suspicious: 'var(--yellow)', Malicious: 'var(--red)', Unknown: 'var(--gray)' };
  return map[verdict] || 'var(--gray)';
}

function renderNav() {
  return `
<nav style="background:var(--surface);border-bottom:1px solid var(--surface2);position:sticky;top:0;z-index:100;">
  <div style="width:100%;padding:0 24px;height:56px;display:flex;align-items:center;justify-content:space-between;">
    <a href="/" onclick="navigate('/');return false;" style="display:flex;align-items:center;gap:6px;text-decoration:none;">
      <img src="/static/img/logo.png" alt="PhishSniffer" style="height:1.4rem;width:auto;">
      <span style="font-weight:700;color:var(--blue);letter-spacing:-0.02em;font-size:1rem;">PhishSniffer</span>
      <span class="tag" style="font-size:0.65rem;">v2.0</span>
    </a>
    <div style="display:flex;align-items:center;gap:8px;">
      ${state.user ? `
        <a href="/dashboard" onclick="navigate('/dashboard');return false;" class="btn btn-sm btn-secondary">Dashboard</a>
        <a href="/history" onclick="navigate('/history');return false;" class="btn btn-sm btn-secondary">History</a>
        <div style="display:flex;align-items:center;gap:8px;padding:4px 12px;background:var(--surface2);border-radius:999px;border:1px solid var(--border);">
          <div style="width:24px;height:24px;background:var(--blue);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:0.7rem;font-weight:700;color:#fff;">${state.user.username.charAt(0).toUpperCase()}</div>
          <span style="font-size:0.82rem;color:var(--text);font-weight:500;">${state.user.username}</span>
        </div>
        <button class="btn btn-sm btn-secondary" onclick="logout()">Sign out</button>
      ` : `
        <a href="/login" onclick="navigate('/login');return false;" class="btn btn-sm btn-secondary">Sign in</a>
        <a href="/register" onclick="navigate('/register');return false;" class="btn btn-sm btn-primary">Register</a>
      `}
    </div>
  </div>
</nav>`;
}

async function render() {
  const path = window.location.pathname;
  const app = document.getElementById('app');
  app.innerHTML = renderNav();

  if (path.startsWith('/results/')) {
    await renderResults(path.split('/results/')[1]);
    return;
  }

  const routes = {
    '/': renderHome,
    '/scan': renderScan,
    '/login': renderLogin,
    '/register': renderRegister,
    '/history': renderHistory,
    '/dashboard': renderDashboard,
  };

  const handler = routes[path] || renderHome;
  await handler();
}

window.addEventListener('popstate', render);

(async () => {
  await loadUser();
  await render();
})();

function renderLogin() {
  const app = document.getElementById('app');
  app.innerHTML += `
<div style="max-width:420px;margin:80px auto;padding:0 24px;">
  <div class="card" style="padding:36px;">
    <div class="label" style="margin-bottom:8px;">Welcome back</div>
    <h1 style="font-size:1.5rem;font-weight:700;margin-bottom:28px;">Sign in</h1>
    <div style="margin-bottom:16px;">
      <div style="font-size:0.8rem;color:var(--muted);margin-bottom:6px;">Username</div>
      <input class="input" id="loginUser" type="text" placeholder="your_username" autocomplete="username">
    </div>
    <div style="margin-bottom:8px;">
      <div style="font-size:0.8rem;color:var(--muted);margin-bottom:6px;">Password</div>
      <input class="input" id="loginPass" type="password" placeholder="Password" autocomplete="current-password" onkeydown="if(event.key==='Enter')doLogin()">
    </div>
    <div id="loginError" style="min-height:24px;margin-bottom:12px;font-size:0.82rem;color:var(--red);"></div>
    <button class="btn btn-primary" style="width:100%;" id="loginBtn" onclick="doLogin()">Sign in</button>
    <div style="text-align:center;margin-top:20px;font-size:0.85rem;color:var(--muted);">
      No account? <a href="/register" onclick="navigate('/register');return false;">Register</a>
    </div>
  </div>
</div>`;
}

async function doLogin() {
  const username = document.getElementById('loginUser')?.value.trim();
  const password = document.getElementById('loginPass')?.value;
  const errorEl = document.getElementById('loginError');
  const btn = document.getElementById('loginBtn');

  errorEl.textContent = '';
  if (!username) { errorEl.textContent = 'Enter your username'; return; }
  if (!password) { errorEl.textContent = 'Enter your password'; return; }
  if (btn.disabled) return;

  btn.disabled = true;
  btn.textContent = 'Signing in...';

  try {
    const res = await fetch('routers/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    if (!res.ok) {
      const err = await res.json();
      errorEl.textContent = err.detail || 'Login failed';
      btn.disabled = false;
      btn.textContent = 'Sign in';
      return;
    }

    const data = await res.json();
    state.token = data.access_token;
    sessionStorage.setItem('token', state.token);
    await loadUser();
    navigate('/dashboard');

  } catch {
    errorEl.textContent = 'Network error — try again';
    btn.disabled = false;
    btn.textContent = 'Sign in';
  }
}

function renderRegister() {
  const app = document.getElementById('app');
  app.innerHTML += `
<div style="max-width:420px;margin:80px auto;padding:0 24px;">
  <div class="card" style="padding:36px;">
    <div class="label" style="margin-bottom:8px;">Get started</div>
    <h1 style="font-size:1.5rem;font-weight:700;margin-bottom:28px;">Create account</h1>
    <div style="margin-bottom:16px;">
      <div style="font-size:0.8rem;color:var(--muted);margin-bottom:6px;">Username</div>
      <input class="input" id="regUser" type="text" placeholder="analyst_name">
    </div>
    <div style="margin-bottom:6px;">
      <div style="font-size:0.8rem;color:var(--muted);margin-bottom:6px;">Email</div>
      <input class="input" id="regEmail" type="email" placeholder="analyst@soc.com" onblur="validateEmailField()">
    </div>
    <div id="emailError" style="min-height:18px;margin-bottom:10px;font-size:0.8rem;color:var(--red);"></div>
    <div style="margin-bottom:8px;">
      <div style="font-size:0.8rem;color:var(--muted);margin-bottom:6px;">Password</div>
      <input class="input" id="regPass" type="password" placeholder="Min 6 characters" onkeydown="if(event.key==='Enter')doRegister()">
    </div>
    <div id="registerError" style="min-height:24px;margin-bottom:12px;font-size:0.82rem;color:var(--red);"></div>
    <button class="btn btn-primary" style="width:100%;" id="regBtn" onclick="doRegister()">Create account</button>
    <div style="text-align:center;margin-top:20px;font-size:0.85rem;color:var(--muted);">
      Already have an account? <a href="/login" onclick="navigate('/login');return false;">Sign in</a>
    </div>
  </div>
</div>`;
}

function validateEmailField() {
  const email = document.getElementById('regEmail')?.value.trim();
  const errorEl = document.getElementById('emailError');
  if (!errorEl) return;
  if (!email) { errorEl.textContent = ''; return; }
  const valid = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(email);
  errorEl.textContent = valid ? '' : 'Enter a valid email address';
}

async function doRegister() {
  const username = document.getElementById('regUser')?.value.trim();
  const email = document.getElementById('regEmail')?.value.trim();
  const password = document.getElementById('regPass')?.value;
  const errorEl = document.getElementById('registerError');
  const emailErrorEl = document.getElementById('emailError');
  const btn = document.getElementById('regBtn');

  errorEl.textContent = '';
  emailErrorEl.textContent = '';

  if (!username) { errorEl.textContent = 'Enter a username'; return; }
  if (username.length < 3) { errorEl.textContent = 'Username must be at least 3 characters'; return; }
  if (!email) { errorEl.textContent = 'Enter your email'; return; }
  if (!/^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(email)) {
    emailErrorEl.textContent = 'Enter a valid email address'; return;
  }
  if (!password) { errorEl.textContent = 'Enter a password'; return; }
  if (password.length < 6) { errorEl.textContent = 'Password must be at least 6 characters'; return; }
  if (btn.disabled) return;

  btn.disabled = true;
  btn.textContent = 'Creating account...';

  try {
    const res = await fetch('routers/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password })
    });

    if (!res.ok) {
      const err = await res.json();
      const msg = err.detail || 'Registration failed';
      if (msg.toLowerCase().includes('email')) {
        emailErrorEl.textContent = msg;
      } else {
        errorEl.textContent = msg;
      }
      btn.disabled = false;
      btn.textContent = 'Create account';
      return;
    }

    const loginRes = await fetch('routers/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    if (loginRes.ok) {
      const data = await loginRes.json();
      state.token = data.access_token;
      sessionStorage.setItem('token', state.token);
      await loadUser();
      navigate('/dashboard');
    } else {
      navigate('/login');
    }

  } catch {
    errorEl.textContent = 'Network error — try again';
    btn.disabled = false;
    btn.textContent = 'Create account';
  }
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
          <span style="font-size:0.8rem;color:var(--muted);">${s.scan_name || new Date(s.created_at).toLocaleString()}</span>
        </div>
        <span class="badge badge-${(s.verdict||'unknown').toLowerCase()}">${s.verdict || 'Unknown'}</span>
      </div>`).join('');
  } catch {
    container.innerHTML = '<div style="color:var(--muted);font-size:0.8rem;">Could not load recent scans.</div>';
  }
}
function showConfirmModal(message, onConfirm) {
  const existing = document.getElementById('confirmModal');
  if (existing) existing.remove();

  const modal = document.createElement('div');
  modal.id = 'confirmModal';
  modal.style.cssText = `
    position:fixed;inset:0;background:rgba(0,0,0,0.6);
    z-index:9999;display:flex;align-items:center;justify-content:center;
    animation:fadeIn 0.15s ease;
  `;
  modal.innerHTML = `
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:32px;max-width:380px;width:90%;box-shadow:0 24px 64px rgba(0,0,0,0.5);">
      <div style="font-size:1rem;font-weight:600;color:var(--text);margin-bottom:8px;">Sign out</div>
      <div style="font-size:0.875rem;color:var(--muted);margin-bottom:24px;line-height:1.6;">${message}</div>
      <div style="display:flex;gap:10px;justify-content:flex-end;">
        <button class="btn btn-secondary" id="confirmCancel">Cancel</button>
        <button class="btn btn-danger" id="confirmOk">Sign out</button>
      </div>
    </div>
  `;

  document.body.appendChild(modal);

  document.getElementById('confirmCancel').onclick = () => modal.remove();
  document.getElementById('confirmOk').onclick = () => { modal.remove(); onConfirm(); };
  modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
}

function logout() {
  showConfirmModal('Are you sure you want to sign out?', () => {
    state.token = null;
    state.user = null;
    sessionStorage.removeItem('token');
    navigate('/');
  });
}