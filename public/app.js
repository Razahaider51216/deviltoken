// DEVILTOKEN — frontend logic
// Handles login flow, MFA, token display, timeout countdown

/* ─── STATE ─── */
const S = {
  token: null,
  mfaTicket: null,
  mfaMode: 'totp',
  timeoutSec: 300,
  timeoutHandle: null,
};

/* ─── LOGIN ─── */
async function doLogin() {
  const email = document.getElementById('email')?.value.trim();
  const password = document.getElementById('password')?.value.trim();
  const errEl = document.getElementById('err-msg');
  const btn = document.getElementById('btn-login');

  if (!email || !password) {
    showErr(errEl, '// กรุณากรอก Email และ Password');
    return;
  }

  btn.classList.add('loading');
  btn.disabled = true;
  btn.textContent = '// กำลังดึงข้อมูล...';
  hideErr(errEl);

  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();

    if (data.success && data.token) {
      sessionStorage.setItem('dt_token', data.token);
      window.location.href = '/dashboard.html';
      return;
    }

    if (data.success && data.mfa) {
      sessionStorage.setItem('dt_ticket', data.ticket);
      window.location.href = '/mfa.html';
      return;
    }

    showErr(errEl, `// ${data.error || 'Login failed'}`);
  } catch (e) {
    showErr(errEl, '// Server error — ตรวจสอบการเชื่อมต่อ');
  } finally {
    btn.classList.remove('loading');
    btn.disabled = false;
    btn.textContent = '▶ EXTRACT TOKEN';
  }
}

/* ─── MFA ─── */
function switchTab(mode) {
  S.mfaMode = mode;
  document.getElementById('tab-totp').classList.toggle('active', mode === 'totp');
  document.getElementById('tab-backup').classList.toggle('active', mode === 'backup');
  document.getElementById('totp-section').classList.toggle('hidden', mode !== 'totp');
  document.getElementById('backup-section').classList.toggle('hidden', mode !== 'backup');
}

async function doMFA() {
  const ticket = sessionStorage.getItem('dt_ticket');
  const errEl = document.getElementById('mfa-err');
  const btn = document.getElementById('btn-mfa');

  if (!ticket) {
    showErr(errEl, '// Session หมดอายุ — กลับไปล็อกอินใหม่');
    return;
  }

  let code = '';
  let endpoint = '';

  if (S.mfaMode === 'totp') {
    code = document.getElementById('totp-code')?.value.trim();
    endpoint = '/api/mfa/totp';
  } else {
    code = document.getElementById('backup-code')?.value.trim();
    endpoint = '/api/mfa/backup';
  }

  if (!code) {
    showErr(errEl, '// กรุณากรอกรหัส');
    return;
  }

  btn.classList.add('loading');
  btn.disabled = true;
  btn.textContent = '// กำลังยืนยัน...';
  hideErr(errEl);

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ticket, code }),
    });
    const data = await res.json();

    if (data.success && data.token) {
      sessionStorage.setItem('dt_token', data.token);
      sessionStorage.removeItem('dt_ticket');
      window.location.href = '/dashboard.html';
      return;
    }

    showErr(errEl, `// ${data.error || 'MFA failed'}`);
  } catch (e) {
    showErr(errEl, '// Server error');
  } finally {
    btn.classList.remove('loading');
    btn.disabled = false;
    btn.textContent = '▶ VERIFY & EXTRACT';
  }
}

/* ─── DASHBOARD ─── */
async function initDashboard() {
  const token = sessionStorage.getItem('dt_token');
  if (!token) {
    window.location.href = '/login.html';
    return;
  }

  S.token = token;

  // Show token immediately
  const tvEl = document.getElementById('token-value');
  if (tvEl) tvEl.textContent = token;

  // Start timeout
  startTimeout();

  // Fetch user info
  await reloadInfo();

  // Status time
  setInterval(() => {
    const el = document.getElementById('st-time');
    if (el) el.textContent = new Date().toLocaleTimeString('th-TH');
  }, 1000);
}

async function reloadInfo() {
  const token = S.token || sessionStorage.getItem('dt_token');
  if (!token) return;

  try {
    const res = await fetch('/api/userinfo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    const data = await res.json();

    if (!data.success) return;
    renderUser(data.data);
  } catch (e) {
    console.error('userinfo fetch failed:', e);
  }
}

function renderUser(u) {
  // Avatar
  const imgEl = document.getElementById('u-avatar');
  const fbEl = document.getElementById('u-avatar-fb');
  if (u.avatar) {
    imgEl.src = u.avatar;
    imgEl.style.display = 'block';
    if (fbEl) fbEl.style.display = 'none';
  } else {
    if (imgEl) imgEl.style.display = 'none';
    if (fbEl) fbEl.textContent = (u.username || '?')[0].toUpperCase();
  }

  // Name
  const disc = u.discriminator && u.discriminator !== '0' ? `#${u.discriminator}` : '';
  setText('u-name', `${u.username || '—'}${disc}`);
  setText('u-tag', u.id ? `ID: ${u.id}` : '—');

  // Badges
  const badgesEl = document.getElementById('u-badges');
  if (badgesEl) {
    badgesEl.innerHTML = '';
    if (u.nitro !== 'None') {
      const b = document.createElement('span');
      b.className = 'badge nitro';
      b.textContent = u.nitro;
      badgesEl.appendChild(b);
    }
    (u.flags || []).forEach(f => {
      const b = document.createElement('span');
      b.className = 'badge';
      b.textContent = f;
      badgesEl.appendChild(b);
    });
  }

  // Info cells
  setText('i-id', u.id || '—');
  setText('i-email', u.email || '—');
  setText('i-phone', u.phone || 'ไม่มี');
  setTextColored('i-verified', u.verified ? 'YES' : 'NO', u.verified ? 'green' : 'red');
  setTextColored('i-mfa', u.mfa_enabled ? 'YES' : 'NO', u.mfa_enabled ? 'green' : 'dim');
  setTextColored('i-nitro', u.nitro || 'None', u.nitro !== 'None' ? 'green' : 'dim');
  setText('i-guilds', u.guilds_count?.toString() || '—');
  setText('i-owned', u.guilds_owned?.toString() || '—');
  setText('i-locale', u.locale || '—');
  setText('i-created', u.created_at ? new Date(u.created_at).toLocaleDateString('th-TH', { year:'numeric',month:'long',day:'numeric' }) : '—');
  setText('i-flags', (u.flags?.join(', ')) || 'None');
  setText('i-nitro-exp', u.nitro_expires ? new Date(u.nitro_expires).toLocaleDateString('th-TH') : '—');
}

/* ─── COPY ─── */
async function copyToken() {
  const token = S.token || sessionStorage.getItem('dt_token');
  if (!token) return;
  try {
    await navigator.clipboard.writeText(token);
    const btn = document.getElementById('btn-copy');
    if (btn) {
      btn.textContent = '✓ COPIED';
      btn.classList.add('copied');
      setTimeout(() => {
        btn.textContent = '⧉ COPY TOKEN';
        btn.classList.remove('copied');
      }, 2000);
    }
  } catch (e) {
    // fallback
    const ta = document.createElement('textarea');
    ta.value = token;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  }
}

/* ─── TIMEOUT ─── */
function startTimeout() {
  S.timeoutSec = 300;
  const el = document.getElementById('timeout-timer');
  if (!el) return;

  S.timeoutHandle = setInterval(() => {
    S.timeoutSec--;
    const m = Math.floor(S.timeoutSec / 60).toString().padStart(2, '0');
    const s = (S.timeoutSec % 60).toString().padStart(2, '0');
    el.textContent = `${m}:${s}`;

    el.className = 'timeout-timer';
    if (S.timeoutSec <= 60) el.classList.add('warning');
    if (S.timeoutSec <= 15) el.classList.add('critical');

    if (S.timeoutSec <= 0) {
      clearInterval(S.timeoutHandle);
      sessionStorage.clear();
      window.location.href = '/index.html';
    }
  }, 1000);

  // Reset on activity
  ['mousemove','keydown','click'].forEach(ev => {
    document.addEventListener(ev, () => { S.timeoutSec = 300; });
  });
}

/* ─── UTILS ─── */
function showErr(el, msg) {
  if (!el) return;
  el.textContent = msg;
  el.classList.add('visible');
}

function hideErr(el) {
  if (!el) return;
  el.classList.remove('visible');
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function setTextColored(id, val, color) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = val;
  el.className = `info-val ${color}`;
}

/* ─── ROUTER INIT ─── */
const page = window.location.pathname;

if (page.includes('dashboard')) {
  window.addEventListener('DOMContentLoaded', initDashboard);
}

if (page.includes('mfa')) {
  window.addEventListener('DOMContentLoaded', () => {
    const ticket = sessionStorage.getItem('dt_ticket');
    if (!ticket) window.location.href = '/login.html';
  });
}