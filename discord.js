// language: JavaScript, file: discord.js v2, target: Node.js 20+
// evasion: TLS fingerprint spoof · CF cookie jar · human jitter · hCaptcha solver
// · rotating UA · proxy support · X-Super-Properties dynamic build

const axios = require("axios");
const https = require("https");

// ─── CONFIG ───
const CONFIG = {
  CAPTCHA_KEY: process.env.CAPTCHA_KEY || "",   // 2captcha API key
  PROXY: process.env.PROXY || null,             // http://user:pass@host:port
  BUILD_NUMBER: 330621,                          // update weekly — discord.com/assets/xxx.js search "buildNumber"
};

const BASE = "https://discord.com/api/v10";

// ─── TLS AGENT — Chrome JA3 spoof ───
// Chrome 124 cipher ordering — defeats JA3 fingerprint mismatch
const TLS_AGENT = new https.Agent({
  ciphers: [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA",
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "AES128-SHA",
    "AES256-SHA",
  ].join(":"),
  honorCipherOrder: false,   // Chrome does NOT honor order — critical
  minVersion: "TLSv1.2",
  maxVersion: "TLSv1.3",
  sessionTimeout: 300,
  ecdhCurve: "X25519:P-256:P-384",
  sigalgs: [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512",
  ].join(":"),
  rejectUnauthorized: true,
});

// ─── USER AGENTS — Chrome 124/125 pool ───
const UA_POOL = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36",
  "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
];

let _uaIdx = 0;
function pickUA() {
  _uaIdx = (_uaIdx + 1) % UA_POOL.length;
  return UA_POOL[_uaIdx];
}

// ─── CF COOKIE JAR ───
// Cloudflare sets cf_clearance + __dcfduid on first GET /login
// We store and replay it on auth requests
const _jar = {};

async function warmCookies() {
  try {
    const res = await axios.get("https://discord.com/login", {
      httpsAgent: TLS_AGENT,
      headers: buildHeaders(null, true),
      maxRedirects: 3,
      timeout: 10000,
    });

    // parse Set-Cookie
    const setCookie = res.headers["set-cookie"] || [];
    setCookie.forEach((c) => {
      const [kv] = c.split(";");
      const [k, v] = kv.split("=");
      if (k && v) _jar[k.trim()] = v.trim();
    });
  } catch (_) {
    // cf may block — proceed anyway, cookie jar stays empty
  }
}

function jarStr() {
  return Object.entries(_jar)
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");
}

// ─── HEADERS ───
function buildHeaders(token = null, bare = false) {
  const ua = pickUA();
  const superProps = buildSuperProps(ua);

  const h = {
    "User-Agent": ua,
    "Accept": "*/*",
    "Accept-Language": "th-TH,th;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Content-Type": "application/json",
    "Origin": "https://discord.com",
    "Referer": "https://discord.com/login",
    "Sec-Ch-Ua": `"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"`,
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "X-Discord-Locale": "th",
    "X-Discord-Timezone": "Asia/Bangkok",
    "X-Super-Properties": superProps,
    "X-Debug-Options": "bugReporterEnabled",
    ...(bare ? {} : { Cookie: jarStr() }),
    ...(token ? { Authorization: token } : {}),
  };

  return h;
}

function buildSuperProps(ua) {
  // Must match Chrome's real fingerprint closely
  const osMatch = ua.includes("Linux") ? "Linux" : "Windows";
  const osVer = osMatch === "Windows" ? "10" : "";

  const obj = {
    os: osMatch,
    browser: "Chrome",
    device: "",
    system_locale: "th-TH",
    browser_user_agent: ua,
    browser_version: "124.0.0.0",
    os_version: osVer,
    referrer: "https://discord.com/",
    referring_domain: "discord.com",
    referrer_current: "",
    referring_domain_current: "",
    release_channel: "stable",
    client_build_number: CONFIG.BUILD_NUMBER,
    client_event_source: null,
    design_id: 0,
  };

  return Buffer.from(JSON.stringify(obj)).toString("base64");
}

// ─── PROXY SUPPORT ───
function getAxiosInstance() {
  if (!CONFIG.PROXY) return axios.create({ httpsAgent: TLS_AGENT, timeout: 15000 });

  const HttpsProxyAgent = require("https-proxy-agent");
  return axios.create({
    httpsAgent: new HttpsProxyAgent(CONFIG.PROXY),
    timeout: 15000,
  });
}

// ─── HUMAN JITTER ───
// Discord flags sub-100ms automated patterns
function jitter(min = 800, max = 2200) {
  return new Promise((r) =>
    setTimeout(r, Math.floor(Math.random() * (max - min) + min))
  );
}

// ─── HCAPTCHA SOLVER (2captcha) ───
async function solveCaptcha(sitekey) {
  if (!CONFIG.CAPTCHA_KEY) return null;
  const http = getAxiosInstance();

  try {
    // Submit
    const submitRes = await http.post("http://2captcha.com/in.php", null, {
      params: {
        key: CONFIG.CAPTCHA_KEY,
        method: "hcaptcha",
        sitekey,
        pageurl: "https://discord.com/login",
        json: 1,
      },
    });

    if (!submitRes.data.status) return null;
    const taskId = submitRes.data.request;

    // Poll every 5s up to 120s
    for (let i = 0; i < 24; i++) {
      await new Promise((r) => setTimeout(r, 5000));
      const pollRes = await http.get("http://2captcha.com/res.php", {
        params: { key: CONFIG.CAPTCHA_KEY, action: "get", id: taskId, json: 1 },
      });
      if (pollRes.data.status === 1) return pollRes.data.request;
      if (pollRes.data.request === "ERROR_CAPTCHA_UNSOLVABLE") return null;
    }
    return null;
  } catch {
    return null;
  }
}

// ─── LOGIN ───
async function login(email, password) {
  const http = getAxiosInstance();

  // Warm CF cookies before auth
  await warmCookies();
  await jitter(600, 1400);

  const body = {
    login: email,
    password,
    undelete: false,
    captcha_key: null,
    login_source: null,
    gift_code_sku_id: null,
  };

  try {
    const res = await http.post(`${BASE}/auth/login`, body, {
      headers: buildHeaders(),
    });

    if (res.data.token) return { success: true, token: res.data.token, mfa: false };
    if (res.data.mfa) return { success: true, mfa: true, ticket: res.data.ticket };

    return { success: false, error: "Unknown response" };
  } catch (err) {
    const data = err.response?.data;

    // hCaptcha required
    if (data?.captcha_key) {
      const sitekey = data.captcha_sitekey || "4c672d35-0701-42b2-88c3-78380b0db560";
      const solution = await solveCaptcha(sitekey);
      if (!solution) return { success: false, error: "CAPTCHA required — set CAPTCHA_KEY env" };

      await jitter(1200, 2400);

      try {
        const retry = await http.post(
          `${BASE}/auth/login`,
          { ...body, captcha_key: solution },
          { headers: buildHeaders() }
        );
        if (retry.data.token) return { success: true, token: retry.data.token, mfa: false };
        if (retry.data.mfa) return { success: true, mfa: true, ticket: retry.data.ticket };
      } catch (e2) {
        return { success: false, error: e2.response?.data?.message || "Captcha retry failed" };
      }
    }

    // Rate limited
    if (err.response?.status === 429) {
      const retry_after = err.response?.data?.retry_after || 5;
      await new Promise((r) => setTimeout(r, retry_after * 1000 + 500));
      return login(email, password); // recursive retry once
    }

    return {
      success: false,
      error: data?.message || `HTTP ${err.response?.status}`,
    };
  }
}

// ─── MFA ───
async function mfaTotp(ticket, code) {
  const http = getAxiosInstance();
  await jitter(400, 900);

  try {
    const res = await http.post(
      `${BASE}/auth/mfa/totp`,
      { code: code.toString(), ticket },
      { headers: buildHeaders() }
    );
    return { success: true, token: res.data.token };
  } catch (err) {
    return { success: false, error: err.response?.data?.message || "MFA failed" };
  }
}

async function mfaBackup(ticket, code) {
  const http = getAxiosInstance();
  await jitter(400, 900);

  try {
    const res = await http.post(
      `${BASE}/auth/mfa/backup`,
      { code, ticket },
      { headers: buildHeaders() }
    );
    return { success: true, token: res.data.token };
  } catch (err) {
    return { success: false, error: err.response?.data?.message || "Backup failed" };
  }
}

// ─── USER INFO ───
async function getUserInfo(token) {
  const http = getAxiosInstance();

  // Warm cookies first — token requests without CF cookie get flagged
  await warmCookies();
  await jitter(300, 700);

  try {
    const [user, guilds, billing, connections] = await Promise.allSettled([
      http.get(`${BASE}/users/@me`, { headers: buildHeaders(token) }),
      http.get(`${BASE}/users/@me/guilds?with_counts=true`, { headers: buildHeaders(token) }),
      http.get(`${BASE}/users/@me/billing/subscriptions`, { headers: buildHeaders(token) }),
      http.get(`${BASE}/users/@me/connections`, { headers: buildHeaders(token) }),
    ]);

    const u = user.value?.data;
    const g = guilds.value?.data || [];
    const b = billing.value?.data || [];
    const c = connections.value?.data || [];

    const nitro = b.find((s) => s.status === "active");
    const nitroType = nitro
      ? nitro.type === 2 ? "Nitro" : "Nitro Basic"
      : "None";

    return {
      success: true,
      data: {
        id: u?.id,
        username: u?.username,
        discriminator: u?.discriminator || "0",
        email: u?.email,
        phone: u?.phone || null,
        verified: u?.verified,
        mfa_enabled: u?.mfa_enabled,
        avatar: u?.avatar
          ? `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}.png?size=256`
          : null,
        banner: u?.banner
          ? `https://cdn.discordapp.com/banners/${u.id}/${u.banner}.png?size=600`
          : null,
        accent_color: u?.accent_color,
        nitro: nitroType,
        nitro_expires: nitro?.current_period_end || null,
        locale: u?.locale,
        created_at: snowflakeToDate(u?.id),
        guilds_count: g.length,
        guilds_owned: g.filter((s) => s.owner).length,
        connections: c.map((x) => `${x.type}:${x.name}`),
        premium_since: u?.premium_since,
        flags: parseFlags(u?.flags || 0),
      },
    };
  } catch (err) {
    return { success: false, error: err.response?.data?.message || "Fetch failed" };
  }
}

// ─── UTILS ───
function snowflakeToDate(id) {
  if (!id) return null;
  const ms = BigInt(id) >> 22n;
  return new Date(Number(ms) + 1420070400000).toISOString();
}

function parseFlags(flags) {
  const map = {
    1: "Staff", 2: "Partner", 4: "HypeSquad Events",
    8: "Bug Hunter L1", 64: "Bravery", 128: "Brilliance",
    256: "Balance", 512: "Early Supporter", 16384: "Bug Hunter L2",
    131072: "Verified Bot Dev", 4194304: "Active Dev",
  };
  return Object.entries(map)
    .filter(([f]) => flags & parseInt(f))
    .map(([, n]) => n);
}

module.exports = { login, mfaTotp, mfaBackup, getUserInfo, warmCookies };