import { type Env, MIN_TOKEN_LENGTH } from "./env";

const enc = new TextEncoder();

// safeEqual compares two strings in constant time. Hashing first makes the
// lengths equal, so the comparison leaks neither content nor length.
export async function safeEqual(a: string, b: string): Promise<boolean> {
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  return crypto.subtle.timingSafeEqual(ha, hb);
}

export function bearer(req: Request): string | null {
  const h = req.headers.get("authorization") ?? "";
  const m = /^Bearer\s+(\S+)\s*$/i.exec(h);
  return m ? m[1] : null;
}

export const usableToken = (t: string | undefined): t is string => !!t && t.length >= MIN_TOKEN_LENGTH;

// ---- Cloudflare Access ----

function b64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlEncode(buf: ArrayBuffer): string {
  let s = "";
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function accessConfigured(env: Env): boolean {
  return !!(env.ACCESS_TEAM_DOMAIN && env.ACCESS_AUD);
}

function teamOrigin(env: Env): string {
  const d = (env.ACCESS_TEAM_DOMAIN ?? "").trim().replace(/^https?:\/\//, "").replace(/\/+$/, "");
  return `https://${d}`;
}

type Jwk = JsonWebKey & { kid?: string };
let jwks: { origin: string; keys: Map<string, CryptoKey>; fetched: number } | undefined;

async function accessKey(env: Env, kid: string, now: number): Promise<CryptoKey | undefined> {
  const origin = teamOrigin(env);
  const fresh = jwks && jwks.origin === origin && now - jwks.fetched < 60 * 60 * 1000;
  if (fresh && jwks!.keys.has(kid)) return jwks!.keys.get(kid);
  // Unknown kid: refetch, at most once a minute (Access rotates keys).
  if (jwks && jwks.origin === origin && now - jwks.fetched < 60 * 1000) return jwks.keys.get(kid);
  const res = await fetch(`${origin}/cdn-cgi/access/certs`);
  if (!res.ok) throw new Error(`Access certs: ${res.status}`);
  const body = (await res.json()) as { keys?: Jwk[] };
  const keys = new Map<string, CryptoKey>();
  for (const k of body.keys ?? []) {
    if (!k.kid || k.kty !== "RSA") continue;
    keys.set(
      k.kid,
      await crypto.subtle.importKey("jwk", k, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]),
    );
  }
  jwks = { origin, keys, fetched: now };
  return keys.get(kid);
}

export function resetAccessKeys() {
  jwks = undefined;
}

// accessIdentity returns the signed-in email (or service token name) if the
// request carries a valid Access JWT for this application, else null.
export async function accessIdentity(req: Request, env: Env, now = Date.now()): Promise<string | null> {
  if (!accessConfigured(env)) return null;
  const token = req.headers.get("cf-access-jwt-assertion");
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0])));
    if (header.alg !== "RS256" || typeof header.kid !== "string") return null;
    const key = await accessKey(env, header.kid, now);
    if (!key) return null;
    const ok = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      b64urlDecode(parts[2]),
      enc.encode(`${parts[0]}.${parts[1]}`),
    );
    if (!ok) return null;
    const p = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1])));
    const aud: unknown[] = Array.isArray(p.aud) ? p.aud : [p.aud];
    if (!aud.includes(env.ACCESS_AUD)) return null;
    if (p.iss !== teamOrigin(env)) return null;
    const sec = now / 1000;
    if (typeof p.exp !== "number" || p.exp < sec) return null;
    if (typeof p.nbf === "number" && p.nbf > sec + 60) return null;
    return String(p.email || p.common_name || "Access");
  } catch {
    return null;
  }
}

// ---- Admin token sessions ----

export const SESSION_COOKIE = "bc_session";
const SESSION_TTL = 12 * 60 * 60; // seconds

async function sessionKey(env: Env): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", enc.encode(`bordercheck-session:${env.ADMIN_TOKEN}`), {
    name: "HMAC",
    hash: "SHA-256",
  }, false, ["sign", "verify"]);
}

// A session is "<expiry>.<HMAC(expiry)>" keyed by ADMIN_TOKEN, so changing the
// token signs everyone out.
export async function newSession(env: Env, now = Date.now()): Promise<string> {
  const exp = Math.floor(now / 1000) + SESSION_TTL;
  const sig = await crypto.subtle.sign("HMAC", await sessionKey(env), enc.encode(String(exp)));
  return `${exp}.${b64urlEncode(sig)}`;
}

export function sessionCookie(value: string, maxAge = SESSION_TTL): string {
  return `${SESSION_COOKIE}=${value}; Path=/admin; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}

function cookie(req: Request, name: string): string | null {
  for (const part of (req.headers.get("cookie") ?? "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

async function validSession(req: Request, env: Env, now: number): Promise<boolean> {
  const v = cookie(req, SESSION_COOKIE);
  const m = v && /^(\d{1,12})\.([A-Za-z0-9_-]{20,100})$/.exec(v);
  if (!m) return false;
  if (Number(m[1]) < now / 1000) return false;
  try {
    return await crypto.subtle.verify("HMAC", await sessionKey(env), b64urlDecode(m[2]), enc.encode(m[1]));
  } catch {
    return false;
  }
}

export interface Viewer {
  who: string; // shown in the page header
  via: "access" | "session" | "bearer";
}

export function dashboardConfigured(env: Env): boolean {
  return accessConfigured(env) || usableToken(env.ADMIN_TOKEN);
}

// viewer works out who is looking at the dashboard, or null if nobody we trust.
export async function viewer(req: Request, env: Env, now = Date.now()): Promise<Viewer | null> {
  const who = await accessIdentity(req, env, now);
  if (who) return { who, via: "access" };
  if (!usableToken(env.ADMIN_TOKEN)) return null;
  const b = bearer(req);
  if (b) return (await safeEqual(b, env.ADMIN_TOKEN)) ? { who: "admin token", via: "bearer" } : null;
  if (await validSession(req, env, now)) return { who: "admin token", via: "session" };
  return null;
}

// sameOrigin guards state-changing requests made with cookies (Access or our
// session) against cross-site form posts.
//
// Our pages send Referrer-Policy: no-referrer, and under that policy browsers
// send "Origin: null" on a form post, even a same-origin one. So "null" says
// nothing either way and Sec-Fetch-Site decides, as it does when Origin is
// absent. A page cannot set either header.
export function sameOrigin(req: Request): boolean {
  const origin = req.headers.get("origin");
  if (origin && origin !== "null") return origin === new URL(req.url).origin;
  return req.headers.get("sec-fetch-site") === "same-origin";
}
