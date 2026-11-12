import { type Env, MIN_TOKEN_LENGTH } from "./env";
import type { Scope } from "./scope";
import { sha256hex } from "./tokens";

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
// token signs everyone out. A session opened with a passkey is
// "<expiry>p.<HMAC(<expiry>p)>": the marker is signed with the rest, so a
// token session cannot be turned into a passkey one. A named admin's session
// adds "a<id>g<gen>" (also signed): "<expiry>[p]a<id>g<gen>.<HMAC>". It is
// valid only while that admin's row exists with the same gen (admins.ts).
export type SessionKind = "token" | "passkey";

export interface SessionAdmin {
  id: number;
  gen: number;
}

export async function newSession(env: Env, now = Date.now(), kind: SessionKind = "token", admin?: SessionAdmin): Promise<string> {
  const v = String(Math.floor(now / 1000) + SESSION_TTL) + (kind === "passkey" ? "p" : "") + (admin ? `a${admin.id}g${admin.gen}` : "");
  const sig = await crypto.subtle.sign("HMAC", await sessionKey(env), enc.encode(v));
  return `${v}.${b64urlEncode(sig)}`;
}

export function sessionCookie(value: string, maxAge = SESSION_TTL): string {
  return `${SESSION_COOKIE}=${value}; Path=/admin; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}

export function cookie(req: Request, name: string): string | null {
  for (const part of (req.headers.get("cookie") ?? "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

interface Session {
  kind: SessionKind;
  admin?: SessionAdmin;
}

async function validSession(req: Request, env: Env, now: number): Promise<Session | null> {
  const v = cookie(req, SESSION_COOKIE);
  const m = v && /^(\d{1,12})(p?)(?:a(\d{1,12})g(\d{1,12}))?\.([A-Za-z0-9_-]{20,100})$/.exec(v);
  if (!m) return null;
  if (Number(m[1]) < now / 1000) return null;
  const signed = m[0].slice(0, m[0].lastIndexOf("."));
  try {
    const ok = await crypto.subtle.verify("HMAC", await sessionKey(env), b64urlDecode(m[5]), enc.encode(signed));
    if (!ok) return null;
    const kind: SessionKind = m[2] ? "passkey" : "token";
    return m[3] ? { kind, admin: { id: Number(m[3]), gen: Number(m[4]) } } : { kind };
  } catch {
    return null;
  }
}

// ---- Whether the admin token may sign in ----

// The admin can switch sign-in with ADMIN_TOKEN off once a passkey works
// (passkeys.ts). It is a row in meta; absent means on. Recovery when every
// passkey is lost: delete the row with `wrangler d1 execute` (README).
export const TOKEN_LOGIN_KEY = "admin_token_login";

export async function tokenLoginOn(env: Env): Promise<boolean> {
  const v = await env.DB.prepare("SELECT value FROM meta WHERE key = ?").bind(TOKEN_LOGIN_KEY).first<string>("value");
  return v !== "off";
}

// Names shown in the header and written to the audit trail.
export const TOKEN_WHO = "admin token";
export const PASSKEY_WHO = "admin passkey";

export interface Viewer {
  who: string; // shown in the page header, written to the audit trail
  via: "access" | "session" | "bearer";
  // The session was opened with a passkey (only for via "session").
  passkey?: boolean;
  // A named admin (admins.ts): their row id. Absent for the owner and Access.
  adminId?: number;
  // The owner: signed in with ADMIN_TOKEN (session or bearer) or with one of
  // the owner's passkeys. Only the owner adds and removes admins and switches
  // token sign-in. Access viewers are not the owner: they manage the fleet,
  // but the portal's own sign-in (passkeys, admins) is not theirs to change,
  // and those pages answer 404 for them.
  owner: boolean;
  // A named admin's scope: the roles they manage (scope.ts). Undefined, for
  // the owner and Access viewers, means everything.
  scope?: Scope;
}

export function dashboardConfigured(env: Env): boolean {
  return accessConfigured(env) || usableToken(env.ADMIN_TOKEN);
}

// viewer works out who is looking at the dashboard, or null if nobody we trust.
export async function viewer(req: Request, env: Env, now = Date.now()): Promise<Viewer | null> {
  const who = await accessIdentity(req, env, now);
  if (who) return { who, via: "access", owner: false };
  if (!usableToken(env.ADMIN_TOKEN)) return null;
  // With token sign-in switched off, ADMIN_TOKEN is no admin credential at
  // all: neither as a bearer header nor through a session it opened earlier.
  // Passkey sessions still work (their HMAC is keyed by ADMIN_TOKEN too, which
  // stays secret).
  // The same goes for named admins' tokens and token sessions.
  const b = bearer(req);
  if (b) {
    if (await safeEqual(b, env.ADMIN_TOKEN)) return (await tokenLoginOn(env)) ? { who: TOKEN_WHO, via: "bearer", owner: true } : null;
    const a = await adminByToken(env, b);
    return a && (await tokenLoginOn(env)) ? { who: a.name, via: "bearer", adminId: a.id, owner: false, scope: await scopeOf(env, a.id) } : null;
  }
  const s = await validSession(req, env, now);
  if (!s) return null;
  if (s.kind === "token" && !(await tokenLoginOn(env))) return null;
  const passkey = s.kind === "passkey";
  if (!s.admin) return passkey ? { who: PASSKEY_WHO, via: "session", passkey: true, owner: true } : { who: TOKEN_WHO, via: "session", owner: true };
  const a = await adminById(env, s.admin.id);
  if (!a || a.gen !== s.admin.gen) return null;
  return { who: a.name, via: "session", ...(passkey ? { passkey: true } : {}), adminId: a.id, owner: false, scope: await scopeOf(env, a.id) };
}

// scopeOf loads a named admin's roles. A failed query is an empty scope,
// never everything.
async function scopeOf(env: Env, admin: number): Promise<Scope> {
  try {
    const r = await env.DB.prepare("SELECT role_id FROM admin_roles WHERE admin_id = ?").bind(admin).all<{ role_id: number }>();
    return { admin, roles: r.results.map((x) => x.role_id) };
  } catch {
    return { admin, roles: [] };
  }
}

// ---- Named admins: lookups (the pages are in admins.ts) ----

export interface AdminRow {
  id: number;
  name: string;
  gen: number;
}

// Their tokens: a recognisable prefix (for secret scanners) and 32 random bytes.
export const ADMIN_TOKEN_PREFIX = "bca_";
export const ADMIN_TOKEN_RE = /^bca_[A-Za-z0-9_-]{43}$/;

// adminByToken finds the named admin a token belongs to, by its SHA-256 (see
// tokens.ts on why a plain hash and a lookup are enough). Null for anything
// else, including before migration 0006 is applied (no table).
export async function adminByToken(env: Env, token: string): Promise<AdminRow | null> {
  if (!ADMIN_TOKEN_RE.test(token)) return null;
  try {
    return await env.DB.prepare("SELECT id, name, gen FROM admins WHERE token_hash = ?").bind(await sha256hex(token)).first<AdminRow>();
  } catch {
    return null;
  }
}

export async function adminById(env: Env, id: number): Promise<AdminRow | null> {
  try {
    return await env.DB.prepare("SELECT id, name, gen FROM admins WHERE id = ?").bind(id).first<AdminRow>();
  } catch {
    return null;
  }
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

// adminsReady: whether migration 0006 (named admins) is applied. Asked where a
// query needs passkeys.admin_id; before 0006 every passkey is the owner's and
// there are no named admins. Not cached: the migration may be applied while
// this isolate lives.
export async function adminsReady(env: Env): Promise<boolean> {
  try {
    await env.DB.prepare("SELECT (SELECT COUNT(*) FROM admins WHERE 0) AS a, (SELECT admin_id FROM passkeys LIMIT 0) AS b").first();
    return true;
  } catch {
    return false;
  }
}
