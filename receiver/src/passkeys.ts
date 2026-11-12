// Passkeys (WebAuthn) for the dashboard's own sign-in, the one ADMIN_TOKEN
// gives (not Cloudflare Access). WebCrypto only: the browser hands us the
// public key as SPKI (getPublicKey()) and the authenticator data as raw bytes
// (getAuthenticatorData()), so no CBOR parser is needed.
//
// Routes (index.ts):
//   POST /admin/login/passkey/options  public: a login challenge
//   POST /admin/login/passkey          public: verify an assertion, open a session
//   GET  /admin/passkeys               the setup page
//   POST /admin/passkeys/options       a registration challenge
//   POST /admin/passkeys               verify and store a new passkey
//   POST /admin/passkeys/<id>/delete
//   POST /admin/passkeys/token-login   switch sign-in with ADMIN_TOKEN on or off
//
// A passkey belongs to the owner (admin_id NULL) or to one named admin
// (admins.ts): it is stored with the admin_id of whoever registered it, and
// signing in with it opens a session for that admin. Each admin sees and
// deletes only their own. The user handle is per admin (so one authenticator
// can hold the owner's and an admin's passkey side by side) and not checked
// on sign-in: the credential id decides.

import { auditStmt } from "./audit";
import { adminById, adminsReady, cookie, newSession, sessionCookie, TOKEN_LOGIN_KEY, tokenLoginOn, type Viewer } from "./auth";
import { publicOrigin } from "./enroll";
import type { Env } from "./env";
import { html, layout, note, page, PASSKEY_HEADERS } from "./html";
import type { I18n, Key } from "./i18n";
import { json } from "./ingest";
import { b64url, sha256hex } from "./tokens";

const enc = new TextEncoder();
const CHALLENGE_TTL = 5 * 60 * 1000;
const CLIENT_TIMEOUT = 2 * 60 * 1000; // what the browser is asked to wait, under CHALLENGE_TTL
const MAX_BODY = 16 * 1024;
const ES256 = -7;
const RS256 = -257;
// The owner keeps the handle every passkey had before named admins existed.
const userId = (adminId?: number) => b64url(enc.encode(adminId === undefined ? "bordercheck-admin" : `bordercheck-admin-${adminId}`));

// "This browser has used a passkey here": makes the sign-in page start the
// passkey prompt by itself. It says nothing secret; HttpOnly because only the
// server reads it.
export const PK_COOKIE = "bc_pk";
export const pkCookie = () => `${PK_COOKIE}=1; Path=/admin; Max-Age=${365 * 24 * 3600}; HttpOnly; Secure; SameSite=Lax`;
// Logout lands on /admin/login?<SIGNED_OUT>=1, which never auto-prompts.
export const SIGNED_OUT = "signed_out";

function b64urlBytes(s: unknown): Uint8Array | null {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]{1,8192}$/.test(s)) return null;
  try {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

const sha256 = async (b: Uint8Array) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

// ---- Stored state ----

export interface PasskeyRow {
  id: number;
  credential_id: string;
  public_key: string;
  alg: number;
  sign_count: number;
  label: string;
  created_at: string;
  last_used_at: string | null;
  admin_id?: number | null; // absent before migration 0006
}

// ownWhere: the SQL condition "this passkey is the viewer's", with ?<n> bound
// to v.adminId ?? null. Before migration 0006 there is no admin_id column and
// every passkey is the owner's (nobody else can be signed in then).
async function ownWhere(env: Env, n: number): Promise<string> {
  return (await adminsReady(env)) ? `admin_id IS ?${n}` : `?${n} IS NULL`;
}
const ownId = (v: Viewer) => v.adminId ?? null;

// ownPasskeyCount: how many passkeys the owner (adminId undefined) or a named admin has.
export async function ownPasskeyCount(env: Env, adminId?: number): Promise<number> {
  try {
    return (await env.DB.prepare(`SELECT COUNT(*) AS n FROM passkeys WHERE ${await ownWhere(env, 1)}`).bind(adminId ?? null).first<number>("n")) ?? 0;
  } catch {
    return 0;
  }
}

// The sign-in page asks this on every view. Deployed before migration 0005 is
// applied, the table is missing: then there are no passkeys, rather than a
// sign-in page that fails.
export async function passkeyCount(env: Env): Promise<number> {
  try {
    return (await env.DB.prepare("SELECT COUNT(*) AS n FROM passkeys").first<number>("n")) ?? 0;
  } catch {
    return 0;
  }
}

async function newChallenge(env: Env, kind: "register" | "login", now: number): Promise<string> {
  const c = crypto.getRandomValues(new Uint8Array(32));
  await env.DB.batch([
    env.DB.prepare("DELETE FROM passkey_challenges WHERE expires_at < ?").bind(now),
    env.DB.prepare("INSERT INTO passkey_challenges (hash, kind, expires_at) VALUES (?, ?, ?)").bind(hex(await sha256(c)), kind, now + CHALLENGE_TTL),
  ]);
  return b64url(c);
}

// takeChallenge consumes the challenge the client says it signed: single use
// whether or not the rest of the check succeeds.
async function takeChallenge(env: Env, challenge: unknown, kind: "register" | "login", now: number): Promise<boolean> {
  const c = b64urlBytes(challenge);
  if (!c || c.length !== 32) return false;
  const exp = await env.DB.prepare("DELETE FROM passkey_challenges WHERE hash = ? AND kind = ? RETURNING expires_at")
    .bind(hex(await sha256(c)), kind)
    .first<number>("expires_at");
  return exp !== null && exp >= now;
}

// ---- WebAuthn checks shared by registration and sign-in ----

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;

interface Checked {
  authData: Uint8Array;
  clientData: Uint8Array;
  flags: number;
  signCount: number;
}

// checkCommon: clientDataJSON says `type`, carries a challenge we issued for
// `kind`, comes from the portal's public origin (not cross-origin); the
// authenticator data is for this host (rpIdHash) with the user present and
// verified.
async function checkCommon(env: Env, req: Request, body: Record<string, unknown>, type: string, kind: "register" | "login", now: number): Promise<Checked | null> {
  const clientData = b64urlBytes(body.clientDataJSON);
  const authData = b64urlBytes(body.authenticatorData);
  if (!clientData || !authData || authData.length < 37) return null;
  let cd: { type?: unknown; challenge?: unknown; origin?: unknown; crossOrigin?: unknown };
  try {
    cd = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(clientData));
  } catch {
    return null;
  }
  if (!cd || typeof cd !== "object" || cd.type !== type) return null;
  // Consume the challenge before any other verdict, so a failed attempt cannot be retried with it.
  if (!(await takeChallenge(env, cd.challenge, kind, now))) return null;
  const origin = publicOrigin(env, req);
  if (cd.origin !== origin || cd.crossOrigin === true) return null;
  if (!sameBytes(authData.subarray(0, 32), await sha256(enc.encode(new URL(origin).hostname)))) return null;
  const flags = authData[32];
  if (!(flags & FLAG_UP) || !(flags & FLAG_UV)) return null;
  const signCount = new DataView(authData.buffer, authData.byteOffset + 33, 4).getUint32(0);
  return { authData, clientData, flags, signCount };
}

function importParams(alg: number): { name: string; namedCurve?: string; hash?: string } | null {
  if (alg === ES256) return { name: "ECDSA", namedCurve: "P-256" };
  if (alg === RS256) return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  return null;
}

async function importKey(spki: Uint8Array, alg: number): Promise<CryptoKey | null> {
  const p = importParams(alg);
  if (!p) return null;
  try {
    return await crypto.subtle.importKey("spki", spki, p, false, ["verify"]);
  } catch {
    return null;
  }
}

// derToRaw turns an ECDSA DER signature (SEQUENCE of two INTEGERs) into the
// 64-byte r||s WebCrypto verifies. Null for anything malformed.
export function derToRaw(der: Uint8Array): Uint8Array | null {
  if (der.length < 8 || der[0] !== 0x30 || der[1] !== der.length - 2) return null;
  const out = new Uint8Array(64);
  let i = 2;
  for (const at of [0, 32]) {
    if (der[i] !== 0x02) return null;
    const len = der[i + 1];
    let v = der.subarray(i + 2, i + 2 + len);
    if (len < 1 || v.length !== len) return null;
    while (v.length > 1 && v[0] === 0) v = v.subarray(1);
    if (v.length > 32) return null;
    out.set(v, at + 32 - v.length);
    i += 2 + len;
  }
  return i === der.length ? out : null;
}

// ---- Public: sign in ----

export async function loginOptions(env: Env, req: Request, now = Date.now()): Promise<Response> {
  const challenge = await newChallenge(env, "login", now);
  return json({ challenge, rpId: new URL(publicOrigin(env, req)).hostname, timeout: CLIENT_TIMEOUT }, 200, { "cache-control": "no-store" });
}

async function readJson(req: Request): Promise<Record<string, unknown> | null> {
  if (Number(req.headers.get("content-length") ?? "0") > MAX_BODY) return null;
  try {
    const t = await req.text();
    if (t.length > MAX_BODY) return null;
    const v = JSON.parse(t);
    return v && typeof v === "object" && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

// One answer for every failed sign-in, whatever step failed.
const LOGIN_FAILED = () => json({ error: "passkey sign-in failed" }, 400, { "cache-control": "no-store" });

export async function loginVerify(env: Env, req: Request, now = Date.now()): Promise<Response> {
  const body = await readJson(req);
  if (!body || typeof body.id !== "string") return LOGIN_FAILED();
  const c = await checkCommon(env, req, body, "webauthn.get", "login", now);
  if (!c) return LOGIN_FAILED();
  const row = await env.DB.prepare("SELECT * FROM passkeys WHERE credential_id = ?").bind(body.id).first<PasskeyRow>();
  const sig = b64urlBytes(body.signature);
  const spki = row && b64urlBytes(row.public_key);
  if (!row || !sig || !spki) return LOGIN_FAILED();
  const key = await importKey(spki, row.alg);
  if (!key) return LOGIN_FAILED();
  const signed = new Uint8Array(c.authData.length + 32);
  signed.set(c.authData);
  signed.set(await sha256(c.clientData), c.authData.length);
  let ok = false;
  try {
    if (row.alg === ES256) {
      const raw = derToRaw(sig);
      ok = !!raw && (await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, raw, signed));
    } else {
      ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, sig, signed);
    }
  } catch {
    ok = false;
  }
  if (!ok) return LOGIN_FAILED();
  // A named admin's passkey signs in as that admin, while the admin exists.
  const adm = row.admin_id == null ? null : await adminById(env, row.admin_id);
  if (row.admin_id != null && !adm) return LOGIN_FAILED();
  // A counter that does not move forward suggests a cloned authenticator.
  // Many passkeys (synced ones) always send 0: then there is nothing to compare.
  if (row.sign_count !== 0 && c.signCount !== 0 && c.signCount <= row.sign_count) return LOGIN_FAILED();
  // The update re-checks the counter, so two racing sign-ins with one assertion cannot both win.
  const upd = await env.DB.prepare(
    "UPDATE passkeys SET sign_count = MAX(sign_count, ?), last_used_at = ? WHERE id = ? AND (sign_count = 0 OR ? = 0 OR sign_count < ?)",
  )
    .bind(c.signCount, new Date(now).toISOString(), row.id, c.signCount, c.signCount)
    .run();
  if (upd.meta.changes !== 1) return LOGIN_FAILED();
  if (adm) await env.DB.prepare("UPDATE admins SET last_used_at = ? WHERE id = ?").bind(new Date(now).toISOString(), adm.id).run();
  const headers = new Headers({ "content-type": "application/json", "cache-control": "no-store" });
  headers.append("set-cookie", sessionCookie(await newSession(env, now, "passkey", adm ? { id: adm.id, gen: adm.gen } : undefined)));
  headers.append("set-cookie", pkCookie());
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}

// ---- Signed in: set up ----

export async function registerOptions(env: Env, req: Request, v: Viewer, now = Date.now()): Promise<Response> {
  const origin = publicOrigin(env, req);
  const host = new URL(origin).hostname;
  const existing = await env.DB.prepare(`SELECT credential_id FROM passkeys WHERE ${await ownWhere(env, 1)} ORDER BY id`).bind(ownId(v)).all<{ credential_id: string }>();
  const named = v.adminId !== undefined;
  return json(
    {
      challenge: await newChallenge(env, "register", now),
      rp: { id: host, name: `bordercheck (${host})` },
      user: named
        ? { id: userId(v.adminId), name: `${v.who}@${host}`, displayName: `bordercheck: ${v.who}` }
        : { id: userId(), name: `admin@${host}`, displayName: "bordercheck admin" },
      exclude: existing.results.map((r) => r.credential_id),
      timeout: CLIENT_TIMEOUT,
    },
    200,
    { "cache-control": "no-store" },
  );
}

// register verifies a new credential and stores it.
//
// The attestation statement is not verified: we ask for attestation "none",
// the request is already authenticated as the admin and same-origin, and we
// do not restrict which authenticators may be used. What is checked: the
// clientData (type, our challenge, origin), the authenticator data (rpIdHash,
// UP, UV, and the attested credential id equal to the id sent), and that the
// public key is for an algorithm we offered and imports with WebCrypto. The
// SPKI comes from the browser's own parse of the same attestation object.
export async function register(env: Env, req: Request, v: Viewer, now = Date.now()): Promise<Response> {
  const fail = () => json({ error: "passkey not added" }, 400, { "cache-control": "no-store" });
  const body = await readJson(req);
  if (!body || typeof body.id !== "string") return fail();
  const id = b64urlBytes(body.id);
  const spki = b64urlBytes(body.publicKey);
  const alg = body.alg;
  if (!id || id.length > 1023 || !spki || (alg !== ES256 && alg !== RS256)) return fail();
  const c = await checkCommon(env, req, body, "webauthn.create", "register", now);
  if (!c || !(c.flags & FLAG_AT) || c.authData.length < 55) return fail();
  const idLen = (c.authData[53] << 8) | c.authData[54];
  if (!sameBytes(c.authData.subarray(55, 55 + idLen), id)) return fail();
  if (!(await importKey(spki, alg))) return fail();
  const label = (typeof body.label === "string" ? body.label : "").replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, 64);
  const credId = b64url(id);
  const at = new Date(now);
  // Stored as the viewer's own. Before migration 0006 only the owner can be signed in.
  const ready = await adminsReady(env);
  if (!ready && v.adminId !== undefined) return fail();
  const res = await env.DB.batch([
    (ready
      ? env.DB.prepare("INSERT INTO passkeys (credential_id, public_key, alg, sign_count, label, created_at, admin_id) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (credential_id) DO NOTHING")
          .bind(credId, b64url(spki), alg, c.signCount, label, at.toISOString(), ownId(v))
      : env.DB.prepare("INSERT INTO passkeys (credential_id, public_key, alg, sign_count, label, created_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (credential_id) DO NOTHING")
          .bind(credId, b64url(spki), alg, c.signCount, label, at.toISOString())),
    env.DB.prepare("INSERT INTO audit (at, who, action, target, detail) SELECT ?, ?, 'passkey.add', ?, ? WHERE changes() > 0")
      .bind(at.toISOString(), v.who.slice(0, 200), label || "(no label)", JSON.stringify({ alg: alg === ES256 ? "ES256" : "RS256" })),
  ]);
  if (res[0].meta.changes !== 1) return fail();
  const headers = new Headers({ "content-type": "application/json", "cache-control": "no-store" });
  headers.append("set-cookie", pkCookie());
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}

// deletePasskey deletes one of the viewer's own passkeys (anyone else's is "not found").
export async function deletePasskey(env: Env, req: Request, v: Viewer, id: number, L: I18n): Promise<Response> {
  const row = await env.DB.prepare(`SELECT id, label FROM passkeys WHERE id = ?1 AND ${await ownWhere(env, 2)}`).bind(id, ownId(v)).first<{ id: number; label: string }>();
  if (!row) return passkeysPage(env, req, v, L, "passkeys.notFound", 404);
  // No lockout: while token sign-in is off, nobody deletes their own last passkey.
  if (!(await tokenLoginOn(env)) && (await ownPasskeyCount(env, v.adminId)) <= 1) return passkeysPage(env, req, v, L, "passkeys.lastWhileOff", 409);
  // The DELETE re-checks both conditions, so a concurrent delete cannot remove the last one.
  const own = await ownWhere(env, 3);
  const res = await env.DB.batch([
    env.DB.prepare(
      `DELETE FROM passkeys WHERE id = ?1 AND ${own} AND (
         (SELECT value FROM meta WHERE key = ?2) IS NOT 'off' OR (SELECT COUNT(*) FROM passkeys WHERE ${own}) > 1)`,
    ).bind(id, TOKEN_LOGIN_KEY, ownId(v)),
    env.DB.prepare("INSERT INTO audit (at, who, action, target, detail) SELECT ?, ?, 'passkey.delete', ?, '{}' WHERE changes() > 0")
      .bind(new Date().toISOString(), v.who.slice(0, 200), row.label || "(no label)"),
  ]);
  if (res[0].meta.changes !== 1) return passkeysPage(env, req, v, L, "passkeys.lastWhileOff", 409);
  return passkeysPage(env, req, v, L, "passkeys.deleted", 200);
}

// setTokenLogin switches sign-in with tokens (ADMIN_TOKEN and every named
// admin's), both ways, and only the owner may. Off needs an owner passkey and
// a session opened with one, so nobody switches the token off on the strength
// of a passkey that has never worked.
export async function setTokenLogin(env: Env, req: Request, v: Viewer, form: FormData, L: I18n): Promise<Response> {
  if (!v.owner) return passkeysPage(env, req, v, L, "admins.ownerOnly", 403);
  const want = String(form.get("state") ?? "");
  if (want !== "on" && want !== "off") return passkeysPage(env, req, v, L, "passkeys.badState", 400);
  if (want === "off") {
    if ((await ownPasskeyCount(env)) === 0) return passkeysPage(env, req, v, L, "passkeys.needPasskey", 409);
    if (!v.passkey) return passkeysPage(env, req, v, L, "passkeys.needPasskeySession", 409);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO meta (key, value) VALUES (?, 'off') ON CONFLICT (key) DO UPDATE SET value = 'off'").bind(TOKEN_LOGIN_KEY),
      auditStmt(env, v.who, "token-login.off", "admin token"),
    ]);
    return passkeysPage(env, req, v, L, "passkeys.tokenNowOff", 200);
  }
  await env.DB.batch([
    env.DB.prepare("DELETE FROM meta WHERE key = ?").bind(TOKEN_LOGIN_KEY),
    auditStmt(env, v.who, "token-login.on", "admin token"),
  ]);
  return passkeysPage(env, req, v, L, "passkeys.tokenNowOn", 200);
}

// ---- Pages ----

export async function passkeysPage(env: Env, req: Request, v: Viewer, L: I18n, message?: Key, status = 200): Promise<Response> {
  const rows = (await env.DB.prepare(`SELECT * FROM passkeys WHERE ${await ownWhere(env, 1)} ORDER BY id`).bind(ownId(v)).all<PasskeyRow>()).results;
  const tokenOn = await tokenLoginOn(env);
  const bare = v.owner ? await adminsWithoutPasskey(env) : 0;
  const host = new URL(publicOrigin(env, req)).hostname;
  const body = html`<div class="hero"><p class="eyebrow">${L.t("passkeys.eyebrow")}</p><h1>${L.t("nav.passkeys")}</h1>
<p class="lead">${L.t("passkeys.lead")}</p></div>
${message ? note(L.t(message), status >= 400 ? "s-fail" : "s-pass") : ""}
<div class="panel flush"><div class="scroll"><table><thead><tr><th>${L.t("passkeys.thLabel")}</th><th>${L.t("passkeys.thCreated")}</th><th>${L.t("passkeys.thUsed")}</th><th></th></tr></thead><tbody>
${rows.map(
    (r) => html`<tr><td class="wrap">${r.label || html`<span class="muted">${L.t("passkeys.noLabel")}</span>`}</td><td class="nowrap">${L.when(r.created_at)}</td><td class="nowrap">${r.last_used_at ? L.when(r.last_used_at) : L.s("time.never")}</td>
<td class="n"><form class="inline" method="post" action="/admin/passkeys/${r.id}/delete"><button class="sm danger">${L.t("passkeys.delete")}</button></form></td></tr>`,
  )}</tbody></table></div>${rows.length === 0 ? html`<p class="empty">${L.t("passkeys.empty")}</p>` : ""}</div>
<h2>${L.t("passkeys.add")}</h2>
<div class="panel"><p id="pk-unsupported" class="muted">${L.t("passkeys.unsupported")}</p>
<div id="pk" data-mode="register" data-fail="${L.s("passkeys.addFail")}" hidden><div class="field"><label for="pk-label">${L.t("passkeys.labelField")}</label><input id="pk-label" class="w-name" maxlength="64" placeholder="${L.s("passkeys.labelPlaceholder")}" autocomplete="off"></div>
<div class="actions"><button type="button" id="pk-go" class="primary">${L.t("passkeys.add")}</button></div><p id="pk-msg" class="small" role="status" aria-live="polite"></p></div>
<p class="muted small">${L.t("passkeys.hostNote", { host })}</p></div>
<h2>${L.t("passkeys.tokenTitle")}</h2>
<div class="panel"><p>${tokenOn ? L.t("passkeys.tokenOnState") : L.t("passkeys.tokenOffState")}</p>
<p class="muted small">${L.t("passkeys.tokenRule")}</p>
${bare ? note(L.t(tokenOn ? "passkeys.adminsNoPasskey" : "passkeys.adminsNoPasskeyOff", { n: bare }), "s-warn") : ""}
${v.owner
    ? html`<form method="post" action="/admin/passkeys/token-login"><input type="hidden" name="state" value="${tokenOn ? "off" : "on"}"><div class="actions"><button class="${tokenOn ? "danger" : "primary"}">${tokenOn ? L.t("passkeys.turnOff") : L.t("passkeys.turnOn")}</button></div></form>`
    : html`<p class="muted small">${L.t("passkeys.ownerSwitch")}</p>`}</div>`;
  return page(layout(L, L.s("nav.passkeys"), v.who, body, "Passkeys", { passkey: true }), status, PASSKEY_HEADERS);
}

// adminsWithoutPasskey: named admins who cannot sign in while tokens are off.
async function adminsWithoutPasskey(env: Env): Promise<number> {
  try {
    return (await env.DB.prepare("SELECT COUNT(*) AS n FROM admins a WHERE NOT EXISTS (SELECT 1 FROM passkeys p WHERE p.admin_id = a.id)").first<number>("n")) ?? 0;
  } catch {
    return 0;
  }
}

// autoPrompt decides whether the sign-in page starts the passkey prompt by
// itself: a GET, from a browser that has used a passkey here (bc_pk=1), not
// right after signing out, and only while a passkey exists.
export function autoPrompt(req: Request, url: URL, passkeys: number): boolean {
  return req.method === "GET" && passkeys > 0 && cookie(req, PK_COOKIE) === "1" && !url.searchParams.has(SIGNED_OUT);
}
