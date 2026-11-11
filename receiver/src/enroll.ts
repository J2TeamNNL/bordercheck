// Enrollment: an invite code becomes a per-machine token (POST /enroll), the
// token fetches that machine's policy (GET /policy) and sends its reports
// (POST /report, see ingest.ts). The invite link itself (GET /i/<code>) is a
// page for a person, with the install commands.

import { bearer } from "./auth";
import { config, type Env } from "./env";
import { COPY_HEADERS, copyButton, html, layout, MARK, page } from "./html";
import { forRequest, type I18n, type Key } from "./i18n";
import { json } from "./ingest";
import { hit } from "./ratelimit";
import { str } from "./report";
import { composePolicy, type WaiverRow } from "./roles";
import { CODE_RE, newInstallId, newToken, sha256hex, TOKEN_RE } from "./tokens";

export interface Enrollment {
  install_id: string;
  email: string;
  role_id: number;
  revoked_at: string | null;
  last_policy_at: string | null;
}

// machineByToken finds the enrollment a bearer token belongs to, or null.
// Revoked enrollments are returned too, so callers can say "revoked".
export async function machineByToken(env: Env, token: string | null): Promise<Enrollment | null> {
  // Always hash, so a malformed token costs the same as a well-formed one.
  const h = await sha256hex(token ?? "");
  if (!token || !TOKEN_RE.test(token)) return null;
  return env.DB.prepare("SELECT install_id, email, role_id, revoked_at, last_policy_at FROM enrollments WHERE token_hash = ?")
    .bind(h)
    .first<Enrollment>();
}

export function enrollError(error: string, status: number, message: string, headers: Record<string, string> = {}) {
  return json({ error, message }, status, headers);
}

const MAX_ENROLL_BYTES = 8 * 1024;

export async function handleEnroll(req: Request, env: Env, now = new Date()): Promise<Response> {
  const rl = await hit(env, req, "enroll", now.getTime());
  if (!rl.ok) {
    return enrollError("rate_limited", 429, "Too many enrollment attempts from this network. Wait a few minutes and try again.", {
      "retry-after": String(rl.retryAfter),
    });
  }
  const len = Number(req.headers.get("content-length") ?? "0");
  if (len > MAX_ENROLL_BYTES) return enrollError("bad_request", 400, "The request is too large.");
  let body: Record<string, unknown>;
  try {
    const text = await req.text();
    if (text.length > MAX_ENROLL_BYTES) return enrollError("bad_request", 400, "The request is too large.");
    const v = JSON.parse(text);
    if (!v || typeof v !== "object" || Array.isArray(v)) throw new SyntaxError();
    body = v as Record<string, unknown>;
  } catch {
    return enrollError("bad_request", 400, "The request body must be a JSON object.");
  }
  if (typeof body.code !== "string") return enrollError("bad_request", 400, 'The request needs a "code".');
  const host = body.host === undefined ? {} : body.host;
  if (!host || typeof host !== "object" || Array.isArray(host)) return enrollError("bad_request", 400, '"host" must be an object.');
  const h = host as Record<string, unknown>;

  // Same work for every code: hash first, then one transaction whatever the code.
  const codeHash = await sha256hex(body.code);
  const wellFormed = CODE_RE.test(body.code);
  const installId = newInstallId();
  const token = newToken();
  const tokenHash = await sha256hex(token);
  const ts = now.toISOString();
  const db = env.DB;
  const hostname = str(h.hostname, 255);
  const os = str(h.os, 32);
  const arch = str(h.arch, 32);
  const version = str(body.version, 64);

  // The UPDATE claims the invite only if it is still pending; the INSERT and
  // the audit row only happen if this request's UPDATE did (they select the
  // invite by the install ID just written). D1 runs a batch as one
  // transaction, so of two concurrent enrolls with one code exactly one wins.
  const res = await db.batch([
    db.prepare(
      `UPDATE invites SET used_at = ?1, used_install_id = ?2
       WHERE code_hash = ?3 AND ?4 = 1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?1`,
    ).bind(ts, installId, codeHash, wellFormed ? 1 : 0),
    db.prepare(
      `INSERT INTO enrollments (install_id, token_hash, email, role_id, invite_id, hostname, os, arch, version, enrolled_at)
       SELECT ?1, ?2, email, role_id, id, ?3, ?4, ?5, ?6, ?7 FROM invites WHERE code_hash = ?8 AND used_install_id = ?1`,
    ).bind(installId, tokenHash, hostname, os, arch, version, ts, codeHash),
    db.prepare(
      `INSERT INTO audit (at, who, action, target, detail)
       SELECT ?1, 'enrollment', 'machine.enroll', ?2, json_object('invite', id, 'email', email, 'hostname', ?3)
       FROM invites WHERE code_hash = ?4 AND used_install_id = ?2`,
    ).bind(ts, installId, hostname, codeHash),
  ]);

  if (res[1].meta.changes === 1) {
    const row = await db
      .prepare("SELECT e.email, r.name AS role FROM enrollments e JOIN roles r ON r.id = e.role_id WHERE e.install_id = ?")
      .bind(installId)
      .first<{ email: string; role: string }>();
    const origin = new URL(req.url).origin;
    return json({
      install_id: installId,
      email: row?.email ?? "",
      role: row?.role ?? "",
      token,
      policy_url: `${origin}/policy`,
      report_url: `${origin}/report`,
    });
  }

  const inv = wellFormed
    ? await db.prepare("SELECT used_at, revoked_at, expires_at FROM invites WHERE code_hash = ?")
        .bind(codeHash)
        .first<{ used_at: string | null; revoked_at: string | null; expires_at: string }>()
    : null;
  if (!inv) return enrollError("invalid_code", 404, "This invite code is not valid. Check the link, or ask IT for a new invite.");
  if (inv.revoked_at) return enrollError("revoked", 410, "This invite was cancelled. Ask IT for a new one.");
  if (inv.used_at) return enrollError("used", 409, "This invite has already been used to install bordercheck. Ask IT for a new invite to install on another machine.");
  return enrollError("expired", 410, "This invite has expired. Ask IT for a new one.");
}

// ---- GET /policy ----

export async function serveMachinePolicy(req: Request, env: Env, now = new Date()): Promise<Response> {
  const m = await machineByToken(env, bearer(req));
  if (!m) return json({ error: "unauthorized" }, 401, { "www-authenticate": "Bearer" });
  if (m.revoked_at) return json({ error: "revoked" }, 401, { "www-authenticate": "Bearer" });
  const [role, waivers] = await Promise.all([
    env.DB.prepare("SELECT name, policy FROM roles WHERE id = ?").bind(m.role_id).first<{ name: string; policy: string }>(),
    env.DB.prepare("SELECT check_id, until, reason FROM machine_waivers WHERE install_id = ? AND removed_at IS NULL ORDER BY id")
      .bind(m.install_id)
      .all<WaiverRow>(),
  ]);
  if (!role) return json({ error: "role_missing" }, 500);
  let rolePolicy: Record<string, unknown>;
  try {
    rolePolicy = JSON.parse(role.policy);
  } catch {
    return json({ error: "role_policy_unreadable" }, 500);
  }
  const p = composePolicy(rolePolicy, role.name, m, waivers.results, new URL(req.url).origin, now);
  if (!m.last_policy_at || Date.parse(m.last_policy_at) < now.getTime() - 60 * 60 * 1000) {
    await env.DB.prepare("UPDATE enrollments SET last_policy_at = ? WHERE install_id = ?").bind(now.toISOString(), m.install_id).run();
  }
  return new Response(JSON.stringify(p, null, 2) + "\n", {
    headers: { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff" },
  });
}

// ---- Invite links ----

// The base URL invites point at: DASHBOARD_URL when set (so links made while
// browsing a workers.dev URL still use the custom domain), else this request's.
export function publicOrigin(env: Env, req: Request): string {
  const d = (env.DASHBOARD_URL ?? "").trim().replace(/\/+$/, "");
  if (/^https:\/\/[A-Za-z0-9.-]+(:\d+)?$/.test(d)) return d;
  return new URL(req.url).origin;
}

export interface InstallCommands {
  link: string;
  shURL: string;
  ps1URL: string;
  sh: string;
  ps1: string;
}

// installCommands builds the commands an invitee runs. Every part is either a
// deployment origin or the base64url code. The script URLs are served
// separately so an invitee can review the script before running it.
export function installCommands(env: Env, origin: string, code: string): InstallCommands {
  const cfg = config(env);
  const link = `${origin}/i/${code}`;
  return {
    link,
    shURL: cfg.installSh,
    ps1URL: cfg.installPs1,
    sh: `sh ./install.sh '${link}'`,
    ps1: `.\\install.ps1 '${link}'`,
  };
}

// Capability pages post the language switcher to their own URL (see html.ts).
export const SELF = { switcher: "self" } as const;

export const CAPABILITY_HEADERS = { "x-robots-tag": "noindex, nofollow", "referrer-policy": "no-referrer", "cache-control": "no-store" };

// The two install commands as copyable blocks: one click selects a whole
// command (CSS user-select: all; there is no script to copy with).
// With `copyId`, the block gets that id and a Copy button (see COPY_SCRIPT in
// html.ts; only on pages that include the script).
function cmdBlock(L: I18n, title: Key, sub: Key, script: string, filename: string, text: string, big: boolean, copyId?: string) {
  return html`<div class="cmd${big ? " big" : ""}"><div class="cmd-h"><b>${L.t(title)}</b><span>${L.t(sub)}</span>${
    copyId ? copyButton(L, copyId, "copy.command") : ""
  }</div><p><a href="${script}" rel="noreferrer">${filename}</a> · ${L.t("inv.reviewScript")}</p><code tabindex="0"${copyId ? html` id="${copyId}"` : ""}>${text}</code></div>`;
}

export function shBlock(L: I18n, c: InstallCommands, big = false, copyId?: string) {
  return cmdBlock(L, "inv.cmdUnix", "inv.cmdTerminal", c.shURL, "install.sh", c.sh, big, copyId);
}

export function ps1Block(L: I18n, c: InstallCommands, big = false, copyId?: string) {
  return cmdBlock(L, "inv.cmdWindows", "inv.cmdPowerShell", c.ps1URL, "install.ps1", c.ps1, big, copyId);
}

export function commandBlock(L: I18n, c: InstallCommands, copyPrefix?: string) {
  return html`${shBlock(L, c, false, copyPrefix && `${copyPrefix}-sh`)}${ps1Block(L, c, false, copyPrefix && `${copyPrefix}-ps1`)}`;
}

type Platform = "mac" | "windows" | "linux" | "";

// platformOf guesses the visitor's OS from the User-Agent, only to put their
// command first. Phones and anything unknown get the default order.
function platformOf(ua: string): Platform {
  if (/iPhone|iPad|iPod|Android/i.test(ua)) return "";
  if (/Windows/i.test(ua)) return "windows";
  if (/Macintosh|Mac OS X/i.test(ua)) return "mac";
  if (/Linux|X11|CrOS/i.test(ua)) return "linux";
  return "";
}

function inviteSteps(L: I18n, p: Platform) {
  const open = L.t(p === "windows" ? "inv.winOpen" : p === "mac" ? "inv.macOpen" : "inv.linuxOpen");
  return html`<ol class="steps"><li><span>${open}</span></li>
<li><span>${L.t("inv.follow")}</span></li></ol>`;
}

export function tooManyRequests(L: I18n, retryAfter: number): Response {
  return page(layout(L, L.s("slow.title"), null, html`<h1>${L.t("slow.h1")}</h1><p>${L.t("slow.text")}</p>`, undefined, SELF), 429, {
    ...CAPABILITY_HEADERS,
    "retry-after": String(retryAfter),
  });
}

// GET /i/<code>: a page for the person who got the invite. It reads the
// invite's state but never consumes it, shows no email or role, and is
// rate-limited like /enroll's sibling buckets.
export async function invitePage(req: Request, env: Env, code: string, now = new Date(), L: I18n = forRequest(req)): Promise<Response> {
  const rl = await hit(env, req, "page", now.getTime());
  if (!rl.ok) return tooManyRequests(L, rl.retryAfter);
  const ok = CODE_RE.test(code);
  const h = await sha256hex(code);
  const inv = ok
    ? await env.DB.prepare("SELECT used_at, revoked_at, expires_at FROM invites WHERE code_hash = ?")
        .bind(h)
        .first<{ used_at: string | null; revoked_at: string | null; expires_at: string }>()
    : null;
  let state: Key | "" = "";
  if (!inv) state = "inv.invalid";
  else if (inv.revoked_at) state = "inv.cancelled";
  else if (inv.used_at) state = "inv.used";
  else if (inv.expires_at <= now.toISOString()) state = "inv.expired";
  if (state) {
    return page(
      layout(L, L.s("inv.badTitle"), null, html`<div class="center-card"><span class="mark lg">${MARK}</span><p class="eyebrow">${L.t("inv.badEyebrow")}</p><h1>${L.t("inv.badH1")}</h1>
<p class="lead">${L.t("inv.badLead", { state: L.t(state) })}</p></div>`, undefined, SELF),
      404,
      CAPABILITY_HEADERS,
    );
  }
  const c = installCommands(env, new URL(req.url).origin, code);
  const p = platformOf(req.headers.get("user-agent") ?? "");
  const windowsFirst = p === "windows";
  const here = p === "mac" ? "inv.hereMac" : p === "windows" ? "inv.hereWindows" : p === "linux" ? "inv.hereLinux" : "inv.hereAny";
  const body = html`<span class="mark lg">${MARK}</span><p class="eyebrow">${L.t("inv.eyebrow")}</p><h1>${L.t("inv.title")}</h1>
<p class="lead">${L.t("inv.lead")}</p>
<div class="chips"><span class="chip">${L.t("inv.single")}</span><span class="chip">${L.t("inv.expires", { date: L.day(inv!.expires_at.slice(0, 10)) })}</span></div>
<h2>${L.t(here)}</h2>
${p === "" ? html`<p class="dim">${L.t("inv.runOne")}</p>` : inviteSteps(L, p)}
${windowsFirst ? ps1Block(L, c, true, "cmd-ps1") : shBlock(L, c, true, "cmd-sh")}
${p === ""
    ? (windowsFirst ? shBlock(L, c, true, "cmd-sh") : ps1Block(L, c, true, "cmd-ps1"))
    : html`<details class="alt"><summary>${windowsFirst ? L.t("inv.otherMac") : L.t("inv.otherWindows")}</summary><div>${
        windowsFirst ? html`${inviteSteps(L, "mac")}${shBlock(L, c, false, "cmd-sh-alt")}` : html`${inviteSteps(L, "windows")}${ps1Block(L, c, false, "cmd-ps1-alt")}`
      }</div></details>`}
<p class="foot">${L.t("inv.foot")}</p>`;
  return page(layout(L, L.s("inv.title"), null, body, undefined, { ...SELF, copy: true }), 200, { ...CAPABILITY_HEADERS, ...COPY_HEADERS });
}
