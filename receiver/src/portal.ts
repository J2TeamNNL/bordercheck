// The enrollment portal's admin pages: roles, invites, the audit trail, and
// the enrollment part of a machine's page (role, source invite,
// revoke/restore, waivers, report link). Auth and same-origin checks are done
// by the /admin router in index.ts before anything here runs.
//
// The shared write operations return their errors as messages (Msg), so the
// dashboard shows them in the admin's language and the MCP server in English.

import samplePolicy from "./sample-policy.json";
import { audit, auditStmt, auditStmtIf, MCP_ACTOR, MCP_READ_ACTOR } from "./audit";
import { commandBlock, installCommands, publicOrigin } from "./enroll";
import { config, DAY, type Env } from "./env";
import { COPY_HEADERS, copyButton, html, Html, layout, note, page, pill } from "./html";
import { type I18n, type Key, type Msg, msg } from "./i18n";
import { CHECK_ID_RE, POLICY_CHECKS, today, validateRolePolicy, waiverDateError } from "./roles";
import { newCode, sha256hex } from "./tokens";

const MAX_ROLE_POLICY = 256 * 1024;
const MAX_BULK = 500;
const EMAIL_RE = /^[^\s@<>"'(),;:\\]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/;

const machineLink = (id: string) => `/admin/machine/${encodeURIComponent(id)}`;

function cleanLine(s: string, max: number): string {
  return s.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, max);
}

// ---- Roles ----

interface RoleRow {
  id: number;
  name: string;
  policy: string;
  created_at: string;
  updated_at: string;
}

// What the new-role form starts with: every check with its main settings
// spelled out at their defaults, to edit. internal/policy has a test that
// bordercheck accepts it.
export const SAMPLE_POLICY = JSON.stringify(samplePolicy, null, 2);

// roleRows: every role with its active machines and pending invites.
export async function roleRows(env: Env) {
  const rows = await env.DB.prepare(
    `SELECT r.id, r.name, r.updated_at,
       (SELECT COUNT(*) FROM enrollments e WHERE e.role_id = r.id AND e.revoked_at IS NULL) AS machines,
       (SELECT COUNT(*) FROM invites i WHERE i.role_id = r.id AND i.used_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > ?) AS pending
     FROM roles r ORDER BY r.name`,
  )
    .bind(new Date().toISOString())
    .all<{ id: number; name: string; updated_at: string; machines: number; pending: number }>();
  return rows.results;
}

export async function rolesPage(env: Env, who: string, L: I18n, message: string | Html = "", draft?: { name: string; policy: string }, status = 200) {
  const rows = await roleRows(env);
  const body = html`<div class="hero"><p class="eyebrow">${L.t("enrollment.eyebrow")}</p><h1>${L.t("nav.roles")}</h1>
<p class="lead">${L.t("roles.lead")}</p></div>
${note(message, tone(status))}
${rows.length
    ? html`<div class="shelf-row">${rows.map(
        (r) => html`<a class="card" href="/admin/roles/${r.id}"><span class="t">${r.name}</span><span class="muted small">${L.t("roles.updated", { date: L.day(r.updated_at.slice(0, 10)) })}</span>
<span class="meta"><span class="big plain">${L.num(r.machines)}</span>${L.t("roles.machines", { n: r.machines })}${r.pending ? L.t("roles.pending", { n: r.pending }) : ""}</span></a>`,
      )}</div>`
    : html`<div class="panel"><p class="muted">${L.t("roles.empty")}</p></div>`}
<details class="adder" id="new-role"${draft || rows.length === 0 ? new Html(" open") : ""}><summary class="btn primary">${L.t("roles.add")}</summary>
<h2>${L.t("roles.new")}</h2>
${roleForm(L, "/admin/roles", draft?.name ?? "", draft?.policy ?? SAMPLE_POLICY, L.t("roles.create"), L.t("roles.intro"))}</details>`;
  return page(layout(L, L.s("nav.roles"), who, body, "Roles"), status);
}

// Messages after a form: an error when the response is one, else a confirmation.
const tone = (status: number) => (status >= 400 ? "s-fail" : "s-pass");

function roleForm(L: I18n, action: string, name: string, policy: string, label: Html, intro: Html | string = ""): Html {
  return html`<form method="post" action="${action}"><div class="cols"><div class="panel">
<div class="field"><label for="role-name">${L.t("roles.name")}</label><input id="role-name" name="name" value="${name}" maxlength="64" required class="w-name"></div>
<label for="role-policy">${L.t("roles.policy")}</label><textarea id="role-policy" class="code" name="policy" spellcheck="false">${policy}</textarea>
<div class="actions"><button class="primary">${label}</button></div></div>
<aside class="panel">${intro ? html`<p>${intro}</p>` : ""}<h3>${L.t("roles.checkedHere")}</h3>
<p class="muted small">${L.t("roles.checkedText")}</p>
<h3>${L.t("roles.notChecked")}</h3>
<p class="muted small">${L.t("roles.notCheckedText")}</p>
<div class="cmd"><code>bordercheck -policy role.json -print-policy</code></div></aside></div></form>`;
}

async function checkRole(env: Env, name: string, policyText: string, now: Date): Promise<{ errs: Msg[]; policy?: string }> {
  const errs: Msg[] = [];
  if (!name) errs.push(msg("err.roleName"));
  if (policyText.length > MAX_ROLE_POLICY) return { errs: [...errs, msg("err.policyTooLarge")] };
  let p: unknown;
  try {
    p = JSON.parse(policyText);
  } catch (e) {
    // The parser's own message (English, from the runtime) is a parameter.
    return { errs: [...errs, msg("err.badJson", { detail: (e as Error).message })] };
  }
  errs.push(...validateRolePolicy(p, now));
  return { errs, policy: JSON.stringify(p, null, 2) };
}

function errorList(L: I18n, head: Key, errs: Msg[]): Html {
  return html`${L.t(head)}<ul>${errs.slice(0, 50).map((e) => html`<li>${L.m(e)}</li>`)}</ul>`;
}

// ---- Shared write operations ----
//
// The dashboard's forms and the MCP tools (mcp.ts) both go through these, so
// validation, atomicity, limits and the audit trail are the same whichever
// way a change is made. `extra` is merged into the audit row's detail (the MCP
// server records the tool name and its arguments there).

export type AuditExtra = Record<string, unknown>;
export type OpResult<T> = ({ ok: true } & T) | { ok: false; status: number; errors: Msg[] };

// saveRole creates a role (no id) or updates one (id): same checks either way.
export async function saveRole(
  env: Env,
  who: string,
  input: { id?: number; name: string; policyText: string },
  extra: AuditExtra = {},
): Promise<OpResult<{ id: number; name: string; policyChanged: boolean }>> {
  const now = new Date();
  const name = cleanLine(input.name, 64);
  const old = input.id === undefined
    ? null
    : await env.DB.prepare("SELECT name, policy FROM roles WHERE id = ?").bind(input.id).first<{ name: string; policy: string }>();
  if (input.id !== undefined && !old) return { ok: false, status: 404, errors: [msg("err.noSuchRole")] };
  const { errs, policy } = await checkRole(env, name, input.policyText, now);
  if (errs.length) return { ok: false, status: 400, errors: errs };
  const ts = now.toISOString();
  if (input.id === undefined) {
    const exists = await env.DB.prepare("SELECT id FROM roles WHERE name = ?").bind(name).first();
    if (exists) return { ok: false, status: 400, errors: [msg("err.roleExists")] };
    const id = await env.DB.prepare("INSERT INTO roles (name, policy, created_at, updated_at) VALUES (?, ?, ?, ?) RETURNING id")
      .bind(name, policy, ts, ts)
      .first<number>("id");
    await audit(env, who, "role.create", `role ${name}`, { role_id: id, ...extra });
    return { ok: true, id: id!, name, policyChanged: true };
  }
  const id = input.id;
  const clash = await env.DB.prepare("SELECT id FROM roles WHERE name = ? AND id != ?").bind(name, id).first();
  if (clash) return { ok: false, status: 400, errors: [msg("err.roleClash")] };
  const policyChanged = old!.policy !== policy;
  await env.DB.batch([
    env.DB.prepare("UPDATE roles SET name = ?, policy = ?, updated_at = ? WHERE id = ?").bind(name, policy, ts, id),
    auditStmt(env, who, "role.update", `role ${name}`, {
      role_id: id,
      renamed_from: old!.name !== name ? old!.name : undefined,
      policy_changed: policyChanged,
      ...extra,
    }),
  ]);
  return { ok: true, id, name, policyChanged };
}

export async function createRole(env: Env, who: string, form: FormData, L: I18n): Promise<Response> {
  const name = String(form.get("name") ?? "");
  const text = String(form.get("policy") ?? "");
  const r = await saveRole(env, who, { name, policyText: text });
  if (!r.ok) {
    const msgHtml = r.errors.length === 1 && r.errors[0].key === "err.roleExists" ? L.m(r.errors[0]) : errorList(L, "roles.notSaved", r.errors);
    return rolesPage(env, who, L, msgHtml, { name: cleanLine(name, 64), policy: text }, 400);
  }
  return rolesPage(env, who, L, L.t("roles.created", { name: r.name }));
}

export async function rolePage(env: Env, id: number, who: string, L: I18n, message: string | Html = "", draft?: { name: string; policy: string }, status = 200) {
  const r = await env.DB.prepare("SELECT * FROM roles WHERE id = ?").bind(id).first<RoleRow>();
  if (!r) return noSuchRole(L, who);
  const machines = await env.DB.prepare(
    `SELECT e.install_id, e.email, e.hostname, e.revoked_at FROM enrollments e WHERE e.role_id = ? ORDER BY e.email LIMIT 500`,
  )
    .bind(id)
    .all<{ install_id: string; email: string; hostname: string; revoked_at: string | null }>();
  const n = machines.results.length;
  const body = html`<div class="hero"><p class="eyebrow"><a href="/admin/roles">${L.t("nav.roles")}</a> · ${L.t("role.crumb")}</p><h1>${r.name}</h1>
<p class="lead">${L.t("role.lead", { n, when: L.when(r.updated_at) })}</p></div>
${note(message, tone(status))}
${roleForm(L, `/admin/roles/${r.id}`, draft?.name ?? r.name, draft?.policy ?? r.policy, L.t("role.save"), L.t("role.intro"))}
<h2>${L.t("role.machines", { n })}</h2>
${n
    ? html`<div class="panel flush"><div class="scroll"><table><thead><tr><th>${L.t("common.personMachine")}</th><th>${L.t("common.status")}</th></tr></thead><tbody>${machines.results.map(
        (m) => html`<tr${m.revoked_at ? html` class="off"` : ""}><td class="who-cell"><a href="${machineLink(m.install_id)}">${m.email}</a><span class="sub">${m.hostname}</span></td><td>${m.revoked_at ? pill("s-fail", L.t("state.revoked")) : pill("s-pass", L.t("state.active"))}</td></tr>`,
      )}</tbody></table></div></div>`
    : html`<div class="panel"><p class="muted">${L.t("common.noneYet")}</p></div>`}
<h2>${L.t("role.delete")}</h2>
<div class="panel danger-zone"><p class="muted">${L.t("role.deleteText")}</p>
<form method="post" action="/admin/roles/${r.id}/delete"><button class="danger">${L.t("role.deleteButton")}</button></form></div>`;
  return page(layout(L, r.name, who, body, "Roles"), status);
}

function noSuchRole(L: I18n, who: string): Response {
  return page(layout(L, L.s("common.notFound"), who, html`<h1>${L.t("role.noSuch")}</h1>`, "Roles"), 404);
}

export async function updateRole(env: Env, id: number, who: string, form: FormData, L: I18n): Promise<Response> {
  const name = String(form.get("name") ?? "");
  const text = String(form.get("policy") ?? "");
  const r = await saveRole(env, who, { id, name, policyText: text });
  if (!r.ok) {
    if (r.status === 404) return noSuchRole(L, who);
    const msgHtml = r.errors.length === 1 && r.errors[0].key === "err.roleClash" ? L.m(r.errors[0]) : errorList(L, "roles.notSaved", r.errors);
    return rolePage(env, id, who, L, msgHtml, { name: cleanLine(name, 64), policy: text }, 400);
  }
  return rolePage(env, id, who, L, L.t("role.saved"));
}

export async function deleteRole(env: Env, id: number, who: string, L: I18n): Promise<Response> {
  const r = await env.DB.prepare("SELECT name FROM roles WHERE id = ?").bind(id).first<{ name: string }>();
  if (!r) return noSuchRole(L, who);
  const used = await env.DB.prepare(
    `SELECT (SELECT COUNT(*) FROM enrollments WHERE role_id = ?1) + (SELECT COUNT(*) FROM invites WHERE role_id = ?1) AS n`,
  )
    .bind(id)
    .first<number>("n");
  if (used) return rolePage(env, id, who, L, L.t("role.inUse"), undefined, 409);
  await env.DB.batch([env.DB.prepare("DELETE FROM roles WHERE id = ?").bind(id), auditStmt(env, who, "role.delete", `role ${r.name}`, { role_id: id })]);
  return rolesPage(env, who, L, L.t("roles.deleted", { name: r.name }));
}

// ---- Invites ----

const STATUS_SQL = `CASE WHEN i.revoked_at IS NOT NULL THEN 'revoked' WHEN i.used_at IS NOT NULL THEN 'used'
  WHEN i.expires_at <= ?1 THEN 'expired' ELSE 'pending' END`;
const INVITE_FILTERS = ["pending", "used", "expired", "revoked", "all"] as const;
const INVITE_KEY: Record<string, Key> = {
  pending: "invite.pending", used: "invite.used", expired: "invite.expired", revoked: "invite.revoked", all: "invites.all",
};

export interface InviteRow {
  id: number;
  email: string;
  role: string;
  note: string;
  created_at: string;
  created_by: string;
  expires_at: string;
  used_at: string | null;
  used_install_id: string | null;
  revoked_at: string | null;
  reissued_as: number | null;
  status: string;
}

async function roleOptions(env: Env, selected?: number): Promise<Html> {
  const roles = await env.DB.prepare("SELECT id, name FROM roles ORDER BY name").all<{ id: number; name: string }>();
  return html`${roles.results.map((r) => html`<option value="${r.id}" ${r.id === selected ? "selected" : ""}>${r.name}</option>`)}`;
}

export type InviteFilter = (typeof INVITE_FILTERS)[number];
export const isInviteFilter = (f: string): f is InviteFilter => (INVITE_FILTERS as readonly string[]).includes(f);

// inviteRows lists invites by state, newest first, with per-state counts.
// Never selects code_hash.
export async function inviteRows(env: Env, filter: InviteFilter, limit: number): Promise<{ rows: InviteRow[]; counts: Record<string, number> }> {
  const nowIso = new Date().toISOString();
  const rows = await env.DB.prepare(
    `SELECT i.id, i.email, r.name AS role, i.note, i.created_at, i.created_by, i.expires_at, i.used_at, i.used_install_id,
            i.revoked_at, i.reissued_as, ${STATUS_SQL} AS status
     FROM invites i JOIN roles r ON r.id = i.role_id
     WHERE ?2 = 'all' OR ${STATUS_SQL} = ?2
     ORDER BY i.id DESC LIMIT ?3`,
  )
    .bind(nowIso, filter, limit)
    .all<InviteRow>();
  const counts = await env.DB.prepare(`SELECT ${STATUS_SQL} AS status, COUNT(*) AS n FROM invites i GROUP BY 1`)
    .bind(nowIso)
    .all<{ status: string; n: number }>();
  const c: Record<string, number> = { pending: 0, used: 0, expired: 0, revoked: 0 };
  for (const r of counts.results) c[r.status] = r.n;
  return { rows: rows.results, counts: c };
}

export async function invitesPage(env: Env, url: URL, who: string, L: I18n, message: string | Html = "", status = 200): Promise<Response> {
  const f = url.searchParams.get("status") ?? "pending";
  const filter = isInviteFilter(f) ? f : "pending";
  const { rows: inviteList, counts } = await inviteRows(env, filter, 1000);
  const rows = { results: inviteList };
  const count = (s: string) => counts[s] ?? 0;
  const options = await roleOptions(env);
  const cfg = config(env);
  const inviteWord = (s: string) => (INVITE_KEY[s] ? L.t(INVITE_KEY[s]) : s);

  const now = Date.now();
  const body = html`<div class="hero"><p class="eyebrow">${L.t("enrollment.eyebrow")}</p><h1>${L.t("nav.invites")}</h1>
<p class="lead">${L.t("invites.lead")}</p></div>
${note(message, tone(status))}
<h2 id="new">${L.t("invites.new")}</h2>
${options.value ? html`<form method="post" action="/admin/invites"><div class="panel"><div class="cols">
<div class="field"><label for="inv-emails">${L.t("invites.emails")}</label><textarea id="inv-emails" class="emails" name="emails" rows="6" spellcheck="false" required placeholder="an@acme.com&#10;bo@acme.com"></textarea></div>
<div><div class="field"><label for="inv-role">${L.t("common.role")}</label><select id="inv-role" name="role_id" class="full">${options}</select></div>
<div class="field"><label for="inv-days">${L.t("invites.expires")}</label><input id="inv-days" name="days" type="number" min="1" max="90" value="${cfg.inviteDays}"></div>
<div class="field"><label for="inv-note">${L.t("invites.note")}</label><input id="inv-note" name="note" maxlength="200" class="full"></div></div></div>
<div class="actions"><button class="primary">${L.t("invites.create")}</button><span class="muted small">${L.t("invites.atMost", { n: MAX_BULK })}</span></div></div></form>`
    : html`<div class="panel"><p>${L.t("invites.needRole", { link: html`<a href="/admin/roles">${L.t("invites.createRole")}</a>` })}</p></div>`}
<div class="shelf"><h2>${L.t("invites.sent")}</h2></div>
<div class="toolbar"><nav class="seg" aria-label="${L.s("common.status")}">${INVITE_FILTERS.map(
    (s) => html`<a class="${s === filter ? "on" : ""}" href="/admin/invites?status=${s}">${inviteWord(s)}${s !== "all" ? html`<span class="c">${L.num(count(s))}</span>` : ""}</a>`,
  )}</nav></div>
<div class="panel flush"><div class="scroll"><table><thead><tr><th class="n">#</th><th>${L.t("invites.thPerson")}</th><th>${L.t("common.role")}</th><th>${L.t("common.status")}</th><th>${L.t("invites.thCreated")}</th><th>${L.t("invites.thExpires")}</th><th></th></tr></thead><tbody>
${rows.results.map(
    (i) => html`<tr${i.status === "revoked" || i.status === "expired" ? html` class="off"` : ""}><td class="n muted">${i.id}</td><td class="who-cell"><b>${i.email}</b>${i.note ? html`<span class="sub">${i.note}</span>` : ""}</td><td>${i.role}</td>
<td class="nowrap">${pill(INVITE_TONE[i.status] ?? "s-other", inviteWord(i.status))}${i.used_install_id ? html`<span class="sub"><a class="u" href="${machineLink(i.used_install_id)}">${L.t("invites.machine")}</a></span>` : ""}${i.reissued_as ? html`<span class="sub">${L.t("invites.reissuedAs", { id: i.reissued_as })}</span>` : ""}</td>
<td class="nowrap">${L.when(i.created_at)}<span class="sub">${i.created_by}</span></td><td class="nowrap">${L.when(i.expires_at)}${i.status === "pending" ? html`<span class="sub">${L.inDays(i.expires_at, now)}</span>` : ""}</td>
<td class="nowrap">${i.status === "pending" ? html`<form class="inline" method="post" action="/admin/invites/${i.id}/revoke"><button class="sm">${L.t("invites.revoke")}</button></form> ` : ""}${
      i.status !== "used" && !i.reissued_as ? html`<form class="inline" method="post" action="/admin/invites/${i.id}/reissue"><button class="sm">${L.t("invites.reissue")}</button></form>` : ""
    }</td></tr>`,
  )}</tbody></table></div>${rows.results.length === 0 ? html`<p class="empty">${L.t("common.none")}</p>` : ""}</div>`;
  return page(layout(L, L.s("nav.invites"), who, body, "Invites"), status);
}

const INVITE_TONE: Record<string, string> = { pending: "s-waived", used: "s-pass", expired: "s-skip", revoked: "s-fail" };

export function parseEmails(text: string): { ok: string[]; bad: string[] } {
  const ok: string[] = [];
  const bad: string[] = [];
  for (const raw of text.split(/[\s,;]+/)) {
    const e = raw.trim().toLowerCase();
    if (!e) continue;
    if (e.length > 254 || !EMAIL_RE.test(e)) bad.push(raw.slice(0, 100));
    else if (!ok.includes(e)) ok.push(e);
  }
  return { ok, bad };
}

export interface Issued {
  id: number;
  email: string;
  code: string;
  expires: string; // ISO time
}

async function issueInvites(env: Env, who: string, emails: string[], roleId: number, days: number, note: string, now: Date): Promise<Issued[]> {
  const ts = now.toISOString();
  const expires = new Date(now.getTime() + days * DAY).toISOString();
  const out: Issued[] = [];
  const stmts: D1PreparedStatement[] = [];
  const pending: { email: string; code: string; hash: string }[] = [];
  for (const email of emails) {
    const code = newCode();
    pending.push({ email, code, hash: await sha256hex(code) });
  }
  for (const p of pending) {
    stmts.push(
      env.DB.prepare(
        "INSERT INTO invites (code_hash, email, role_id, note, created_at, created_by, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
      ).bind(p.hash, p.email, roleId, note, ts, who.slice(0, 200), expires),
    );
  }
  const res = await env.DB.batch<{ id: number }>(stmts);
  res.forEach((r, i) => out.push({ id: r.results[0].id, email: pending[i].email, code: pending[i].code, expires }));
  return out;
}

// The page with freshly made codes. It has no language switcher: it exists
// only as the answer to a POST, and switching would reload the invite list
// and lose the codes.
function issuedPage(env: Env, req: Request, who: string, L: I18n, issued: Issued[], title: string, extra: Html | string = ""): Response {
  const heading = title;
  const origin = publicOrigin(env, req);
  const body = html`<div class="hero"><p class="eyebrow"><a href="/admin/invites">${L.t("nav.invites")}</a></p><h1>${heading}</h1></div>
${note(L.t("issued.copy"), "s-warn")}
${extra}
${issued.map((i) => {
    const c = installCommands(env, origin, i.code);
    // Ids come from the invite's number only, never from its text.
    const id = `inv-${i.id}`;
    // The message is plain text in the admin's language, escaped like any other value.
    const message = L.s("issued.messageText", { link: c.link, date: L.day(i.expires.slice(0, 10)) });
    return html`<h2>${i.email} <span class="muted">#${i.id}</span></h2>
<div class="panel"><div class="cmd"><div class="cmd-h"><b>${L.t("issued.link")}</b><span>${L.t("issued.linkSub")}</span>${copyButton(L, `${id}-link`, "copy.link")}</div><code tabindex="0" id="${id}-link">${c.link}</code></div>
${commandBlock(L, c, id)}
<div class="cmd"><div class="cmd-h"><b>${L.t("issued.message")}</b><span>${L.t("issued.messageSub")}</span>${copyButton(L, `${id}-msg`, "copy.message")}</div><code tabindex="0" class="msg" id="${id}-msg">${message}</code></div></div>`;
  })}
<div class="actions"><a class="btn" href="/admin/invites">${L.t("issued.back")}</a></div>`;
  // The one admin page with a script (COPY_SCRIPT): its CSP allows exactly that script.
  return page(layout(L, title, who, body, "Invites", { switcher: false, copy: true }), 200, COPY_HEADERS);
}

// createInviteBatch validates and issues invites for the given emails (text:
// one per line or comma-separated, parsed by parseEmails). Nothing is created
// unless all of them are valid. The codes are in the result only: they are
// never stored, logged or audited.
export async function createInviteBatch(
  env: Env,
  who: string,
  input: { emails: string; roleId: number; days: number; note: string },
  opts: { maxBulk?: number; extra?: AuditExtra } = {},
): Promise<OpResult<{ issued: Issued[]; role: string; days: number }>> {
  const cfg = config(env);
  const maxBulk = Math.min(opts.maxBulk ?? MAX_BULK, MAX_BULK);
  const { ok, bad } = parseEmails(input.emails);
  const roleId = input.roleId;
  const days = input.days;
  const noteText = cleanLine(input.note, 200);
  const role = Number.isInteger(roleId) ? await env.DB.prepare("SELECT id, name FROM roles WHERE id = ?").bind(roleId).first<{ id: number; name: string }>() : null;
  const problems: Msg[] = [];
  if (!role) problems.push(msg("err.pickRole"));
  if (bad.length) problems.push(msg("err.notEmails", { list: `${bad.slice(0, 20).join(", ")}${bad.length > 20 ? "…" : ""}` }));
  if (!ok.length && !bad.length) problems.push(msg("err.noEmails"));
  if (ok.length > maxBulk) problems.push(msg("err.tooMany", { n: maxBulk }));
  if (!Number.isInteger(days) || days < 1 || days > 90) problems.push(msg("err.expiry"));
  if (cfg.emailDomains.length) {
    const outside = ok.filter((e) => !cfg.emailDomains.includes(e.split("@")[1]));
    if (outside.length) problems.push(msg("err.outsideDomains", { list: outside.slice(0, 20).join(", ") }));
  }
  if (problems.length) return { ok: false, status: 400, errors: problems };

  const now = new Date();
  const issued = await issueInvites(env, who, ok, role!.id, days, noteText, now);
  await audit(env, who, ok.length > 1 ? "invite.bulk_create" : "invite.create", `role ${role!.name}`, {
    invites: issued.map((i) => ({ id: i.id, email: i.email })),
    days,
    ...opts.extra,
  });
  return { ok: true, issued, role: role!.name, days };
}

export async function createInvites(env: Env, req: Request, url: URL, who: string, form: FormData, L: I18n): Promise<Response> {
  const cfg = config(env);
  const daysIn = Number(form.get("days") || cfg.inviteDays);
  const days = Number.isFinite(daysIn) && daysIn >= 1 && daysIn <= 90 ? Math.floor(daysIn) : cfg.inviteDays;
  const r = await createInviteBatch(env, who, {
    emails: String(form.get("emails") ?? ""),
    roleId: Number(form.get("role_id")),
    days,
    note: String(form.get("note") ?? ""),
  });
  if (!r.ok) return invitesPage(env, url, who, L, errorList(L, "invites.nothingCreated", r.errors), 400);
  const n = r.issued.length;
  return issuedPage(env, req, who, L, r.issued, n === 1 ? L.s("issued.one") : L.s("issued.many", { n }));
}

export async function revokeInviteOp(env: Env, who: string, id: number, extra: AuditExtra = {}): Promise<OpResult<{ email: string }>> {
  const ts = new Date().toISOString();
  const inv = await env.DB.prepare("SELECT email FROM invites WHERE id = ?").bind(id).first<{ email: string }>();
  if (!inv) return { ok: false, status: 404, errors: [msg("err.noSuchInvite")] };
  // The audit row is written only if this request's UPDATE revoked it.
  const res = await env.DB.batch([
    env.DB.prepare("UPDATE invites SET revoked_at = ?, revoked_by = ? WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL").bind(ts, who, id),
    auditStmtIf(env, { sql: "SELECT 1 FROM invites WHERE id = ? AND revoked_at = ? AND revoked_by = ? AND reissued_as IS NULL", binds: [id, ts, who] },
      who, "invite.revoke", `invite #${id}`, { email: inv.email, ...extra }),
  ]);
  if (res[0].meta.changes !== 1) return { ok: false, status: 409, errors: [msg("err.inviteUsedOrRevoked", { id })] };
  return { ok: true, email: inv.email };
}

export async function revokeInvite(env: Env, url: URL, who: string, id: number, L: I18n): Promise<Response> {
  const r = await revokeInviteOp(env, who, id);
  if (!r.ok) return invitesPage(env, url, who, L, L.m(r.errors[0]), r.status);
  return invitesPage(env, url, who, L, L.t("invites.revoked", { id }));
}

export async function reissueInviteOp(env: Env, who: string, id: number, extra: AuditExtra = {}): Promise<OpResult<{ issued: Issued }>> {
  const inv = await env.DB.prepare("SELECT id, email, role_id, note, used_at, reissued_as FROM invites WHERE id = ?")
    .bind(id)
    .first<{ id: number; email: string; role_id: number; note: string; used_at: string | null; reissued_as: number | null }>();
  if (!inv) return { ok: false, status: 404, errors: [msg("err.noSuchInvite")] };
  if (inv.used_at || inv.reissued_as) return { ok: false, status: 409, errors: [msg("err.inviteNotReissuable", { id })] };
  const now = new Date();
  const ts = now.toISOString();
  // Revoke the old one first; only the request that does so issues the new one.
  const claim = await env.DB.prepare(
    "UPDATE invites SET revoked_at = COALESCE(revoked_at, ?1), revoked_by = COALESCE(revoked_by, ?2), reissued_as = -1 WHERE id = ?3 AND used_at IS NULL AND reissued_as IS NULL",
  )
    .bind(ts, who, id)
    .run();
  if (claim.meta.changes !== 1) return { ok: false, status: 409, errors: [msg("err.inviteRaced", { id })] };
  const [n] = await issueInvites(env, who, [inv.email], inv.role_id, config(env).inviteDays, inv.note, now);
  await env.DB.batch([
    env.DB.prepare("UPDATE invites SET reissued_as = ? WHERE id = ?").bind(n.id, id),
    auditStmt(env, who, "invite.reissue", `invite #${id}`, { email: inv.email, new_invite: n.id, ...extra }),
  ]);
  return { ok: true, issued: n };
}

export async function reissueInvite(env: Env, req: Request, url: URL, who: string, id: number, L: I18n): Promise<Response> {
  const r = await reissueInviteOp(env, who, id);
  if (!r.ok) return invitesPage(env, url, who, L, L.m(r.errors[0]), r.status);
  return issuedPage(env, req, who, L, [r.issued], L.s("issued.reissued"), html`<p class="muted">${L.t("issued.oldGone", { id })}</p>`);
}

// ---- Machines: enrollment, role, revoke, waivers, report link ----

interface EnrollmentRow {
  install_id: string;
  email: string;
  role_id: number;
  role: string;
  invite_id: number | null;
  invite_by: string | null;
  invite_note: string | null;
  hostname: string;
  os: string;
  arch: string;
  version: string;
  enrolled_at: string;
  revoked_at: string | null;
  revoked_by: string | null;
  last_policy_at: string | null;
}

export async function enrollmentOf(env: Env, id: string): Promise<EnrollmentRow | null> {
  return env.DB.prepare(
    `SELECT e.install_id, e.email, e.role_id, r.name AS role, e.invite_id, i.created_by AS invite_by, i.note AS invite_note,
            e.hostname, e.os, e.arch, e.version, e.enrolled_at, e.revoked_at, e.revoked_by, e.last_policy_at
     FROM enrollments e JOIN roles r ON r.id = e.role_id LEFT JOIN invites i ON i.id = e.invite_id WHERE e.install_id = ?`,
  )
    .bind(id)
    .first<EnrollmentRow>();
}

export async function enrollmentSection(L: I18n, env: Env, id: string, e: EnrollmentRow | null, now: Date): Promise<Html> {
  const linkForm = html`<h2>${L.t("enr.linkTitle")}</h2>
<div class="panel"><p class="muted">${L.t("enr.linkText")}</p>
<form method="post" action="${machineLink(id)}/reset-link"><button>${L.t("enr.linkReset")}</button></form></div>`;
  if (!e) return html`<h2>${L.t("enr.title")}</h2><div class="panel"><p class="muted">${L.t("enr.none")}</p></div>${linkForm}`;
  const [waivers, options] = await Promise.all([
    env.DB.prepare("SELECT * FROM machine_waivers WHERE install_id = ? ORDER BY removed_at IS NOT NULL, until DESC LIMIT 200")
      .bind(id)
      .all<{ id: number; check_id: string; until: string; reason: string; created_at: string; created_by: string; removed_at: string | null; removed_by: string | null }>(),
    roleOptions(env, e.role_id),
  ]);
  const t = today(now);
  const active = waivers.results.filter((w) => !w.removed_at && w.until >= t).length;
  return html`<h2>${L.t("enr.title")}</h2>
<div class="cols"><div class="panel"><dl class="facts">
<div><dt>${L.t("common.status")}</dt><dd>${e.revoked_at ? html`${pill("s-fail", L.t("state.revoked"))}<br><span class="muted small">${L.t("enr.revokedBy", { when: L.when(e.revoked_at), who: e.revoked_by })}</span>` : pill("s-pass", L.t("state.active"))}</dd></div>
<div><dt>${L.t("common.role")}</dt><dd>${e.role}</dd></div>
<div><dt>${L.t("enr.email")}</dt><dd>${e.email}<br><span class="muted small">${L.t("enr.emailSub")}</span></dd></div>
<div><dt>${L.t("enr.invite")}</dt><dd>${e.invite_id ? html`${L.t("enr.inviteBy", { id: e.invite_id, who: e.invite_by })}${e.invite_note ? html`<br><span class="muted small">${e.invite_note}</span>` : ""}` : "?"}</dd></div>
<div><dt>${L.t("enr.enrolled")}</dt><dd>${L.when(e.enrolled_at)}<br><span class="muted small">${L.t("enr.as", { host: e.hostname || "?", platform: `${e.os}/${e.arch}`, version: e.version || "?" })}</span></dd></div>
<div><dt>${L.t("enr.lastPolicy")}</dt><dd>${L.when(e.last_policy_at) || L.s("time.never")}${e.last_policy_at ? html`<br><span class="muted small">${L.ago(e.last_policy_at, now.getTime())}</span>` : ""}</dd></div></dl></div>
<div class="panel"><form method="post" action="${machineLink(id)}/role"><label for="m-role">${L.t("common.role")}</label><div class="row"><div class="grow"><select id="m-role" name="role_id">${options}</select></div><button>${L.t("enr.changeRole")}</button></div></form>
<div class="actions">${e.revoked_at
    ? html`<form method="post" action="${machineLink(id)}/restore"><button>${L.t("enr.restore")}</button></form><span class="muted small">${L.t("enr.restoreSub")}</span>`
    : html`<form method="post" action="${machineLink(id)}/revoke"><button class="danger">${L.t("enr.revoke")}</button></form><span class="muted small">${L.t("enr.revokeSub")}</span>`}</div></div></div>
<h2>${L.t("enr.waivers")}${active ? html` <span class="muted">${L.t("enr.active", { n: active })}</span>` : ""}</h2>
<p class="muted">${L.t("enr.waiversText")}</p>
${waivers.results.length
    ? html`<div class="panel flush"><div class="scroll"><table><thead><tr><th>${L.t("common.check")}</th><th>${L.t("enr.thUntil")}</th><th>${L.t("enr.thReason")}</th><th>${L.t("enr.thAdded")}</th><th></th></tr></thead><tbody>
${waivers.results.map(
        (w) => html`<tr${w.removed_at || w.until < t ? html` class="off"` : ""}><td><code>${w.check_id}</code></td><td class="nowrap">${L.day(w.until)}${w.until < t ? html`<span class="sub">${L.t("enr.ended")}</span>` : ""}${w.removed_at ? html`<span class="sub">${L.t("enr.removed")}</span>` : ""}</td><td class="wrap">${w.reason}</td>
<td class="nowrap">${L.when(w.created_at)}<span class="sub">${L.t("common.byWho", { who: w.created_by })}${w.removed_at ? L.t("enr.removedBy", { when: L.when(w.removed_at), who: w.removed_by }) : ""}</span></td>
<td>${w.removed_at ? "" : html`<form method="post" action="${machineLink(id)}/waivers/${w.id}/remove"><button class="sm">${L.t("enr.remove")}</button></form>`}</td></tr>`,
      )}</tbody></table></div></div>`
    : ""}
<form method="post" action="${machineLink(id)}/waivers"><div class="panel"><h3>${L.t("enr.add")}</h3><div class="row">
<div class="field"><label for="w-check">${L.t("common.check")}</label><select id="w-check" name="check">${POLICY_CHECKS.map((c) => html`<option>${c}</option>`)}</select></div>
<div class="field"><label for="w-until">${L.t("enr.thUntil")}</label><input id="w-until" type="date" name="until" required min="${t}"></div>
<div class="field grow"><label for="w-reason">${L.t("enr.thReason")}</label><input id="w-reason" name="reason" maxlength="300" required placeholder="${L.s("enr.reasonPlaceholder")}"></div>
<button>${L.t("enr.addButton")}</button></div></div></form>
${linkForm}`;
}

async function machineExists(env: Env, id: string): Promise<boolean> {
  return !!(await env.DB.prepare("SELECT 1 FROM enrollments WHERE install_id = ?1 UNION SELECT 1 FROM machines WHERE install_id = ?1").bind(id).first());
}

export type MachineAction = "revoke" | "restore" | "role" | "waivers" | "reset-link" | "remove-waiver";

export interface MachineParams {
  role_id?: number;
  check?: string;
  until?: string;
  reason?: string;
  waiver_id?: number;
}

export function machineParams(form: FormData, waiverId = 0): MachineParams {
  return {
    role_id: Number(form.get("role_id")),
    check: String(form.get("check") ?? ""),
    until: String(form.get("until") ?? ""),
    reason: String(form.get("reason") ?? ""),
    waiver_id: waiverId,
  };
}

// machineAction runs a write on one machine (from its dashboard page or an MCP
// tool) and returns an error message for the admin, or none on success.
// `extra` is merged into the audit row's detail.
export async function machineAction(
  env: Env,
  who: string,
  id: string,
  action: MachineAction,
  params: MachineParams,
  extra: AuditExtra = {},
): Promise<{ status: number; error?: Msg; detail?: Record<string, unknown> }> {
  const now = new Date();
  const ts = now.toISOString();
  const db = env.DB;
  const e = await db.prepare("SELECT install_id, role_id, revoked_at FROM enrollments WHERE install_id = ?").bind(id).first<{ install_id: string; role_id: number; revoked_at: string | null }>();
  if (action === "reset-link") {
    if (!(await machineExists(env, id))) return { status: 404, error: msg("err.noSuchMachine") };
    await db.batch([db.prepare("DELETE FROM report_links WHERE install_id = ?").bind(id), auditStmt(env, who, "machine.reset_link", id, { ...extra })]);
    return { status: 200 };
  }
  if (!e) return { status: 409, error: msg("err.notEnrolled") };
  switch (action) {
    case "revoke":
    case "restore": {
      const revoking = action === "revoke";
      // Either way, links issued so far stop working.
      await db.batch([
        revoking
          ? db.prepare("UPDATE enrollments SET revoked_at = ?, revoked_by = ? WHERE install_id = ? AND revoked_at IS NULL").bind(ts, who, id)
          : db.prepare("UPDATE enrollments SET revoked_at = NULL, revoked_by = NULL WHERE install_id = ?").bind(id),
        db.prepare("DELETE FROM report_links WHERE install_id = ?").bind(id),
        auditStmt(env, who, revoking ? "machine.revoke" : "machine.restore", id, { ...extra }),
      ]);
      return { status: 200 };
    }
    case "role": {
      const roleId = Number(params.role_id);
      const role = Number.isInteger(roleId) ? await db.prepare("SELECT id, name FROM roles WHERE id = ?").bind(roleId).first<{ id: number; name: string }>() : null;
      if (!role) return { status: 400, error: msg("err.noSuchRole") };
      const old = await db.prepare("SELECT name FROM roles WHERE id = ?").bind(e.role_id).first<string>("name");
      await db.batch([
        db.prepare("UPDATE enrollments SET role_id = ? WHERE install_id = ?").bind(role.id, id),
        auditStmt(env, who, "machine.change_role", id, { from: old, to: role.name, ...extra }),
      ]);
      return { status: 200, detail: { from: old, to: role.name } };
    }
    case "waivers": {
      const check = cleanLine(String(params.check ?? ""), 64);
      const until = cleanLine(String(params.until ?? ""), 16);
      const reason = cleanLine(String(params.reason ?? ""), 300);
      if (!CHECK_ID_RE.test(check) || !POLICY_CHECKS.includes(check)) {
        return { status: 400, error: msg("err.waiverCheck", { list: POLICY_CHECKS.join(", ") }) };
      }
      const dateErr = waiverDateError(until, now);
      if (dateErr) return { status: 400, error: msg("err.waiverNotAdded", { problem: dateErr }) };
      if (!reason) return { status: 400, error: msg("err.waiverReason") };
      const res = await db.batch([
        db.prepare("INSERT INTO machine_waivers (install_id, check_id, until, reason, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?) RETURNING id").bind(id, check, until, reason, ts, who),
        auditStmt(env, who, "waiver.add", id, { check, until, reason, ...extra }),
      ]);
      const waiverId = (res[0].results[0] as { id: number } | undefined)?.id;
      return { status: 200, detail: { waiver_id: waiverId, check, until, reason } };
    }
    case "remove-waiver": {
      const waiverId = Number(params.waiver_id ?? 0);
      const res = await db.batch([
        db.prepare("UPDATE machine_waivers SET removed_at = ?, removed_by = ? WHERE id = ? AND install_id = ? AND removed_at IS NULL").bind(ts, who, waiverId, id),
        auditStmtIf(env, { sql: "SELECT 1 FROM machine_waivers WHERE id = ? AND install_id = ? AND removed_at = ? AND removed_by = ?", binds: [waiverId, id, ts, who] },
          who, "waiver.remove", id, { waiver: waiverId, ...extra }),
      ]);
      return res[0].meta.changes === 1 ? { status: 200 } : { status: 404, error: msg("err.noSuchWaiver") };
    }
  }
  return { status: 400, error: msg("err.unknownAction") };
}

// ---- Audit ----

export interface AuditRow {
  id: number;
  at: string;
  who: string;
  action: string;
  target: string;
  detail: string;
}

// auditRows: newest first. mcpOnly keeps the rows written through the MCP
// server (actor "mcp" or "mcp (read-only)").
export async function auditRows(env: Env, limit: number, mcpOnly = false): Promise<AuditRow[]> {
  const rows = await env.DB.prepare(
    "SELECT id, at, who, action, target, detail FROM audit WHERE ?1 = 0 OR who IN (?2, ?3) ORDER BY id DESC LIMIT ?4",
  ).bind(mcpOnly ? 1 : 0, MCP_ACTOR, MCP_READ_ACTOR, limit).all<AuditRow>();
  return rows.results;
}

export async function auditPage(env: Env, url: URL, who: string, L: I18n): Promise<Response> {
  const mcpOnly = url.searchParams.get("who") === "mcp";
  const rows = { results: await auditRows(env, 500, mcpOnly) };
  const body = html`<div class="hero"><p class="eyebrow">${L.t("audit.eyebrow")}</p><h1>${L.t("audit.title")}</h1>
<p class="lead">${L.t("audit.lead")}</p></div>
<div class="toolbar"><nav class="seg" aria-label="${L.s("audit.thWho")}"><a class="${mcpOnly ? "" : "on"}" href="/admin/audit">${L.t("audit.all")}</a><a class="${mcpOnly ? "on" : ""}" href="/admin/audit?who=mcp">${L.t("audit.mcpOnly")}</a></nav></div>
<div class="panel flush"><div class="scroll"><table><thead><tr><th>${L.t("audit.thWhen")}</th><th>${L.t("audit.thWho")}</th><th>${L.t("audit.thAction")}</th><th>${L.t("audit.thTarget")}</th><th>${L.t("audit.thDetail")}</th></tr></thead><tbody>
${rows.results.map(
    (a) => html`<tr><td class="nowrap">${L.when(a.at)}</td><td class="wrap">${a.who.startsWith("mcp") ? pill("s-error", a.who) : a.who}</td><td class="nowrap"><code>${a.action}</code></td><td class="wrap">${
      /^[0-9a-f]{32}$/.test(a.target) ? html`<a class="u mono" href="${machineLink(a.target)}">${a.target}</a>` : a.target
    }</td><td class="ev wrap">${a.detail === "{}" ? "" : a.detail}</td></tr>`,
  )}</tbody></table></div>${rows.results.length === 0 ? html`<p class="empty">${L.t("audit.empty")}</p>` : ""}</div>`;
  return page(layout(L, L.s("audit.title"), who, body, "Audit"));
}
