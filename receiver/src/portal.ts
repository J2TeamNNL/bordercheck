// The enrollment portal's admin pages: roles, invites, the audit trail, and
// the enrollment part of a machine's page (role, source invite,
// revoke/restore, waivers, report link). Auth and same-origin checks are done
// by the /admin router in index.ts before anything here runs.

import { audit, auditStmt } from "./audit";
import { commandBlock, installCommands, publicOrigin } from "./enroll";
import { config, DAY, type Env } from "./env";
import { html, type Html, layout, page, when } from "./html";
import { CHECK_ID_RE, POLICY_CHECKS, today, validateRolePolicy, waiverDateError } from "./roles";
import { newCode, sha256hex } from "./tokens";
import { usableToken } from "./auth";

const MAX_ROLE_POLICY = 256 * 1024;
const MAX_BULK = 500;
const EMAIL_RE = /^[^\s@<>"'(),;:\\]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/;

const machineLink = (id: string) => `/admin/machine/${encodeURIComponent(id)}`;
const note = (m: string | Html) => (m ? html`<div class="note">${m}</div>` : "");

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

const STARTER_POLICY = `{
  "report": { "interval": "24h" },
  "update": { "binary": true },
  "checks": {}
}`;

function legacyTokens(env: Env): string[] {
  return [env.REPORT_TOKEN, env.REPORT_TOKEN_PREVIOUS].filter(usableToken);
}

export async function rolesPage(env: Env, who: string, message: string | Html = "", draft?: { name: string; policy: string }, status = 200) {
  const rows = await env.DB.prepare(
    `SELECT r.id, r.name, r.updated_at,
       (SELECT COUNT(*) FROM enrollments e WHERE e.role_id = r.id AND e.revoked_at IS NULL) AS machines,
       (SELECT COUNT(*) FROM invites i WHERE i.role_id = r.id AND i.used_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > ?) AS pending
     FROM roles r ORDER BY r.name`,
  )
    .bind(new Date().toISOString())
    .all<{ id: number; name: string; updated_at: string; machines: number; pending: number }>();
  const body = html`<h1>Roles</h1>
<p class="muted">A role is a policy (the same JSON as policies.json) that enrolled machines get from <code>/policy</code>.
When served, <code>report.url</code> and <code>update.policy_url</code> are set to this receiver, <code>report.headers</code>
never carry a token (each machine sends its own), and the machine's waivers are added.</p>
${note(message)}
<div class="scroll"><table><thead><tr><th>Role</th><th>Machines</th><th>Pending invites</th><th>Updated</th></tr></thead><tbody>
${rows.results.map(
    (r) => html`<tr><td><a href="/admin/roles/${r.id}">${r.name}</a></td><td class="n">${r.machines}</td><td class="n">${r.pending}</td><td>${when(r.updated_at)}</td></tr>`,
  )}</tbody></table></div>
${rows.results.length === 0 ? html`<p class="muted">No roles yet. Create one to start inviting people.</p>` : ""}
<h2>New role</h2>
${roleForm("/admin/roles", draft?.name ?? "", draft?.policy ?? STARTER_POLICY, "Create role")}`;
  return page(layout("Roles", who, body), status);
}

function roleForm(action: string, name: string, policy: string, label: string): Html {
  return html`<form method="post" action="${action}"><p><label>Name <input name="name" value="${name}" maxlength="64" required></label></p>
<textarea name="policy" spellcheck="false">${policy}</textarea>
<p class="muted">Checked here: it is a JSON object; only fields bordercheck knows at the top level and in report, update,
notify and waivers; check names; types of enabled and on_problem; durations; waiver fields; no report token in headers.
Not checked here: the settings inside each check (globs, regexes, versions, lists). bordercheck validates the whole
file and keeps its last good policy if one is invalid, so try it locally first: <code>bordercheck -policy role.json -print-policy</code>.</p>
<p><button>${label}</button></p></form>`;
}

async function checkRole(env: Env, name: string, policyText: string, now: Date): Promise<{ errs: string[]; policy?: string }> {
  const errs: string[] = [];
  if (!name) errs.push("The role needs a name.");
  if (policyText.length > MAX_ROLE_POLICY) return { errs: [...errs, "The policy is too large."] };
  let p: unknown;
  try {
    p = JSON.parse(policyText);
  } catch (e) {
    return { errs: [...errs, `Not valid JSON: ${(e as Error).message}`] };
  }
  errs.push(...validateRolePolicy(p, now, legacyTokens(env)));
  return { errs, policy: JSON.stringify(p, null, 2) };
}

function errorList(errs: string[]): Html {
  return html`Not saved:<ul>${errs.slice(0, 50).map((e) => html`<li>${e}</li>`)}</ul>`;
}

export async function createRole(env: Env, who: string, form: FormData): Promise<Response> {
  const name = cleanLine(String(form.get("name") ?? ""), 64);
  const text = String(form.get("policy") ?? "");
  const now = new Date();
  const { errs, policy } = await checkRole(env, name, text, now);
  if (errs.length) return rolesPage(env, who, errorList(errs), { name, policy: text }, 400);
  const exists = await env.DB.prepare("SELECT id FROM roles WHERE name = ?").bind(name).first();
  if (exists) return rolesPage(env, who, "A role with that name exists.", { name, policy: text }, 400);
  const ts = now.toISOString();
  const res = await env.DB.prepare("INSERT INTO roles (name, policy, created_at, updated_at) VALUES (?, ?, ?, ?) RETURNING id")
    .bind(name, policy, ts, ts)
    .first<number>("id");
  await audit(env, who, "role.create", `role ${name}`, { role_id: res });
  return rolesPage(env, who, html`Role <b>${name}</b> created.`);
}

export async function rolePage(env: Env, id: number, who: string, message: string | Html = "", draft?: { name: string; policy: string }, status = 200) {
  const r = await env.DB.prepare("SELECT * FROM roles WHERE id = ?").bind(id).first<RoleRow>();
  if (!r) return page(layout("Not found", who, html`<h1>No such role</h1>`), 404);
  const machines = await env.DB.prepare(
    `SELECT e.install_id, e.email, e.hostname, e.revoked_at FROM enrollments e WHERE e.role_id = ? ORDER BY e.email LIMIT 500`,
  )
    .bind(id)
    .all<{ install_id: string; email: string; hostname: string; revoked_at: string | null }>();
  const body = html`<h1>Role: ${r.name}</h1>
${note(message)}
${roleForm(`/admin/roles/${r.id}`, draft?.name ?? r.name, draft?.policy ?? r.policy, "Save")}
<h2>Machines in this role (${machines.results.length})</h2>
<ul>${machines.results.map(
    (m) => html`<li><a href="${machineLink(m.install_id)}">${m.email}</a> ${m.hostname}${m.revoked_at ? html` <span class="badge s-fail">revoked</span>` : ""}</li>`,
  )}</ul>
<h2>Delete</h2>
<p class="muted">Only a role no machine or pending invite uses can be deleted.</p>
<form method="post" action="/admin/roles/${r.id}/delete"><button class="danger">Delete role</button></form>`;
  return page(layout(r.name, who, body), status);
}

export async function updateRole(env: Env, id: number, who: string, form: FormData): Promise<Response> {
  const r = await env.DB.prepare("SELECT name, policy FROM roles WHERE id = ?").bind(id).first<{ name: string; policy: string }>();
  if (!r) return page(layout("Not found", who, html`<h1>No such role</h1>`), 404);
  const name = cleanLine(String(form.get("name") ?? ""), 64);
  const text = String(form.get("policy") ?? "");
  const now = new Date();
  const { errs, policy } = await checkRole(env, name, text, now);
  if (errs.length) return rolePage(env, id, who, errorList(errs), { name, policy: text }, 400);
  const clash = await env.DB.prepare("SELECT id FROM roles WHERE name = ? AND id != ?").bind(name, id).first();
  if (clash) return rolePage(env, id, who, "Another role has that name.", { name, policy: text }, 400);
  await env.DB.batch([
    env.DB.prepare("UPDATE roles SET name = ?, policy = ?, updated_at = ? WHERE id = ?").bind(name, policy, now.toISOString(), id),
    auditStmt(env, who, "role.update", `role ${name}`, {
      role_id: id,
      renamed_from: r.name !== name ? r.name : undefined,
      policy_changed: r.policy !== policy,
    }),
  ]);
  return rolePage(env, id, who, "Saved. Machines pick it up at their next policy refresh (hourly).");
}

export async function deleteRole(env: Env, id: number, who: string): Promise<Response> {
  const r = await env.DB.prepare("SELECT name FROM roles WHERE id = ?").bind(id).first<{ name: string }>();
  if (!r) return page(layout("Not found", who, html`<h1>No such role</h1>`), 404);
  const used = await env.DB.prepare(
    `SELECT (SELECT COUNT(*) FROM enrollments WHERE role_id = ?1) + (SELECT COUNT(*) FROM invites WHERE role_id = ?1) AS n`,
  )
    .bind(id)
    .first<number>("n");
  if (used) return rolePage(env, id, who, "This role is used by machines or invites (including past ones), so it can't be deleted. Move them to another role first, or keep it.", undefined, 409);
  await env.DB.batch([env.DB.prepare("DELETE FROM roles WHERE id = ?").bind(id), auditStmt(env, who, "role.delete", `role ${r.name}`, { role_id: id })]);
  return rolesPage(env, who, html`Role <b>${r.name}</b> deleted.`);
}

// ---- Invites ----

const STATUS_SQL = `CASE WHEN i.revoked_at IS NOT NULL THEN 'revoked' WHEN i.used_at IS NOT NULL THEN 'used'
  WHEN i.expires_at <= ?1 THEN 'expired' ELSE 'pending' END`;
const INVITE_FILTERS = ["pending", "used", "expired", "revoked", "all"] as const;

interface InviteRow {
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

export async function invitesPage(env: Env, url: URL, who: string, message: string | Html = "", status = 200): Promise<Response> {
  const f = url.searchParams.get("status") ?? "pending";
  const filter = (INVITE_FILTERS as readonly string[]).includes(f) ? f : "pending";
  const nowIso = new Date().toISOString();
  const rows = await env.DB.prepare(
    `SELECT i.id, i.email, r.name AS role, i.note, i.created_at, i.created_by, i.expires_at, i.used_at, i.used_install_id,
            i.revoked_at, i.reissued_as, ${STATUS_SQL} AS status
     FROM invites i JOIN roles r ON r.id = i.role_id
     WHERE ?2 = 'all' OR ${STATUS_SQL} = ?2
     ORDER BY i.id DESC LIMIT 1000`,
  )
    .bind(nowIso, filter)
    .all<InviteRow>();
  const counts = await env.DB.prepare(`SELECT ${STATUS_SQL} AS status, COUNT(*) AS n FROM invites i GROUP BY 1`)
    .bind(nowIso)
    .all<{ status: string; n: number }>();
  const count = (s: string) => counts.results.find((c) => c.status === s)?.n ?? 0;
  const options = await roleOptions(env);
  const cfg = config(env);

  const body = html`<h1>Invites</h1>
<p class="muted">An invite lets one person enroll one machine. Its code is shown once, when it is made; to get a
new command for someone, re-issue their invite (the old code stops working).</p>
${note(message)}
<div class="filters">${INVITE_FILTERS.map(
    (s) => html`<a class="${s === filter ? "on" : ""}" href="/admin/invites?status=${s}">${s}${s !== "all" ? html` (${count(s)})` : ""}</a>`,
  )}</div>
<div class="scroll"><table><thead><tr><th>#</th><th>Email</th><th>Role</th><th>Note</th><th>Status</th><th>Created</th><th>Expires</th><th></th></tr></thead><tbody>
${rows.results.map(
    (i) => html`<tr><td class="n">${i.id}</td><td>${i.email}</td><td>${i.role}</td><td>${i.note}</td>
<td>${i.status}${i.used_install_id ? html` · <a href="${machineLink(i.used_install_id)}">machine</a>` : ""}${i.reissued_as ? html` · re-issued as #${i.reissued_as}` : ""}</td>
<td>${when(i.created_at)}<br><span class="muted">${i.created_by}</span></td><td>${when(i.expires_at)}</td>
<td>${i.status === "pending" ? html`<form method="post" action="/admin/invites/${i.id}/revoke" style="display:inline"><button>Revoke</button></form> ` : ""}${
      i.status !== "used" && !i.reissued_as ? html`<form method="post" action="/admin/invites/${i.id}/reissue" style="display:inline"><button>Re-issue</button></form>` : ""
    }</td></tr>`,
  )}</tbody></table></div>
${rows.results.length === 0 ? html`<p class="muted">None.</p>` : ""}
<h2>Invite people</h2>
${options.value ? html`<form method="post" action="/admin/invites">
<p><label>Emails, one per line (or separated by commas)<br><textarea name="emails" rows="6" style="min-height:0" spellcheck="false" required></textarea></label></p>
<p><label>Role <select name="role_id">${options}</select></label>
<label>Expires after <input name="days" type="number" min="1" max="90" value="${cfg.inviteDays}" style="width:5em"> days</label></p>
<p><label>Note (optional, for you) <input name="note" maxlength="200" size="50"></label></p>
<p><button>Create invites</button> <span class="muted">At most ${MAX_BULK} at once.</span></p></form>` : html`<p><a href="/admin/roles">Create a role</a> first.</p>`}`;
  return page(layout("Invites", who, body), status);
}

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

interface Issued {
  id: number;
  email: string;
  code: string;
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
  res.forEach((r, i) => out.push({ id: r.results[0].id, email: pending[i].email, code: pending[i].code }));
  return out;
}

function issuedPage(env: Env, req: Request, who: string, issued: Issued[], heading: string, extra: Html | string = ""): Response {
  const origin = publicOrigin(env, req);
  const body = html`<h1>${heading}</h1>
<div class="note"><b>Copy these now.</b> The codes are not stored and can't be shown again; if one is lost, re-issue that invite.
Each works once, for one machine, until it expires. Send each person only their own.</div>
${extra}
${issued.map((i) => {
    const c = installCommands(env, origin, i.code);
    return html`<h2>#${i.id} · ${i.email}</h2>
<p>Invite link (opens a page with these instructions):</p>
<textarea class="cmd" readonly rows="2" spellcheck="false">${c.link}</textarea>
${commandBlock(c)}`;
  })}
<p><a href="/admin/invites">Back to invites</a></p>`;
  return page(layout(heading, who, body));
}

export async function createInvites(env: Env, req: Request, url: URL, who: string, form: FormData): Promise<Response> {
  const cfg = config(env);
  const { ok, bad } = parseEmails(String(form.get("emails") ?? ""));
  const roleId = Number(form.get("role_id"));
  const daysIn = Number(form.get("days") || cfg.inviteDays);
  const days = Number.isFinite(daysIn) && daysIn >= 1 && daysIn <= 90 ? Math.floor(daysIn) : cfg.inviteDays;
  const noteText = cleanLine(String(form.get("note") ?? ""), 200);
  const role = Number.isInteger(roleId) ? await env.DB.prepare("SELECT id, name FROM roles WHERE id = ?").bind(roleId).first<{ id: number; name: string }>() : null;
  const problems: string[] = [];
  if (!role) problems.push("Pick a role.");
  if (bad.length) problems.push(`Not email addresses: ${bad.slice(0, 20).join(", ")}${bad.length > 20 ? "…" : ""}`);
  if (!ok.length && !bad.length) problems.push("Enter at least one email.");
  if (ok.length > MAX_BULK) problems.push(`At most ${MAX_BULK} invites at once.`);
  if (cfg.emailDomains.length) {
    const outside = ok.filter((e) => !cfg.emailDomains.includes(e.split("@")[1]));
    if (outside.length) problems.push(`Outside ALLOWED_EMAIL_DOMAINS: ${outside.slice(0, 20).join(", ")}`);
  }
  if (problems.length) return invitesPage(env, url, who, html`Nothing created:<ul>${problems.map((p) => html`<li>${p}</li>`)}</ul>`, 400);

  const now = new Date();
  const issued = await issueInvites(env, who, ok, role!.id, days, noteText, now);
  await audit(env, who, ok.length > 1 ? "invite.bulk_create" : "invite.create", `role ${role!.name}`, {
    invites: issued.map((i) => ({ id: i.id, email: i.email })),
    days,
  });
  return issuedPage(env, req, who, issued, issued.length === 1 ? "Invite created" : `${issued.length} invites created`);
}

export async function revokeInvite(env: Env, url: URL, who: string, id: number): Promise<Response> {
  const ts = new Date().toISOString();
  const inv = await env.DB.prepare("SELECT email FROM invites WHERE id = ?").bind(id).first<{ email: string }>();
  if (!inv) return invitesPage(env, url, who, "No such invite.", 404);
  const res = await env.DB.batch([
    env.DB.prepare("UPDATE invites SET revoked_at = ?, revoked_by = ? WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL").bind(ts, who, id),
    auditStmt(env, who, "invite.revoke", `invite #${id}`, { email: inv.email }),
  ]);
  if (res[0].meta.changes !== 1) return invitesPage(env, url, who, `Invite #${id} was already used or revoked.`, 409);
  return invitesPage(env, url, who, `Invite #${id} revoked.`);
}

export async function reissueInvite(env: Env, req: Request, url: URL, who: string, id: number): Promise<Response> {
  const inv = await env.DB.prepare("SELECT id, email, role_id, note, used_at, reissued_as FROM invites WHERE id = ?")
    .bind(id)
    .first<{ id: number; email: string; role_id: number; note: string; used_at: string | null; reissued_as: number | null }>();
  if (!inv) return invitesPage(env, url, who, "No such invite.", 404);
  if (inv.used_at || inv.reissued_as) return invitesPage(env, url, who, `Invite #${id} was used or already re-issued; create a new invite instead.`, 409);
  const now = new Date();
  const ts = now.toISOString();
  // Revoke the old one first; only the request that does so issues the new one.
  const claim = await env.DB.prepare(
    "UPDATE invites SET revoked_at = COALESCE(revoked_at, ?1), revoked_by = COALESCE(revoked_by, ?2), reissued_as = -1 WHERE id = ?3 AND used_at IS NULL AND reissued_as IS NULL",
  )
    .bind(ts, who, id)
    .run();
  if (claim.meta.changes !== 1) return invitesPage(env, url, who, `Invite #${id} was used or already re-issued.`, 409);
  const [n] = await issueInvites(env, who, [inv.email], inv.role_id, config(env).inviteDays, inv.note, now);
  await env.DB.batch([
    env.DB.prepare("UPDATE invites SET reissued_as = ? WHERE id = ?").bind(n.id, id),
    auditStmt(env, who, "invite.reissue", `invite #${id}`, { email: inv.email, new_invite: n.id }),
  ]);
  return issuedPage(env, req, who, [n], "Invite re-issued", html`<p class="muted">Invite #${id} no longer works.</p>`);
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

export async function enrollmentSection(env: Env, id: string, e: EnrollmentRow | null, now: Date): Promise<Html> {
  const linkForm = html`<h2>Report link</h2>
<p class="muted">Each accepted report gets a login-free link to that machine's own latest results, which bordercheck can open for
the person at the machine. Reset to make every link issued so far stop working.</p>
<form method="post" action="${machineLink(id)}/reset-link"><button>Reset report links</button></form>`;
  if (!e) {
    return html`<h2>Enrollment</h2><p><span class="badge s-skip">legacy</span> This machine reports with the shared
REPORT_TOKEN and gets its policy from <code>/policies.json</code>. To manage it here (role, revoke, waivers), invite its
user and have them reinstall with the invite link; it then appears as a new machine and this one goes silent.</p>${linkForm}`;
  }
  const [waivers, options] = await Promise.all([
    env.DB.prepare("SELECT * FROM machine_waivers WHERE install_id = ? ORDER BY removed_at IS NOT NULL, until DESC LIMIT 200")
      .bind(id)
      .all<{ id: number; check_id: string; until: string; reason: string; created_at: string; created_by: string; removed_at: string | null; removed_by: string | null }>(),
    roleOptions(env, e.role_id),
  ]);
  const t = today(now);
  return html`<h2>Enrollment</h2>
<dl><dt>Status</dt><dd>${e.revoked_at ? html`<span class="badge s-fail">revoked</span> ${when(e.revoked_at)} by ${e.revoked_by}` : html`<span class="badge s-pass">active</span>`}</dd>
<dt>Role</dt><dd>${e.role}</dd><dt>Email</dt><dd>${e.email} <span class="muted">(from the invite; reports can't change it)</span></dd>
<dt>Invite</dt><dd>${e.invite_id ? html`#${e.invite_id} by ${e.invite_by}${e.invite_note ? html` · ${e.invite_note}` : ""}` : "?"}</dd>
<dt>Enrolled</dt><dd>${when(e.enrolled_at)} as ${e.hostname || "?"} (${e.os}/${e.arch}, ${e.version || "?"})</dd>
<dt>Last policy fetch</dt><dd>${when(e.last_policy_at) || "never"}</dd></dl>
<p><form method="post" action="${machineLink(id)}/role" style="display:inline"><label>Role <select name="role_id">${options}</select></label> <button>Change role</button></form></p>
${e.revoked_at
    ? html`<form method="post" action="${machineLink(id)}/restore"><button>Restore</button> <span class="muted">Its token works again.</span></form>`
    : html`<form method="post" action="${machineLink(id)}/revoke"><button class="danger">Revoke</button> <span class="muted">Its token stops working at once; its history stays.</span></form>`}
<h2>Waivers</h2>
<p class="muted">Delivered to this machine through <code>/policy</code>, keyed by its install ID, at its next hourly refresh.</p>
<div class="scroll"><table><thead><tr><th>Check</th><th>Until</th><th>Reason</th><th>Added</th><th></th></tr></thead><tbody>
${waivers.results.map(
    (w) => html`<tr class="${w.removed_at || w.until < t ? "muted" : ""}"><td><code>${w.check_id}</code></td><td>${w.until}${w.until < t ? " (ended)" : ""}</td><td>${w.reason}</td>
<td>${when(w.created_at)} by ${w.created_by}${w.removed_at ? html`<br>removed ${when(w.removed_at)} by ${w.removed_by}` : ""}</td>
<td>${w.removed_at ? "" : html`<form method="post" action="${machineLink(id)}/waivers/${w.id}/remove"><button>Remove</button></form>`}</td></tr>`,
  )}</tbody></table></div>
<form method="post" action="${machineLink(id)}/waivers"><p>
<label>Check <select name="check">${POLICY_CHECKS.map((c) => html`<option>${c}</option>`)}</select></label>
<label>Until <input type="date" name="until" required min="${t}"></label>
<label>Reason <input name="reason" maxlength="300" size="40" required></label> <button>Add waiver</button></p></form>
${linkForm}`;
}

async function machineExists(env: Env, id: string): Promise<boolean> {
  return !!(await env.DB.prepare("SELECT 1 FROM enrollments WHERE install_id = ?1 UNION SELECT 1 FROM machines WHERE install_id = ?1").bind(id).first());
}

export type MachineAction = "revoke" | "restore" | "role" | "waivers" | "reset-link" | "remove-waiver";

// machineAction runs a write from the machine page and returns an error
// message for the admin, or "" on success.
export async function machineAction(env: Env, who: string, id: string, action: MachineAction, form: FormData, waiverId = 0): Promise<{ status: number; error: string }> {
  const now = new Date();
  const ts = now.toISOString();
  const db = env.DB;
  const e = await db.prepare("SELECT install_id, role_id, revoked_at FROM enrollments WHERE install_id = ?").bind(id).first<{ install_id: string; role_id: number; revoked_at: string | null }>();
  if (action === "reset-link") {
    if (!(await machineExists(env, id))) return { status: 404, error: "No such machine." };
    await db.batch([db.prepare("DELETE FROM report_links WHERE install_id = ?").bind(id), auditStmt(env, who, "machine.reset_link", id)]);
    return { status: 200, error: "" };
  }
  if (!e) return { status: 409, error: "This machine is not enrolled (legacy); that can only be done for enrolled machines." };
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
        auditStmt(env, who, revoking ? "machine.revoke" : "machine.restore", id),
      ]);
      return { status: 200, error: "" };
    }
    case "role": {
      const roleId = Number(form.get("role_id"));
      const role = Number.isInteger(roleId) ? await db.prepare("SELECT id, name FROM roles WHERE id = ?").bind(roleId).first<{ id: number; name: string }>() : null;
      if (!role) return { status: 400, error: "No such role." };
      const old = await db.prepare("SELECT name FROM roles WHERE id = ?").bind(e.role_id).first<string>("name");
      await db.batch([
        db.prepare("UPDATE enrollments SET role_id = ? WHERE install_id = ?").bind(role.id, id),
        auditStmt(env, who, "machine.change_role", id, { from: old, to: role.name }),
      ]);
      return { status: 200, error: "" };
    }
    case "waivers": {
      const check = cleanLine(String(form.get("check") ?? ""), 64);
      const until = cleanLine(String(form.get("until") ?? ""), 16);
      const reason = cleanLine(String(form.get("reason") ?? ""), 300);
      if (!CHECK_ID_RE.test(check) || !POLICY_CHECKS.includes(check)) {
        return { status: 400, error: `Check must be one of the checks bordercheck's policy knows: ${POLICY_CHECKS.join(", ")}.` };
      }
      const dateErr = waiverDateError(until, now);
      if (dateErr) return { status: 400, error: `Waiver not added: ${dateErr}.` };
      if (!reason) return { status: 400, error: "Waiver not added: a reason is required." };
      await db.batch([
        db.prepare("INSERT INTO machine_waivers (install_id, check_id, until, reason, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)").bind(id, check, until, reason, ts, who),
        auditStmt(env, who, "waiver.add", id, { check, until, reason }),
      ]);
      return { status: 200, error: "" };
    }
    case "remove-waiver": {
      const res = await db.batch([
        db.prepare("UPDATE machine_waivers SET removed_at = ?, removed_by = ? WHERE id = ? AND install_id = ? AND removed_at IS NULL").bind(ts, who, waiverId, id),
        auditStmt(env, who, "waiver.remove", id, { waiver: waiverId }),
      ]);
      return res[0].meta.changes === 1 ? { status: 200, error: "" } : { status: 404, error: "No such waiver." };
    }
  }
  return { status: 400, error: "Unknown action." };
}

// ---- Audit ----

export async function auditPage(env: Env, who: string): Promise<Response> {
  const rows = await env.DB.prepare("SELECT at, who, action, target, detail FROM audit ORDER BY id DESC LIMIT 500").all<{
    at: string;
    who: string;
    action: string;
    target: string;
    detail: string;
  }>();
  const body = html`<h1>Audit trail</h1>
<p class="muted">Every change made in the dashboard or by the admin token, and every enrollment. Newest first, last 500.</p>
<div class="scroll"><table><thead><tr><th>When</th><th>Who</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead><tbody>
${rows.results.map(
    (a) => html`<tr><td>${when(a.at)}</td><td>${a.who}</td><td>${a.action}</td><td>${
      /^[0-9a-f]{32}$/.test(a.target) ? html`<a href="${machineLink(a.target)}">${a.target}</a>` : a.target
    }</td><td class="ev">${a.detail === "{}" ? "" : a.detail}</td></tr>`,
  )}</tbody></table></div>`;
  return page(layout("Audit", who, body));
}
