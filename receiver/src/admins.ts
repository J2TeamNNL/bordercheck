// Named admins: people the owner lets into the portal, each with a name and a
// token of their own. The owner is whoever signs in with ADMIN_TOKEN or with
// one of the owner's passkeys (Viewer.owner). A named admin can do everything
// in the portal that the owner can, except: add or remove admins, make a new
// token for anyone but themself, and switch token sign-in. Their name is
// what the header shows and the audit trail records.
//
// Routes (index.ts), for the portal's own sign-in only (404 under Cloudflare
// Access or without ADMIN_TOKEN, like the passkey pages):
//   GET  /admin/admins                 the list; the add form for the owner
//   POST /admin/admins                 add (owner): the new token, shown once
//   POST /admin/admins/<id>/token      new token (owner, or that admin): shown once
//   POST /admin/admins/<id>/delete     remove, with their passkeys (owner)
//
// Tokens are "bca_" + 32 random bytes base64url; only their SHA-256 is kept
// (auth.ts looks them up). Not part of /api/v1 or MCP.

import { ADMIN_TOKEN_PREFIX, newSession, PASSKEY_WHO, sessionCookie, TOKEN_WHO, type Viewer } from "./auth";
import type { Env } from "./env";
import { COPY_HEADERS, copyButton, type Html, html, layout, note, page } from "./html";
import { type I18n, type Key, type Msg, msg } from "./i18n";
import { randomB64url, sha256hex } from "./tokens";

export const newAdminToken = () => ADMIN_TOKEN_PREFIX + randomB64url(32);

// ---- Names ----

export const MAX_NAME = 40;
// A letter or digit first, then letters (with their combining marks), digits,
// space and . _ @ -
const NAME_RE = /^[\p{L}\p{N}][\p{L}\p{M}\p{N} ._@-]*$/u;
// Names the audit trail already uses for someone else.
const RESERVED = [TOKEN_WHO, PASSKEY_WHO, "mcp", "api"];

const fold = (s: string) => s.toLocaleLowerCase("en");

export function checkName(raw: string): { name: string } | { error: Key } {
  const name = raw.normalize("NFC").trim();
  if (!name) return { error: "admins.nameEmpty" };
  if ([...name].length > MAX_NAME) return { error: "admins.nameLong" };
  if (!NAME_RE.test(name)) return { error: "admins.nameChars" };
  if (RESERVED.includes(fold(name))) return { error: "admins.nameReserved" };
  return { name };
}

// ---- Stored state ----

interface AdminListRow {
  id: number;
  name: string;
  created_at: string;
  created_by: string;
  last_used_at: string | null;
  passkeys: number;
}

// null: migration 0006 is not applied yet.
async function listAdmins(env: Env): Promise<AdminListRow[] | null> {
  try {
    return (
      await env.DB.prepare(
        `SELECT a.id, a.name, a.created_at, a.created_by, a.last_used_at,
           (SELECT COUNT(*) FROM passkeys p WHERE p.admin_id = a.id) AS passkeys
         FROM admins a ORDER BY a.name COLLATE NOCASE, a.id`,
      ).all<AdminListRow>()
    ).results;
  } catch {
    return null;
  }
}

async function adminName(env: Env, id: number): Promise<string | null> {
  try {
    return await env.DB.prepare("SELECT name FROM admins WHERE id = ?").bind(id).first<string>("name");
  } catch {
    return null;
  }
}

// Every role, and which roles each admin manages (admin_roles).
async function roleChoices(env: Env): Promise<{ id: number; name: string }[]> {
  return (await env.DB.prepare("SELECT id, name FROM roles ORDER BY name").all<{ id: number; name: string }>()).results;
}

async function rolesByAdmin(env: Env): Promise<Map<number, { id: number; name: string }[]>> {
  const out = new Map<number, { id: number; name: string }[]>();
  try {
    const r = await env.DB.prepare("SELECT ar.admin_id, r.id, r.name FROM admin_roles ar JOIN roles r ON r.id = ar.role_id ORDER BY r.name")
      .all<{ admin_id: number; id: number; name: string }>();
    for (const x of r.results) {
      if (!out.has(x.admin_id)) out.set(x.admin_id, []);
      out.get(x.admin_id)!.push({ id: x.id, name: x.name });
    }
  } catch {
    // before migration 0006: nobody manages anything
  }
  return out;
}

// roleIds reads the checked roles from a form ("role", repeated), keeping
// whole numbers only; which of them exist is up to the INSERT.
function roleIds(form: FormData): number[] {
  return [...new Set(form.getAll("role").map((x) => Number(x)).filter((n) => Number.isSafeInteger(n) && n > 0))].slice(0, 1000);
}

function roleBoxes(L: I18n, prefix: string, roles: { id: number; name: string }[], checked: Set<number>): Html {
  if (!roles.length) return html`<p class="muted small">${L.t("admins.noRolesYet")}</p>`;
  return html`<fieldset class="field"><legend>${L.t("admins.rolesField")}</legend>${roles.map(
    (r) => html`<label class="check" for="${prefix}-${r.id}"><input type="checkbox" id="${prefix}-${r.id}" name="role" value="${r.id}"${checked.has(r.id) ? html` checked` : ""}> ${r.name}</label> `,
  )}</fieldset>`;
}

// ---- Pages ----

const tone = (status: number) => (status >= 400 ? "s-fail" : "s-pass");

// adminsPage: the owner sees every admin, with the add form and per-admin
// role and remove controls; a named admin sees only their own row.
export async function adminsPage(env: Env, v: Viewer, L: I18n, message?: Key | Msg, status = 200, draft = ""): Promise<Response> {
  const all = await listAdmins(env);
  const rows = all && (v.owner ? all : all.filter((r) => r.id === v.adminId));
  const [roles, scopes] = await Promise.all([v.owner ? roleChoices(env) : Promise.resolve([]), rolesByAdmin(env)]);
  const roleCell = (r: AdminListRow) => {
    const mine = scopes.get(r.id) ?? [];
    const names = mine.length ? mine.map((x, i) => html`${i ? ", " : ""}${x.name}`) : html`<span class="muted">${L.t("admins.noRoles")}</span>`;
    if (!v.owner) return names;
    return html`${names}<details class="adder"><summary class="btn sm">${L.t("admins.editRoles")}</summary>
<form method="post" action="/admin/admins/${r.id}/roles">${roleBoxes(L, `ar-${r.id}`, roles, new Set(mine.map((x) => x.id)))}<div class="actions"><button class="sm primary">${L.t("admins.saveRoles")}</button></div></form></details>`;
  };
  const action = (r: AdminListRow) => {
    const self = r.id === v.adminId;
    const token = v.owner || self
      ? html`<form class="inline" method="post" action="/admin/admins/${r.id}/token"><button class="sm">${L.t("admins.newToken")}</button></form>`
      : "";
    const del = v.owner
      ? html` <form class="inline" method="post" action="/admin/admins/${r.id}/delete"><button class="sm danger">${L.t("admins.remove")}</button></form>`
      : "";
    return html`${token}${del}`;
  };
  const list = rows
    ? html`<div class="panel flush"><div class="scroll"><table><thead><tr><th>${L.t("admins.thName")}</th><th>${L.t("nav.roles")}</th><th>${L.t("admins.thCreated")}</th><th>${L.t("admins.thBy")}</th><th>${L.t("admins.thUsed")}</th><th class="n">${L.t("nav.passkeys")}</th><th></th></tr></thead><tbody>
${rows.map(
        (r) => html`<tr><td class="wrap"><b>${r.name}</b>${r.id === v.adminId ? html` <span class="muted">${L.t("admins.you")}</span>` : ""}</td><td class="wrap">${roleCell(r)}</td><td class="nowrap">${L.when(r.created_at)}</td><td class="wrap">${r.created_by}</td><td class="nowrap">${r.last_used_at ? L.when(r.last_used_at) : L.s("time.never")}</td><td class="n">${L.num(r.passkeys)}</td>
<td class="n nowrap">${action(r)}</td></tr>`,
      )}</tbody></table></div>${rows.length === 0 ? html`<p class="empty">${L.t("admins.empty")}</p>` : ""}</div>`
    : note(L.t("admins.noTable"), "s-warn");
  const add = v.owner && rows
    ? html`<h2>${L.t("admins.add")}</h2>
<form method="post" action="/admin/admins"><div class="panel"><div class="field"><label for="admin-name">${L.t("admins.nameField")}</label><input id="admin-name" name="name" value="${draft}" maxlength="${MAX_NAME}" required class="w-name" autocomplete="off" placeholder="${L.s("admins.namePlaceholder")}"></div>
<p class="muted small">${L.t("admins.nameRule")}</p>
${roleBoxes(L, "new-role", roles, new Set())}
<p class="muted small">${L.t("admins.rolesRule")}</p>
<div class="actions"><button class="primary">${L.t("admins.addButton")}</button></div></div></form>`
    : "";
  const body = html`<div class="hero"><p class="eyebrow">${L.t("passkeys.eyebrow")}</p><h1>${L.t("nav.admins")}</h1>
<p class="lead">${L.t(v.owner ? "admins.lead" : "admins.leadSelf")}</p></div>
${message ? note(L.m(typeof message === "string" ? msg(message) : message), tone(status)) : ""}
${list}${add}`;
  return page(layout(L, L.s("nav.admins"), v.who, body, "Admins"), status);
}

// tokenPage shows a named admin's token, once, with a Copy button. Like the
// other shown-once pages it has no language switcher (going "back" there
// would lose the token) and carries only the hashed Copy script.
function tokenPage(L: I18n, v: Viewer, name: string, token: string, fresh: boolean, setCookie?: string): Response {
  const body = html`<p class="eyebrow">${L.t("nav.admins")}</p><h1>${L.t(fresh ? "admins.addedTitle" : "admins.tokenTitle", { name })}</h1>
${note(L.t("admins.tokenOnce", { name }), "s-warn")}
<div class="panel"><div class="cmd"><div class="cmd-h"><b>${L.t("admins.tokenLabel")}</b><span>${name}</span>${copyButton(L, "admin-token", "copy.token")}</div><code tabindex="0" id="admin-token">${token}</code></div>
<p class="muted small">${L.t("admins.tokenUse")}</p></div>
<div class="actions"><a class="btn" href="/admin/admins">${L.t("admins.back")}</a></div>`;
  const res = page(layout(L, L.s("nav.admins"), v.who, body, "Admins", { switcher: false, copy: true }), 200, COPY_HEADERS);
  if (setCookie) res.headers.append("set-cookie", setCookie);
  return res;
}

// ---- Changes ----

export async function addAdmin(env: Env, v: Viewer, form: FormData, L: I18n, now = Date.now()): Promise<Response> {
  if (!v.owner) return adminsPage(env, v, L, "admins.ownerOnly", 403);
  const raw = String(form.get("name") ?? "");
  const checked = checkName(raw);
  if ("error" in checked) return adminsPage(env, v, L, checked.error, 400, raw.slice(0, 200));
  const { name } = checked;
  const rows = await listAdmins(env);
  if (!rows) return adminsPage(env, v, L, "admins.noTable", 409);
  // NOCASE folds ASCII only; this catches "Đức" and "đức" too.
  if (rows.some((r) => fold(r.name) === fold(name))) return adminsPage(env, v, L, "admins.nameTaken", 409, name);
  const token = newAdminToken();
  const at = new Date(now);
  const ids = JSON.stringify(roleIds(form));
  const res = await env.DB.batch([
    env.DB.prepare("INSERT INTO admins (name, token_hash, created_at, created_by) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING")
      .bind(name, await sha256hex(token), at.toISOString(), v.who.slice(0, 200)),
    env.DB.prepare("INSERT INTO audit (at, who, action, target, detail) SELECT ?1, ?2, 'admin.add', ?3, json_object('roles', (SELECT json_group_array(name) FROM (SELECT name FROM roles WHERE id IN (SELECT value FROM json_each(?4)) ORDER BY name))) WHERE changes() > 0")
      .bind(at.toISOString(), v.who.slice(0, 200), name, ids),
    // The roles go in only with the admin this request added (token_hash is theirs alone).
    env.DB.prepare("INSERT OR IGNORE INTO admin_roles (admin_id, role_id) SELECT a.id, r.id FROM admins a, roles r WHERE a.token_hash = ? AND r.id IN (SELECT value FROM json_each(?))")
      .bind(await sha256hex(token), ids),
  ]);
  if (res[0].meta.changes !== 1) return adminsPage(env, v, L, "admins.nameTaken", 409, name);
  return tokenPage(L, v, name, token, true);
}

// newToken replaces an admin's token and bumps gen, which signs all their
// sessions out. When admins do it for themselves, the page that shows the new
// token also carries a fresh session for them (the same kind as the one they
// used), so they stay signed in here.
export async function newToken(env: Env, v: Viewer, id: number, L: I18n, now = Date.now()): Promise<Response> {
  const self = v.adminId === id;
  if (!v.owner && !self) return adminsPage(env, v, L, "admins.ownerOnly", 403);
  const name = await adminName(env, id);
  if (!name) return adminsPage(env, v, L, "admins.notFound", 404);
  const token = newAdminToken();
  const res = await env.DB.batch([
    env.DB.prepare("UPDATE admins SET token_hash = ?, gen = gen + 1 WHERE id = ? RETURNING gen").bind(await sha256hex(token), id),
    env.DB.prepare("INSERT INTO audit (at, who, action, target, detail) SELECT ?, ?, 'admin.token', ?, '{}' WHERE changes() > 0")
      .bind(new Date(now).toISOString(), v.who.slice(0, 200), name),
  ]);
  const gen = (res[0].results[0] as { gen?: number } | undefined)?.gen;
  if (gen === undefined) return adminsPage(env, v, L, "admins.notFound", 404);
  const cookie = self && v.via === "session"
    ? sessionCookie(await newSession(env, now, v.passkey ? "passkey" : "token", { id, gen }))
    : undefined;
  return tokenPage(L, v, name, token, false, cookie);
}

// deleteAdmin removes an admin, their passkeys and their roles. Their sessions end with the
// row: auth.ts finds no admin for them on the next request.
export async function deleteAdmin(env: Env, v: Viewer, id: number, L: I18n): Promise<Response> {
  if (!v.owner) return adminsPage(env, v, L, "admins.ownerOnly", 403);
  const name = await adminName(env, id);
  if (!name) return adminsPage(env, v, L, "admins.notFound", 404);
  const res = await env.DB.batch([
    env.DB.prepare("DELETE FROM passkeys WHERE admin_id = ?").bind(id),
    env.DB.prepare("DELETE FROM admin_roles WHERE admin_id = ?").bind(id),
    env.DB.prepare("DELETE FROM admins WHERE id = ?").bind(id),
    env.DB.prepare("INSERT INTO audit (at, who, action, target, detail) SELECT ?, ?, 'admin.delete', ?, '{}' WHERE changes() > 0")
      .bind(new Date().toISOString(), v.who.slice(0, 200), name),
  ]);
  if (res[2].meta.changes !== 1) return adminsPage(env, v, L, "admins.notFound", 404);
  return adminsPage(env, v, L, msg("admins.removed", { name }), 200);
}

// setRoles replaces the roles an admin manages (owner only). Takes effect on
// that admin's next request: their scope is loaded per request.
export async function setRoles(env: Env, v: Viewer, id: number, form: FormData, L: I18n): Promise<Response> {
  if (!v.owner) return adminsPage(env, v, L, "admins.ownerOnly", 403);
  const name = await adminName(env, id);
  if (!name) return adminsPage(env, v, L, "admins.notFound", 404);
  const ids = JSON.stringify(roleIds(form));
  await env.DB.batch([
    env.DB.prepare("DELETE FROM admin_roles WHERE admin_id = ?").bind(id),
    env.DB.prepare("INSERT INTO admin_roles (admin_id, role_id) SELECT a.id, r.id FROM admins a, roles r WHERE a.id = ? AND r.id IN (SELECT value FROM json_each(?))").bind(id, ids),
    env.DB.prepare("INSERT INTO audit (at, who, action, target, detail) VALUES (?, ?, 'admin.roles', ?, json_object('roles', (SELECT json_group_array(name) FROM (SELECT r.name FROM admin_roles ar JOIN roles r ON r.id = ar.role_id WHERE ar.admin_id = ? ORDER BY r.name))))")
      .bind(new Date().toISOString(), v.who.slice(0, 200), name, id),
  ]);
  return adminsPage(env, v, L, msg("admins.rolesSaved", { name }), 200);
}
