// The MCP page of the dashboard: whether the MCP server (mcp.ts) is on, how to
// get a token and add it to Claude, and what its tools can do. It shows a
// token only once, right after it is made. The owner makes their own MCP token
// here (the whole fleet); setting MCP_TOKEN / MCP_READ_TOKEN as Worker secrets
// is folded away under it. Access viewers see only those secrets. A named
// admin sees their own MCP token's state and where to make one (the Admins
// page), never wrangler commands they could not run.
//   POST /admin/mcp/token          the owner's MCP token, read or write: shown once
//   POST /admin/mcp/token-delete   remove it
import { mcpAddCommand, mcpTokenPage, newMcpToken } from "./admins";
import { audit } from "./audit";
import { OWNER_MCP_KEY, ownerMcp, usableToken, type Viewer } from "./auth";
import { publicOrigin } from "./enroll";
import type { Env } from "./env";
import { COPY_HEADERS, copyButton, html, layout, note, page } from "./html";
import type { I18n, Key } from "./i18n";
import { sha256hex } from "./tokens";
import { TOOLS } from "./mcp-tools";

async function ownMcp(env: Env, id: number): Promise<{ write: boolean; at: string | null } | null> {
  try {
    const r = await env.DB.prepare("SELECT mcp_write, mcp_created_at FROM admins WHERE id = ? AND mcp_hash IS NOT NULL")
      .bind(id).first<{ mcp_write: number; mcp_created_at: string | null }>();
    return r ? { write: r.mcp_write === 1, at: r.mcp_created_at } : null;
  } catch {
    return null; // before migration 0007
  }
}

export async function mcpPage(env: Env, req: Request, v: Viewer, L: I18n, message?: Key, status = 200): Promise<Response> {
  const url = `${publicOrigin(env, req)}/mcp`;
  const cmd = (id: string, title: Key, text: string) =>
    html`<div class="cmd"><div class="cmd-h"><b>${L.t(title)}</b>${copyButton(L, id, "copy.command")}</div><code class="msg" tabindex="0" id="${id}">${text}</code></div>`;
  const tools = (w: boolean) => TOOLS.filter((t) => t.write === w);
  const list = (w: boolean) => html`<ul>${tools(w).map((t) => html`<li><code>${t.name}</code> <span class="muted">${t.annotations.title}</span></li>`)}</ul>`;
  const add = html`<h2>${L.t("mcp.addTitle")}</h2>
<div class="panel"><p>${L.t("mcp.addText")}</p>
${cmd("mcp-add", "mcp.addCode", mcpAddCommand(url))}
<p class="muted small">${L.t("mcp.addNote")}</p>
<p class="muted small">${L.t("mcp.others")}</p></div>`;

  let top;
  let scope;
  if (v.adminId !== undefined) {
    const mine = await ownMcp(env, v.adminId);
    top = html`${note(
      mine
        ? L.t("mcp.mineOn", { url, access: L.s(mine.write ? "admins.mcpWrite" : "admins.mcpRead"), when: mine.at ? L.when(mine.at) : "" })
        : L.t("mcp.mineOff", { url }),
      mine ? "" : "s-warn",
    )}
<h2>${L.t("mcp.mineTitle")}</h2>
<div class="panel"><p>${L.t("mcp.mineText")}</p><div class="actions"><a class="btn primary" href="/admin/admins">${L.t("mcp.mineButton")}</a></div></div>`;
    scope = html`${L.t("mcp.mineScope")} <a href="/admin/audit">${L.t("nav.audit")}</a>`;
  } else {
    const write = usableToken(env.MCP_TOKEN);
    const read = usableToken(env.MCP_READ_TOKEN);
    const envStatus: Key = write && read ? "mcp.statusBoth" : write ? "mcp.statusWrite" : read ? "mcp.statusRead" : "mcp.statusOff";
    const secrets = html`<p>${L.t("mcp.tokenText")}</p>
${cmd("mcp-set-write", "mcp.tokenWrite", "openssl rand -hex 32 | npx wrangler secret put MCP_TOKEN")}
${cmd("mcp-set-read", "mcp.tokenRead", "openssl rand -hex 32 | npx wrangler secret put MCP_READ_TOKEN")}
<p class="muted small">${L.t("mcp.tokenCut")}</p>`;
    if (v.owner) {
      const own = await ownerMcp(env);
      const access = own ? L.s(own.write ? "admins.mcpWrite" : "admins.mcpRead") : "";
      top = html`${message ? note(L.t(message), status >= 400 ? "s-fail" : "s-pass") : ""}
${note(own ? L.t("mcp.ownOn", { url, access, when: L.when(own.at) }) : write || read ? L.t(envStatus, { url }) : L.t("mcp.ownOff", { url }), own || write || read ? "" : "s-warn")}
<h2>${L.t("mcp.ownTitle")}</h2>
<div class="panel"><p>${L.t("mcp.ownText")}</p>
<form method="post" action="/admin/mcp/token"><fieldset class="field"><legend>${L.t("admins.mcpAccess")}</legend>
<label class="check" for="own-r"><input type="radio" id="own-r" name="access" value="read" checked> ${L.t("admins.mcpRead")}</label>
<label class="check" for="own-w"><input type="radio" id="own-w" name="access" value="write"> ${L.t("admins.mcpWrite")}</label></fieldset>
<div class="actions"><button class="primary">${L.t("admins.mcpMake")}</button></div></form>
${own ? html`<form method="post" action="/admin/mcp/token-delete"><div class="actions"><button class="danger sm">${L.t("admins.mcpRemove")}</button></div></form>` : ""}
<details class="adder"><summary class="muted small">${L.t("mcp.secretTitle")}</summary>${note(L.t(envStatus, { url }), "")}${secrets}</details></div>`;
    } else {
      top = html`${note(L.t(envStatus, { url }), write || read ? "" : "s-warn")}
<h2>${L.t("mcp.tokenTitle")}</h2>
<div class="panel">${secrets}</div>`;
    }
    scope = html`${L.t("mcp.scope")} <a href="/admin/audit?who=mcp">${L.t("mcp.audit")}</a>`;
  }
  const body = html`<div class="hero"><h1>${L.t("nav.mcp")}</h1><p class="lead">${L.t("mcp.lead")}</p></div>
${top}
${add}
<h2>${L.t("mcp.toolsTitle")}</h2>
<div class="panel"><p><b>${L.t("mcp.toolsRead", { n: tools(false).length })}</b></p>${list(false)}
<p><b>${L.t("mcp.toolsWrite", { n: tools(true).length })}</b></p>${list(true)}
<p class="muted small">${scope}</p></div>`;
  return page(layout(L, L.s("nav.mcp"), v.who, body, "MCP", { copy: true }), status, COPY_HEADERS);
}

// newOwnerMcp makes (or replaces) the owner's MCP token.
export async function newOwnerMcp(env: Env, req: Request, v: Viewer, form: FormData, L: I18n): Promise<Response> {
  if (!v.owner) return mcpPage(env, req, v, L, "admins.ownerOnly", 403);
  const write = form.get("access") === "write";
  const token = newMcpToken();
  const at = new Date().toISOString();
  await env.DB.prepare("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value")
    .bind(OWNER_MCP_KEY, JSON.stringify({ hash: await sha256hex(token), write, at }))
    .run();
  await audit(env, v.who, "mcp.owner_token", "owner", { access: write ? "write" : "read" });
  return mcpTokenPage(L, v, token, write, `${publicOrigin(env, req)}/mcp`, { owner: true });
}

export async function deleteOwnerMcp(env: Env, req: Request, v: Viewer, L: I18n): Promise<Response> {
  if (!v.owner) return mcpPage(env, req, v, L, "admins.ownerOnly", 403);
  const r = await env.DB.prepare("DELETE FROM meta WHERE key = ?").bind(OWNER_MCP_KEY).run();
  if (r.meta.changes) await audit(env, v.who, "mcp.owner_token_remove", "owner");
  return mcpPage(env, req, v, L, "mcp.ownRemoved");
}
