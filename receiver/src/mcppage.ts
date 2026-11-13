// The MCP page of the dashboard: whether the MCP server (mcp.ts) is on, how to
// set its tokens and add it to Claude, and what its tools can do. It shows no
// token: they exist only as the Worker's secrets.
import { usableToken } from "./auth";
import { publicOrigin } from "./enroll";
import type { Env } from "./env";
import { COPY_HEADERS, copyButton, html, layout, note, page } from "./html";
import type { I18n, Key } from "./i18n";
import { TOOLS } from "./mcp-tools";

export function mcpPage(env: Env, req: Request, who: string, L: I18n): Response {
  const write = usableToken(env.MCP_TOKEN);
  const read = usableToken(env.MCP_READ_TOKEN);
  const url = `${publicOrigin(env, req)}/mcp`;
  const status: Key = write && read ? "mcp.statusBoth" : write ? "mcp.statusWrite" : read ? "mcp.statusRead" : "mcp.statusOff";
  const cmd = (id: string, title: Key, text: string) =>
    html`<div class="cmd"><div class="cmd-h"><b>${L.t(title)}</b>${copyButton(L, id, "copy.command")}</div><code class="msg" tabindex="0" id="${id}">${text}</code></div>`;
  const tools = (w: boolean) => TOOLS.filter((t) => t.write === w);
  const list = (w: boolean) => html`<ul>${tools(w).map((t) => html`<li><code>${t.name}</code> <span class="muted">${t.annotations.title}</span></li>`)}</ul>`;
  const body = html`<div class="hero"><h1>${L.t("nav.mcp")}</h1><p class="lead">${L.t("mcp.lead")}</p></div>
${note(L.t(status, { url }), write || read ? "" : "s-warn")}
<h2>${L.t("mcp.tokenTitle")}</h2>
<div class="panel"><p>${L.t("mcp.tokenText")}</p>
${cmd("mcp-set-write", "mcp.tokenWrite", "openssl rand -hex 32 | npx wrangler secret put MCP_TOKEN")}
${cmd("mcp-set-read", "mcp.tokenRead", "openssl rand -hex 32 | npx wrangler secret put MCP_READ_TOKEN")}
<p class="muted small">${L.t("mcp.tokenCut")}</p></div>
<h2>${L.t("mcp.addTitle")}</h2>
<div class="panel"><p>${L.t("mcp.addText")}</p>
${cmd("mcp-add", "mcp.addCode", `claude mcp add --transport http bordercheck ${url} --header "Authorization: Bearer $BORDERCHECK_MCP_TOKEN"`)}
<p class="muted small">${L.t("mcp.addNote")}</p>
<p class="muted small">${L.t("mcp.others")}</p></div>
<h2>${L.t("mcp.toolsTitle")}</h2>
<div class="panel"><p><b>${L.t("mcp.toolsRead", { n: tools(false).length })}</b></p>${list(false)}
<p><b>${L.t("mcp.toolsWrite", { n: tools(true).length })}</b></p>${list(true)}
<p class="muted small">${L.t("mcp.scope")} <a href="/admin/audit?who=mcp">${L.t("mcp.audit")}</a></p></div>`;
  return page(layout(L, L.s("nav.mcp"), who, body, "MCP", { copy: true }), 200, COPY_HEADERS);
}
