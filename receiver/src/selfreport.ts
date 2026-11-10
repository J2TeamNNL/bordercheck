// GET /r/<id>: a login-free page showing one machine its own latest results,
// for the person at that machine. The id is a capability: 192 random bits,
// issued in the response to an accepted report, stored only as a hash,
// expiring after REPORT_LINK_DAYS, and dropped when the machine is revoked,
// restored or its link is reset.
//
// The page shows what failed or warned with severity, summary and fix,
// waived items with their end date, when the machine was checked, and which
// machine and email it is. It never shows evidence (file paths, ports,
// container names: a map of the machine for whoever holds the link; the
// person at the machine sees it by running bordercheck), other machines,
// admin controls, audit data, IPs or locations.

import { config, type Env } from "./env";
import { CAPABILITY_HEADERS } from "./enroll";
import { badge, html, layout, page, statusClass, when } from "./html";
import { hit } from "./ratelimit";
import { parseReport, type Result, statusRank } from "./report";
import { LINK_RE, sha256hex } from "./tokens";

function notFound(): Response {
  return page(
    layout("Not found", null, html`<h1>Link not valid</h1><p>This report link is unknown or has expired. Run <code>bordercheck status</code> on your computer, or ask your IT team.</p>`),
    404,
    CAPABILITY_HEADERS,
  );
}

export async function selfReportPage(req: Request, env: Env, id: string, now = new Date()): Promise<Response> {
  if (!config(env).reportLinks) return notFound();
  const rl = await hit(env, req, "page", now.getTime());
  if (!rl.ok) {
    return page(layout("Slow down", null, html`<h1>Too many requests</h1><p>Wait a few minutes and reload.</p>`), 429, {
      ...CAPABILITY_HEADERS,
      "retry-after": String(rl.retryAfter),
    });
  }
  // Same work for every id: hash, then one query.
  const h = await sha256hex(id);
  const row = await env.DB.prepare(
    `SELECT m.email, m.hostname, m.last_seen, m.report
     FROM report_links l
     JOIN machines m ON m.install_id = l.install_id
     LEFT JOIN enrollments e ON e.install_id = l.install_id
     WHERE l.link_hash = ?1 AND ?2 = 1 AND l.expires_at > ?3 AND e.revoked_at IS NULL`,
  )
    .bind(h, LINK_RE.test(id) ? 1 : 0, now.toISOString())
    .first<{ email: string; hostname: string; last_seen: string; report: string }>();
  if (!row) return notFound();

  let results: Result[] = [];
  try {
    results = parseReport(JSON.parse(row.report)).results;
  } catch {
    results = [];
  }
  results.sort((a, b) => statusRank(a.status) - statusRank(b.status));
  const problems = results.filter((r) => r.status === "fail" || r.status === "warn" || r.status === "error");
  const waived = results.filter((r) => r.status === "waived");
  const okCount = results.filter((r) => r.status === "pass" || r.status === "skip").length;

  const body = html`<h1>Your bordercheck report</h1>
<p>For <b>${row.email || "(no email)"}</b> on <b>${row.hostname || "(no hostname)"}</b>, checked ${when(row.last_seen)}.
This page shows only this computer's latest results. If this is not your computer, close it.</p>
<h2>To fix (${problems.length})</h2>
${problems.length === 0 ? html`<p class="muted">Nothing is failing. ${okCount} checks passed or did not apply.</p>` : ""}
${problems.map(
    (r) => html`<div class="result ${statusClass(r.status)}"><div>${badge(r.status)} ${r.severity ? html`<span class="muted">[${r.severity}]</span>` : ""}
<b class="body">${r.title || r.id}</b></div>
${r.summary ? html`<div class="body">${r.summary}</div>` : ""}
${r.fix ? html`<div class="body"><b>Fix:</b> ${r.fix}</div>` : ""}</div>`,
  )}
${waived.length
    ? html`<h2>Exempted for now (${waived.length})</h2>${waived.map(
        (r) => html`<div class="result s-waived"><div>${badge(r.status)} <b class="body">${r.title || r.id}</b></div>
<div>Until ${r.waived?.until || "?"}${r.waived?.reason ? html`: <span class="body">${r.waived.reason}</span>` : ""}</div>
${r.fix ? html`<div class="body"><b>Fix:</b> ${r.fix}</div>` : ""}</div>`,
      )}`
    : ""}
<p class="muted">Details such as file paths are not shown here. Run <code>bordercheck</code> on this computer to see them.</p>`;
  return page(layout("Your report", null, body), 200, CAPABILITY_HEADERS);
}
