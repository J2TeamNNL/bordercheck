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
import { badge, Html, html, layout, MARK, page, sev, statusClass, when } from "./html";

const GLYPH_OK = new Html(
  `<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m5.5 12.5 4.2 4.2 8.8-9.2" stroke="#fff" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
);
const GLYPH_ATTENTION = new Html(
  `<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 6.5v7" stroke="#fff" stroke-width="2.8" stroke-linecap="round"/><circle cx="12" cy="17.6" r="1.7" fill="#fff"/></svg>`,
);
import { hit } from "./ratelimit";
import { parseReport, type Result, statusRank } from "./report";
import { LINK_RE, sha256hex } from "./tokens";

function notFound(): Response {
  return page(
    layout("Not found", null, html`<div class="center-card"><span class="mark lg">${MARK}</span><p class="eyebrow">bordercheck</p><h1>Link not valid</h1>
<p class="lead">This report link is unknown or has expired. Run <code>bordercheck status</code> on your computer, or ask your IT team.</p></div>`),
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
     JOIN enrollments e ON e.install_id = l.install_id
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

  const failing = problems.some((r) => r.status === "fail");
  const tone = problems.length === 0 ? "s-pass" : failing ? "s-fail" : "s-warn";
  const headline =
    problems.length === 0 ? "All clear" : problems.length === 1 ? "One thing to fix" : `${problems.length} things to fix`;
  const body = html`<div class="status-mark ${tone}">${problems.length === 0 ? GLYPH_OK : GLYPH_ATTENTION}</div>
<p class="eyebrow">Your bordercheck report</p><h1>${headline}</h1>
<p class="lead">For <b>${row.email || "(no email)"}</b> on <b>${row.hostname || "(no hostname)"}</b>, checked ${when(row.last_seen)}.
${problems.length === 0
    ? "This computer meets your organisation's checks. Nothing for you to do."
    : "Each item below says what's wrong and how to fix it. bordercheck checks again on its own, so a fix shows up here after its next run."}</p>
<div class="chips"><span class="chip"><b>${okCount}</b> passed or did not apply</span>${waived.length ? html`<span class="chip"><b>${waived.length}</b> exempted for now</span>` : ""}</div>
${problems.length === 0
    ? ""
    : html`<h2>To fix (${problems.length})</h2>${problems.map(
        (r) => html`<div class="result ${statusClass(r.status)}"><div class="head">${badge(r.status)} ${sev(r.severity)}</div>
<h3>${r.title || r.id}</h3>
${r.summary ? html`<div class="body">${r.summary}</div>` : ""}
${r.fix ? html`<div class="fix"><b>How to fix</b><span>${r.fix}</span></div>` : ""}</div>`,
      )}`}
${waived.length
    ? html`<h2>Exempted for now (${waived.length})</h2><p class="dim">IT has agreed these can wait until the date shown.</p>${waived.map(
        (r) => html`<div class="result s-waived"><div class="head">${badge(r.status)}</div><h3>${r.title || r.id}</h3>
<div class="waiver">Until ${r.waived?.until || "?"}${r.waived?.reason ? html`: <span class="body">${r.waived.reason}</span>` : ""}</div>
${r.fix ? html`<div class="fix"><b>How to fix</b><span>${r.fix}</span></div>` : ""}</div>`,
      )}`
    : ""}
<p class="foot">This page shows only this computer's latest results; if this is not your computer, close it. Details such as file paths are not shown here: run <code>bordercheck</code> on this computer to see them.</p>`;
  return page(layout("Your report", null, body), 200, CAPABILITY_HEADERS);
}
