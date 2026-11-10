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
import { CAPABILITY_HEADERS, SELF, tooManyRequests } from "./enroll";
import { forRequest, type I18n } from "./i18n";
import { badge, Html, html, layout, MARK, page, sev, statusClass } from "./html";

const GLYPH_OK = new Html(
  `<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m5.5 12.5 4.2 4.2 8.8-9.2" stroke="#fff" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
);
const GLYPH_ATTENTION = new Html(
  `<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 6.5v7" stroke="#fff" stroke-width="2.8" stroke-linecap="round"/><circle cx="12" cy="17.6" r="1.7" fill="#fff"/></svg>`,
);
import { hit } from "./ratelimit";
import { parseReport, type Result, statusRank } from "./report";
import { LINK_RE, sha256hex } from "./tokens";

function notFound(L: I18n): Response {
  return page(
    layout(L, L.s("common.notFound"), null, html`<div class="center-card"><span class="mark lg">${MARK}</span><p class="eyebrow">bordercheck</p><h1>${L.t("rep.badTitle")}</h1>
<p class="lead">${L.t("rep.badLead")}</p></div>`, undefined, SELF),
    404,
    CAPABILITY_HEADERS,
  );
}

export async function selfReportPage(req: Request, env: Env, id: string, now = new Date(), L: I18n = forRequest(req)): Promise<Response> {
  if (!config(env).reportLinks) return notFound(L);
  const rl = await hit(env, req, "page", now.getTime());
  if (!rl.ok) return tooManyRequests(L, rl.retryAfter);
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
  if (!row) return notFound(L);

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
  const headline = problems.length === 0 ? L.t("rep.allClear") : L.t("rep.toFixHeadline", { n: problems.length });
  const body = html`<div class="status-mark ${tone}">${problems.length === 0 ? GLYPH_OK : GLYPH_ATTENTION}</div>
<p class="eyebrow">${L.t("rep.eyebrow")}</p><h1>${headline}</h1>
<p class="lead">${L.t("rep.for", { email: row.email || L.s("common.noEmail"), host: row.hostname || L.s("common.noHostname"), when: L.when(row.last_seen) })}${L.lang === "zh" ? "" : " "}${problems.length === 0 ? L.t("rep.okText") : L.t("rep.fixText")}</p>
<div class="chips"><span class="chip">${L.t("rep.passed", { n: okCount })}</span>${waived.length ? html`<span class="chip">${L.t("rep.exempted", { n: waived.length })}</span>` : ""}</div>
${problems.length === 0
    ? ""
    : html`<h2>${L.t("rep.toFix", { n: problems.length })}</h2>${problems.map(
        (r) => html`<div class="result ${statusClass(r.status)}"><div class="head">${badge(L, r.status)} ${sev(L, r.severity)}</div>
<h3>${r.title || r.id}</h3>
${r.summary ? html`<div class="body">${r.summary}</div>` : ""}
${r.fix ? html`<div class="fix"><b>${L.t("rep.howToFix")}</b><span>${r.fix}</span></div>` : ""}</div>`,
      )}`}
${waived.length
    ? html`<h2>${L.t("rep.exemptedTitle", { n: waived.length })}</h2><p class="dim">${L.t("rep.exemptedText")}</p>${waived.map(
        (r) => html`<div class="result s-waived"><div class="head">${badge(L, r.status)}</div><h3>${r.title || r.id}</h3>
<div class="waiver">${L.t("rep.until", { date: r.waived?.until ? L.day(r.waived.until) : "?" })}${r.waived?.reason ? html`: <span class="body">${r.waived.reason}</span>` : ""}</div>
${r.fix ? html`<div class="fix"><b>${L.t("rep.howToFix")}</b><span>${r.fix}</span></div>` : ""}</div>`,
      )}`
    : ""}
<p class="foot">${L.t("rep.foot")}</p>`;
  return page(layout(L, L.s("rep.title"), null, body, undefined, SELF), 200, CAPABILITY_HEADERS);
}
