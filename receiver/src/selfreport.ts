// GET /r/<id>: a login-free page showing one machine its own latest results,
// for the person at that machine. The id is a capability: 192 random bits,
// issued in the response to an accepted report, stored only as a hash,
// expiring after REPORT_LINK_DAYS, and dropped when the machine is revoked,
// restored or its link is reset.
//
// The page shows what failed or warned with severity, summary and fix,
// waived items with their end date, when the machine was checked, and which
// machine and email it is. It never shows other machines, admin controls,
// audit data, IPs or locations, and of the evidence (file paths, ports,
// container names: a map of the machine for whoever holds the link) only one
// thing: which production secrets sit in plain text, by name and file, with
// the last characters of the value removed, because "4 marked production" is
// no use to the person who has to move them. The rest they see by running
// bordercheck. Of the findings they marked as not sensitive (bordercheck
// ignore), only the number.
//
// When something fails or warns, the page also offers a one-line prompt for an
// AI coding assistant ("Run `bordercheck fix` and follow what it prints") with
// a Copy button. The prompt is the same for every report apart from where the
// program lives on that OS: nothing the machine reported goes into it, the
// findings and the rules for handling them are printed by bordercheck itself.

import { config, type Env } from "./env";
import { CAPABILITY_HEADERS, SELF, tooManyRequests } from "./enroll";
import { fixHtml, summaryHtml } from "./checktext";
import { checkTitle, forRequest, type I18n } from "./i18n";
import { badge, COPY_HEADERS, copyButton, Html, html, layout, MARK, page, sev, statusClass } from "./html";

const GLYPH_OK = new Html(
  `<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m5.5 12.5 4.2 4.2 8.8-9.2" stroke="#fff" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
);
const GLYPH_ATTENTION = new Html(
  `<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 6.5v7" stroke="#fff" stroke-width="2.8" stroke-linecap="round"/><circle cx="12" cy="17.6" r="1.7" fill="#fff"/></svg>`,
);
import { hit } from "./ratelimit";
import { parseReport, type Result, statusRank } from "./report";
import { countLikelySamples } from "./samples";
import { LINK_RE, sha256hex } from "./tokens";

// fixCommand is how to run the installed bordercheck's `fix` on that OS: the
// install folder is not on PATH (see Dir in internal/agent/agent.go).
export function fixCommand(os: string): string {
  switch (os) {
    case "darwin":
      return `"$HOME/Library/Application Support/bordercheck/bordercheck" fix`;
    case "linux":
      return `"\${XDG_DATA_HOME:-$HOME/.local/share}/bordercheck/bordercheck" fix`;
    case "windows":
      return `& "$env:LOCALAPPDATA\\bordercheck\\bordercheck.exe" fix`;
  }
  return "bordercheck fix";
}

// fixSupported: `bordercheck fix` exists from v0.5.0. A version that is not a
// release number (a development build) is taken to have it.
export function fixSupported(version: string): boolean {
  const m = /^v?(\d+)\.(\d+)\./.exec(version);
  return !m || Number(m[1]) > 0 || Number(m[2]) >= 5;
}

// fixAllowed: the role's policy can turn the prompt off (report.fix_prompt).
function fixAllowed(rolePolicy: string): boolean {
  try {
    return (JSON.parse(rolePolicy) as { report?: { fix_prompt?: unknown } })?.report?.fix_prompt !== false;
  } catch {
    return true;
  }
}

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
    `SELECT m.email, m.hostname, m.last_seen, m.report, ro.policy AS role_policy
     FROM report_links l
     JOIN machines m ON m.install_id = l.install_id
     JOIN enrollments e ON e.install_id = l.install_id
     JOIN roles ro ON ro.id = e.role_id
     WHERE l.link_hash = ?1 AND ?2 = 1 AND l.expires_at > ?3 AND e.revoked_at IS NULL`,
  )
    .bind(h, LINK_RE.test(id) ? 1 : 0, now.toISOString())
    .first<{ email: string; hostname: string; last_seen: string; report: string; role_policy: string }>();
  if (!row) return notFound(L);

  let results: Result[] = [];
  let version = "";
  let os = "";
  try {
    const parsed = parseReport(JSON.parse(row.report));
    results = parsed.results;
    version = parsed.version;
    os = parsed.host.os;
  } catch {
    results = [];
  }
  results.sort((a, b) => statusRank(a.status) - statusRank(b.status));
  const problems = results.filter((r) => r.status === "fail" || r.status === "warn" || r.status === "error");
  const waived = results.filter((r) => r.status === "waived");
  const okCount = results.filter((r) => r.status === "pass" || r.status === "skip").length;
  // Only how many the person marked as not sensitive: like the rest of the
  // evidence, which files and why stay off a page reached by link alone.
  const userIgnored = results.reduce((n, r) => n + (r.user_ignored?.length ?? 0), 0);
  // Likewise only how many were set aside as likely sample keys.
  const likelySamples = countLikelySamples(results);

  const failing = problems.some((r) => r.status === "fail");
  const tone = problems.length === 0 ? "s-pass" : failing ? "s-fail" : "s-warn";
  const fixPrompt =
    problems.some((r) => r.status === "fail" || r.status === "warn") && fixSupported(version) && fixAllowed(row.role_policy)
      ? html`<div class="cmd fixp"><div class="cmd-h"><b>${L.t("rep.fixPromptTitle")}</b><span>${L.t("rep.fixPromptSub")}</span>${copyButton(L, "fix-prompt", "copy.prompt")}</div><code class="msg" tabindex="0" id="fix-prompt">${L.s("rep.fixPrompt", { cmd: fixCommand(os) })}</code></div>`
      : "";
  const headline = problems.length === 0 ? L.t("rep.allClear") : L.t("rep.toFixHeadline", { n: problems.length });
  const body = html`<div class="status-mark ${tone}">${problems.length === 0 ? GLYPH_OK : GLYPH_ATTENTION}</div>
<p class="eyebrow">${L.t("rep.eyebrow")}</p><h1>${headline}</h1>
<p class="lead">${L.t("rep.for", { email: row.email || L.s("common.noEmail"), host: row.hostname || L.s("common.noHostname"), when: L.when(row.last_seen) })}${L.lang === "zh" ? "" : " "}${problems.length === 0 ? L.t("rep.okText") : L.t("rep.fixText")}</p>
<div class="chips"><span class="chip">${L.t("rep.passed", { n: okCount })}</span>${waived.length ? html`<span class="chip">${L.t("rep.exempted", { n: waived.length })}</span>` : ""}${userIgnored ? html`<span class="chip">${L.t("rep.userIgnored", { n: userIgnored })}</span>` : ""}${likelySamples ? html`<span class="chip">${L.t("rep.likelySamples", { n: likelySamples })}</span>` : ""}${version ? html`<span class="chip">bordercheck <b>${version}</b></span>` : ""}</div>
${fixPrompt}
${problems.length === 0
    ? ""
    : html`<h2>${L.t("rep.toFix", { n: problems.length })}</h2>${problems.map(
        (r) => html`<div class="result ${statusClass(r.status)}"><div class="head">${badge(L, r.status)} ${sev(L, r.severity)}</div>
<h3>${checkTitle(L, r.id, r.title)}</h3>
${r.summary ? html`<div class="body">${summaryHtml(L, r)}</div>` : ""}
${prodSecrets(L, r)}
${r.user_ignored?.length ? html`<p class="dim">${L.t("rep.userIgnored", { n: r.user_ignored.length })}</p>` : ""}
${r.likely_samples?.length ? html`<p class="dim">${L.t("rep.likelySamples", { n: r.likely_samples.length })}</p>` : ""}
${r.fix ? html`<div class="fix"><b>${L.t("rep.howToFix")}</b><span>${fixHtml(L, r)}</span></div>` : ""}</div>`,
      )}`}
${waived.length
    ? html`<h2>${L.t("rep.exemptedTitle", { n: waived.length })}</h2><p class="dim">${L.t("rep.exemptedText")}</p>${waived.map(
        (r) => html`<div class="result s-waived"><div class="head">${badge(L, r.status)}</div><h3>${checkTitle(L, r.id, r.title)}</h3>
<div class="waiver">${L.t("rep.until", { date: r.waived?.until ? L.day(r.waived.until) : "?" })}${r.waived?.reason ? html`: <span class="body">${r.waived.reason}</span>` : ""}</div>
${r.fix ? html`<div class="fix"><b>${L.t("rep.howToFix")}</b><span>${fixHtml(L, r)}</span></div>` : ""}</div>`,
      )}`
    : ""}
<p class="foot">${L.t("rep.foot")}</p>`;
  // With the prompt comes its Copy button, so that response alone carries the hashed Copy script.
  if (fixPrompt) return page(layout(L, L.s("rep.title"), null, body, undefined, { ...SELF, copy: true }), 200, { ...CAPABILITY_HEADERS, ...COPY_HEADERS });
  return page(layout(L, L.s("rep.title"), null, body, undefined, SELF), 200, CAPABILITY_HEADERS);
}

// prodSecrets lists the secrets check's evidence lines that the client marked
// "[production]": path, kind and variable name. The client appends the last
// four characters of some tokens (" …abcd") so an owner can tell keys apart;
// on a page reached by link alone those are dropped.
const PROD_MARK = /\s*\[production\]\s*$/;
function prodSecrets(L: I18n, r: Result): Html | string {
  if (r.id !== "secrets") return "";
  const lines = r.evidence.filter((e) => PROD_MARK.test(e)).map((e) => e.replace(PROD_MARK, "").replace(/\s+…\S{1,8}$/, ""));
  if (lines.length === 0) return "";
  return html`<p class="prod"><b>${L.t("rep.prodSecrets", { n: lines.length })}</b> <span class="dim">${L.t("rep.prodSecretsNote")}</span></p>
<ul class="evidence">${lines.slice(0, 60).map((e) => html`<li><code>${e}</code></li>`)}</ul>`;
}
