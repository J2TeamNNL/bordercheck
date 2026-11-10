import { config, DAY, type Env } from "./env";
import { ago, badge, html, type Html, layout, page, statusClass, when } from "./html";
import { parseReport, type Result, statusRank } from "./report";

interface MachineRow {
  install_id: string;
  email: string;
  hostname: string;
  os: string;
  arch: string;
  version: string;
  policy: string;
  first_seen: string;
  last_seen: string;
  report_time: string | null;
  fail: number;
  high_fail: number;
  error: number;
  warn: number;
  waived: number;
  pass: number;
  skip: number;
  other: number;
}

const FILTERS = {
  all: { label: "All", where: "1 = 1" },
  failing: { label: "Failing", where: "fail > 0" },
  attention: { label: "Fail, error or warn", where: "(fail > 0 OR error > 0 OR warn > 0)" },
  silent: { label: "Silent", where: "last_seen < ?2" },
} as const;
type Filter = keyof typeof FILTERS;

function state(m: MachineRow, silentBefore: string): Html {
  const parts: Html[] = [];
  if (m.last_seen < silentBefore) parts.push(html`<span class="badge s-skip">silent</span> `);
  if (m.fail) parts.push(html`<span class="badge s-fail">non-compliant</span>`);
  else if (m.error || m.warn) parts.push(html`<span class="badge s-warn">attention</span>`);
  else parts.push(html`<span class="badge s-pass">ok</span>`);
  return html`${parts}`;
}

const machineLink = (id: string) => `/admin/machine/${encodeURIComponent(id)}`;

export async function machinesPage(env: Env, url: URL, who: string, now: number): Promise<Response> {
  const f = (url.searchParams.get("filter") ?? "all") as Filter;
  const filter: Filter = f in FILTERS ? f : "all";
  const q = (url.searchParams.get("q") ?? "").trim().slice(0, 100);
  const silentBefore = new Date(now - config(env).silentDays * DAY).toISOString();
  const like = `%${q.replace(/[\\%_]/g, (c) => "\\" + c)}%`;
  const rows = await env.DB.prepare(
    `SELECT install_id, email, hostname, os, arch, version, policy, first_seen, last_seen, report_time,
            fail, high_fail, error, warn, waived, pass, skip, other
     FROM machines
     WHERE ${FILTERS[filter].where} AND (?1 = '' OR email LIKE ?3 ESCAPE '\\' OR hostname LIKE ?3 ESCAPE '\\')
     ORDER BY fail > 0 DESC, high_fail DESC, fail DESC, last_seen DESC LIMIT 2000`,
  )
    .bind(q, silentBefore, like)
    .all<MachineRow>();
  const totals = await env.DB.prepare(
    `SELECT COUNT(*) AS n, SUM(fail > 0) AS failing, SUM(last_seen < ?1) AS silent FROM machines`,
  )
    .bind(silentBefore)
    .first<{ n: number; failing: number | null; silent: number | null }>();

  const link = (k: Filter) => {
    const p = new URLSearchParams();
    if (k !== "all") p.set("filter", k);
    if (q) p.set("q", q);
    const s = p.toString();
    return `/admin${s ? "?" + s : ""}`;
  };
  const body = html`<h1>Machines</h1>
<p class="muted">${totals?.n ?? 0} machines · ${totals?.failing ?? 0} non-compliant · ${totals?.silent ?? 0} silent for more than ${config(env).silentDays} days</p>
<div class="filters">${(Object.keys(FILTERS) as Filter[]).map(
    (k) => html`<a href="${link(k)}" class="${k === filter ? "on" : ""}">${FILTERS[k].label}</a>`,
  )}
<form method="get" action="/admin">${filter !== "all" ? html`<input type="hidden" name="filter" value="${filter}">` : ""}<input name="q" value="${q}" placeholder="email or hostname"> <button>Search</button></form></div>
<div class="scroll"><table><thead><tr><th>Email</th><th>Hostname</th><th>OS</th><th>Version</th><th>Last seen</th>
<th>Fail</th><th>Error</th><th>Warn</th><th>Waived</th><th>State</th></tr></thead><tbody>
${rows.results.map(
    (m) => html`<tr><td><a href="${machineLink(m.install_id)}">${m.email || "(no email)"}</a></td>
<td>${m.hostname}</td><td>${m.os}/${m.arch}</td><td>${m.version}</td>
<td title="${when(m.last_seen)}">${ago(m.last_seen, now)}</td>
<td class="n ${m.fail ? "s-fail" : ""}">${m.fail}${m.high_fail ? html` <span class="muted">(${m.high_fail} high)</span>` : ""}</td>
<td class="n ${m.error ? "s-error" : ""}">${m.error}</td><td class="n ${m.warn ? "s-warn" : ""}">${m.warn}</td>
<td class="n ${m.waived ? "s-waived" : ""}">${m.waived}</td><td>${state(m, silentBefore)}</td></tr>`,
  )}
</tbody></table></div>
${rows.results.length === 0 ? html`<p class="muted">No machines match.</p>` : ""}`;
  return page(layout("Machines", who, body));
}

function waiverNote(r: Result, now: number): Html | string {
  if (!r.waived) return "";
  const until = Date.parse(r.waived.until + (r.waived.until.length === 10 ? "T23:59:59Z" : ""));
  let left = "";
  if (!Number.isNaN(until)) {
    const days = Math.ceil((until - now) / DAY);
    left = days < 0 ? " (expired)" : days === 0 ? " (expires today)" : ` (${days} d left)`;
  }
  return html`<div class="s-waived">Waived until ${r.waived.until || "?"}${left}${
    r.waived.reason ? html`: <span class="body">${r.waived.reason}</span>` : ""
  }</div>`;
}

interface HistoryRow {
  received_at: string;
  version: string;
  fail: number;
  warn: number;
  error: number;
  waived: number;
  statuses: string;
}

function changes(prev: Record<string, string> | null, cur: Record<string, string>): Html[] {
  if (!prev) return [html`<span class="muted">oldest report kept</span>`];
  const out: Html[] = [];
  for (const [id, s] of Object.entries(cur)) {
    if (prev[id] !== s) out.push(html`<code>${id}</code> ${prev[id] ?? "new"} → <span class="${statusClass(s)}">${s}</span><br>`);
  }
  for (const id of Object.keys(prev)) if (!(id in cur)) out.push(html`<code>${id}</code> gone<br>`);
  return out;
}

function parseStatuses(s: string): Record<string, string> {
  try {
    const v = JSON.parse(s);
    return v && typeof v === "object" ? v : {};
  } catch {
    return {};
  }
}

export async function machinePage(env: Env, id: string, who: string, now: number): Promise<Response> {
  const m = await env.DB.prepare("SELECT * FROM machines WHERE install_id = ?").bind(id).first<MachineRow & { report: string }>();
  if (!m) return page(layout("Not found", who, html`<h1>No such machine</h1><p><a href="/admin">Back</a></p>`), 404);
  const [checks, hist] = await Promise.all([
    env.DB.prepare("SELECT check_id, since FROM checks WHERE install_id = ?").bind(id).all<{ check_id: string; since: string }>(),
    env.DB.prepare(
      "SELECT received_at, version, fail, warn, error, waived, statuses FROM reports WHERE install_id = ? ORDER BY id DESC LIMIT 61",
    ).bind(id).all<HistoryRow>(),
  ]);
  const since = new Map(checks.results.map((c) => [c.check_id, c.since]));

  let results: Result[] = [];
  let unreadable = false;
  try {
    results = parseReport(JSON.parse(m.report)).results;
  } catch {
    unreadable = true;
  }
  results.sort((a, b) => statusRank(a.status) - statusRank(b.status));
  const problems = results.filter((r) => !["pass", "skip"].includes(r.status));
  const fine = results.filter((r) => ["pass", "skip"].includes(r.status));
  const silent = Date.parse(m.last_seen) < now - config(env).silentDays * DAY;

  // History newest first; each row shows what changed since the one before.
  const h = hist.results;
  const histRows = h.slice(0, 60).map((r, i) => {
    const older = h[i + 1] ? parseStatuses(h[i + 1].statuses) : null;
    return html`<tr><td title="${r.received_at}">${when(r.received_at)}</td><td>${r.version}</td>
<td class="n">${r.fail}</td><td class="n">${r.error}</td><td class="n">${r.warn}</td><td class="n">${r.waived}</td>
<td>${changes(older, parseStatuses(r.statuses))}</td></tr>`;
  });

  const body = html`<h1>${m.email || "(no email)"} · ${m.hostname}</h1>
${silent ? html`<div class="note s-warn">No report for ${ago(m.last_seen, now)}. The tool may have been uninstalled, or the machine is off.</div>` : ""}
<dl><dt>OS</dt><dd>${m.os}/${m.arch}</dd><dt>bordercheck</dt><dd>${m.version}</dd><dt>Policy</dt><dd>${m.policy}</dd>
<dt>Last report</dt><dd>${when(m.last_seen)} (${ago(m.last_seen, now)}); machine clock said ${when(m.report_time) || "nothing"}</dd>
<dt>First seen</dt><dd>${when(m.first_seen)}</dd><dt>Install ID</dt><dd><code>${m.install_id}</code></dd></dl>
${unreadable ? html`<p class="note">The stored report could not be read.</p>` : ""}
<h2>Needs attention (${problems.length})</h2>
${problems.length === 0 ? html`<p class="muted">Nothing failing.</p>` : ""}
${problems.map(
    (r) => html`<div class="result ${statusClass(r.status)}"><div>${badge(r.status)} ${r.severity ? html`<span class="muted">[${r.severity}]</span>` : ""}
<b class="body">${r.title || r.id}</b> <code class="muted">${r.id}</code>
${since.has(r.id) ? html`<span class="muted"> · since ${when(since.get(r.id))}</span>` : ""}</div>
${waiverNote(r, now)}
${r.summary ? html`<div class="body">${r.summary}</div>` : ""}
${r.evidence.length ? html`<ul>${r.evidence.map((e) => html`<li class="ev">${e}</li>`)}</ul>` : ""}
${r.fix ? html`<div class="body"><b>Fix:</b> ${r.fix}</div>` : ""}</div>`,
  )}
<h2>Passing or not applicable (${fine.length})</h2>
<div class="scroll"><table><tbody>${fine.map(
    (r) => html`<tr><td>${badge(r.status)}</td><td>${r.title || r.id}</td><td><code>${r.id}</code></td><td class="muted">${r.summary}</td></tr>`,
  )}</tbody></table></div>
<h2>History</h2>
<div class="scroll"><table><thead><tr><th>Received</th><th>Version</th><th>Fail</th><th>Error</th><th>Warn</th><th>Waived</th><th>Changed</th></tr></thead>
<tbody>${histRows}</tbody></table></div>
<h2>Forget this machine</h2>
<p class="muted">Deletes its reports and history, for a laptop that was retired. If it reports again it comes back as new.</p>
<form method="post" action="${machineLink(m.install_id)}/forget"><button class="danger">Forget machine</button></form>`;
  return page(layout(m.hostname || m.email || "Machine", who, body));
}

export async function forgetMachine(env: Env, id: string): Promise<void> {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM machines WHERE install_id = ?").bind(id),
    env.DB.prepare("DELETE FROM checks WHERE install_id = ?").bind(id),
    env.DB.prepare("DELETE FROM reports WHERE install_id = ?").bind(id),
    env.DB.prepare("DELETE FROM alerts WHERE install_id = ? AND sent_at IS NULL").bind(id),
  ]);
}

interface CheckStat {
  check_id: string;
  title: string;
  fail: number;
  high: number;
  error: number;
  warn: number;
  waived: number;
  pass: number;
  total: number;
}

export async function checksPage(env: Env, who: string): Promise<Response> {
  const rows = await env.DB.prepare(
    `SELECT check_id, MAX(title) AS title, SUM(status = 'fail') AS fail, SUM(status = 'fail' AND severity = 'high') AS high,
            SUM(status = 'error') AS error, SUM(status = 'warn') AS warn, SUM(status = 'waived') AS waived,
            SUM(status = 'pass') AS pass, COUNT(*) AS total
     FROM checks GROUP BY check_id ORDER BY fail DESC, high DESC, error DESC, warn DESC, check_id`,
  ).all<CheckStat>();
  const cell = (id: string, status: string, n: number) =>
    n ? html`<a class="${statusClass(status)}" href="/admin/checks/${encodeURIComponent(id)}?status=${status}">${n}</a>` : html`<span class="muted">0</span>`;
  const body = html`<h1>Checks across all machines</h1>
<p class="muted">From each machine's latest report. Most failing first.</p>
<div class="scroll"><table><thead><tr><th>Check</th><th>Fail</th><th>of which high</th><th>Error</th><th>Warn</th><th>Waived</th><th>Pass</th><th>Reported by</th></tr></thead><tbody>
${rows.results.map(
    (c) => html`<tr><td><a href="/admin/checks/${encodeURIComponent(c.check_id)}">${c.title || c.check_id}</a> <code class="muted">${c.check_id}</code></td>
<td class="n">${cell(c.check_id, "fail", c.fail)}</td><td class="n">${c.high}</td><td class="n">${cell(c.check_id, "error", c.error)}</td>
<td class="n">${cell(c.check_id, "warn", c.warn)}</td><td class="n">${cell(c.check_id, "waived", c.waived)}</td>
<td class="n">${c.pass}</td><td class="n">${c.total}</td></tr>`,
  )}</tbody></table></div>`;
  return page(layout("Checks", who, body));
}

export async function checkPage(env: Env, checkId: string, url: URL, who: string, now: number): Promise<Response> {
  const status = (url.searchParams.get("status") ?? "").slice(0, 32);
  const rows = await env.DB.prepare(
    `SELECT c.status, c.severity, c.title, c.since, m.install_id, m.email, m.hostname, m.last_seen
     FROM checks c JOIN machines m ON m.install_id = c.install_id
     WHERE c.check_id = ?1 AND (?2 = '' OR c.status = ?2)
     ORDER BY c.status = 'fail' DESC, c.status = 'error' DESC, c.status = 'warn' DESC, c.since LIMIT 2000`,
  )
    .bind(checkId, status)
    .all<{ status: string; severity: string; title: string; since: string; install_id: string; email: string; hostname: string; last_seen: string }>();
  const title = rows.results[0]?.title || checkId;
  const body = html`<h1>${title} <code class="muted">${checkId}</code></h1>
<div class="filters">${["", "fail", "error", "warn", "waived", "pass"].map(
    (s) => html`<a class="${s === status ? "on" : ""}" href="/admin/checks/${encodeURIComponent(checkId)}${s ? `?status=${s}` : ""}">${s || "all"}</a>`,
  )}</div>
<div class="scroll"><table><thead><tr><th>Email</th><th>Hostname</th><th>Status</th><th>Since</th><th>Last seen</th></tr></thead><tbody>
${rows.results.map(
    (r) => html`<tr><td><a href="${machineLink(r.install_id)}">${r.email || "(no email)"}</a></td><td>${r.hostname}</td>
<td>${badge(r.status)} ${r.severity ? html`<span class="muted">${r.severity}</span>` : ""}</td><td>${when(r.since)}</td><td>${ago(r.last_seen, now)}</td></tr>`,
  )}</tbody></table></div>`;
  return page(layout(title, who, body));
}

export async function alertsPage(env: Env, who: string): Promise<Response> {
  const rows = await env.DB.prepare(
    "SELECT id, kind, install_id, check_id, detail, created_at, sent_at, delivery FROM alerts ORDER BY id DESC LIMIT 200",
  ).all<{ id: number; kind: string; install_id: string; check_id: string; detail: string; created_at: string; sent_at: string | null; delivery: string }>();
  const body = html`<h1>Alerts</h1>
<p class="muted">Raised by reports and the hourly cron; delivered to the webhook by the cron.${
    env.ALERT_WEBHOOK_URL ? "" : " No webhook is set (ALERT_WEBHOOK_URL), so they are only listed here."
  }</p>
<div class="scroll"><table><thead><tr><th>Raised</th><th>Kind</th><th>Machine</th><th>Check</th><th>Delivery</th></tr></thead><tbody>
${rows.results.map((a) => {
    const d = parseStatuses(a.detail);
    return html`<tr><td>${when(a.created_at)}</td><td>${a.kind.replace("_", " ")}</td>
<td><a href="${machineLink(a.install_id)}">${d.email || "(no email)"}</a> ${d.hostname}</td>
<td>${a.check_id ? html`<code>${a.check_id}</code> ${d.title}` : ""}</td><td class="muted">${a.sent_at ? a.delivery : "pending"}</td></tr>`;
  })}</tbody></table></div>`;
  return page(layout("Alerts", who, body));
}
