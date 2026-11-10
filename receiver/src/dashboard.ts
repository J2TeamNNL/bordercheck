import { config, DAY, type Env } from "./env";
import { age, ago, badge, count, html, type Html, layout, note, page, pct, pill, sev, statusClass, when } from "./html";
import { type Geo, mapLink, parseGeo, place } from "./geo";
import { enrollmentOf, enrollmentSection } from "./portal";
import { type DeviceLocation, parseReport, type Result, statusRank } from "./report";

export interface MachineRow {
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

export const FILTERS = {
  all: { label: "All", where: "1 = 1" },
  failing: { label: "Failing", where: "m.fail > 0" },
  attention: { label: "Fail, error or warn", where: "(m.fail > 0 OR m.error > 0 OR m.warn > 0)" },
  silent: { label: "Silent", where: "m.last_seen < ?2" },
  revoked: { label: "Revoked", where: "e.revoked_at IS NOT NULL" },
} as const;
export type Filter = keyof typeof FILTERS;

export type MachineListRow = MachineRow & {
  public_ip: string;
  geo: string;
  enrolled: number;
  revoked_at: string | null;
  role: string | null;
  failing_since: string | null; // the oldest `since` among its failing checks
};

// machineRows is the machine list (dashboard front page, MCP list_machines):
// a filter, a substring of email or hostname, and optionally only machines
// whose latest report has `check` at `checkStatus`.
export async function machineRows(
  env: Env,
  o: { filter: Filter; q: string; silentBefore: string; limit: number; check?: string; checkStatus?: string; roleId?: number },
): Promise<MachineListRow[]> {
  const like = `%${o.q.replace(/[\\%_]/g, (c) => "\\" + c)}%`;
  const rows = await env.DB.prepare(
    `SELECT m.install_id, m.email, m.hostname, m.os, m.arch, m.version, m.policy, m.first_seen, m.last_seen, m.report_time,
            m.fail, m.high_fail, m.error, m.warn, m.waived, m.pass, m.skip, m.other, m.public_ip, m.geo,
            e.install_id IS NOT NULL AS enrolled, e.revoked_at, r.name AS role,
            (SELECT MIN(c.since) FROM checks c WHERE c.install_id = m.install_id AND c.status = 'fail') AS failing_since
     FROM machines m LEFT JOIN enrollments e ON e.install_id = m.install_id LEFT JOIN roles r ON r.id = e.role_id
     WHERE ${FILTERS[o.filter].where} AND (?1 = '' OR m.email LIKE ?3 ESCAPE '\\' OR m.hostname LIKE ?3 ESCAPE '\\')
       AND (?5 = '' OR EXISTS (SELECT 1 FROM checks c WHERE c.install_id = m.install_id AND c.check_id = ?5 AND (?6 = '' OR c.status = ?6)))
       AND (?7 = 0 OR e.role_id = ?7)
     ORDER BY m.fail > 0 DESC, m.high_fail DESC, m.fail DESC, m.last_seen DESC LIMIT ?4`,
  )
    .bind(o.q, o.silentBefore, like, o.limit, o.check ?? "", o.checkStatus ?? "", o.roleId ?? 0)
    .all<MachineListRow>();
  return rows.results;
}

export async function waitingRows(env: Env, limit: number) {
  const r = await env.DB.prepare(
    `SELECT e.install_id, e.email, e.hostname, e.enrolled_at, r.name AS role FROM enrollments e JOIN roles r ON r.id = e.role_id
     WHERE e.revoked_at IS NULL AND NOT EXISTS (SELECT 1 FROM machines m WHERE m.install_id = e.install_id)
     ORDER BY e.enrolled_at DESC LIMIT ?`,
  ).bind(limit).all<{ install_id: string; email: string; hostname: string; enrolled_at: string; role: string }>();
  return r.results;
}

// The state of a machine as one pill (worst first), plus "silent".
function state(m: MachineRow, silentBefore: string): Html {
  const parts: Html[] = [];
  if (m.fail) parts.push(pill("s-fail", "non-compliant"));
  else if (m.error || m.warn) parts.push(pill("s-warn", "attention"));
  else parts.push(pill("s-pass", "ok"));
  if (m.last_seen < silentBefore) parts.push(pill("s-skip", "silent"));
  return html`${parts}`;
}

const machineLink = (id: string) => `/admin/machine/${encodeURIComponent(id)}`;

function tile(href: string, n: number, label: string, sub: string, tone: string): Html {
  return html`<a class="tile ${n ? tone : "zero"}" href="${href}"><span class="l">${label}</span><span class="s">${sub}</span><span class="n">${n}</span></a>`;
}

export async function machinesPage(env: Env, url: URL, who: string, now: number): Promise<Response> {
  const f = (url.searchParams.get("filter") ?? "all") as Filter;
  const filter: Filter = f in FILTERS ? f : "all";
  const q = (url.searchParams.get("q") ?? "").trim().slice(0, 100);
  const cfg = config(env);
  const silentBefore = new Date(now - cfg.silentDays * DAY).toISOString();
  const [rows, waiting, totals, top, pending] = await Promise.all([
    machineRows(env, { filter, q, silentBefore, limit: 2000 }),
    waitingRows(env, 500),
    env.DB.prepare(
      `SELECT COUNT(*) AS n, SUM(m.fail > 0) AS failing, SUM(m.fail = 0 AND (m.error > 0 OR m.warn > 0)) AS attention,
              SUM(m.last_seen < ?1) AS silent, SUM(e.revoked_at IS NOT NULL) AS revoked
       FROM machines m LEFT JOIN enrollments e ON e.install_id = m.install_id`,
    )
      .bind(silentBefore)
      .first<{ n: number; failing: number | null; attention: number | null; silent: number | null; revoked: number | null }>(),
    checkStats(env, 4),
    env.DB.prepare("SELECT COUNT(*) AS n FROM invites WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at > ?")
      .bind(new Date(now).toISOString())
      .first<number>("n"),
  ]);
  const n = totals?.n ?? 0;
  const failing = totals?.failing ?? 0;
  const attention = totals?.attention ?? 0;
  const ok = Math.max(0, n - failing - attention);
  const topFailing = top.filter((c) => c.fail > 0);

  const link = (k: Filter) => {
    const p = new URLSearchParams();
    if (k !== "all") p.set("filter", k);
    if (q) p.set("q", q);
    const s = p.toString();
    return `/admin${s ? "?" + s : ""}`;
  };

  const overview = html`<div class="tiles">
${tile("/admin?filter=failing", failing, "Failing", "at least one check fails", "t-fail")}
${tile("/admin?filter=attention", attention, "Attention", "errors or warnings, no fail", "t-warn")}
${tile("/admin?filter=silent", totals?.silent ?? 0, "Silent", `no report for ${cfg.silentDays}+ days`, "t-skip")}
${tile("/admin/invites?status=pending", pending ?? 0, "Pending invites", "not installed yet", "t-accent")}
${tile("#waiting", waiting.length, "Awaiting first report", "enrolled, nothing received", "t-accent")}
</div>
${n
    ? html`<div class="health" aria-label="Fleet health"><div class="bar">${failing ? html`<i class="b-fail" style="width:${pct(failing, n)}"></i>` : ""}${
        attention ? html`<i class="b-warn" style="width:${pct(attention, n)}"></i>` : ""
      }${ok ? html`<i class="b-ok" style="width:${pct(ok, n)}"></i>` : ""}</div>
<div class="legend"><span class="b-fail">${failing} non-compliant</span><span class="b-warn">${attention} attention</span><span class="b-ok">${ok} ok</span>${
        totals?.revoked ? html`<span class="b-skip">${totals.revoked} revoked</span>` : ""
      }</div></div>`
    : ""}
${topFailing.length
    ? html`<div class="shelf"><h2>Failing most</h2><a href="/admin/checks">All checks ›</a></div>
<div class="shelf-row">${topFailing.map(
        (c) => html`<a class="card" href="/admin/checks/${encodeURIComponent(c.check_id)}?status=fail"><span class="t">${c.title || c.check_id}</span><code class="muted">${c.check_id}</code>
<span class="meta"><span class="big">${c.fail}</span>failing${c.high ? html` · ${c.high} high` : ""} · of ${c.total}</span></a>`,
      )}</div>`
    : ""}`;

  const table = html`<div class="panel flush"><div class="scroll"><table><thead><tr><th>State</th><th>Person · machine</th><th>Role</th><th>Platform</th><th>From</th><th>Last seen</th>
<th class="n">Fail</th><th class="n">Error</th><th class="n">Warn</th><th class="n">Waived</th></tr></thead><tbody>
${rows.map(
    (m) => html`<tr${m.revoked_at ? html` class="off"` : ""}><td class="nowrap">${state(m, silentBefore)}${
      m.failing_since ? html`<span class="sub">failing for ${age(m.failing_since, now)}</span>` : ""
    }</td>
<td class="who-cell"><a href="${machineLink(m.install_id)}">${m.email || "(no email)"}</a><span class="sub">${m.hostname}</span></td>
<td>${m.role ?? ""}${m.revoked_at ? html` ${pill("s-fail", "revoked")}` : ""}</td>
<td class="nowrap">${m.os}/${m.arch}<span class="sub">${m.version}</span></td>
<td>${place(parseGeo(m.geo))}${m.public_ip ? html`<span class="sub mono">${m.public_ip}</span>` : ""}</td>
<td class="nowrap" title="${when(m.last_seen)}">${ago(m.last_seen, now)}</td>
<td class="n">${count(m.fail, "num-fail")}${m.high_fail ? html`<span class="sub">${m.high_fail} high</span>` : ""}</td>
<td class="n">${count(m.error, "num-error")}</td><td class="n">${count(m.warn, "num-warn")}</td>
<td class="n">${count(m.waived, "num-waived")}</td></tr>`,
  )}
</tbody></table></div>${rows.length === 0 ? html`<p class="empty">No machines match.</p>` : ""}</div>`;

  const body = html`<div class="hero"><p class="eyebrow">Fleet</p><h1>Machines</h1>
<p class="lead">${n} reporting · ${failing} non-compliant · ${totals?.silent ?? 0} silent for more than ${cfg.silentDays} days</p></div>
${overview}
<div class="shelf"><h2>${filter === "all" ? "Every machine" : FILTERS[filter].label}${q ? html` matching “${q}”` : ""}</h2><span class="muted small">${rows.length} shown</span></div>
<div class="toolbar"><nav class="seg" aria-label="Filter">${(Object.keys(FILTERS) as Filter[]).map(
    (k) => html`<a href="${link(k)}" class="${k === filter ? "on" : ""}">${FILTERS[k].label}</a>`,
  )}</nav>
<form class="search" method="get" action="/admin">${filter !== "all" ? html`<input type="hidden" name="filter" value="${filter}">` : ""}<input name="q" value="${q}" placeholder="Email or hostname" aria-label="Search by email or hostname"><button>Search</button></form></div>
${table}
${waiting.length
    ? html`<h2 id="waiting">Enrolled, no report yet (${waiting.length})</h2>
<div class="panel flush"><div class="scroll"><table><thead><tr><th>Person · machine</th><th>Role</th><th>Enrolled</th></tr></thead><tbody>${waiting.map(
        (w) => html`<tr><td class="who-cell"><a href="${machineLink(w.install_id)}">${w.email}</a><span class="sub">${w.hostname}</span></td><td>${w.role}</td><td class="nowrap">${ago(w.enrolled_at, now)}</td></tr>`,
      )}</tbody></table></div></div>`
    : html`<span id="waiting"></span>`}`;
  return page(layout("Machines", who, body, "Machines"));
}

function waiverNote(r: Result, now: number): Html | string {
  if (!r.waived) return "";
  const until = Date.parse(r.waived.until + (r.waived.until.length === 10 ? "T23:59:59Z" : ""));
  let left = "";
  if (!Number.isNaN(until)) {
    const days = Math.ceil((until - now) / DAY);
    left = days < 0 ? " (expired)" : days === 0 ? " (expires today)" : ` (${days} d left)`;
  }
  return html`<div class="waiver">Waived until ${r.waived.until || "?"}${left}${
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
  ip: string;
  geo: string;
  device_location: string;
}

function changes(prev: Record<string, string> | null, cur: Record<string, string>): Html[] {
  if (!prev) return [html`<span class="muted">oldest report kept</span>`];
  const out: Html[] = [];
  for (const [id, s] of Object.entries(cur)) {
    if (prev[id] !== s) out.push(html`<div><code>${id}</code> <span class="muted">${prev[id] ?? "new"} →</span> ${badge(s)}</div>`);
  }
  for (const id of Object.keys(prev)) if (!(id in cur)) out.push(html`<div><code>${id}</code> <span class="muted">gone</span></div>`);
  return out;
}

export function parseStatuses(s: string): Record<string, string> {
  try {
    const v = JSON.parse(s);
    return v && typeof v === "object" ? v : {};
  } catch {
    return {};
  }
}

function parseJSON<T>(s: string | null | undefined): T | null {
  if (!s) return null;
  try {
    return JSON.parse(s) as T;
  } catch {
    return null;
  }
}

function geoLine(g: Geo | null): Html | string {
  if (!g) return "";
  const coords = g.lat !== undefined && g.lon !== undefined
    ? html` · <a href="${mapLink(g.lat, g.lon)}" rel="noreferrer noopener" target="_blank">${g.lat.toFixed(3)}, ${g.lon.toFixed(3)} (map)</a>`
    : "";
  return html`${place(g) || "?"}${coords}${g.timezone ? html` · ${g.timezone}` : ""}${g.asn ? html` · AS${g.asn} ${g.as_org ?? ""}` : ""}`;
}

function deviceLine(d: DeviceLocation | null): Html | string {
  if (!d || typeof d.lat !== "number" || typeof d.lon !== "number") return "";
  return html`<a href="${mapLink(d.lat, d.lon)}" rel="noreferrer noopener" target="_blank">${d.lat.toFixed(5)}, ${d.lon.toFixed(5)} (map)</a>${
    d.accuracy_m !== null && d.accuracy_m !== undefined ? html` ±${d.accuracy_m} m` : ""
  }${d.source ? html` · source ${d.source}` : ""}${d.time ? html` · at ${when(d.time)}` : ""}`;
}

function whereSection(m: { public_ip: string; geo: string; local_ips: string; device_location: string }): Html {
  const g = parseGeo(m.geo);
  const d = parseJSON<DeviceLocation>(m.device_location);
  const ips = parseJSON<string[]>(m.local_ips) ?? [];
  if (!m.public_ip && !g && !d && !ips.length) {
    return html`<h2>Where it reports from</h2><div class="panel"><p class="muted">Nothing recorded (collection is off, or the receiver runs without Cloudflare in front).</p></div>`;
  }
  return html`<h2>Where it reports from</h2>
<div class="panel"><dl class="facts"><div><dt>Public IP</dt><dd>${m.public_ip ? html`<code>${m.public_ip}</code>` : "?"}<br><span class="muted small">seen by Cloudflare</span></dd></div>
<div><dt>IP-based location</dt><dd>${geoLine(g) || "?"}<br><span class="muted small">Cloudflare's estimate from the IP</span></dd></div>
<div><dt>Device-reported location</dt><dd>${deviceLine(d) || html`<span class="muted">none</span>`}<br><span class="muted small">sent by the machine; unverified</span></dd></div>
<div><dt>Local addresses</dt><dd>${ips.length ? ips.map((ip, i) => html`${i ? ", " : ""}<code>${ip}</code>`) : html`<span class="muted">none</span>`}<br><span class="muted small">sent by the machine; unverified</span></dd></div></dl>
<p class="muted small">Map links open OpenStreetMap with only the coordinates, and only if you click them.</p></div>`;
}

function resultCard(r: Result, since: string | undefined, now: number): Html {
  return html`<div class="result ${statusClass(r.status)}"><div class="head">${badge(r.status)} ${sev(r.severity)}
<h3>${r.title || r.id}</h3> <code class="muted">${r.id}</code>${since ? html`<span class="since">since ${when(since)}</span>` : ""}</div>
${waiverNote(r, now)}
${r.summary ? html`<div class="body">${r.summary}</div>` : ""}
${r.evidence.length ? html`<ul class="evidence">${r.evidence.map((e) => html`<li class="ev">${e}</li>`)}</ul>` : ""}
${r.fix ? html`<div class="fix"><b>Fix</b><span>${r.fix}</span></div>` : ""}</div>`;
}

function statTile(n: number, label: string, tone: string): Html {
  return html`<div class="tile ${n ? tone : "zero"}"><span class="l">${label}</span><span class="n">${n}</span></div>`;
}

export async function machinePage(env: Env, id: string, who: string, now: number): Promise<Response> {
  const [mRow, enrollment] = await Promise.all([
    env.DB.prepare("SELECT * FROM machines WHERE install_id = ?").bind(id).first<MachineRow & { report: string; public_ip: string; geo: string; local_ips: string; device_location: string }>(),
    enrollmentOf(env, id),
  ]);
  if (!mRow && !enrollment) {
    return page(layout("Not found", who, html`<p class="eyebrow">Machines</p><h1>No such machine</h1><p><a href="/admin">Back to machines</a></p>`, "Machines"), 404);
  }
  const enrollHtml = await enrollmentSection(env, id, enrollment, new Date(now));
  const crumb = html`<p class="eyebrow"><a href="/admin">Machines</a> · ${enrollment?.role ?? "machine"}</p>`;
  if (!mRow) {
    const e = enrollment!;
    const body = html`<div class="hero">${crumb}<h1>${e.hostname || e.email}</h1><p class="lead">${e.email}</p></div>
${note(html`Enrolled ${ago(e.enrolled_at, now)}; no report has arrived yet.`)}
<div class="panel"><dl class="facts"><div><dt>Install ID</dt><dd><code>${e.install_id}</code></dd></div></dl></div>${enrollHtml}`;
    return page(layout(e.hostname || e.email, who, body, "Machines"));
  }
  const m = mRow;
  const [checks, hist] = await Promise.all([
    env.DB.prepare("SELECT check_id, since FROM checks WHERE install_id = ?").bind(id).all<{ check_id: string; since: string }>(),
    env.DB.prepare(
      "SELECT received_at, version, fail, warn, error, waived, statuses, ip, geo, device_location FROM reports WHERE install_id = ? ORDER BY id DESC LIMIT 61",
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
  const silentBefore = new Date(now - config(env).silentDays * DAY).toISOString();
  const silent = m.last_seen < silentBefore;

  // History newest first; each row shows what changed since the one before.
  const h = hist.results;
  const histRows = h.slice(0, 60).map((r, i) => {
    const older = h[i + 1] ? parseStatuses(h[i + 1].statuses) : null;
    return html`<tr><td class="nowrap" title="${r.received_at}">${when(r.received_at)}</td><td>${r.version}</td>
<td class="n">${count(r.fail, "num-fail")}</td><td class="n">${count(r.error, "num-error")}</td><td class="n">${count(r.warn, "num-warn")}</td><td class="n">${count(r.waived, "num-waived")}</td>
<td>${place(parseGeo(r.geo))}${r.ip ? html`<span class="sub mono">${r.ip}</span>` : ""}${r.device_location ? html`<span class="sub">+ device location</span>` : ""}</td>
<td class="wrap">${changes(older, parseStatuses(r.statuses))}</td></tr>`;
  });

  const body = html`<div class="hero">${crumb}<h1>${m.hostname || "(no hostname)"}</h1>
<p class="lead">${m.email || "(no email)"}</p>
<div class="chips">${state(m, silentBefore)}${enrollment?.revoked_at ? pill("s-fail", "revoked") : ""}<span class="chip">${m.os}/${m.arch}</span><span class="chip">bordercheck <b>${m.version}</b></span><span class="chip" title="${when(m.last_seen)}">reported <b>${ago(m.last_seen, now)}</b></span></div></div>
${silent ? note(html`No report for ${age(m.last_seen, now)}. The tool may have been uninstalled, or the machine is off.`, "s-warn") : ""}
${unreadable ? note("The stored report could not be read.", "s-fail") : ""}
<div class="tiles">${statTile(m.fail, m.high_fail ? `Fail · ${m.high_fail} high` : "Fail", "t-fail")}${statTile(m.error, "Error", "t-err")}${statTile(m.warn, "Warn", "t-warn")}${statTile(m.waived, "Waived", "t-accent")}${statTile(m.pass, "Pass", "t-ok")}</div>
<h2>Needs attention (${problems.length})</h2>
${problems.length === 0 ? html`<div class="panel"><p class="muted">Nothing failing.</p></div>` : ""}
${problems.map((r) => resultCard(r, since.get(r.id), now))}
<h2>Passing or not applicable (${fine.length})</h2>
${fine.length
    ? html`<div class="compact">${fine.map(
        (r) => html`<div>${badge(r.status)}<div><div class="t">${r.title || r.id}</div><div class="sub"><code>${r.id}</code>${r.summary ? html` · ${r.summary}` : ""}</div></div></div>`,
      )}</div>`
    : html`<div class="panel"><p class="muted">None.</p></div>`}
<h2>Details</h2>
<div class="panel"><dl class="facts"><div><dt>OS</dt><dd>${m.os}/${m.arch}</dd></div><div><dt>bordercheck</dt><dd>${m.version}</dd></div><div><dt>Policy</dt><dd>${m.policy}</dd></div>
<div><dt>Last report</dt><dd>${when(m.last_seen)}<br><span class="muted small">${ago(m.last_seen, now)}; machine clock said ${when(m.report_time) || "nothing"}</span></dd></div>
<div><dt>First seen</dt><dd>${when(m.first_seen)}</dd></div><div><dt>Install ID</dt><dd><code>${m.install_id}</code></dd></div></dl></div>
<h2>History</h2>
<div class="panel flush"><div class="scroll"><table><thead><tr><th>Received</th><th>Version</th><th class="n">Fail</th><th class="n">Error</th><th class="n">Warn</th><th class="n">Waived</th><th>From</th><th>Changed</th></tr></thead>
<tbody>${histRows}</tbody></table></div></div>
${whereSection(m)}
${enrollHtml}
<h2>Forget this machine</h2>
<div class="panel danger-zone"><p class="muted">Deletes its reports, history, recorded IPs and locations and report links, for a laptop that was retired.
If it reports again it comes back as new.${enrollment ? " Its enrollment (and token) stays; revoke it first so it can't." : ""}</p>
<form method="post" action="${machineLink(m.install_id)}/forget"><button class="danger">Forget machine</button></form></div>`;
  return page(layout(m.hostname || m.email || "Machine", who, body, "Machines"));
}

export async function forgetMachine(env: Env, id: string): Promise<void> {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM machines WHERE install_id = ?").bind(id),
    env.DB.prepare("DELETE FROM checks WHERE install_id = ?").bind(id),
    env.DB.prepare("DELETE FROM reports WHERE install_id = ?").bind(id),
    env.DB.prepare("DELETE FROM alerts WHERE install_id = ? AND sent_at IS NULL").bind(id),
    env.DB.prepare("DELETE FROM report_links WHERE install_id = ?").bind(id),
  ]);
}

export interface CheckStat {
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

// checkStats: each check across all machines' latest reports, most failing first.
export async function checkStats(env: Env, limit = 1000): Promise<CheckStat[]> {
  const rows = await env.DB.prepare(
    `SELECT check_id, MAX(title) AS title, SUM(status = 'fail') AS fail, SUM(status = 'fail' AND severity = 'high') AS high,
            SUM(status = 'error') AS error, SUM(status = 'warn') AS warn, SUM(status = 'waived') AS waived,
            SUM(status = 'pass') AS pass, COUNT(*) AS total
     FROM checks GROUP BY check_id ORDER BY fail DESC, high DESC, error DESC, warn DESC, check_id LIMIT ?`,
  ).bind(limit).all<CheckStat>();
  return rows.results;
}

export async function checksPage(env: Env, who: string): Promise<Response> {
  const rows = await checkStats(env);
  const cell = (id: string, status: string, n: number, cls: string) =>
    n ? html`<a class="${cls}" href="/admin/checks/${encodeURIComponent(id)}?status=${status}">${n}</a>` : html`<span class="zero">0</span>`;
  const body = html`<div class="hero"><p class="eyebrow">Fleet</p><h1>Checks</h1>
<p class="lead">Each check across every machine's latest report, most failing first.</p></div>
<div class="panel flush"><div class="scroll"><table><thead><tr><th>Check</th><th class="n">Fail</th><th class="n">High</th><th class="n">Error</th><th class="n">Warn</th><th class="n">Waived</th><th class="n">Pass</th><th class="n">Reported by</th></tr></thead><tbody>
${rows.map(
    (c) => html`<tr><td class="wrap"><a class="strong" href="/admin/checks/${encodeURIComponent(c.check_id)}">${c.title || c.check_id}</a> <code class="muted">${c.check_id}</code>
<div class="minibar">${c.fail ? html`<i class="b-fail" style="width:${pct(c.fail, c.total)}"></i>` : ""}${c.error ? html`<i class="b-err" style="width:${pct(c.error, c.total)}"></i>` : ""}${
      c.warn ? html`<i class="b-warn" style="width:${pct(c.warn, c.total)}"></i>` : ""
    }${c.waived ? html`<i class="b-waived" style="width:${pct(c.waived, c.total)}"></i>` : ""}${c.pass ? html`<i class="b-ok" style="width:${pct(c.pass, c.total)}"></i>` : ""}</div></td>
<td class="n">${cell(c.check_id, "fail", c.fail, "num-fail")}</td><td class="n">${count(c.high, "num-fail")}</td><td class="n">${cell(c.check_id, "error", c.error, "num-error")}</td>
<td class="n">${cell(c.check_id, "warn", c.warn, "num-warn")}</td><td class="n">${cell(c.check_id, "waived", c.waived, "num-waived")}</td>
<td class="n">${c.pass}</td><td class="n">${c.total}</td></tr>`,
  )}</tbody></table></div>${rows.length === 0 ? html`<p class="empty">No reports yet.</p>` : ""}</div>`;
  return page(layout("Checks", who, body, "Checks"));
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
  const body = html`<div class="hero"><p class="eyebrow"><a href="/admin/checks">Checks</a> · <code>${checkId}</code></p><h1>${title}</h1>
<p class="lead">${rows.results.length} machine${rows.results.length === 1 ? "" : "s"}${status ? html` at <b>${status}</b>` : ""}, worst and longest-standing first.</p></div>
<div class="toolbar"><nav class="seg" aria-label="Status">${["", "fail", "error", "warn", "waived", "pass"].map(
    (s) => html`<a class="${s === status ? "on" : ""}" href="/admin/checks/${encodeURIComponent(checkId)}${s ? `?status=${s}` : ""}">${s || "all"}</a>`,
  )}</nav></div>
<div class="panel flush"><div class="scroll"><table><thead><tr><th>Status</th><th>Person · machine</th><th>Since</th><th>Last seen</th></tr></thead><tbody>
${rows.results.map(
    (r) => html`<tr><td class="nowrap">${badge(r.status)} ${sev(r.severity)}</td><td class="who-cell"><a href="${machineLink(r.install_id)}">${r.email || "(no email)"}</a><span class="sub">${r.hostname}</span></td>
<td class="nowrap">${when(r.since)}<span class="sub">${age(r.since, now)}</span></td><td class="nowrap">${ago(r.last_seen, now)}</td></tr>`,
  )}</tbody></table></div>${rows.results.length === 0 ? html`<p class="empty">No machines.</p>` : ""}</div>`;
  return page(layout(title, who, body, "Checks"));
}

export interface AlertListRow {
  id: number;
  kind: string;
  install_id: string;
  check_id: string;
  detail: string;
  created_at: string;
  sent_at: string | null;
  delivery: string;
}

export async function alertRows(env: Env, limit: number, pendingOnly = false): Promise<AlertListRow[]> {
  const rows = await env.DB.prepare(
    "SELECT id, kind, install_id, check_id, detail, created_at, sent_at, delivery FROM alerts WHERE ?1 = 0 OR sent_at IS NULL ORDER BY id DESC LIMIT ?2",
  ).bind(pendingOnly ? 1 : 0, limit).all<AlertListRow>();
  return rows.results;
}

const ALERT_TONE: Record<string, string> = { high_fail: "s-fail", silent: "s-skip", back: "s-pass", new_country: "s-warn" };

export async function alertsPage(env: Env, who: string): Promise<Response> {
  const rows = await alertRows(env, 200);
  const body = html`<div class="hero"><p class="eyebrow">Fleet</p><h1>Alerts</h1>
<p class="lead">Raised by reports and the hourly cron; delivered to the webhook by the cron.${
    env.ALERT_WEBHOOK_URL ? "" : " No webhook is set (ALERT_WEBHOOK_URL), so they are only listed here."
  }</p></div>
<div class="panel flush"><div class="scroll"><table><thead><tr><th>Raised</th><th>Kind</th><th>Person · machine</th><th>Check</th><th>Delivery</th></tr></thead><tbody>
${rows.map((a) => {
    const d = parseStatuses(a.detail);
    return html`<tr><td class="nowrap">${when(a.created_at)}</td><td class="nowrap">${pill(ALERT_TONE[a.kind] ?? "s-other", a.kind.replace("_", " "))}</td>
<td class="who-cell"><a href="${machineLink(a.install_id)}">${d.email || "(no email)"}</a><span class="sub">${d.hostname}</span></td>
<td class="wrap">${a.check_id ? html`<code>${a.check_id}</code><span class="sub">${d.title}</span>` : ""}</td><td class="muted">${a.sent_at ? a.delivery : "pending"}</td></tr>`;
  })}</tbody></table></div>${rows.length === 0 ? html`<p class="empty">No alerts.</p>` : ""}</div>`;
  return page(layout("Alerts", who, body, "Alerts"));
}
