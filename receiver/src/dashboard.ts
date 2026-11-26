import { config, DAY, type Env } from "./env";
import { fixHtml, infoItems, renderParts, summaryHtml } from "./checktext";
import { badge, count, FILTER_HEADERS, Html, html, layout, note, page, pct, pill, sev, statusClass } from "./html";
import { type Geo, mapLink, parseGeo, place } from "./geo";
import { checkTitle, type I18n, type Key } from "./i18n";
import { enrollmentOf, enrollmentSection } from "./portal";
import { type DeviceLocation, parseReport, type Result, statusRank } from "./report";
import { likelySamplesList } from "./samples";
import { machineIn, roleIn, type Scope, scopeBind } from "./scope";
import { machineWaiverRequests, pendingRequests, pendingRequestsNote, pendingRequestsSection, waiverRequestsSection } from "./waiverrequests";

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
  info: number; // checks carrying Info (migration 0008)
  // When the current run of reports saying "compromised" began; null when the
  // latest report does not say so (and for older clients).
  compromised_since: string | null;
}

export const FILTERS = {
  all: { label: "All", key: "filter.all", where: "1 = 1" },
  compromised: { label: "Compromised", key: "filter.compromised", where: "m.compromised_since IS NOT NULL" },
  failing: { label: "Failing", key: "filter.failing", where: "m.fail > 0" },
  attention: { label: "Fail, error or warn", key: "filter.attention", where: "(m.fail > 0 OR m.error > 0 OR m.warn > 0)" },
  silent: { label: "Silent", key: "filter.silent", where: "m.last_seen < ?2" },
  revoked: { label: "Revoked", key: "filter.revoked", where: "e.revoked_at IS NOT NULL" },
  info: { label: "With info", key: "filter.info", where: "m.info > 0" },
} as const satisfies Record<string, { label: string; key: Key; where: string }>;
export type Filter = keyof typeof FILTERS;

export type MachineListRow = MachineRow & {
  public_ip: string;
  geo: string;
  enrolled: number;
  revoked_at: string | null;
  role: string | null;
  failing_since: string | null; // the oldest `since` among its failing checks
};

// machineRows is the machine list (dashboard front page, MCP list_machines,
// REST GET /machines): a filter, a substring of email or hostname, and
// optionally only machines whose latest report has `check` at `checkStatus`.
// Worst first by default; byId orders by install_id and starts after `after`,
// which is what a cursor needs (stable while reports keep arriving).
export interface MachineQuery {
  filter: Filter;
  q: string;
  silentBefore: string;
  limit: number;
  check?: string;
  checkStatus?: string;
  roleId?: number;
  byId?: boolean;
  after?: string;
  // A named admin's scope (dashboard only); absent: every machine.
  scope?: Scope;
  // Dashboard only: a column to sort by (ignored with byId), and its direction.
  sort?: SortKey;
  desc?: boolean;
}

// geoField: one field of machines.geo, '' when there is none (geo is '' without
// request.cf, and json_extract fails on that).
function geoField(k: "city" | "region" | "country" | "as_org"): string {
  return `CASE WHEN json_valid(m.geo) THEN COALESCE(json_extract(m.geo, '$.${k}'), '') ELSE '' END`;
}

// Columns of the machine table that sort, as ORDER BY terms for ascending
// order (descending flips each). Fixed strings: only these go into the query.
const SORT_SQL = {
  state: ["(m.compromised_since IS NOT NULL) * 4 + (m.fail > 0) * 2 + (m.error > 0 OR m.warn > 0)", "m.high_fail", "m.fail"],
  who: ["lower(m.email)", "lower(m.hostname)"],
  role: ["lower(COALESCE(r.name, ''))", "lower(m.email)"],
  platform: ["m.os", "m.arch", "m.version"],
  from: [geoField("country"), geoField("city"), "m.public_ip"],
  seen: ["m.last_seen"],
  fail: ["m.fail", "m.high_fail"],
  error: ["m.error"],
  warn: ["m.warn"],
  waived: ["m.waived"],
} as const;
export type SortKey = keyof typeof SORT_SQL;
export const isSortKey = (s: string): s is SortKey => Object.hasOwn(SORT_SQL, s);
// Columns that start descending when first clicked (worst, newest, most first).
const SORT_DESC_FIRST = new Set<SortKey>(["state", "seen", "fail", "error", "warn", "waived"]);

const MACHINE_FROM = `FROM machines m LEFT JOIN enrollments e ON e.install_id = m.install_id LEFT JOIN roles r ON r.id = e.role_id`;
const machineWhere = (o: MachineQuery) =>
  `WHERE ${FILTERS[o.filter].where} AND ${roleIn("e.role_id", 9, o.scope)} AND (?1 = '' OR m.email LIKE ?3 ESCAPE '\\' OR m.hostname LIKE ?3 ESCAPE '\\')
       AND (?5 = '' OR EXISTS (SELECT 1 FROM checks c WHERE c.install_id = m.install_id AND c.check_id = ?5 AND (?6 = '' OR c.status = ?6)))
       AND (?7 = 0 OR e.role_id = ?7) AND (?8 = '' OR m.install_id > ?8)`;
const machineBinds = (o: MachineQuery, after: string) =>
  [o.q, o.silentBefore, `%${o.q.replace(/[\\%_]/g, (c) => "\\" + c)}%`, o.limit, o.check ?? "", o.checkStatus ?? "", o.roleId ?? 0, after, scopeBind(o.scope)];

function machineOrder(o: MachineQuery): string {
  if (o.byId) return "m.install_id";
  if (!o.sort || !isSortKey(o.sort)) return "m.compromised_since IS NOT NULL DESC, m.fail > 0 DESC, m.high_fail DESC, m.fail DESC, m.last_seen DESC";
  const dir = o.desc ? " DESC" : "";
  return [...SORT_SQL[o.sort].map((t) => t + dir), "m.install_id"].join(", ");
}

export async function machineRows(env: Env, o: MachineQuery): Promise<MachineListRow[]> {
  const order = machineOrder(o);
  const rows = await env.DB.prepare(
    `SELECT m.install_id, m.email, m.hostname, m.os, m.arch, m.version, m.policy, m.first_seen, m.last_seen, m.report_time,
            m.fail, m.high_fail, m.error, m.warn, m.waived, m.pass, m.skip, m.other, m.info, m.compromised_since, m.public_ip, m.geo,
            e.install_id IS NOT NULL AS enrolled, e.revoked_at, r.name AS role,
            (SELECT MIN(c.since) FROM checks c WHERE c.install_id = m.install_id AND c.status = 'fail') AS failing_since
     ${MACHINE_FROM}
     ${machineWhere(o)}
     ORDER BY ${order} LIMIT ?4`,
  )
    .bind(...machineBinds(o, o.byId ? o.after ?? "" : ""))
    .all<MachineListRow>();
  return rows.results;
}

// machineCount: how many machines machineRows would list without a limit or cursor.
export async function machineCount(env: Env, o: MachineQuery): Promise<number> {
  const n = await env.DB.prepare(`SELECT COUNT(*) AS n ${MACHINE_FROM} ${machineWhere(o)} AND ?4 = ?4`)
    .bind(...machineBinds(o, ""))
    .first<number>("n");
  return n ?? 0;
}

// waitingRows: enrolled machines that never reported, newest enrollment
// first; with byId, by install_id after `after` (for a cursor), optionally
// narrowed by a substring of email or hostname and by role.
export async function waitingRows(env: Env, limit: number, o: { byId?: boolean; after?: string; q?: string; roleId?: number; scope?: Scope } = {}) {
  const q = o.q ?? "";
  const like = `%${q.replace(/[\\%_]/g, (c) => "\\" + c)}%`;
  const r = await env.DB.prepare(
    `SELECT e.install_id, e.email, e.hostname, e.enrolled_at, r.name AS role FROM enrollments e JOIN roles r ON r.id = e.role_id
     WHERE e.revoked_at IS NULL AND NOT EXISTS (SELECT 1 FROM machines m WHERE m.install_id = e.install_id)
       AND (?2 = '' OR e.install_id > ?2) AND (?3 = '' OR e.email LIKE ?4 ESCAPE '\\' OR e.hostname LIKE ?4 ESCAPE '\\') AND (?5 = 0 OR e.role_id = ?5) AND ${roleIn("e.role_id", 6, o.scope)}
     ORDER BY ${o.byId ? "e.install_id" : "e.enrolled_at DESC"} LIMIT ?1`,
  ).bind(limit, o.byId ? o.after ?? "" : "", q, like, o.roleId ?? 0, scopeBind(o.scope)).all<{ install_id: string; email: string; hostname: string; enrolled_at: string; role: string }>();
  return r.results;
}

export async function waitingCount(env: Env, o: { q?: string; roleId?: number } = {}): Promise<number> {
  const q = o.q ?? "";
  const like = `%${q.replace(/[\\%_]/g, (c) => "\\" + c)}%`;
  const n = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM enrollments e
     WHERE e.revoked_at IS NULL AND NOT EXISTS (SELECT 1 FROM machines m WHERE m.install_id = e.install_id)
       AND (?1 = '' OR e.email LIKE ?2 ESCAPE '\\' OR e.hostname LIKE ?2 ESCAPE '\\') AND (?3 = 0 OR e.role_id = ?3)`,
  ).bind(q, like, o.roleId ?? 0).first<number>("n");
  return n ?? 0;
}

// The state of a machine as one pill (worst first), plus "silent".
function state(L: I18n, m: MachineRow, silentBefore: string): Html {
  const parts: Html[] = [];
  if (m.compromised_since) parts.push(pill("s-comp", L.t("state.compromised")));
  if (m.fail) parts.push(pill("s-fail", L.t("state.noncompliant")));
  else if (m.error || m.warn) parts.push(pill("s-warn", L.t("state.attention")));
  else parts.push(pill("s-pass", L.t("state.ok")));
  if (m.last_seen < silentBefore) parts.push(pill("s-skip", L.t("state.silent")));
  if (m.info) parts.push(pill("s-info", L.t("info.label")));
  return html`${parts}`;
}

// unescapeText: entities back to characters (the title attribute escapes again).
const unescapeText = (s: string) =>
  s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, "&");

// infoPill: "ℹ Info" next to a check that carries Info, its messages as the tooltip.
function infoPill(L: I18n, r: Result): Html | string {
  if (!r.info?.length) return "";
  const tip = infoItems(L, r.info).map((h) => unescapeText(h.toString().replace(/<[^>]*>/g, ""))).join(" · ");
  return html` <span class="pill s-info" title="${tip}">${L.t("info.label")}</span>`;
}

const machineLink = (id: string) => `/admin/machine/${encodeURIComponent(id)}`;

function tile(L: I18n, href: string, n: number, label: Html, sub: Html, tone: string): Html {
  return html`<a class="tile ${n ? tone : "zero"}" href="${href}"><span class="l">${label}</span><span class="s">${sub}</span><span class="n">${L.num(n)}</span></a>`;
}

// searchText: what a table row shows, as one lowercase string without accents
// (so "mat lien lac" finds "mất liên lạc"), for the machine list's search.
// FILTER_SCRIPT normalises what is typed the same way.
export function searchText(s: string): string {
  return s.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[đĐ]/g, "d").toLowerCase().replace(/\s+/g, " ").trim();
}
const rowText = (h: Html) => searchText(unescapeText(h.toString().replace(/<[^>]*>/g, " ")));
// matches: every word of the search appears in the row's text.
const matches = (text: string, terms: string[]) => terms.every((t) => text.includes(t));

export async function machinesPage(env: Env, url: URL, who: string, now: number, L: I18n, scope?: Scope): Promise<Response> {
  const f = (url.searchParams.get("filter") ?? "all") as Filter;
  const filter: Filter = f in FILTERS ? f : "all";
  const q = (url.searchParams.get("q") ?? "").trim().slice(0, 100);
  const roleParam = Number(url.searchParams.get("role") ?? 0);
  const sortParam = url.searchParams.get("sort") ?? "";
  const sort: SortKey | undefined = isSortKey(sortParam) ? sortParam : undefined;
  const desc = sort ? (url.searchParams.get("dir") ?? (SORT_DESC_FIRST.has(sort) ? "desc" : "asc")) === "desc" : false;
  const cfg = config(env);
  const silentBefore = new Date(now - cfg.silentDays * DAY).toISOString();
  const roles = (
    await env.DB.prepare(`SELECT id, name FROM roles WHERE ${roleIn("id", 1, scope)} ORDER BY name`).bind(scopeBind(scope)).all<{ id: number; name: string }>()
  ).results;
  const roleId = roles.some((r) => r.id === roleParam) ? roleParam : 0;
  const narrowed = q !== "" || roleId !== 0;
  const terms = searchText(q).split(" ").filter(Boolean);
  // Every machine of the filter and role comes back; the search marks rows
  // hidden, so FILTER_SCRIPT can show them again as the search changes.
  const [rows, waitingAll, waitingRole, totals, top, pending, requests] = await Promise.all([
    machineRows(env, { filter, q: "", silentBefore, limit: 2000, scope, roleId, sort, desc }),
    waitingRows(env, 500, { scope }),
    roleId ? waitingRows(env, 500, { scope, roleId }) : Promise.resolve(null),
    env.DB.prepare(
      `SELECT COUNT(*) AS n, SUM(m.fail > 0) AS failing, SUM(m.fail = 0 AND (m.error > 0 OR m.warn > 0)) AS attention,
              SUM(m.last_seen < ?1) AS silent, SUM(e.revoked_at IS NOT NULL) AS revoked, SUM(m.compromised_since IS NOT NULL) AS compromised
       FROM machines m LEFT JOIN enrollments e ON e.install_id = m.install_id WHERE ${roleIn("e.role_id", 2, scope)}`,
    )
      .bind(silentBefore, scopeBind(scope))
      .first<{ n: number; failing: number | null; attention: number | null; silent: number | null; revoked: number | null; compromised: number | null }>(),
    checkStats(env, 4, scope),
    env.DB.prepare(`SELECT COUNT(*) AS n FROM invites i WHERE i.used_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > ?1 AND ${roleIn("i.role_id", 2, scope)}`)
      .bind(new Date(now).toISOString(), scopeBind(scope))
      .first<number>("n"),
    pendingRequests(env, 200, scope),
  ]);
  const n = totals?.n ?? 0;
  const failing = totals?.failing ?? 0;
  const attention = totals?.attention ?? 0;
  const ok = Math.max(0, n - failing - attention);
  const topFailing = top.filter((c) => c.fail > 0);
  const waiting = waitingRole ?? waitingAll;

  // A link to this list with some of filter / q / role / sort changed.
  const listLink = (o: { filter?: Filter; sort?: SortKey; desc?: boolean }) => {
    const p = new URLSearchParams();
    const fk = o.filter ?? filter;
    if (fk !== "all") p.set("filter", fk);
    if (q) p.set("q", q);
    if (roleId) p.set("role", String(roleId));
    const sk = "sort" in o ? o.sort : sort;
    if (sk) {
      p.set("sort", sk);
      p.set("dir", ("desc" in o ? o.desc : desc) ? "desc" : "asc");
    }
    const s = p.toString();
    return `/admin${s ? "?" + s : ""}`;
  };
  const link = (k: Filter) => listLink({ filter: k });
  // A column header that sorts: first click in the column's natural order,
  // the next one reverses it; ▲/▼ marks the column in use.
  const th = (k: SortKey, label: Html, cls = "") => {
    const on = sort === k;
    const nextDesc = on ? !desc : SORT_DESC_FIRST.has(k);
    const aria = on ? (desc ? "descending" : "ascending") : "none";
    return html`<th${cls ? html` class="${cls}"` : ""} aria-sort="${aria}"><a class="sort${on ? " on" : ""}" data-keep href="${listLink({ sort: k, desc: nextDesc })}">${label}${on ? (desc ? " ▼" : " ▲") : ""}</a></th>`;
  };

  const compromised = totals?.compromised ?? 0;
  const overview = html`<div class="tiles">
${tile(L, "/admin?filter=compromised", compromised, L.t("tile.compromised"), L.t("tile.compromisedSub"), "t-fail t-comp")}
${tile(L, "/admin?filter=failing", failing, L.t("tile.failing"), L.t("tile.failingSub"), "t-fail")}
${tile(L, "/admin?filter=attention", attention, L.t("tile.attention"), L.t("tile.attentionSub"), "t-warn")}
${tile(L, "/admin?filter=silent", totals?.silent ?? 0, L.t("tile.silent"), L.t("tile.silentSub", { n: cfg.silentDays }), "t-skip")}
${tile(L, "/admin/invites?status=pending", pending ?? 0, L.t("tile.pending"), L.t("tile.pendingSub"), "t-accent")}
${tile(L, "#waiting", waitingAll.length, L.t("tile.waiting"), L.t("tile.waitingSub"), "t-accent")}
</div>
${n
    ? html`<div class="health" aria-label="${L.s("health.aria")}"><div class="bar">${failing ? html`<i class="b-fail" style="width:${pct(failing, n)}"></i>` : ""}${
        attention ? html`<i class="b-warn" style="width:${pct(attention, n)}"></i>` : ""
      }${ok ? html`<i class="b-ok" style="width:${pct(ok, n)}"></i>` : ""}</div>
<div class="legend"><span class="b-fail">${L.t("legend.noncompliant", { n: failing })}</span><span class="b-warn">${L.t("legend.attention", { n: attention })}</span><span class="b-ok">${L.t("legend.ok", { n: ok })}</span>${
        totals?.revoked ? html`<span class="b-skip">${L.t("legend.revoked", { n: totals.revoked })}</span>` : ""
      }</div></div>`
    : ""}
${topFailing.length
    ? html`<div class="shelf"><h2>${L.t("top.title")}</h2><a href="/admin/checks">${L.t("top.all")}</a></div>
<div class="shelf-row">${topFailing.map(
        (c) => html`<a class="card" href="/admin/checks/${encodeURIComponent(c.check_id)}?status=fail"><span class="t">${checkTitle(L, c.check_id, c.title)}</span><code class="muted">${c.check_id}</code>
<span class="meta"><span class="big">${L.num(c.fail)}</span>${L.t("top.failing")}${c.high ? html` · ${L.t("top.high", { n: c.high })}` : ""} · ${L.t("top.of", { n: c.total })}</span></a>`,
      )}</div>`
    : ""}`;

  // Each row carries its own text (data-q) so the search, here and in
  // FILTER_SCRIPT, matches exactly what the table shows.
  const machineCells = (m: MachineListRow) => html`<td class="nowrap">${state(L, m, silentBefore)}${
      m.failing_since ? html`<span class="sub">${L.t("machines.failingFor", { age: L.age(m.failing_since, now) })}</span>` : ""
    }</td>
<td class="who-cell"><a href="${machineLink(m.install_id)}">${m.email || L.s("common.noEmail")}</a><span class="sub">${m.hostname}</span></td>
<td>${m.role ?? ""}${m.revoked_at ? html` ${pill("s-fail", L.t("state.revoked"))}` : ""}</td>
<td class="nowrap">${m.os}/${m.arch}<span class="sub">${m.version}</span></td>
<td>${place(parseGeo(m.geo))}${m.public_ip ? html`<span class="sub mono">${m.public_ip}</span>` : ""}</td>
<td class="nowrap" title="${L.when(m.last_seen)}">${L.ago(m.last_seen, now)}</td>
<td class="n">${count(L, m.fail, "num-fail")}${m.high_fail ? html`<span class="sub">${L.t("machines.nHigh", { n: m.high_fail })}</span>` : ""}</td>
<td class="n">${count(L, m.error, "num-error")}</td><td class="n">${count(L, m.warn, "num-warn")}</td>
<td class="n">${count(L, m.waived, "num-waived")}</td>`;
  let shown = 0;
  const machineTrs = rows.map((m) => {
    const cells = machineCells(m);
    const text = rowText(cells);
    const ok = matches(text, terms);
    if (ok) shown++;
    return html`<tr data-q="${text}"${m.revoked_at ? html` class="off"` : ""}${ok ? "" : html` hidden`}>${cells}</tr>`;
  });
  let waitingShown = 0;
  const waitingTrs = waiting.map((w) => {
    const cells = html`<td class="who-cell"><a href="${machineLink(w.install_id)}">${w.email}</a><span class="sub">${w.hostname}</span></td><td>${w.role}</td><td class="nowrap">${L.ago(w.enrolled_at, now)}</td>`;
    const text = rowText(cells);
    const ok = matches(text, terms);
    if (ok) waitingShown++;
    return html`<tr data-q="${text}"${ok ? "" : html` hidden`}>${cells}</tr>`;
  });
  const nShown = (k: string, v: number) => new Html(`<span data-n="${k}">${L.num(v)}</span>`);
  const [matchA, matchB] = L.s("machines.matching", { q: "\u0001" }).split("\u0001");

  const table = html`<div class="panel flush"><div class="scroll"><table><thead><tr>${th("state", L.t("machines.thState"))}${th("who", L.t("common.personMachine"))}${th("role", L.t("common.role"))}${th("platform", L.t("machines.thPlatform"))}${th("from", L.t("machines.thFrom"))}${th("seen", L.t("machines.thLastSeen"))}
${th("fail", L.t("common.fail"), "n")}${th("error", L.t("common.error"), "n")}${th("warn", L.t("common.warn"), "n")}${th("waived", L.t("common.waived"), "n")}</tr></thead><tbody data-list="machines">
${machineTrs}
</tbody></table></div><p class="empty" data-empty="machines"${shown ? html` hidden` : ""}>${L.t("machines.noMatch")}</p></div>`;

  const body = html`<div class="hero"><p class="eyebrow">${L.t("fleet.eyebrow")}</p><h1>${L.t("nav.machines")}</h1>
<p class="lead">${L.t("machines.lead", { n, failing, silent: totals?.silent ?? 0, days: cfg.silentDays })}</p></div>
${scopeNote(L, scope)}
${pendingRequestsNote(L, requests.length)}
${overview}
<div class="shelf"><h2>${filter === "all" ? L.t("machines.every") : L.t(FILTERS[filter].key)}<span data-matching data-a="${matchA}" data-b="${matchB ?? ""}">${q ? L.s("machines.matching", { q }) : ""}</span>${roleId ? L.t("machines.inRole", { role: roles.find((r) => r.id === roleId)?.name ?? "" }) : ""}</h2><span class="muted small">${L.t("machines.shown", { n: nShown("machines", shown) })}</span></div>
<div class="toolbar"><nav class="seg" aria-label="${L.s("filter.aria")}">${(Object.keys(FILTERS) as Filter[]).map(
    (k) => html`<a href="${link(k)}" data-keep class="${k === filter ? "on" : ""}">${L.t(FILTERS[k].key)}</a>`,
  )}</nav>
<form class="search" id="mf" method="get" action="/admin">${filter !== "all" ? html`<input type="hidden" name="filter" value="${filter}">` : ""}${
    sort ? html`<input type="hidden" name="sort" value="${sort}"><input type="hidden" name="dir" value="${desc ? "desc" : "asc"}">` : ""
  }<input type="search" name="q" value="${q}" autocomplete="off" placeholder="${L.s("machines.searchPlaceholder")}" aria-label="${L.s("machines.searchAria")}">${
    roles.length > 1 || roleId
      ? html`<select name="role" aria-label="${L.s("machines.roleAria")}"><option value="">${L.t("machines.allRoles")}</option>${roles.map(
          (r) => html`<option value="${r.id}"${r.id === roleId ? html` selected` : ""}>${r.name}</option>`,
        )}</select>`
      : ""
  }<button>${L.t("machines.search")}</button>${narrowed || sort ? html`<a class="muted small" href="${filter === "all" ? "/admin" : `/admin?filter=${filter}`}">${L.t("machines.clear")}</a>` : ""}</form></div>
${table}
${waiting.length
    ? html`<section id="waiting" data-empty-hide="waiting"${waitingShown ? "" : html` hidden`}><h2>${L.t("machines.waiting", { n: nShown("waiting", waitingShown) })}</h2>
<div class="panel flush"><div class="scroll"><table><thead><tr><th>${L.t("common.personMachine")}</th><th>${L.t("common.role")}</th><th>${L.t("machines.thEnrolled")}</th></tr></thead><tbody data-list="waiting">${waitingTrs}</tbody></table></div></div></section>`
    : html`<span id="waiting"></span>`}
${pendingRequestsSection(L, requests, now)}`;
  return page(layout(L, L.s("nav.machines"), who, body, "Machines", { filter: true }), 200, FILTER_HEADERS);
}

// scopeNote explains an empty page to a named admin who manages no role yet.
export function scopeNote(L: I18n, scope?: Scope): Html | string {
  return scope && scope.roles.length === 0 ? note(L.t("scope.none"), "s-warn") : "";
}

function waiverNote(L: I18n, r: Result, now: number): Html | string {
  if (!r.waived) return "";
  const until = Date.parse(r.waived.until + (r.waived.until.length === 10 ? "T23:59:59Z" : ""));
  let left: Html | string = "";
  if (!Number.isNaN(until)) {
    const days = Math.ceil((until - now) / DAY);
    left = days < 0 ? L.t("machine.waiverExpired") : days === 0 ? L.t("machine.waiverToday") : L.t("machine.waiverLeft", { n: days });
  }
  return html`<div class="waiver">${L.t("machine.waivedUntil", { date: r.waived.until ? L.day(r.waived.until) : "?" })}${left ? html` ${left}` : ""}${
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

function changes(L: I18n, prev: Record<string, string> | null, cur: Record<string, string>): Html[] {
  if (!prev) return [html`<span class="muted">${L.t("machine.oldest")}</span>`];
  const out: Html[] = [];
  for (const [id, s] of Object.entries(cur)) {
    if (prev[id] !== s) out.push(html`<div><code>${id}</code> <span class="muted">${prev[id] !== undefined ? L.status(prev[id]) : L.s("machine.new")} →</span> ${badge(L, s)}</div>`);
  }
  for (const id of Object.keys(prev)) if (!(id in cur)) out.push(html`<div><code>${id}</code> <span class="muted">${L.t("machine.gone")}</span></div>`);
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

function geoLine(L: I18n, g: Geo | null): Html | string {
  if (!g) return "";
  const coords = g.lat !== undefined && g.lon !== undefined
    ? html` · <a href="${mapLink(g.lat, g.lon)}" rel="noreferrer noopener" target="_blank">${g.lat.toFixed(3)}, ${g.lon.toFixed(3)} ${L.t("common.map")}</a>`
    : "";
  return html`${place(g) || "?"}${coords}${g.timezone ? html` · ${g.timezone}` : ""}${g.asn ? html` · AS${g.asn} ${g.as_org ?? ""}` : ""}`;
}

function deviceLine(L: I18n, d: DeviceLocation | null): Html | string {
  if (!d || typeof d.lat !== "number" || typeof d.lon !== "number") return "";
  return html`<a href="${mapLink(d.lat, d.lon)}" rel="noreferrer noopener" target="_blank">${d.lat.toFixed(5)}, ${d.lon.toFixed(5)} ${L.t("common.map")}</a>${
    d.accuracy_m !== null && d.accuracy_m !== undefined ? html` ±${d.accuracy_m} m` : ""
  }${d.source ? html` · ${L.t("where.source", { source: d.source })}` : ""}${d.time ? html` · ${L.t("where.at", { when: L.when(d.time) })}` : ""}`;
}

function whereSection(L: I18n, m: { public_ip: string; geo: string; local_ips: string; device_location: string }): Html {
  const g = parseGeo(m.geo);
  const d = parseJSON<DeviceLocation>(m.device_location);
  const ips = parseJSON<string[]>(m.local_ips) ?? [];
  if (!m.public_ip && !g && !d && !ips.length) {
    return html`<h2>${L.t("where.title")}</h2><div class="panel"><p class="muted">${L.t("where.nothing")}</p></div>`;
  }
  const none = html`<span class="muted">${L.t("common.noneLower")}</span>`;
  return html`<h2>${L.t("where.title")}</h2>
<div class="panel"><dl class="facts"><div><dt>${L.t("where.publicIp")}</dt><dd>${m.public_ip ? html`<code>${m.public_ip}</code>` : "?"}<br><span class="muted small">${L.t("where.seenByCf")}</span></dd></div>
<div><dt>${L.t("where.ipLocation")}</dt><dd>${geoLine(L, g) || "?"}<br><span class="muted small">${L.t("where.cfEstimate")}</span></dd></div>
<div><dt>${L.t("where.device")}</dt><dd>${deviceLine(L, d) || none}<br><span class="muted small">${L.t("common.unverified")}</span></dd></div>
<div><dt>${L.t("where.local")}</dt><dd>${ips.length ? ips.map((ip, i) => html`${i ? ", " : ""}<code>${ip}</code>`) : none}<br><span class="muted small">${L.t("common.unverified")}</span></dd></div></dl>
<p class="muted small">${L.t("where.mapNote")}</p></div>`;
}

function resultCard(L: I18n, r: Result, since: string | undefined, now: number): Html {
  return html`<div class="result ${statusClass(r.status)}"><div class="head">${badge(L, r.status)} ${sev(L, r.severity)}
<h3>${checkTitle(L, r.id, r.title)}</h3> <code class="muted">${r.id}</code>${infoPill(L, r)}${since ? html`<span class="since">${L.t("machine.since", { when: L.when(since) })}</span>` : ""}</div>
${waiverNote(L, r, now)}
${r.summary ? html`<div class="body">${summaryHtml(L, r)}</div>` : ""}
${r.evidence.length ? html`<ul class="evidence">${r.evidence.map((e) => html`<li class="ev">${e}</li>`)}</ul>` : ""}
${r.fix ? html`<div class="fix"><b>${L.t("machine.fix")}</b><span>${fixHtml(L, r)}</span></div>` : ""}
${userIgnoredList(L, r)}
${likelySamplesList(L, r.likely_samples)}</div>`;
}

// userIgnoredList shows what the person at the machine marked as not
// sensitive (bordercheck ignore), with their reasons: every field came from
// the report, so all of it is escaped like any other report text.
export function userIgnoredList(L: I18n, r: Result): Html | string {
  const items = r.user_ignored ?? [];
  if (!items.length) return "";
  return html`<div class="ignored"><p><b>${L.t("machine.userIgnored", { n: items.length })}</b> <span class="muted small">${L.t("machine.userIgnoredNote")}</span></p>
<ul class="evidence">${items.map(
    (i) => html`<li class="ev">${i.path}  ${i.kind}${i.name ? html` (${i.name})` : ""}: <span class="reason">${i.reason}</span>${i.since ? html` <span class="muted">· ${L.t("machine.userIgnoredSince", { date: L.day(i.since) })}</span>` : ""}</li>`,
  )}</ul></div>`;
}

// compromiseBanner heads the page of a machine whose latest report says it is
// compromised: since when, each check, and each sign with its item when the
// machine sent one. Everything here came from the report, so it is all
// escaped like any other report text; the signs are rendered from the
// message catalogue, never from free text.
export function compromiseBanner(L: I18n, since: string, checks: string[], results: Result[]): Html {
  const byId = new Map(results.map((r) => [r.id, r]));
  const ids = [...checks];
  for (const r of results) if (r.compromise?.length && !ids.includes(r.id)) ids.push(r.id);
  const items = ids.slice(0, 50).map((id) => {
    const r = byId.get(id);
    const signs = (r?.compromise ?? []).map((i) => {
      const what = renderParts(L, [i.what]) ?? html`<code>${i.what.key}</code>`;
      return html`<li>${what} ${i.detail ? html`<code class="ev">${i.detail}</code>` : html`<span class="muted small">(${L.t("machine.compNoDetail")})</span>`}</li>`;
    });
    return html`<li><b>${checkTitle(L, id, r?.title)}</b> <code class="muted">${id}</code>${signs.length ? html`<ul>${signs}</ul>` : ""}</li>`;
  });
  return html`<div class="note s-comp" role="alert"><div><h2>${L.t("machine.compTitle")}</h2>
<p>${L.t("machine.compLead", { when: L.when(since) })}</p>${items.length ? html`<ul>${items}</ul>` : ""}
<p class="muted small">${L.t("machine.compNote")}</p></div></div>`;
}

function statTile(L: I18n, n: number, label: Html, tone: string): Html {
  return html`<div class="tile ${n ? tone : "zero"}"><span class="l">${label}</span><span class="n">${L.num(n)}</span></div>`;
}

// machinePage: index.ts has already checked that a scoped viewer may see this
// machine (scope.machineVisible); `scope` narrows the role choices.
export async function machinePage(env: Env, id: string, who: string, now: number, L: I18n, scope?: Scope): Promise<Response> {
  // One round of queries for everything keyed by the install ID alone: the
  // database can be far from where the request landed, so each extra round
  // is a long wait.
  const [mRow, enrollment, checks, hist, requests] = await Promise.all([
    env.DB.prepare("SELECT * FROM machines WHERE install_id = ?").bind(id).first<MachineRow & { report: string; public_ip: string; geo: string; local_ips: string; device_location: string }>(),
    enrollmentOf(env, id),
    env.DB.prepare("SELECT check_id, since FROM checks WHERE install_id = ?").bind(id).all<{ check_id: string; since: string }>(),
    env.DB.prepare(
      "SELECT received_at, version, fail, warn, error, waived, statuses, ip, geo, device_location FROM reports WHERE install_id = ? ORDER BY id DESC LIMIT 61",
    ).bind(id).all<HistoryRow>(),
    machineWaiverRequests(env, id),
  ]);
  if (!mRow && !enrollment) {
    return page(layout(L, L.s("common.notFound"), who, html`<p class="eyebrow">${L.t("nav.machines")}</p><h1>${L.t("machine.noSuch")}</h1><p><a href="/admin">${L.t("machine.back")}</a></p>`, "Machines"), 404);
  }
  const enrollHtml = html`${waiverRequestsSection(L, id, requests)}${await enrollmentSection(L, env, id, enrollment, new Date(now), scope)}`;
  const crumb = html`<p class="eyebrow"><a href="/admin">${L.t("nav.machines")}</a> · ${enrollment?.role ?? L.s("common.machine")}</p>`;
  if (!mRow) {
    const e = enrollment!;
    const body = html`<div class="hero">${crumb}<h1>${e.hostname || e.email}</h1><p class="lead">${e.email}</p></div>
${note(L.t("machine.noReportYet", { ago: L.ago(e.enrolled_at, now) }))}
<div class="panel"><dl class="facts"><div><dt>${L.t("machine.installId")}</dt><dd><code>${e.install_id}</code></dd></div></dl></div>${enrollHtml}`;
    return page(layout(L, e.hostname || e.email, who, body, "Machines"));
  }
  const m = mRow;
  const since = new Map(checks.results.map((c) => [c.check_id, c.since]));

  let results: Result[] = [];
  let compromiseChecks: string[] = [];
  let unreadable = false;
  try {
    const rep = parseReport(JSON.parse(m.report));
    results = rep.results;
    compromiseChecks = rep.compromiseChecks;
  } catch {
    unreadable = true;
  }
  const comp = m.compromised_since ? compromiseBanner(L, m.compromised_since, compromiseChecks, results) : "";
  results.sort((a, b) => statusRank(a.status) - statusRank(b.status));
  const problems = results.filter((r) => !["pass", "skip"].includes(r.status));
  const fine = results.filter((r) => ["pass", "skip"].includes(r.status));
  const silentBefore = new Date(now - config(env).silentDays * DAY).toISOString();
  const silent = m.last_seen < silentBefore;

  // History newest first; each row shows what changed since the one before.
  const h = hist.results;
  const histRows = h.slice(0, 60).map((r, i) => {
    const older = h[i + 1] ? parseStatuses(h[i + 1].statuses) : null;
    return html`<tr><td class="nowrap" title="${r.received_at}">${L.when(r.received_at)}</td><td>${r.version}</td>
<td class="n">${count(L, r.fail, "num-fail")}</td><td class="n">${count(L, r.error, "num-error")}</td><td class="n">${count(L, r.warn, "num-warn")}</td><td class="n">${count(L, r.waived, "num-waived")}</td>
<td>${place(parseGeo(r.geo))}${r.ip ? html`<span class="sub mono">${r.ip}</span>` : ""}${r.device_location ? html`<span class="sub">${L.t("machine.deviceLocation")}</span>` : ""}</td>
<td class="wrap">${changes(L, older, parseStatuses(r.statuses))}</td></tr>`;
  });

  const body = html`<div class="hero">${crumb}<h1>${m.hostname || L.s("common.noHostname")}</h1>
<p class="lead">${m.email || L.s("common.noEmail")}</p>
<div class="chips">${state(L, m, silentBefore)}${enrollment?.revoked_at ? pill("s-fail", L.t("state.revoked")) : ""}<span class="chip">${m.os}/${m.arch}</span><span class="chip">BorderCheck <b>${m.version}</b></span><span class="chip" title="${L.when(m.last_seen)}">${L.t("machine.reported", { ago: L.ago(m.last_seen, now) })}</span></div></div>
${comp}
${silent ? note(L.t("machine.silentNote", { age: L.age(m.last_seen, now) }), "s-warn") : ""}
${unreadable ? note(L.t("machine.unreadable"), "s-fail") : ""}
<div class="tiles">${statTile(L, m.fail, m.high_fail ? L.t("machine.failHigh", { n: m.high_fail }) : L.t("common.fail"), "t-fail")}${statTile(L, m.error, L.t("common.error"), "t-err")}${statTile(L, m.warn, L.t("common.warn"), "t-warn")}${statTile(L, m.waived, L.t("common.waived"), "t-accent")}${statTile(L, m.pass, L.t("common.pass"), "t-ok")}</div>
<h2>${L.t("machine.needsAttention", { n: problems.length })}</h2>
${problems.length === 0 ? html`<div class="panel"><p class="muted">${L.t("machine.nothingFailing")}</p></div>` : ""}
${problems.map((r) => resultCard(L, r, since.get(r.id), now))}
<h2>${L.t("machine.fine", { n: fine.length })}</h2>
${fine.length
    ? html`<div class="compact">${fine.map(
        (r) => html`<div>${badge(L, r.status)}<div><div class="t">${checkTitle(L, r.id, r.title)}${infoPill(L, r)}</div><div class="sub"><code>${r.id}</code>${r.summary ? html` · ${summaryHtml(L, r)}` : ""}</div>${userIgnoredList(L, r)}${likelySamplesList(L, r.likely_samples)}</div></div>`,
      )}</div>`
    : html`<div class="panel"><p class="muted">${L.t("common.none")}</p></div>`}
<h2>${L.t("machine.details")}</h2>
<div class="panel"><dl class="facts"><div><dt>${L.t("machine.os")}</dt><dd>${m.os}/${m.arch}</dd></div><div><dt>BorderCheck</dt><dd>${m.version}</dd></div><div><dt>${L.t("machine.policy")}</dt><dd>${m.policy}</dd></div>
<div><dt>${L.t("machine.lastReport")}</dt><dd>${L.when(m.last_seen)}<br><span class="muted small">${L.t("machine.clock", { ago: L.ago(m.last_seen, now), when: L.when(m.report_time) || L.s("common.nothing") })}</span></dd></div>
<div><dt>${L.t("machine.firstSeen")}</dt><dd>${L.when(m.first_seen)}</dd></div><div><dt>${L.t("machine.installId")}</dt><dd><code>${m.install_id}</code></dd></div></dl></div>
<h2>${L.t("machine.history")}</h2>
<div class="panel flush"><div class="scroll"><table><thead><tr><th>${L.t("machine.thReceived")}</th><th>${L.t("machine.thVersion")}</th><th class="n">${L.t("common.fail")}</th><th class="n">${L.t("common.error")}</th><th class="n">${L.t("common.warn")}</th><th class="n">${L.t("common.waived")}</th><th>${L.t("machines.thFrom")}</th><th>${L.t("machine.thChanged")}</th></tr></thead>
<tbody>${histRows}</tbody></table></div></div>
${whereSection(L, m)}
${enrollHtml}
<h2>${L.t("machine.forget")}</h2>
<div class="panel danger-zone"><p class="muted">${L.t("machine.forgetText")}${enrollment ? html` ${L.t("machine.forgetEnrolled")}` : ""}</p>
<form method="post" action="${machineLink(m.install_id)}/forget"><button class="danger">${L.t("machine.forgetButton")}</button></form></div>`;
  return page(layout(L, m.hostname || m.email || L.s("machine.fallbackTitle"), who, body, "Machines"));
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

// checkStats: each check across all machines' latest reports (those in
// scope, for a named admin), most failing first.
export async function checkStats(env: Env, limit = 1000, scope?: Scope): Promise<CheckStat[]> {
  const rows = await env.DB.prepare(
    `SELECT check_id, MAX(title) AS title, SUM(status = 'fail') AS fail, SUM(status = 'fail' AND severity = 'high') AS high,
            SUM(status = 'error') AS error, SUM(status = 'warn') AS warn, SUM(status = 'waived') AS waived,
            SUM(status = 'pass') AS pass, COUNT(*) AS total
     FROM checks WHERE ${machineIn("install_id", 2, scope)} GROUP BY check_id ORDER BY fail DESC, high DESC, error DESC, warn DESC, check_id LIMIT ?1`,
  ).bind(limit, scopeBind(scope)).all<CheckStat>();
  return rows.results;
}

export async function checksPage(env: Env, who: string, L: I18n, scope?: Scope): Promise<Response> {
  const rows = await checkStats(env, 1000, scope);
  const cell = (id: string, status: string, n: number, cls: string) =>
    n ? html`<a class="${cls}" href="/admin/checks/${encodeURIComponent(id)}?status=${status}">${L.num(n)}</a>` : html`<span class="zero">${L.num(0)}</span>`;
  const body = html`<div class="hero"><p class="eyebrow">${L.t("fleet.eyebrow")}</p><h1>${L.t("nav.checks")}</h1>
<p class="lead">${L.t("checks.lead")}</p></div>
${scopeNote(L, scope)}
<div class="panel flush"><div class="scroll"><table><thead><tr><th>${L.t("common.check")}</th><th class="n">${L.t("common.fail")}</th><th class="n">${L.t("common.high")}</th><th class="n">${L.t("common.error")}</th><th class="n">${L.t("common.warn")}</th><th class="n">${L.t("common.waived")}</th><th class="n">${L.t("common.pass")}</th><th class="n">${L.t("checks.thReportedBy")}</th></tr></thead><tbody>
${rows.map(
    (c) => html`<tr><td class="wrap"><a class="strong" href="/admin/checks/${encodeURIComponent(c.check_id)}">${checkTitle(L, c.check_id, c.title)}</a> <code class="muted">${c.check_id}</code>
<div class="minibar">${c.fail ? html`<i class="b-fail" style="width:${pct(c.fail, c.total)}"></i>` : ""}${c.error ? html`<i class="b-err" style="width:${pct(c.error, c.total)}"></i>` : ""}${
      c.warn ? html`<i class="b-warn" style="width:${pct(c.warn, c.total)}"></i>` : ""
    }${c.waived ? html`<i class="b-waived" style="width:${pct(c.waived, c.total)}"></i>` : ""}${c.pass ? html`<i class="b-ok" style="width:${pct(c.pass, c.total)}"></i>` : ""}</div></td>
<td class="n">${cell(c.check_id, "fail", c.fail, "num-fail")}</td><td class="n">${count(L, c.high, "num-fail")}</td><td class="n">${cell(c.check_id, "error", c.error, "num-error")}</td>
<td class="n">${cell(c.check_id, "warn", c.warn, "num-warn")}</td><td class="n">${cell(c.check_id, "waived", c.waived, "num-waived")}</td>
<td class="n">${L.num(c.pass)}</td><td class="n">${L.num(c.total)}</td></tr>`,
  )}</tbody></table></div>${rows.length === 0 ? html`<p class="empty">${L.t("checks.empty")}</p>` : ""}</div>`;
  return page(layout(L, L.s("nav.checks"), who, body, "Checks"));
}

export async function checkPage(env: Env, checkId: string, url: URL, who: string, now: number, L: I18n, scope?: Scope): Promise<Response> {
  const status = (url.searchParams.get("status") ?? "").slice(0, 32);
  const rows = await env.DB.prepare(
    `SELECT c.status, c.severity, c.title, c.since, m.install_id, m.email, m.hostname, m.last_seen
     FROM checks c JOIN machines m ON m.install_id = c.install_id
     WHERE c.check_id = ?1 AND (?2 = '' OR c.status = ?2) AND ${machineIn("c.install_id", 3, scope)}
     ORDER BY c.status = 'fail' DESC, c.status = 'error' DESC, c.status = 'warn' DESC, c.since LIMIT 2000`,
  )
    .bind(checkId, status, scopeBind(scope))
    .all<{ status: string; severity: string; title: string; since: string; install_id: string; email: string; hostname: string; last_seen: string }>();
  const title = checkTitle(L, checkId, rows.results[0]?.title);
  const n = rows.results.length;
  const body = html`<div class="hero"><p class="eyebrow"><a href="/admin/checks">${L.t("nav.checks")}</a> · <code>${checkId}</code></p><h1>${title}</h1>
<p class="lead">${status ? L.t("check.leadStatus", { n, status: L.status(status) }) : L.t("check.lead", { n })}</p></div>
<div class="toolbar"><nav class="seg" aria-label="${L.s("common.status")}">${["", "fail", "error", "warn", "waived", "pass"].map(
    (s) => html`<a class="${s === status ? "on" : ""}" href="/admin/checks/${encodeURIComponent(checkId)}${s ? `?status=${s}` : ""}">${s ? L.status(s) : L.t("check.all")}</a>`,
  )}</nav></div>
<div class="panel flush"><div class="scroll"><table><thead><tr><th>${L.t("common.status")}</th><th>${L.t("common.personMachine")}</th><th>${L.t("check.thSince")}</th><th>${L.t("machines.thLastSeen")}</th></tr></thead><tbody>
${rows.results.map(
    (r) => html`<tr><td class="nowrap">${badge(L, r.status)} ${sev(L, r.severity)}</td><td class="who-cell"><a href="${machineLink(r.install_id)}">${r.email || L.s("common.noEmail")}</a><span class="sub">${r.hostname}</span></td>
<td class="nowrap">${L.when(r.since)}<span class="sub">${L.age(r.since, now)}</span></td><td class="nowrap">${L.ago(r.last_seen, now)}</td></tr>`,
  )}</tbody></table></div>${n === 0 ? html`<p class="empty">${L.t("check.empty")}</p>` : ""}</div>`;
  return page(layout(L, title, who, body, "Checks"));
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

// alertRows: newest first; `before` (an alert id) is where a cursor resumes;
// with a scope, only alerts about machines in it.
export async function alertRows(env: Env, limit: number, pendingOnly = false, before = 0, scope?: Scope): Promise<AlertListRow[]> {
  const rows = await env.DB.prepare(
    `SELECT id, kind, install_id, check_id, detail, created_at, sent_at, delivery FROM alerts WHERE (?1 = 0 OR sent_at IS NULL) AND (?3 = 0 OR id < ?3) AND ${machineIn("install_id", 4, scope)} ORDER BY id DESC LIMIT ?2`,
  ).bind(pendingOnly ? 1 : 0, limit, before, scopeBind(scope)).all<AlertListRow>();
  return rows.results;
}

const ALERT_TONE: Record<string, string> = { high_fail: "s-fail", silent: "s-skip", back: "s-pass", new_country: "s-warn", compromised: "s-comp", compromise_cleared: "s-pass" };
const ALERT_KEY: Record<string, Key> = { high_fail: "alert.high_fail", silent: "alert.silent", back: "alert.back", new_country: "alert.new_country", compromised: "alert.compromised", compromise_cleared: "alert.compromise_cleared" };

export async function alertsPage(env: Env, who: string, L: I18n, scope?: Scope): Promise<Response> {
  const rows = await alertRows(env, 200, false, 0, scope);
  const body = html`<div class="hero"><p class="eyebrow">${L.t("fleet.eyebrow")}</p><h1>${L.t("nav.alerts")}</h1>
<p class="lead">${L.t("alerts.lead")}${env.ALERT_WEBHOOK_URL ? "" : html` ${L.t("alerts.noWebhook")}`}</p></div>
${scopeNote(L, scope)}
<div class="panel flush"><div class="scroll"><table><thead><tr><th>${L.t("alerts.thRaised")}</th><th>${L.t("alerts.thKind")}</th><th>${L.t("common.personMachine")}</th><th>${L.t("common.check")}</th><th>${L.t("alerts.thDelivery")}</th></tr></thead><tbody>
${rows.map((a) => {
    const d = parseStatuses(a.detail);
    const kind = ALERT_KEY[a.kind] ? L.t(ALERT_KEY[a.kind]) : a.kind.replace("_", " ");
    return html`<tr><td class="nowrap">${L.when(a.created_at)}</td><td class="nowrap">${pill(ALERT_TONE[a.kind] ?? "s-other", kind)}</td>
<td class="who-cell"><a href="${machineLink(a.install_id)}">${d.email || L.s("common.noEmail")}</a><span class="sub">${d.hostname}</span></td>
<td class="wrap">${a.check_id ? html`<code>${a.check_id}</code><span class="sub">${d.title}</span>` : a.kind === "compromised" && d.checks ? html`<code>${d.checks}</code><span class="sub">${d.titles}</span>` : ""}</td><td class="muted">${a.sent_at ? a.delivery : L.t("alerts.pending")}</td></tr>`;
  })}</tbody></table></div>${rows.length === 0 ? html`<p class="empty">${L.t("alerts.empty")}</p>` : ""}</div>`;
  return page(layout(L, L.s("nav.alerts"), who, body, "Alerts"));
}
