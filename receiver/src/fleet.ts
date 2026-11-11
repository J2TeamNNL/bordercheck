// Structured reads and writes shared by the two automation surfaces: the MCP
// tools (mcp-tools.ts) and the REST API (api.ts). Both reach the database
// only through these and the dashboard's shared operations (portal.ts,
// dashboard.ts), so input checks, limits, atomicity, audit rows and the way
// machine-supplied text is cleaned are the same on every surface.
//
// What differs per surface is passed in: who is acting, what goes into the
// audit row, how a refused write is recorded, and which role-policy fields the
// surface may not set (RoleRules).
//
// Machine-supplied text (hostnames, OS strings, versions, check titles,
// summaries, fixes, evidence, unknown check ids and statuses) is attacker-
// controllable. It is always returned inside an object named "untrusted",
// length-capped, with control and invisible formatting characters removed
// (clean), and never used to build an error message.

import { type AlertListRow, checkStats, type CheckStat, type MachineListRow, parseStatuses } from "./dashboard";
import { installCommands, publicOrigin } from "./enroll";
import { config, DAY, type Env } from "./env";
import { parseGeo, place } from "./geo";
import { english, type Msg } from "./i18n";
import {
  type AuditExtra,
  type AuditRow,
  checkRole,
  createInviteBatch,
  enrollmentOf,
  type InviteRow,
  inviteRows,
  type Issued,
  machineAction,
  type MachineAction,
  type MachineParams,
  reissueInviteOp,
  revokeInviteOp,
  saveRole,
} from "./portal";
import { type DeviceLocation, parseReport, statusRank } from "./report";
import { POLICY_CHECKS } from "./roles";

export const KNOWN_STATUSES = ["fail", "error", "warn", "waived", "pass", "skip"];
const KNOWN_SEVERITIES = ["high", "medium", "low", "info"];
export const INSTALL_ID_PATTERN = "^[A-Za-z0-9_-]{8,128}$";
const INSTALL_ID_RE = new RegExp(INSTALL_ID_PATTERN);

// ---- Results ----

// Out is what a shared read or write returns. A failure carries a fixed
// English message, optional problems (validation messages), and for the REST
// API the HTTP status and the message key it came from.
export type Out =
  | { ok: true; data: Record<string, unknown> }
  | { ok: false; error: string; errors?: string[]; status?: number; key?: string };

export const okData = (data: Record<string, unknown>): Out => ({ ok: true, data });
export const fail = (error: string, errors?: string[], status?: number, key?: string): Out => ({ ok: false, error, errors, status, key });
const failMsg = (m: Msg, status: number): Out => fail(english(m), undefined, status, m.key);

// ---- Sanitising ----

// clean makes untrusted text safe to hand over as data: control characters and
// invisible formatting characters (zero-width, bidi overrides) become spaces,
// runs of whitespace collapse, the length is capped.
export function clean(v: unknown, max: number): string {
  if (v === null || v === undefined) return "";
  const s = String(v)
    .replace(/[\u0000-\u001f\u007f-\u009f\u00ad\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff\ufff9-\ufffb]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return s.length > max ? s.slice(0, max) + "…" : s;
}

const known = (id: string) => POLICY_CHECKS.includes(id);

// checkRef names a check: a check id bordercheck's policy knows is ours; any
// other id came from a report and goes under "untrusted".
export function checkRef(id: string): { check_id: string | null; untrusted?: { check_id: string } } {
  return known(id) ? { check_id: id } : { check_id: null, untrusted: { check_id: clean(id, 64) } };
}

const statusOf = (s: string) => (KNOWN_STATUSES.includes(s) ? s : "other");
const severityOf = (s: string) => (s === "" ? "" : KNOWN_SEVERITIES.includes(s) ? s : "other");

export function parseJSON<T>(s: string | null | undefined): T | null {
  if (!s) return null;
  try {
    return JSON.parse(s) as T;
  } catch {
    return null;
  }
}

// ---- A small JSON Schema subset: a tool's inputSchema, an API route's query
// and body schemas, and their validator ----

export type Schema = {
  type?: string | string[];
  description?: string;
  properties?: Record<string, Schema>;
  required?: string[];
  additionalProperties?: boolean;
  enum?: unknown[];
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  items?: Schema;
  minItems?: number;
  maxItems?: number;
  default?: unknown;
  format?: string;
};

function typeOf(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (typeof v === "number") return Number.isInteger(v) ? "integer" : "number";
  return typeof v;
}

// validate returns problems with `v` against `s`; messages name the field and
// the rule, never the value.
export function validate(s: Schema, v: unknown, at = "arguments"): string[] {
  const errs: string[] = [];
  if (s.type) {
    const types = Array.isArray(s.type) ? s.type : [s.type];
    const t = typeOf(v);
    if (!types.includes(t) && !(t === "integer" && types.includes("number"))) return [`${at} must be ${types.join(" or ")}`];
  }
  if (s.enum && !s.enum.includes(v)) errs.push(`${at} must be one of ${s.enum.join(", ")}`);
  if (typeof v === "number") {
    if (s.minimum !== undefined && v < s.minimum) errs.push(`${at} must be at least ${s.minimum}`);
    if (s.maximum !== undefined && v > s.maximum) errs.push(`${at} must be at most ${s.maximum}`);
  }
  if (typeof v === "string") {
    if (s.minLength !== undefined && v.length < s.minLength) errs.push(`${at} must be at least ${s.minLength} characters`);
    if (s.maxLength !== undefined && v.length > s.maxLength) errs.push(`${at} must be at most ${s.maxLength} characters`);
    if (s.pattern && !new RegExp(s.pattern).test(v)) errs.push(`${at} has the wrong format`);
  }
  if (Array.isArray(v)) {
    if (s.minItems !== undefined && v.length < s.minItems) errs.push(`${at} must have at least ${s.minItems} items`);
    if (s.maxItems !== undefined && v.length > s.maxItems) errs.push(`${at} must have at most ${s.maxItems} items`);
    if (s.items) v.slice(0, 1000).forEach((x, i) => errs.push(...validate(s.items!, x, `${at}[${i}]`)));
  }
  if (typeOf(v) === "object" && (s.properties || s.required)) {
    const o = v as Record<string, unknown>;
    for (const k of s.required ?? []) if (o[k] === undefined) errs.push(`${at}.${k} is required`);
    for (const [k, x] of Object.entries(o)) {
      const ps = s.properties?.[k];
      if (!ps) {
        if (s.additionalProperties === false) errs.push(`${at}: unknown field "${clean(k, 40)}"`);
        continue;
      }
      errs.push(...validate(ps, x, `${at}.${k}`));
    }
  }
  return errs;
}

// ---- Reads ----

export function silentBefore(env: Env, now: Date): string {
  return new Date(now.getTime() - config(env).silentDays * DAY).toISOString();
}

const counts = (m: { fail: number; high_fail: number; error: number; warn: number; waived: number; pass: number; skip: number; other: number }) => ({
  fail: m.fail, high_fail: m.high_fail, error: m.error, warn: m.warn, waived: m.waived, pass: m.pass, skip: m.skip, other: m.other,
});

// machineSummary: one machine in a list, from its latest report.
export function machineSummary(env: Env, m: MachineListRow, silentIso: string) {
  const cfg = config(env);
  const enrolled = !!m.enrolled;
  const state = m.fail ? "non-compliant" : m.error || m.warn ? "attention" : "ok";
  return {
    install_id: m.install_id,
    enrolled,
    revoked: !!m.revoked_at,
    role: enrolled ? m.role : null,
    // The email comes from the machine's invite, never from its reports.
    email: enrolled ? m.email : null,
    last_seen: m.last_seen,
    silent: m.last_seen < silentIso,
    state,
    counts: counts(m),
    place: cfg.storeGeo ? place(parseGeo(m.geo)) || null : null,
    untrusted: {
      hostname: clean(m.hostname, 100),
      os: clean(m.os, 32),
      arch: clean(m.arch, 32),
      bordercheck_version: clean(m.version, 64),
    },
  };
}

// waitingSummary: an enrolled machine that has not reported yet.
export function waitingSummary(w: { install_id: string; email: string; hostname: string; enrolled_at: string; role: string }) {
  return { install_id: w.install_id, enrolled: true, role: w.role, email: w.email, enrolled_at: w.enrolled_at, untrusted: { hostname_at_enrollment: clean(w.hostname, 100) } };
}

export async function fleetSummary(env: Env, now: Date): Promise<Record<string, unknown>> {
  const silentIso = silentBefore(env, now);
  const t = await env.DB.prepare(
    `SELECT COUNT(*) AS machines, SUM(m.fail > 0) AS failing, SUM(m.fail = 0 AND (m.error > 0 OR m.warn > 0)) AS attention,
            SUM(m.last_seen < ?1) AS silent, SUM(e.revoked_at IS NOT NULL) AS revoked
     FROM machines m LEFT JOIN enrollments e ON e.install_id = m.install_id`,
  ).bind(silentIso).first<Record<string, number | null>>();
  const [waiting, roles, invites, pending, top] = await Promise.all([
    env.DB.prepare(
      "SELECT COUNT(*) AS n FROM enrollments e WHERE e.revoked_at IS NULL AND NOT EXISTS (SELECT 1 FROM machines m WHERE m.install_id = e.install_id)",
    ).first<number>("n"),
    env.DB.prepare("SELECT COUNT(*) AS n FROM roles").first<number>("n"),
    inviteRows(env, "pending", 1),
    env.DB.prepare("SELECT COUNT(*) AS n FROM alerts WHERE sent_at IS NULL").first<number>("n"),
    checkStats(env, 5),
  ]);
  return {
    silent_days: config(env).silentDays,
    machines: {
      reporting: t?.machines ?? 0,
      failing: t?.failing ?? 0,
      attention_only: t?.attention ?? 0,
      silent: t?.silent ?? 0,
      revoked: t?.revoked ?? 0,
      enrolled_no_report_yet: waiting ?? 0,
    },
    roles: roles ?? 0,
    invites: invites.counts,
    pending_alerts: pending ?? 0,
    most_failing_checks: top.filter((c) => c.fail > 0).map((c) => ({ ...checkRef(c.check_id), fail: c.fail, high: c.high, reported_by: c.total })),
  };
}

interface StoredMachine extends MachineListRow {
  report: string;
  local_ips: string;
  device_location: string;
}

// machineWaivers: a machine's waivers, active ones first.
export async function machineWaivers(env: Env, id: string, now: Date) {
  const waivers = await env.DB.prepare(
    "SELECT id, check_id, until, reason, created_at, created_by, removed_at, removed_by FROM machine_waivers WHERE install_id = ? ORDER BY removed_at IS NOT NULL, until DESC LIMIT 100",
  ).bind(id).all<{ id: number; check_id: string; until: string; reason: string; created_at: string; created_by: string; removed_at: string | null; removed_by: string | null }>();
  const today = now.toISOString().slice(0, 10);
  return waivers.results.map((w) => ({
    waiver_id: w.id,
    check_id: w.check_id,
    until: w.until,
    active: !w.removed_at && w.until >= today,
    reason: w.reason,
    added_at: w.created_at,
    added_by: w.created_by,
    removed_at: w.removed_at,
    removed_by: w.removed_by,
  }));
}

export async function machineExists(env: Env, id: string): Promise<boolean> {
  return !!(await env.DB.prepare("SELECT 1 FROM enrollments WHERE install_id = ?1 UNION SELECT 1 FROM machines WHERE install_id = ?1").bind(id).first());
}

// machineDetail: one machine (MCP get_machine, REST GET /machines/{id}).
// Evidence and location only when asked for.
export async function machineDetail(env: Env, id: string, o: { evidence?: boolean; location?: boolean; history?: number }, now: Date): Promise<Out> {
  const cfg = config(env);
  const [m, e] = await Promise.all([
    env.DB.prepare(
      `SELECT m.*, e.install_id IS NOT NULL AS enrolled, e.revoked_at, r.name AS role
       FROM machines m LEFT JOIN enrollments e ON e.install_id = m.install_id LEFT JOIN roles r ON r.id = e.role_id WHERE m.install_id = ?`,
    ).bind(id).first<StoredMachine>(),
    enrollmentOf(env, id),
  ]);
  if (!m && !e) return fail("No such machine.", undefined, 404, "err.noSuchMachine");
  const out: Record<string, unknown> = { install_id: id, enrolled: !!e };
  if (e) {
    out.enrollment = {
      role_id: e.role_id,
      role: e.role,
      email: e.email,
      invite_id: e.invite_id,
      invited_by: e.invite_by,
      invite_note: e.invite_note,
      enrolled_at: e.enrolled_at,
      revoked: !!e.revoked_at,
      revoked_at: e.revoked_at,
      revoked_by: e.revoked_by,
      last_policy_fetch: e.last_policy_at,
      untrusted: { hostname_at_enrollment: clean(e.hostname, 100), os: clean(e.os, 32), arch: clean(e.arch, 32), version: clean(e.version, 64) },
    };
    out.waivers = await machineWaivers(env, id, now);
  } else {
    out.enrollment = null;
  }
  if (!m) {
    out.reported = false;
    return okData(out);
  }
  const silentIso = silentBefore(env, now);
  out.reported = true;
  out.summary = machineSummary(env, m, silentIso);
  out.first_seen = m.first_seen;

  const since = new Map(
    (await env.DB.prepare("SELECT check_id, since FROM checks WHERE install_id = ?").bind(id).all<{ check_id: string; since: string }>()).results.map((c) => [c.check_id, c.since]),
  );
  let results: ReturnType<typeof parseReport>["results"] = [];
  try {
    results = parseReport(JSON.parse(m.report)).results;
  } catch {
    out.report_unreadable = true;
  }
  results.sort((x, y) => statusRank(x.status) - statusRank(y.status));
  const problems = results.filter((r) => !["pass", "skip"].includes(r.status)).slice(0, 100);
  const fine = results.filter((r) => ["pass", "skip"].includes(r.status)).slice(0, 200);
  out.checks_needing_attention = problems.map((r) => {
    const ref = checkRef(r.id);
    return {
      check_id: ref.check_id,
      status: statusOf(r.status),
      severity: severityOf(r.severity),
      since: since.get(r.id) ?? null,
      untrusted: {
        ...(ref.untrusted ?? {}),
        ...(statusOf(r.status) === "other" ? { status: clean(r.status, 32) } : {}),
        title: clean(r.title, 120),
        summary: clean(r.summary, 500),
        fix: clean(r.fix, 500),
        ...(r.waived ? { waived_until: clean(r.waived.until, 32), waived_reason: clean(r.waived.reason, 200) } : {}),
        ...(o.evidence ? { evidence: r.evidence.slice(0, 20).map((x) => clean(x, 200)) } : {}),
      },
    };
  });
  out.passing_checks = fine.filter((r) => known(r.id)).map((r) => ({ check_id: r.id, status: r.status }));
  const otherPassing = fine.filter((r) => !known(r.id));
  if (otherPassing.length) out.untrusted = { other_passing_check_ids: otherPassing.slice(0, 50).map((r) => clean(r.id, 64)) };
  // What the person at the machine marked as not sensitive (bordercheck
  // ignore): the count always, the items with evidence, since they name files.
  const ignored = results.filter((r) => r.user_ignored?.length);
  out.user_ignored_count = ignored.reduce((n, r) => n + (r.user_ignored?.length ?? 0), 0);
  if (o.evidence && ignored.length) {
    out.user_ignored = ignored.flatMap((r) => {
      const ref = checkRef(r.id);
      return (r.user_ignored ?? []).slice(0, 50).map((i) => ({
        check_id: ref.check_id,
        untrusted: {
          ...(ref.untrusted ?? {}),
          path: clean(i.path, 200),
          name: clean(i.name, 100),
          kind: clean(i.kind, 64),
          reason: clean(i.reason, 200),
          since: clean(i.since, 32),
        },
      }));
    });
  }
  out.report_untrusted = { machine_clock: clean(m.report_time, 40), policy_name: clean(m.policy, 100) };

  const hl = o.history ?? 10;
  if (hl > 0) {
    const h = (await env.DB.prepare(
      "SELECT received_at, version, fail, warn, error, waived, statuses FROM reports WHERE install_id = ? ORDER BY id DESC LIMIT ?",
    ).bind(id, hl + 1).all<{ received_at: string; version: string; fail: number; warn: number; error: number; waived: number; statuses: string }>()).results;
    out.history = h.slice(0, hl).map((r, i) => {
      const cur = parseStatuses(r.statuses);
      const prev = h[i + 1] ? parseStatuses(h[i + 1].statuses) : null;
      const changes: { check: string; from: string; to: string }[] = [];
      if (prev) {
        for (const [k, s] of Object.entries(cur)) if (prev[k] !== s) changes.push({ check: clean(k, 64), from: clean(prev[k] ?? "new", 32), to: clean(s, 32) });
        for (const k of Object.keys(prev)) if (!(k in cur)) changes.push({ check: clean(k, 64), from: clean(prev[k], 32), to: "gone" });
      }
      return { received_at: r.received_at, fail: r.fail, error: r.error, warn: r.warn, waived: r.waived, untrusted: { version: clean(r.version, 64), changes: prev ? changes.slice(0, 40) : "oldest report kept" } };
    });
  }

  if (o.location) {
    // A switch turned off hides what is still stored from before.
    const g = cfg.storeGeo ? parseGeo(m.geo) : null;
    const d = cfg.storeGeo ? parseJSON<DeviceLocation>(m.device_location) : null;
    const ips = cfg.storeIp ? parseJSON<string[]>(m.local_ips) ?? [] : [];
    out.location = {
      collection: { public_ip: cfg.storeIp, geo: cfg.storeGeo },
      public_ip: cfg.storeIp ? m.public_ip || null : null,
      ip_location: g
        ? { place: place(g) || null, lat: g.lat ?? null, lon: g.lon ?? null, timezone: g.timezone ?? null, asn: g.asn ?? null, network: g.as_org ? clean(g.as_org, 100) : null, source: "Cloudflare's estimate from the IP" }
        : null,
      untrusted: {
        device_location: d && typeof d.lat === "number" && typeof d.lon === "number"
          ? { lat: d.lat, lon: d.lon, accuracy_m: d.accuracy_m, source: clean(d.source, 32), time: clean(d.time, 40) }
          : null,
        local_ips: ips.slice(0, 32).map((x) => clean(x, 64)),
      },
    };
  }
  return okData(out);
}

export function checkStatItem(c: CheckStat) {
  const ref = checkRef(c.check_id);
  return {
    check_id: ref.check_id,
    fail: c.fail, high: c.high, error: c.error, warn: c.warn, waived: c.waived, pass: c.pass, reported_by: c.total,
    untrusted: { ...(ref.untrusted ?? {}), title: clean(c.title, 120) },
  };
}

export function roleItem(r: { id: number; name: string; machines: number; pending: number; updated_at: string }) {
  return { role_id: r.id, name: r.name, machines: r.machines, pending_invites: r.pending, updated_at: r.updated_at };
}

export async function roleDetail(env: Env, id: number): Promise<Out> {
  const r = await env.DB.prepare("SELECT id, name, policy, created_at, updated_at FROM roles WHERE id = ?").bind(id).first<{ id: number; name: string; policy: string; created_at: string; updated_at: string }>();
  if (!r) return fail("No such role.", undefined, 404, "err.noSuchRole");
  const ms = await env.DB.prepare("SELECT install_id, email, hostname, revoked_at FROM enrollments WHERE role_id = ? ORDER BY email LIMIT 200")
    .bind(r.id).all<{ install_id: string; email: string; hostname: string; revoked_at: string | null }>();
  return okData({
    role_id: r.id,
    name: r.name,
    created_at: r.created_at,
    updated_at: r.updated_at,
    policy: parseJSON(r.policy),
    machines: ms.results.map((m) => ({ install_id: m.install_id, email: m.email, revoked: !!m.revoked_at, untrusted: { hostname_at_enrollment: clean(m.hostname, 100) } })),
  });
}

export function inviteItem(i: InviteRow) {
  return {
    invite_id: i.id, email: i.email, role: i.role, note: i.note, status: i.status, created_at: i.created_at, created_by: i.created_by,
    expires_at: i.expires_at, used_at: i.used_at, used_install_id: i.used_install_id, revoked_at: i.revoked_at,
    reissued_as: i.reissued_as && i.reissued_as > 0 ? i.reissued_as : null,
  };
}

export function alertItem(x: AlertListRow) {
  const d = parseStatuses(x.detail);
  const ref = x.check_id ? checkRef(x.check_id) : { check_id: null };
  return {
    alert_id: x.id,
    kind: clean(x.kind, 32),
    install_id: x.install_id,
    check_id: ref.check_id,
    raised_at: x.created_at,
    delivered_at: x.sent_at,
    delivery: x.sent_at ? clean(x.delivery, 100) : "pending",
    untrusted: { ...("untrusted" in ref ? ref.untrusted : {}), email: clean(d.email, 254), hostname: clean(d.hostname, 100), title: clean(d.title, 120) },
  };
}


export function auditItem(r: AuditRow) {
  return { id: r.id, at: r.at, who: clean(r.who, 200), action: clean(r.action, 64), target: clean(r.target, 200), untrusted: { detail: clean(r.detail, 1500) } };
}

// ---- Writes ----

// Writer is who makes a change and how the surface records it.
export interface Writer {
  env: Env;
  req: Request;
  who: string; // the audit actor
  extra: AuditExtra; // merged into the audit row of the change
  refuse(errors: string[]): Promise<void>; // records a refused write
}

// auditArgs is what goes into an audit row: the arguments, capped. Nothing
// secret is ever an argument (codes and tokens are outputs, and nothing takes one).
export function auditArgs(args: Record<string, unknown>): unknown {
  const cap = (v: unknown, depth: number): unknown => {
    if (typeof v === "string") return clean(v, 300);
    if (Array.isArray(v)) return v.slice(0, 60).map((x) => cap(x, depth + 1));
    if (v && typeof v === "object") {
      if (depth > 4) return clean(JSON.stringify(v), 300);
      return Object.fromEntries(Object.entries(v).slice(0, 40).map(([k, x]) => [clean(k, 64), cap(x, depth + 1)]));
    }
    return v;
  };
  const out = cap(args, 0);
  const s = JSON.stringify(out);
  return s.length > 4000 ? { truncated: true, json: s.slice(0, 4000) } : out;
}

// RoleRules: what a surface may not do to a role policy. `locked` fields can't
// be set or changed (only kept as they are); `noEnable` fields can be turned
// off but not on. allProblems: report guard-rail and validation problems
// together, rather than stopping at the guard rails.
export interface RoleRules {
  surface: string; // "MCP", "the API": goes into the messages
  locked: string[][];
  noEnable: string[][];
  allProblems: boolean;
}

// Where reports, policy and binary updates go and come from: a role pointing
// update.repo and update.public_key elsewhere would run someone else's binary
// on every laptop. Neither automation surface may set or change these.
const WHERE_TO: string[][] = [["report", "url"], ["report", "headers"], ["update", "policy_url"], ["update", "repo"], ["update", "public_key"]];

// MCP, whose caller is a model reading attacker-controlled text, also may not
// carry role-level waivers (which can cover many people at once) or turn on
// collection of more personal data.
export const MCP_ROLE_RULES: RoleRules = {
  surface: "MCP",
  locked: [...WHERE_TO, ["waivers"]],
  noEnable: [["report", "include_evidence"], ["report", "include_ips"], ["report", "include_location"]],
  allProblems: false,
};

// A script author holds a credential as strong as a dashboard admin's and
// writes the policy themselves, so the API keeps only the where-to locks.
export const API_ROLE_RULES: RoleRules = { surface: "the API", locked: WHERE_TO, noEnable: [], allProblems: true };

function at(o: unknown, path: string[]): unknown {
  let v = o;
  for (const k of path) v = v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>)[k] : undefined;
  return v;
}

function canon(v: unknown): string {
  if (v === undefined || v === null || v === "") return "";
  if (Array.isArray(v) && v.length === 0) return "";
  if (typeof v === "object" && !Array.isArray(v) && Object.keys(v as object).length === 0) return "";
  return JSON.stringify(v);
}

export function policyGuard(next: unknown, current: unknown, rules: RoleRules): string[] {
  const errs: string[] = [];
  for (const p of rules.locked) {
    if (canon(at(next, p)) !== canon(at(current, p))) errs.push(`${p.join(".")}: can't be set or changed through ${rules.surface}; change it in the dashboard`);
  }
  for (const p of rules.noEnable) {
    if (at(next, p) === true && at(current, p) !== true) errs.push(`${p.join(".")}: can't be turned on through ${rules.surface} (it collects more data from laptops); change it in the dashboard`);
  }
  return errs;
}

function policyText(p: unknown): string {
  return typeof p === "string" ? p : JSON.stringify(p, null, 2);
}

// writeRole creates (no id) or updates a role: the surface's guard rails,
// then saveRole, which validates exactly as the dashboard does.
export async function writeRole(w: Writer, input: { id?: number; name?: string; policy?: unknown }, rules: RoleRules, now = new Date()): Promise<Out> {
  const { env } = w;
  const id = input.id;
  const cur = id === undefined ? null : await env.DB.prepare("SELECT name, policy FROM roles WHERE id = ?").bind(id).first<{ name: string; policy: string }>();
  if (id !== undefined && !cur) return fail("No such role.", undefined, 404, "err.noSuchRole");
  const name = input.name ?? cur!.name;
  const text = input.policy !== undefined ? policyText(input.policy) : cur!.policy;
  let parsed: unknown;
  let parses = true;
  try {
    parsed = JSON.parse(text);
  } catch {
    parses = false;
  }
  if (parses) {
    const g = policyGuard(parsed, cur ? parseJSON(cur.policy) : {}, rules);
    if (g.length) {
      const all = rules.allProblems ? [...g, ...(await checkRole(env, name.trim(), text, now)).errs.map(english)] : g;
      await w.refuse(all);
      return fail("Not saved.", all, 400);
    }
  }
  const r = await saveRole(env, w.who, { id, name, policyText: text }, w.extra);
  if (!r.ok) {
    const errs = r.errors.map(english);
    await w.refuse(errs);
    return fail("Not saved.", errs, r.status, r.errors[0]?.key);
  }
  return okData({ role_id: r.id, name: r.name, policy_changed: r.policyChanged, note: "Machines pick up the policy at their next hourly refresh." });
}

// issuedItem: a fresh invite with its link and install commands (the only
// place a code ever appears).
export function issuedItem(w: { env: Env; req: Request }, i: Issued, withExpiry = false) {
  const c = installCommands(w.env, publicOrigin(w.env, w.req), i.code);
  return {
    invite_id: i.id,
    email: i.email,
    ...(withExpiry ? { expires_at: i.expires } : {}),
    invite_link: c.link,
    install_macos_linux: c.sh,
    install_windows: c.ps1,
  };
}

// createInvites: one invite per email, all or nothing. The result keeps the
// Issued rows (with codes) for the surface to shape; they are never stored.
export async function createInvites(
  w: Writer,
  input: { emails: string[]; roleId: number; days?: number; note?: string },
  maxBulk: number,
): Promise<{ ok: true; role: string; days: number; issued: Issued[] } | (Out & { ok: false })> {
  const r = await createInviteBatch(
    w.env,
    w.who,
    {
      emails: input.emails.join("\n"),
      roleId: input.roleId,
      days: input.days ?? Math.min(90, Math.floor(config(w.env).inviteDays)),
      note: String(input.note ?? ""),
    },
    { maxBulk, extra: w.extra },
  );
  if (!r.ok) {
    const errs = r.errors.map(english);
    await w.refuse(errs);
    return { ok: false, error: "Nothing created.", errors: errs, status: r.status, key: r.errors[0]?.key };
  }
  return { ok: true, role: r.role, days: r.days, issued: r.issued };
}

export async function revokeInvite(w: Writer, id: number): Promise<Out> {
  const r = await revokeInviteOp(w.env, w.who, id, w.extra);
  if (!r.ok) return failMsg(r.errors[0], r.status);
  return okData({ invite_id: id, email: r.email, status: "revoked" });
}

export async function reissueInvite(w: Writer, id: number): Promise<{ ok: true; issued: Issued } | (Out & { ok: false })> {
  const r = await reissueInviteOp(w.env, w.who, id, w.extra);
  if (!r.ok) return failMsg(r.errors[0], r.status) as Out & { ok: false };
  return { ok: true, issued: r.issued };
}

// machineWrite: one write on one machine, by install_id.
export async function machineWrite(w: Writer, id: string, action: MachineAction, params: MachineParams = {}): Promise<Out> {
  if (!INSTALL_ID_RE.test(id)) return fail("install_id has the wrong format.", undefined, 400);
  if (!(await machineExists(w.env, id))) return fail("No such machine.", undefined, 404, "err.noSuchMachine");
  const r = await machineAction(w.env, w.who, id, action, params, w.extra);
  if (r.error) {
    if (r.status === 400) await w.refuse([english(r.error)]);
    return failMsg(r.error, r.status);
  }
  return okData({ install_id: id, ...(r.detail ?? {}) });
}
