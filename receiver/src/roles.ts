// Role policies and how /policy composes a machine's policy from its role and
// its waivers.
//
// validateRolePolicy is a structural check, not the client's validator: it
// catches what would make bordercheck reject the whole file (unknown fields at
// the levels it knows, wrong types, bad durations, a waiver the client would
// refuse) and what must never be in a role (a report token). It does not look
// inside each check's settings beyond `enabled` and `on_problem`: globs,
// regexes, version strings and per-check lists are left to bordercheck, which
// keeps its last good policy when a new one is invalid. Check a role locally
// with `bordercheck -policy role.json -print-policy`.

import { DAY } from "./env";
import { type Msg, msg } from "./i18n";

type Obj = Record<string, unknown>;

// The check IDs bordercheck's policy knows (internal/policy/policy.go, Checks).
// A waiver or checks key outside this list makes the client reject the file.
export const POLICY_CHECKS = [
  "firewall", "disk-encryption", "listeners", "tailscale", "docker", "secrets", "ssh-keys", "tunnels", "ai-agents",
  "os-updates", "screen-lock", "remote-access", "cracked-software",
  "admin-rights", "os-protections", "sharing",
  "extensions", "browser-passwords", "trust-store",
  "package-managers", "startup-items", "backup",
];

export const MAX_WAIVER_DAYS = 365;
export const CHECK_ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

const isObj = (v: unknown): v is Obj => !!v && typeof v === "object" && !Array.isArray(v);

// goDuration parses a Go time.Duration string ("24h", "1h30m", "0") into ms, or null.
export function goDuration(s: unknown): number | null {
  if (typeof s !== "string" || s === "") return null;
  if (s === "0") return 0;
  const unit: Record<string, number> = { ns: 1e-6, us: 1e-3, "µs": 1e-3, ms: 1, s: 1e3, m: 6e4, h: 3.6e6 };
  const re = /(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|ms|s|m|h)/y;
  let total = 0;
  let i = 0;
  while (i < s.length) {
    re.lastIndex = i;
    const m = re.exec(s);
    if (!m) return null;
    total += Number(m[1]) * unit[m[2]];
    i = re.lastIndex;
  }
  return total;
}

export function today(now: Date): string {
  return now.toISOString().slice(0, 10);
}

// waiverDateError says what is wrong with a waiver end date, or null. It is a
// message (Msg), shown in the reader's language on pages and in English to MCP.
export function waiverDateError(until: string, now: Date): Msg | null {
  if (!DATE_RE.test(until) || Number.isNaN(Date.parse(until + "T00:00:00Z")) || new Date(until + "T00:00:00Z").toISOString().slice(0, 10) !== until) {
    return msg("v.untilFormat");
  }
  if (until < today(now)) return msg("v.untilPast");
  const latest = today(new Date(Date.parse(today(now) + "T00:00:00Z") + MAX_WAIVER_DAYS * DAY));
  if (until > latest) return msg("v.untilFar", { n: MAX_WAIVER_DAYS });
  return null;
}

function keysIn(o: Obj, allowed: string[], where: string, errs: Msg[]) {
  for (const k of Object.keys(o)) if (!allowed.includes(k)) errs.push(msg("v.unknownField", { where, field: k }));
}

function strList(v: unknown, where: string, errs: Msg[], allowed?: string[]) {
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
    errs.push(msg("v.strList", { where }));
    return;
  }
  if (allowed) for (const x of v) if (!allowed.includes(x)) errs.push(msg("v.notOneOf", { where, value: x, list: allowed.join(", ") }));
}

// Each machine sends its own token, so a role never carries one.
const isAuthHeader = (name: string): boolean => name.toLowerCase() === "authorization";

// validateRolePolicy returns problems that would stop bordercheck from
// accepting the policy, or that must not be in a role; [] means it passed what
// is checked here (see the comment at the top of this file). The messages
// name JSON paths and fields, which stay as they are in every language.
export function validateRolePolicy(p: unknown, now: Date): Msg[] {
  const errs: Msg[] = [];
  const must = (key: "v.mustString" | "v.mustObject" | "v.mustBool" | "v.mustList", where: string) => errs.push(msg(key, { where }));
  if (!isObj(p)) return [msg("v.notObject")];
  keysIn(p, ["name", "report", "update", "notify", "waivers", "checks"], "policy", errs);
  if (p.name !== undefined && typeof p.name !== "string") must("v.mustString", "name");

  if (p.report !== undefined) {
    if (!isObj(p.report)) must("v.mustObject", "report");
    else {
      const r = p.report;
      keysIn(r, ["url", "headers", "interval", "check_interval", "include_evidence", "email_domains", "include_ips", "include_location", "fix_prompt"], "report", errs);
      if (r.url !== undefined && typeof r.url !== "string") must("v.mustString", "report.url");
      if (r.headers !== undefined) {
        if (!isObj(r.headers)) must("v.mustObject", "report.headers");
        else
          for (const [k, v] of Object.entries(r.headers)) {
            if (typeof v !== "string") must("v.mustString", `report.headers.${k}`);
            if (isAuthHeader(k)) errs.push(msg("v.noToken", { where: `report.headers.${k}` }));
          }
      }
      if (r.interval !== undefined) {
        const d = goDuration(r.interval);
        if (d === null || d < 15 * 60 * 1000) errs.push(msg("v.minDuration", { where: "report.interval", min: "15m" }));
      }
      if (r.check_interval !== undefined && r.check_interval !== "") {
        const d = goDuration(r.check_interval);
        if (d === null || d < 15 * 60 * 1000) errs.push(msg("v.minDuration", { where: "report.check_interval", min: "15m" }));
      }
      for (const k of ["include_evidence", "include_ips", "include_location", "fix_prompt"]) {
        if (r[k] !== undefined && typeof r[k] !== "boolean") must("v.mustBool", `report.${k}`);
      }
      if (r.email_domains !== undefined) strList(r.email_domains, "report.email_domains", errs);
    }
  }

  if (p.update !== undefined) {
    if (!isObj(p.update)) must("v.mustObject", "update");
    else {
      const u = p.update;
      keysIn(u, ["binary", "policy_url", "interval", "repo", "public_key"], "update", errs);
      if (u.binary !== undefined && typeof u.binary !== "boolean") must("v.mustBool", "update.binary");
      if (u.policy_url !== undefined && typeof u.policy_url !== "string") must("v.mustString", "update.policy_url");
      if (u.interval !== undefined) {
        const d = goDuration(u.interval);
        if (d === null || d < 60 * 60 * 1000) errs.push(msg("v.minDuration", { where: "update.interval", min: "1h" }));
      }
      if (u.repo !== undefined && (typeof u.repo !== "string" || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(u.repo))) {
        errs.push(msg("v.repo", { where: "update.repo" }));
      }
      if (u.public_key !== undefined && u.public_key !== "") {
        let ok = false;
        try {
          ok = typeof u.public_key === "string" && atob(u.public_key).length === 32;
        } catch {
          ok = false;
        }
        if (!ok) errs.push(msg("v.publicKey", { where: "update.public_key" }));
      }
    }
  }

  if (p.notify !== undefined) {
    if (!isObj(p.notify)) must("v.mustObject", "notify");
    else {
      const n = p.notify;
      keysIn(n, ["enabled", "statuses", "severities", "remind_every", "open_report"], "notify", errs);
      if (n.open_report !== undefined && typeof n.open_report !== "boolean") must("v.mustBool", "notify.open_report");
      if (n.enabled !== undefined && typeof n.enabled !== "boolean") must("v.mustBool", "notify.enabled");
      if (n.statuses !== undefined) strList(n.statuses, "notify.statuses", errs, ["fail", "warn"]);
      if (n.severities !== undefined) strList(n.severities, "notify.severities", errs);
      if (n.remind_every !== undefined && goDuration(n.remind_every) === null) errs.push(msg("v.duration", { where: "notify.remind_every" }));
    }
  }

  if (p.waivers !== undefined) {
    if (!Array.isArray(p.waivers)) must("v.mustList", "waivers");
    else
      p.waivers.forEach((w, i) => {
        const at = `waivers[${i}]`;
        if (!isObj(w)) return must("v.mustObject", at);
        keysIn(w, ["check", "email", "install_id", "hostname", "until", "reason"], at, errs);
        if (typeof w.check !== "string" || !POLICY_CHECKS.includes(w.check)) errs.push(msg("v.waiverCheck", { where: at, list: POLICY_CHECKS.join(", ") }));
        if (!w.email && !w.install_id) errs.push(msg("v.waiverWho", { where: at }));
        if (w.email !== undefined && (typeof w.email !== "string" || !w.email.includes("@"))) errs.push(msg("v.waiverEmail", { where: at }));
        if (typeof w.reason !== "string" || !w.reason.trim()) errs.push(msg("v.waiverReason", { where: at }));
        const e = typeof w.until === "string" ? waiverDateError(w.until, now) : msg("v.untilRequired");
        if (e && e.key !== "v.untilPast") errs.push(msg("v.at", { where: at, problem: e }));
      });
  }

  if (p.checks !== undefined) {
    if (!isObj(p.checks)) must("v.mustObject", "checks");
    else
      for (const [id, c] of Object.entries(p.checks)) {
        if (!POLICY_CHECKS.includes(id)) {
          errs.push(msg("v.unknownCheck", { id }));
          continue;
        }
        if (!isObj(c)) {
          must("v.mustObject", `checks.${id}`);
          continue;
        }
        if (c.enabled !== undefined && typeof c.enabled !== "boolean") must("v.mustBool", `checks.${id}.enabled`);
        if (c.on_problem !== undefined && c.on_problem !== "fail" && c.on_problem !== "warn") {
          errs.push(msg("v.onProblem", { where: `checks.${id}.on_problem` }));
        }
      }
  }
  return errs;
}

export interface MachineIdentity {
  install_id: string;
  email: string;
}

export interface WaiverRow {
  check_id: string;
  until: string;
  reason: string;
}

// composePolicy builds the policy one machine gets from /policy: its role's
// policy, pointed at this deployment, with no token in it, and with the
// waivers that apply to this machine. Role waivers for other people are left
// out (they would tell this machine about colleagues); machine waivers are
// keyed by install_id. Waivers that ended more than 30 days ago are dropped;
// recently ended ones stay so bordercheck can say they ended.
export function composePolicy(
  rolePolicy: Obj,
  roleName: string,
  m: MachineIdentity,
  waivers: WaiverRow[],
  origin: string,
  now: Date,
): Obj {
  const p = structuredClone(rolePolicy);
  if (typeof p.name !== "string" || !p.name) p.name = roleName;

  const report = isObj(p.report) ? p.report : {};
  const headers: Obj = {};
  if (isObj(report.headers)) {
    for (const [k, v] of Object.entries(report.headers)) if (!isAuthHeader(k)) headers[k] = v;
  }
  p.report = { ...report, url: `${origin}/report`, headers };

  p.update = { ...(isObj(p.update) ? p.update : {}), policy_url: `${origin}/policy` };

  const oldest = today(new Date(now.getTime() - 30 * DAY));
  const latest = today(new Date(Date.parse(today(now) + "T00:00:00Z") + MAX_WAIVER_DAYS * DAY));
  const fits = (until: unknown, check: unknown) =>
    typeof until === "string" && DATE_RE.test(until) && until >= oldest && until <= latest &&
    typeof check === "string" && POLICY_CHECKS.includes(check);

  const out: Obj[] = [];
  if (Array.isArray(p.waivers)) {
    for (const w of p.waivers) {
      if (!isObj(w) || !fits(w.until, w.check) || typeof w.reason !== "string" || !w.reason.trim()) continue;
      const email = typeof w.email === "string" ? w.email : "";
      const id = typeof w.install_id === "string" ? w.install_id : "";
      if (!email && !id) continue;
      if (email && email.toLowerCase() !== m.email.toLowerCase()) continue;
      if (id && id !== m.install_id) continue;
      out.push(w);
    }
  }
  for (const w of waivers) {
    if (!fits(w.until, w.check_id)) continue;
    out.push({ check: w.check_id, install_id: m.install_id, until: w.until, reason: w.reason });
  }
  p.waivers = out;
  return p;
}
