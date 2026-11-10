// The bordercheck report, as this receiver reads it. Everything in it is
// self-reported by the machine and so untrusted: strings are length-capped
// here and escaped wherever they are shown. Unknown fields are ignored (and
// kept in the stored raw report); unknown statuses are kept as they are.

export interface Waiver {
  until: string;
  reason: string;
}

export interface Result {
  id: string;
  title: string;
  status: string; // pass | warn | fail | skip | error | waived | anything newer
  severity: string;
  summary: string;
  fix: string;
  evidence: string[];
  waived?: Waiver;
}

export interface Report {
  tool: string;
  version: string;
  policy: string;
  time: string | null;
  host: { os: string; arch: string; hostname: string };
  email: string;
  installId: string;
  results: Result[];
}

export interface Counts {
  fail: number;
  high_fail: number;
  error: number;
  warn: number;
  waived: number;
  pass: number;
  skip: number;
  other: number;
}

export const KNOWN_STATUSES = ["fail", "error", "warn", "waived", "pass", "skip"] as const;

// Display order: worst first, statuses we do not know just before pass.
export function statusRank(s: string): number {
  const i = (KNOWN_STATUSES as readonly string[]).indexOf(s);
  if (i === -1) return 4; // after waived, before pass
  return i < 4 ? i : i + 1;
}

export class ReportError extends Error {}

const INSTALL_ID = /^[A-Za-z0-9_-]{8,128}$/;

function str(v: unknown, max: number): string {
  if (typeof v !== "string") return "";
  // Drop control characters except newline and tab; cap the length.
  const clean = v.replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, "");
  return clean.length > max ? clean.slice(0, max) + "…" : clean;
}

function obj(v: unknown): Record<string, unknown> {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

export const MAX_RESULTS = 300;

export function parseReport(raw: unknown): Report {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new ReportError("report must be a JSON object");
  const r = raw as Record<string, unknown>;
  if (r.tool !== "bordercheck") throw new ReportError('"tool" must be "bordercheck"');
  if (typeof r.install_id !== "string" || !INSTALL_ID.test(r.install_id)) {
    throw new ReportError('"install_id" is missing or malformed; reports come from an installed bordercheck');
  }
  if (!Array.isArray(r.results)) throw new ReportError('"results" must be an array');
  if (r.results.length > MAX_RESULTS) throw new ReportError(`at most ${MAX_RESULTS} results`);

  const results: Result[] = r.results.map((x, i) => {
    const o = obj(x);
    const id = str(o.id, 64).trim();
    if (!id) throw new ReportError(`results[${i}].id is missing`);
    const status = str(o.status, 32).trim().toLowerCase();
    if (!status) throw new ReportError(`results[${i}].status is missing`);
    const res: Result = {
      id,
      title: str(o.title, 200),
      status,
      severity: str(o.severity, 16).trim().toLowerCase(),
      summary: str(o.summary, 2000),
      fix: str(o.fix, 2000),
      evidence: Array.isArray(o.evidence) ? o.evidence.slice(0, 100).map((e) => str(e, 500)) : [],
    };
    const w = obj(o.waived);
    if (o.waived !== undefined && (w.until !== undefined || w.reason !== undefined)) {
      res.waived = { until: str(w.until, 32), reason: str(w.reason, 500) };
    }
    return res;
  });

  const host = obj(r.host);
  const t = typeof r.time === "string" && !Number.isNaN(Date.parse(r.time)) ? str(r.time, 40) : null;
  return {
    tool: "bordercheck",
    version: str(r.version, 64),
    policy: str(r.policy, 200),
    time: t,
    host: { os: str(host.os, 32), arch: str(host.arch, 32), hostname: str(host.hostname, 255) },
    email: str(r.email, 254).trim().toLowerCase(),
    installId: r.install_id,
    results,
  };
}

export function countResults(results: Result[]): Counts {
  const c: Counts = { fail: 0, high_fail: 0, error: 0, warn: 0, waived: 0, pass: 0, skip: 0, other: 0 };
  for (const r of results) {
    if ((KNOWN_STATUSES as readonly string[]).includes(r.status)) c[r.status as keyof Counts]++;
    else c.other++;
    if (r.status === "fail" && r.severity === "high") c.high_fail++;
  }
  return c;
}

// One result per check id (the first), for the per-check tables.
export function byCheck(results: Result[]): Map<string, Result> {
  const m = new Map<string, Result>();
  for (const r of results) if (!m.has(r.id)) m.set(r.id, r);
  return m;
}
