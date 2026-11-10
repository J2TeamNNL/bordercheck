export interface Env {
  DB: D1Database;

  // Secrets (wrangler secret put NAME).
  REPORT_TOKEN?: string; // bearer token bordercheck sends with each report
  REPORT_TOKEN_PREVIOUS?: string; // also accepted, while rotating REPORT_TOKEN
  ADMIN_TOKEN?: string; // dashboard login for people without Cloudflare Access
  ALERT_WEBHOOK_URL?: string; // Discord or Slack incoming webhook, or any URL taking JSON
  POLICY_KEY?: string; // if set, GET /policies.json needs ?key=<POLICY_KEY>

  // Vars (wrangler.jsonc "vars").
  ACCESS_TEAM_DOMAIN?: string; // e.g. acme.cloudflareaccess.com
  ACCESS_AUD?: string; // the Access application's AUD tag
  DASHBOARD_URL?: string; // e.g. https://bordercheck.acme.com, for links in alerts
  ALLOWED_EMAIL_DOMAINS?: string; // comma-separated; reports from other emails are refused
  SILENT_DAYS?: string; // alert when a machine has not reported for this many days (default 7)
  DIGEST_HOURS?: string; // hours between digests; 0 or empty = no digest
  HISTORY_DAYS?: string; // keep history and alerts this long (default 180)
  HISTORY_PER_MACHINE?: string; // and at most this many reports per machine (default 500)
  MAX_REPORT_BYTES?: string; // default 262144
  MAX_MACHINES?: string; // refuse new install_ids beyond this (default 10000)
  ALERT_WEBHOOK_FORMAT?: string; // discord | slack | json; default: from the URL
}

export const MIN_TOKEN_LENGTH = 16;

export function num(v: string | undefined, def: number, min = 0): number {
  if (v === undefined || v.trim() === "") return def;
  const n = Number(v);
  return Number.isFinite(n) && n >= min ? n : def;
}

export const config = (env: Env) => ({
  silentDays: num(env.SILENT_DAYS, 7, 1),
  digestHours: num(env.DIGEST_HOURS, 0, 0),
  historyDays: num(env.HISTORY_DAYS, 180, 1),
  maxReportBytes: num(env.MAX_REPORT_BYTES, 256 * 1024, 1024),
  maxMachines: num(env.MAX_MACHINES, 10000, 1),
  historyPerMachine: num(env.HISTORY_PER_MACHINE, 500, 1),
  emailDomains: (env.ALLOWED_EMAIL_DOMAINS ?? "")
    .split(",")
    .map((d) => d.trim().toLowerCase().replace(/^@/, ""))
    .filter(Boolean),
});

export const DAY = 24 * 60 * 60 * 1000;
