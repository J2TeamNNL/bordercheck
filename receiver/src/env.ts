export interface Env {
  DB: D1Database;

  // Secrets (wrangler secret put NAME).
  REPORT_TOKEN?: string; // bearer token bordercheck sends with each report
  REPORT_TOKEN_PREVIOUS?: string; // also accepted, while rotating REPORT_TOKEN
  ADMIN_TOKEN?: string; // dashboard login for people without Cloudflare Access
  ALERT_WEBHOOK_URL?: string; // Discord or Slack incoming webhook, or any URL taking JSON
  POLICY_KEY?: string; // if set, GET /policies.json needs ?key=<POLICY_KEY>
  MCP_TOKEN?: string; // bearer token for the MCP server at /mcp: read and write tools
  MCP_READ_TOKEN?: string; // bearer token for the MCP server: read-only tools
  // Neither set (or both shorter than 16 characters): /mcp answers 404.

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

  // Enrollment portal.
  LEGACY_MODE?: string; // "on" (default): shared REPORT_TOKEN and /policies.json work; "off": only enrolled machines
  INVITE_DAYS?: string; // default lifetime of an invite (7)
  INSTALL_SH_URL?: string; // install script shown in invite commands (macOS/Linux)
  INSTALL_PS1_URL?: string; // and for Windows
  ENROLL_RATE_LIMIT?: string; // /enroll attempts per client IP per window (10)
  PAGE_RATE_LIMIT?: string; // /i/<code> and /r/<id> views per client IP per window (60)
  RATE_WINDOW_SECONDS?: string; // (600)
  MCP_RATE_LIMIT?: string; // /mcp requests per client IP per window (300)

  // Where reports come from. Personal data: see README "What is stored".
  STORE_PUBLIC_IP?: string; // "on" (default) | "off": public IP and the machine's local addresses
  STORE_GEO?: string; // "on" (default) | "off": Cloudflare's IP geolocation and device-reported position
  ALERT_NEW_COUNTRY?: string; // "on" | "off" (default): alert when a machine reports from a new country

  // Login-free links to a machine's own report.
  REPORT_LINKS?: string; // "on" (default) | "off"
  REPORT_LINK_DAYS?: string; // how long a link works (30)
}

export const DEFAULT_INSTALL_SH = "https://raw.githubusercontent.com/ptrinh/bordercheck/main/install.sh";
export const DEFAULT_INSTALL_PS1 = "https://raw.githubusercontent.com/ptrinh/bordercheck/main/install.ps1";

// flag reads an on/off switch; anything unrecognised keeps the default.
export function flag(v: string | undefined, def: boolean): boolean {
  const s = (v ?? "").trim().toLowerCase();
  if (["off", "false", "0", "no"].includes(s)) return false;
  if (["on", "true", "1", "yes"].includes(s)) return true;
  return def;
}

// Install-script URLs go into shell commands, so only plain https URLs are used.
function scriptURL(v: string | undefined, def: string): string {
  const s = (v ?? "").trim();
  return /^https:\/\/[A-Za-z0-9._~\/%:-]+$/.test(s) ? s : def;
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
  legacy: flag(env.LEGACY_MODE, true),
  inviteDays: num(env.INVITE_DAYS, 7, 1),
  installSh: scriptURL(env.INSTALL_SH_URL, DEFAULT_INSTALL_SH),
  installPs1: scriptURL(env.INSTALL_PS1_URL, DEFAULT_INSTALL_PS1),
  enrollRateLimit: num(env.ENROLL_RATE_LIMIT, 10, 1),
  pageRateLimit: num(env.PAGE_RATE_LIMIT, 60, 1),
  rateWindow: num(env.RATE_WINDOW_SECONDS, 600, 10),
  mcpRateLimit: num(env.MCP_RATE_LIMIT, 300, 1),
  storeIp: flag(env.STORE_PUBLIC_IP, true),
  storeGeo: flag(env.STORE_GEO, true),
  alertNewCountry: flag(env.ALERT_NEW_COUNTRY, false),
  reportLinks: flag(env.REPORT_LINKS, true),
  reportLinkDays: num(env.REPORT_LINK_DAYS, 30, 1),
});

export const DAY = 24 * 60 * 60 * 1000;
