// The hourly cron: raise "silent" alerts, send pending alerts and the digest to
// the webhook, prune old history. Alerts are raised once per condition (a
// check newly failing with high severity, a machine going silent) and stay
// pending until the webhook accepts them, so a webhook outage delays alerts
// rather than losing or repeating them.

import { config, DAY, type Env } from "./env";

export type Format = "discord" | "slack" | "json";

export function webhookFormat(env: Env): Format {
  const f = (env.ALERT_WEBHOOK_FORMAT ?? "").toLowerCase();
  if (f === "discord" || f === "slack" || f === "json") return f;
  try {
    const u = new URL(env.ALERT_WEBHOOK_URL ?? "");
    if (/(^|\.)(discord|discordapp)\.com$/.test(u.hostname) && u.pathname.startsWith("/api/webhooks/")) return "discord";
    if (u.hostname === "hooks.slack.com") return "slack";
  } catch {
    // fall through
  }
  return "json";
}

// Report fields are attacker-controlled. In chat they go inside inline code,
// which shows text literally: no mentions, links or formatting. Backticks and
// newlines are removed so the value cannot close the code span.
export function lit(s: unknown, max = 80): string {
  let v = String(s ?? "").replace(/[`\r\n\u0000-\u001f\u007f]/g, " ").trim();
  if (v.length > max) v = v.slice(0, max) + "…";
  return v ? "`" + v + "`" : "`?`";
}

// Slack treats &, < and > as control characters, even inside code.
function slackEscape(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export interface AlertRow {
  id: number;
  kind: string;
  install_id: string;
  check_id: string;
  detail: string;
  created_at: string;
}

function detail(a: AlertRow): Record<string, string> {
  try {
    return JSON.parse(a.detail) ?? {};
  } catch {
    return {};
  }
}

function machineURL(env: Env, id: string): string {
  const base = (env.DASHBOARD_URL ?? "").replace(/\/+$/, "");
  return base ? `${base}/admin/machine/${encodeURIComponent(id)}` : "";
}

export function alertLine(env: Env, a: AlertRow): string {
  const d = detail(a);
  const who = `${lit(d.email || "(no email)", 60)} on ${lit(d.hostname, 60)}`;
  let line: string;
  switch (a.kind) {
    case "high_fail":
      line = `🔴 ${who}: high-severity fail ${lit(a.check_id, 40)} ${lit(d.title)}`;
      break;
    case "silent":
      line = `🔕 ${who}: no report since ${d.last_seen?.slice(0, 10) ?? "?"}`;
      break;
    case "back":
      line = `🔔 ${who}: reporting again (was silent since ${d.last_seen?.slice(0, 10) ?? "?"})`;
      break;
    default:
      line = `${lit(a.kind)} ${who}`;
  }
  const url = machineURL(env, a.install_id);
  return url ? `${line} ${url}` : line;
}

const LIMIT: Record<Format, number> = { discord: 1900, slack: 3500, json: 3500 };

// chunk packs lines into messages under the platform's size limit.
export function chunk(lines: string[], limit: number): string[][] {
  const out: string[][] = [];
  let cur: string[] = [];
  let size = 0;
  for (const l of lines) {
    const line = l.length > limit - 50 ? l.slice(0, limit - 50) + "…" : l;
    if (cur.length && size + line.length + 1 > limit - 50) {
      out.push(cur);
      cur = [];
      size = 0;
    }
    cur.push(line);
    size += line.length + 1;
  }
  if (cur.length) out.push(cur);
  return out;
}

export function payload(format: Format, text: string, extra: Record<string, unknown> = {}): unknown {
  switch (format) {
    case "discord":
      return { username: "bordercheck", content: text, allowed_mentions: { parse: [] } };
    case "slack":
      return { text: slackEscape(text) };
    default:
      return { text, ...extra };
  }
}

export type Send = (url: string, body: unknown) => Promise<void>;

export const postWebhook: Send = async (url, body) => {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`webhook answered ${res.status}`);
};

const MAX_MESSAGES_PER_RUN = 10;
const GIVE_UP_AFTER = 7 * DAY;

export async function raiseSilent(env: Env, now: Date): Promise<number> {
  const before = new Date(now.getTime() - config(env).silentDays * DAY).toISOString();
  const ts = now.toISOString();
  const rows = await env.DB.prepare(
    "SELECT install_id, email, hostname, last_seen FROM machines WHERE last_seen < ? AND silent_alerted_at IS NULL LIMIT 500",
  )
    .bind(before)
    .all<{ install_id: string; email: string; hostname: string; last_seen: string }>();
  if (!rows.results.length) return 0;
  const stmts = rows.results.flatMap((m) => [
    env.DB.prepare("INSERT INTO alerts (kind, install_id, detail, created_at) VALUES ('silent', ?, ?, ?)").bind(
      m.install_id,
      JSON.stringify({ email: m.email, hostname: m.hostname, last_seen: m.last_seen }),
      ts,
    ),
    env.DB.prepare("UPDATE machines SET silent_alerted_at = ? WHERE install_id = ?").bind(ts, m.install_id),
  ]);
  await env.DB.batch(stmts);
  return rows.results.length;
}

async function markDelivered(env: Env, ids: number[], ts: string, delivery: string) {
  if (!ids.length) return;
  // D1 allows 100 bound parameters per statement.
  for (let i = 0; i < ids.length; i += 90) {
    const part = ids.slice(i, i + 90);
    await env.DB.prepare(
      `UPDATE alerts SET sent_at = ?, delivery = ? WHERE id IN (${part.map(() => "?").join(",")})`,
    )
      .bind(ts, delivery, ...part)
      .run();
  }
}

export async function sendPending(env: Env, now: Date, send: Send = postWebhook): Promise<{ sent: number; failed: string | null }> {
  const ts = now.toISOString();
  const pending = await env.DB.prepare(
    "SELECT id, kind, install_id, check_id, detail, created_at FROM alerts WHERE sent_at IS NULL ORDER BY id LIMIT 500",
  ).all<AlertRow>();
  const rows = pending.results;
  if (!rows.length) return { sent: 0, failed: null };
  if (!env.ALERT_WEBHOOK_URL) {
    await markDelivered(env, rows.map((r) => r.id), ts, "no webhook");
    return { sent: 0, failed: null };
  }
  const stale = rows.filter((r) => now.getTime() - Date.parse(r.created_at) > GIVE_UP_AFTER);
  await markDelivered(env, stale.map((r) => r.id), ts, "dropped: webhook failed for 7 days");
  const live = rows.filter((r) => !stale.includes(r));

  const format = webhookFormat(env);
  const lines = live.map((a) => ({ id: a.id, text: alertLine(env, a) }));
  const groups = chunk(lines.map((l) => l.text), LIMIT[format]);
  let sent = 0;
  let offset = 0;
  for (const [i, g] of groups.entries()) {
    if (i >= MAX_MESSAGES_PER_RUN) break; // the rest go next hour
    const ids = lines.slice(offset, offset + g.length).map((l) => l.id);
    const head = i === 0 ? `**bordercheck**: ${live.length} new alert${live.length === 1 ? "" : "s"}\n` : "";
    const text = (format === "slack" ? head.replace(/\*\*/g, "*") : format === "json" ? head.replace(/\*\*/g, "") : head) + g.join("\n");
    try {
      await send(env.ALERT_WEBHOOK_URL, payload(format, text, { alerts: live.filter((a) => ids.includes(a.id)).map(publicAlert) }));
    } catch (e) {
      return { sent, failed: (e as Error).message };
    }
    await markDelivered(env, ids, ts, "sent");
    sent += ids.length;
    offset += g.length;
  }
  return { sent, failed: null };
}

function publicAlert(a: AlertRow) {
  return { kind: a.kind, install_id: a.install_id, check_id: a.check_id || undefined, created_at: a.created_at, ...detail(a) };
}

export async function digestText(env: Env, now: Date, format: Format): Promise<string> {
  const silentBefore = new Date(now.getTime() - config(env).silentDays * DAY).toISOString();
  const t = await env.DB.prepare(
    "SELECT COUNT(*) AS n, SUM(fail > 0) AS failing, SUM(high_fail > 0) AS high, SUM(last_seen < ?) AS silent FROM machines",
  )
    .bind(silentBefore)
    .first<{ n: number; failing: number | null; high: number | null; silent: number | null }>();
  const top = await env.DB.prepare(
    "SELECT check_id, COUNT(*) AS n FROM checks WHERE status = 'fail' GROUP BY check_id ORDER BY n DESC, check_id LIMIT 5",
  ).all<{ check_id: string; n: number }>();
  const bold = format === "discord" ? "**" : format === "slack" ? "*" : "";
  const lines = [
    `${bold}bordercheck digest${bold}: ${t?.n ?? 0} machines, ${t?.failing ?? 0} non-compliant (${t?.high ?? 0} with a high-severity fail), ${t?.silent ?? 0} silent for more than ${config(env).silentDays} days`,
  ];
  if (top.results.length) lines.push("Most failing: " + top.results.map((r) => `${lit(r.check_id, 40)} ${r.n}`).join(", "));
  const base = (env.DASHBOARD_URL ?? "").replace(/\/+$/, "");
  if (base) lines.push(`${base}/admin?filter=failing`);
  return lines.join("\n");
}

async function maybeDigest(env: Env, now: Date, send: Send): Promise<boolean> {
  const hours = config(env).digestHours;
  if (!hours || !env.ALERT_WEBHOOK_URL) return false;
  const last = await env.DB.prepare("SELECT value FROM meta WHERE key = 'last_digest'").first<string>("value");
  // Allow 5 minutes of slack so an hourly cron does not drift a whole run.
  if (last && now.getTime() - Date.parse(last) < hours * 3600_000 - 5 * 60_000) return false;
  const format = webhookFormat(env);
  await send(env.ALERT_WEBHOOK_URL, payload(format, await digestText(env, now, format)));
  await env.DB.prepare(
    "INSERT INTO meta (key, value) VALUES ('last_digest', ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
  )
    .bind(now.toISOString())
    .run();
  return true;
}

export async function prune(env: Env, now: Date): Promise<void> {
  const before = new Date(now.getTime() - config(env).historyDays * DAY).toISOString();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM reports WHERE received_at < ?").bind(before),
    env.DB.prepare("DELETE FROM alerts WHERE created_at < ? AND sent_at IS NOT NULL").bind(before),
  ]);
}

export async function runCron(env: Env, now: Date, send: Send = postWebhook) {
  const silent = await raiseSilent(env, now);
  const result = await sendPending(env, now, send);
  let digest = false;
  try {
    digest = await maybeDigest(env, now, send);
  } catch (e) {
    console.error("digest:", (e as Error).message);
  }
  await prune(env, now);
  if (result.failed) console.error("alerts:", result.failed);
  return { silent, ...result, digest };
}
