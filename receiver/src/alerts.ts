// The hourly cron: raise "silent" alerts, send pending alerts and the digest to
// the webhook, prune old history. Alerts are raised once per condition (a
// check newly failing with high severity, a machine going silent) and stay
// pending until the webhook accepts them, so a webhook outage delays alerts
// rather than losing or repeating them. A machine that starts or stops
// reporting signs of compromise raises an alert that ingest.ts delivers at
// once (URGENT_ALERTS); the cron only retries it if that failed.

import { config, DAY, type Env } from "./env";
import { pruneRateLimits } from "./ratelimit";

export type Format = "discord" | "slack" | "telegram" | "json";

// One place alerts go. ALERT_WEBHOOK_URL holds one URL or several (separated by
// commas, spaces or new lines); each one's format comes from its address.
export interface Hook {
  url: string; // where to POST; for Telegram without chat_id, which goes in the body
  format: Format;
  id: string; // a short, stable name for the URL, kept in alerts.delivered_to
  chatId?: string; // Telegram: the chat to post in
}

function detected(u: URL): Format | null {
  if (/(^|\.)(discord|discordapp)\.com$/.test(u.hostname) && u.pathname.startsWith("/api/webhooks/")) return "discord";
  if (u.hostname === "hooks.slack.com") return "slack";
  if (u.hostname === "api.telegram.org" && u.pathname.startsWith("/bot")) return "telegram";
  return null;
}

// FNV-1a: only tells the configured URLs apart; nothing secret depends on it.
function hookId(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 0x01000193) >>> 0;
  return h.toString(16).padStart(8, "0");
}

export function webhooks(env: Env): Hook[] {
  const forced = (env.ALERT_WEBHOOK_FORMAT ?? "").toLowerCase();
  const out: Hook[] = [];
  for (const raw of (env.ALERT_WEBHOOK_URL ?? "").split(/[\s,]+/)) {
    let u: URL;
    try {
      u = new URL(raw);
    } catch {
      continue;
    }
    if (u.protocol !== "https:" && u.protocol !== "http:") continue;
    // ALERT_WEBHOOK_FORMAT names the format of addresses it can't tell by itself.
    const format: Format =
      detected(u) ?? (forced === "discord" || forced === "slack" || forced === "telegram" || forced === "json" ? forced : "json");
    const hook: Hook = { url: u.toString(), format, id: hookId(u.toString()) };
    if (format === "telegram") {
      hook.chatId = u.searchParams.get("chat_id") || (env.ALERT_TELEGRAM_CHAT_ID ?? "").trim() || undefined;
      u.searchParams.delete("chat_id");
      if (/^\/bot[^/]+\/?$/.test(u.pathname)) u.pathname = u.pathname.replace(/\/?$/, "/sendMessage");
      hook.url = u.toString();
    }
    if (!out.some((h) => h.id === hook.id)) out.push(hook);
  }
  return out;
}

// webhookFormat is the first webhook's format (json when there is none).
export function webhookFormat(env: Env): Format {
  return webhooks(env)[0]?.format ?? "json";
}

// Bold for the message's first line, as each platform writes it; Telegram and
// JSON get plain text.
function bold(format: Format, s: string): string {
  return format === "discord" ? `**${s}**` : format === "slack" ? `*${s}*` : s;
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
  delivered_to?: string;
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
    case "compromised":
      // Check IDs only: which item it is stays on the machine page.
      line = `🚨 ${who}: SIGNS OF COMPROMISE in ${(d.checks ?? "").split(", ").filter(Boolean).slice(0, 10).map((c) => lit(c, 40)).join(", ") || "`?`"}. Treat the machine as compromised: tell its user to stop using it for work, and look at it before anything is removed.`;
      break;
    case "compromise_cleared":
      line = `✅ ${who}: no longer reports signs of compromise (reported since ${d.since?.slice(0, 10) ?? "?"}). Make sure this was IT's doing.`;
      break;
    case "new_country":
      // Country codes only: no IP or coordinates in webhooks.
      line = `🌍 ${who}: reporting from a new country ${lit(d.to, 8)}${d.from ? ` (was ${lit(d.from, 8)})` : ""}`;
      break;
    default:
      line = `${lit(a.kind)} ${who}`;
  }
  const url = machineURL(env, a.install_id);
  return url ? `${line} ${url}` : line;
}

const LIMIT: Record<Format, number> = { discord: 1900, slack: 3500, telegram: 3500, json: 3500 };

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

export function payload(format: Format, text: string, extra: Record<string, unknown> = {}, chatId?: string): unknown {
  switch (format) {
    case "discord":
      return { username: "BorderCheck", content: text, allowed_mentions: { parse: [] } };
    case "slack":
      return { text: slackEscape(text) };
    case "telegram":
      // No parse_mode: Telegram shows the text as it is, so nothing from a report can format or link.
      return { chat_id: chatId, text, disable_web_page_preview: true };
    default:
      return { text, ...extra };
  }
}

export type Send = (url: string, body: unknown) => Promise<void>;

// The error never carries the URL: a Telegram one holds the bot's token.
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
    // A revoked machine is expected to go quiet.
    `SELECT install_id, email, hostname, last_seen FROM machines m WHERE last_seen < ? AND silent_alerted_at IS NULL
       AND NOT EXISTS (SELECT 1 FROM enrollments e WHERE e.install_id = m.install_id AND e.revoked_at IS NOT NULL) LIMIT 500`,
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

// Alerts that go to the webhook as soon as the report that raised them is
// stored (ingest.ts), not at the next hourly cron.
export const URGENT_ALERTS = ["compromised", "compromise_cleared"];

// sendPending delivers pending alerts: every one (the cron), or only one
// machine's alerts of some kinds (ingest, for URGENT_ALERTS).
export async function sendPending(
  env: Env,
  now: Date,
  send: Send = postWebhook,
  only?: { installId: string; kinds: string[] },
): Promise<{ sent: number; failed: string | null }> {
  const ts = now.toISOString();
  const pending = await (only
    ? env.DB.prepare(
        `SELECT id, kind, install_id, check_id, detail, created_at, delivered_to FROM alerts
         WHERE sent_at IS NULL AND install_id = ? AND kind IN (${only.kinds.map(() => "?").join(",")}) ORDER BY id LIMIT 500`,
      ).bind(only.installId, ...only.kinds)
    : env.DB.prepare("SELECT id, kind, install_id, check_id, detail, created_at, delivered_to FROM alerts WHERE sent_at IS NULL ORDER BY id LIMIT 500")
  ).all<AlertRow>();
  const rows = pending.results;
  if (!rows.length) return { sent: 0, failed: null };
  const hooks = webhooks(env);
  if (!hooks.length) {
    await markDelivered(env, rows.map((r) => r.id), ts, "no webhook");
    return { sent: 0, failed: null };
  }
  const stale = rows.filter((r) => now.getTime() - Date.parse(r.created_at) > GIVE_UP_AFTER);
  await markDelivered(env, stale.map((r) => r.id), ts, "dropped: webhook failed for 7 days");
  const live = rows.filter((r) => !stale.includes(r));
  const took = new Map(live.map((a) => [a.id, new Set((a.delivered_to ?? "").split(",").filter(Boolean))]));

  // Each webhook gets the alerts it has not taken yet; one that fails does not
  // hold up the others, and they do not get those alerts again.
  const failures: string[] = [];
  for (const [n, h] of hooks.entries()) {
    const todo = live.filter((a) => !took.get(a.id)!.has(h.id));
    if (!todo.length) continue;
    const where = hooks.length > 1 ? `${h.format} webhook ${n + 1}` : `${h.format} webhook`;
    if (h.format === "telegram" && !h.chatId) {
      failures.push(`${where}: no chat_id (add ?chat_id= to its URL or set ALERT_TELEGRAM_CHAT_ID)`);
      continue;
    }
    const lines = todo.map((a) => ({ id: a.id, text: alertLine(env, a) }));
    const groups = chunk(lines.map((l) => l.text), LIMIT[h.format]);
    let offset = 0;
    for (const [i, g] of groups.entries()) {
      if (i >= MAX_MESSAGES_PER_RUN) break; // the rest go next hour
      const ids = lines.slice(offset, offset + g.length).map((l) => l.id);
      const head = i === 0 ? bold(h.format, "BorderCheck") + `: ${todo.length} new alert${todo.length === 1 ? "" : "s"}\n` : "";
      try {
        await send(h.url, payload(h.format, head + g.join("\n"), { alerts: todo.filter((a) => ids.includes(a.id)).map(publicAlert) }, h.chatId));
      } catch (e) {
        failures.push(`${where}: ${(e as Error).message}`);
        break;
      }
      await addDelivered(env, ids, h.id);
      for (const id of ids) took.get(id)!.add(h.id);
      offset += g.length;
    }
  }
  const done = live.filter((a) => hooks.every((h) => took.get(a.id)!.has(h.id))).map((a) => a.id);
  await markDelivered(env, done, ts, "sent");
  return { sent: done.length, failed: failures.length ? failures.join("; ") : null };
}

async function addDelivered(env: Env, ids: number[], hook: string) {
  for (let i = 0; i < ids.length; i += 90) {
    const part = ids.slice(i, i + 90);
    await env.DB.prepare(`UPDATE alerts SET delivered_to = delivered_to || ? WHERE id IN (${part.map(() => "?").join(",")})`)
      .bind(hook + ",", ...part)
      .run();
  }
}

function publicAlert(a: AlertRow) {
  return { kind: a.kind, install_id: a.install_id, check_id: a.check_id || undefined, created_at: a.created_at, ...detail(a) };
}

export async function digestText(env: Env, now: Date, format: Format): Promise<string> {
  const silentBefore = new Date(now.getTime() - config(env).silentDays * DAY).toISOString();
  const t = await env.DB.prepare(
    `SELECT COUNT(*) AS n, SUM(fail > 0) AS failing, SUM(high_fail > 0) AS high, SUM(last_seen < ?) AS silent,
            SUM(compromised_since IS NOT NULL) AS compromised FROM machines`,
  )
    .bind(silentBefore)
    .first<{ n: number; failing: number | null; high: number | null; silent: number | null; compromised: number | null }>();
  const top = await env.DB.prepare(
    "SELECT check_id, COUNT(*) AS n FROM checks WHERE status = 'fail' GROUP BY check_id ORDER BY n DESC, check_id LIMIT 5",
  ).all<{ check_id: string; n: number }>();
  const lines = [
    `${bold(format, "BorderCheck digest")}: ${t?.n ?? 0} machines, ${t?.failing ?? 0} non-compliant (${t?.high ?? 0} with a high-severity fail), ${t?.silent ?? 0} silent for more than ${config(env).silentDays} days`,
  ];
  if (t?.compromised) lines.push(`🚨 ${t.compromised} reporting signs of compromise`);
  if (top.results.length) lines.push("Most failing: " + top.results.map((r) => `${lit(r.check_id, 40)} ${r.n}`).join(", "));
  const base = (env.DASHBOARD_URL ?? "").replace(/\/+$/, "");
  if (base) lines.push(`${base}/admin?filter=failing`);
  return lines.join("\n");
}

async function maybeDigest(env: Env, now: Date, send: Send): Promise<boolean> {
  const hours = config(env).digestHours;
  const hooks = webhooks(env);
  if (!hours || !hooks.length) return false;
  const last = await env.DB.prepare("SELECT value FROM meta WHERE key = 'last_digest'").first<string>("value");
  // Allow 5 minutes of slack so an hourly cron does not drift a whole run.
  if (last && now.getTime() - Date.parse(last) < hours * 3600_000 - 5 * 60_000) return false;
  // Sent to every webhook; counted as done when at least one took it, so a
  // broken webhook does not make the others get the digest every hour.
  const errors: string[] = [];
  for (const h of hooks) {
    if (h.format === "telegram" && !h.chatId) continue;
    try {
      await send(h.url, payload(h.format, await digestText(env, now, h.format), {}, h.chatId));
    } catch (e) {
      errors.push(`${h.format}: ${(e as Error).message}`);
    }
  }
  if (errors.length === hooks.length) throw new Error(errors.join("; "));
  if (errors.length) console.error("digest:", errors.join("; "));
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
    // A machine silent for longer than history is kept loses its IPs and locations too.
    env.DB.prepare(
      `UPDATE machines SET public_ip = '', geo = '', local_ips = '', device_location = '',
         report = CASE WHEN json_valid(report) THEN json_remove(report, '$.host.ips', '$.location') ELSE report END
       WHERE last_seen < ? AND (public_ip != '' OR geo != '' OR local_ips != '' OR device_location != '')`,
    ).bind(before),
    env.DB.prepare("DELETE FROM report_links WHERE expires_at < ?").bind(now.toISOString()),
    env.DB.prepare("DELETE FROM api_idempotency WHERE expires_at <= ?").bind(now.toISOString()),
  ]);
  await pruneRateLimits(env, now.getTime());
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
