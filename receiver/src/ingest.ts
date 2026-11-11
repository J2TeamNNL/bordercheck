import { postWebhook, type Send, sendPending, URGENT_ALERTS } from "./alerts";
import { bearer } from "./auth";
import { type Enrollment, machineByToken } from "./enroll";
import { config, DAY, type Env } from "./env";
import { geoFromCf, parseGeo, publicIP } from "./geo";
import { byCheck, countResults, parseReport, ReportError } from "./report";
import { newLinkId, sha256hex } from "./tokens";

export const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...headers },
  });

export class TooLarge extends Error {}

export async function readLimited(req: Request, max: number): Promise<string> {
  const len = Number(req.headers.get("content-length") ?? "0");
  if (len > max) throw new TooLarge();
  if (!req.body) return "";
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      throw new TooLarge();
    }
    chunks.push(value);
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder().decode(buf);
}

interface PrevCheck {
  check_id: string;
  status: string;
  severity: string;
  since: string;
}

// Live report links kept per machine: a few, so a link opened just as the
// next report lands still works.
const LINKS_PER_MACHINE = 3;

// handleReport takes a report. The bearer must be an enrolled machine's token
// (from /enroll); install_id and email come from its enrollment and whatever
// the body says is ignored. cf is request.cf, passed separately so tests can
// supply it.
export interface IngestOptions {
  // ctx.waitUntil, so the webhook is called after the response; without it
  // the report waits for the webhook (at most its 10-second timeout).
  waitUntil?: (p: Promise<unknown>) => void;
  send?: Send; // tests
}

export async function handleReport(
  req: Request,
  env: Env,
  now = new Date(),
  cf: unknown = (req as { cf?: unknown }).cf,
  opts: IngestOptions = {},
): Promise<Response> {
  const cfg = config(env);
  const machine: Enrollment | null = await machineByToken(env, bearer(req));
  if (!machine) return json({ error: "unauthorized" }, 401, { "www-authenticate": "Bearer" });
  if (machine.revoked_at) return json({ error: "revoked" }, 401, { "www-authenticate": "Bearer" });

  let text: string;
  try {
    text = await readLimited(req, cfg.maxReportBytes);
  } catch (e) {
    if (e instanceof TooLarge) return json({ error: `report is larger than ${cfg.maxReportBytes} bytes` }, 413);
    throw e;
  }
  let raw: unknown;
  let rep;
  try {
    raw = JSON.parse(text);
    if (raw && typeof raw === "object" && !Array.isArray(raw)) {
      const o = raw as Record<string, unknown>;
      o.install_id = machine.install_id;
      o.email = machine.email;
    }
    rep = parseReport(raw);
  } catch (e) {
    if (e instanceof SyntaxError) return json({ error: "body is not JSON" }, 400);
    if (e instanceof ReportError) return json({ error: e.message }, 400);
    throw e;
  }

  if (cfg.emailDomains.length) {
    const domain = rep.email.split("@")[1] ?? "";
    if (!cfg.emailDomains.includes(domain)) return json({ error: "email is not in an allowed domain" }, 403);
  }

  const ts = now.toISOString();
  const db = env.DB;
  const id = rep.installId;
  const [prevMachine, prevChecks] = await Promise.all([
    db.prepare("SELECT email, hostname, silent_alerted_at, last_seen, geo, compromised_since FROM machines WHERE install_id = ?")
      .bind(id)
      .first<{ email: string; hostname: string; silent_alerted_at: string | null; last_seen: string; geo: string; compromised_since: string | null }>(),
    db.prepare("SELECT check_id, status, severity, since FROM checks WHERE install_id = ?").bind(id).all<PrevCheck>(),
  ]);
  if (!prevMachine) {
    const n = await db.prepare("SELECT COUNT(*) AS n FROM machines").first<number>("n");
    if ((n ?? 0) >= cfg.maxMachines) return json({ error: "machine limit reached" }, 403);
  }

  // Where it came from. Cloudflare's view of the connection, and what the
  // machine says about itself, each only if collection is on.
  const ip = cfg.storeIp ? publicIP(req) : "";
  const geo = cfg.storeGeo ? geoFromCf(cf) : null;
  const localIps = cfg.storeIp ? rep.localIps : [];
  const devLoc = cfg.storeGeo ? rep.location : null;
  const geoJson = geo ? JSON.stringify(geo) : "";
  const devJson = devLoc ? JSON.stringify(devLoc) : "";
  const ipsJson = localIps.length ? JSON.stringify(localIps) : "";

  // Store the report as interpreted: identity from the token, and personal
  // fields only as validated and only when collected.
  const stored = raw as Record<string, unknown>;
  if (stored.host && typeof stored.host === "object" && !Array.isArray(stored.host)) {
    const h = stored.host as Record<string, unknown>;
    if (localIps.length) h.ips = localIps;
    else delete h.ips;
  }
  if (devLoc) stored.location = devLoc;
  else delete stored.location;
  const storedText = JSON.stringify(stored);

  const counts = countResults(rep.results);
  const prev = new Map(prevChecks.results.map((c) => [c.check_id, c]));
  const current = byCheck(rep.results);
  const stmts: D1PreparedStatement[] = [];
  // A machine is compromised while its latest report says so; the episode
  // starts with the first such report and ends with the first that does not.
  const wasCompromised = prevMachine?.compromised_since ?? null;
  const compromisedSince = rep.compromised ? wasCompromised ?? ts : null;

  stmts.push(
    db.prepare(
      `INSERT INTO machines (install_id, email, hostname, os, arch, version, policy, first_seen, last_seen, report_time,
         fail, high_fail, error, warn, waived, pass, skip, other, report, silent_alerted_at,
         public_ip, geo, local_ips, device_location, compromised_since)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, NULL, ?19, ?20, ?21, ?22, ?23)
       ON CONFLICT (install_id) DO UPDATE SET email = ?2, hostname = ?3, os = ?4, arch = ?5, version = ?6,
         policy = ?7, last_seen = ?8, report_time = ?9, fail = ?10, high_fail = ?11, error = ?12, warn = ?13,
         waived = ?14, pass = ?15, skip = ?16, other = ?17, report = ?18, silent_alerted_at = NULL,
         public_ip = ?19, geo = ?20, local_ips = ?21, device_location = ?22, compromised_since = ?23`,
    ).bind(
      id, rep.email, rep.host.hostname, rep.host.os, rep.host.arch, rep.version, rep.policy, ts, rep.time,
      counts.fail, counts.high_fail, counts.error, counts.warn, counts.waived, counts.pass, counts.skip, counts.other,
      storedText, ip, geoJson, ipsJson, devJson, compromisedSince,
    ),
  );

  stmts.push(db.prepare("DELETE FROM checks WHERE install_id = ?").bind(id));
  const statuses: Record<string, string> = {};
  const insCheck = db.prepare(
    "INSERT INTO checks (install_id, check_id, status, severity, title, since) VALUES (?, ?, ?, ?, ?, ?)",
  );
  const insAlert = db.prepare(
    "INSERT INTO alerts (kind, install_id, check_id, detail, created_at) VALUES (?, ?, ?, ?, ?)",
  );
  const who = { email: rep.email, hostname: rep.host.hostname };
  for (const [checkId, r] of current) {
    statuses[checkId] = r.status;
    const p = prev.get(checkId);
    const since = p && p.status === r.status ? p.since : ts;
    stmts.push(insCheck.bind(id, checkId, r.status, r.severity, r.title, since));
    const isHigh = r.status === "fail" && r.severity === "high";
    const wasHigh = p?.status === "fail" && p.severity === "high";
    if (isHigh && !wasHigh) {
      stmts.push(insAlert.bind("high_fail", id, checkId, JSON.stringify({ ...who, title: r.title, summary: r.summary }), ts));
    }
  }
  // Raised once per episode, and delivered to the webhook right after this
  // report is stored rather than by the hourly cron (see below).
  let urgent = false;
  if (rep.compromised && !wasCompromised) {
    const titles = rep.compromiseChecks.map((c) => current.get(c)?.title || c);
    stmts.push(insAlert.bind("compromised", id, "", JSON.stringify({ ...who, checks: rep.compromiseChecks.join(", "), titles: titles.join(", ") }), ts));
    urgent = true;
  } else if (!rep.compromised && wasCompromised) {
    stmts.push(insAlert.bind("compromise_cleared", id, "", JSON.stringify({ ...who, since: wasCompromised }), ts));
    urgent = true;
  }
  if (prevMachine?.silent_alerted_at) {
    stmts.push(insAlert.bind("back", id, "", JSON.stringify({ ...who, last_seen: prevMachine.last_seen }), ts));
  }

  // Opt-in: a machine reports from a country none of its kept history shows.
  // Only the country codes go in the alert, never the IP or coordinates.
  if (cfg.alertNewCountry && geo?.country && prevMachine) {
    const seen = await db
      .prepare(
        `SELECT COUNT(*) AS n, SUM(json_extract(geo, '$.country') = ?2) AS same
         FROM reports WHERE install_id = ?1 AND geo != '' AND json_valid(geo)`,
      )
      .bind(id, geo.country)
      .first<{ n: number; same: number | null }>();
    const prevCountry = parseGeo(prevMachine.geo)?.country;
    if ((seen?.n ?? 0) > 0 && !(seen?.same ?? 0)) {
      stmts.push(insAlert.bind("new_country", id, "", JSON.stringify({ ...who, from: prevCountry ?? "", to: geo.country }), ts));
    }
  }

  stmts.push(
    db.prepare(
      `INSERT INTO reports (install_id, received_at, version, fail, warn, error, waived, statuses, ip, geo, device_location, compromised)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(id, ts, rep.version, counts.fail, counts.warn, counts.error, counts.waived, JSON.stringify(statuses), ip, geoJson, devJson, rep.compromised ? 1 : 0),
  );
  stmts.push(
    db.prepare(
      `DELETE FROM reports WHERE install_id = ?1 AND id <= (
         SELECT id FROM reports WHERE install_id = ?1 ORDER BY id DESC LIMIT 1 OFFSET ?2)`,
    ).bind(id, cfg.historyPerMachine),
  );

  // A login-free link to this machine's latest results (see selfreport.ts).
  // Only its hash is stored; the id is returned here and nowhere else.
  let reportUrl: string | undefined;
  if (cfg.reportLinks) {
    const linkId = newLinkId();
    stmts.push(
      db.prepare("INSERT INTO report_links (link_hash, install_id, created_at, expires_at) VALUES (?, ?, ?, ?)").bind(
        await sha256hex(linkId),
        id,
        ts,
        new Date(now.getTime() + cfg.reportLinkDays * DAY).toISOString(),
      ),
      db.prepare(
        `DELETE FROM report_links WHERE install_id = ?1 AND id NOT IN (
           SELECT id FROM report_links WHERE install_id = ?1 ORDER BY id DESC LIMIT ?2)`,
      ).bind(id, LINKS_PER_MACHINE),
    );
    reportUrl = `${new URL(req.url).origin}/r/${linkId}`;
  }

  await db.batch(stmts); // one transaction

  // A compromise (or its end) goes to the webhook now, not at the next cron.
  // After the response when the runtime lets work outlive it; a failure
  // leaves the alert pending, and the cron tries again.
  if (urgent) {
    const deliver = sendPending(env, now, opts.send ?? postWebhook, { installId: id, kinds: URGENT_ALERTS }).then(
      (r) => {
        if (r.failed) console.error("alerts:", r.failed);
      },
      (e) => console.error("alerts:", (e as Error).message),
    );
    if (opts.waitUntil) opts.waitUntil(deliver);
    else await deliver;
  }
  return json({ ok: true, fail: counts.fail, warn: counts.warn, ...(reportUrl ? { report_url: reportUrl } : {}) });
}
