import { reportAuth } from "./auth";
import { config, type Env } from "./env";
import { byCheck, countResults, parseReport, ReportError } from "./report";

export const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...headers },
  });

class TooLarge extends Error {}

async function readLimited(req: Request, max: number): Promise<string> {
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

export async function handleReport(req: Request, env: Env, now = new Date()): Promise<Response> {
  const auth = await reportAuth(req, env);
  if (auth === "unconfigured") return json({ error: "receiver has no REPORT_TOKEN set" }, 503);
  if (auth === "unauthorized") return json({ error: "unauthorized" }, 401, { "www-authenticate": "Bearer" });

  const cfg = config(env);
  let text: string;
  try {
    text = await readLimited(req, cfg.maxReportBytes);
  } catch (e) {
    if (e instanceof TooLarge) return json({ error: `report is larger than ${cfg.maxReportBytes} bytes` }, 413);
    throw e;
  }
  let rep;
  try {
    rep = parseReport(JSON.parse(text));
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
    db.prepare("SELECT email, hostname, silent_alerted_at, last_seen FROM machines WHERE install_id = ?")
      .bind(id)
      .first<{ email: string; hostname: string; silent_alerted_at: string | null; last_seen: string }>(),
    db.prepare("SELECT check_id, status, severity, since FROM checks WHERE install_id = ?").bind(id).all<PrevCheck>(),
  ]);
  if (!prevMachine) {
    const n = await db.prepare("SELECT COUNT(*) AS n FROM machines").first<number>("n");
    if ((n ?? 0) >= cfg.maxMachines) return json({ error: "machine limit reached" }, 403);
  }

  const counts = countResults(rep.results);
  const prev = new Map(prevChecks.results.map((c) => [c.check_id, c]));
  const current = byCheck(rep.results);
  const stmts: D1PreparedStatement[] = [];

  stmts.push(
    db.prepare(
      `INSERT INTO machines (install_id, email, hostname, os, arch, version, policy, first_seen, last_seen, report_time,
         fail, high_fail, error, warn, waived, pass, skip, other, report, silent_alerted_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, NULL)
       ON CONFLICT (install_id) DO UPDATE SET email = ?2, hostname = ?3, os = ?4, arch = ?5, version = ?6,
         policy = ?7, last_seen = ?8, report_time = ?9, fail = ?10, high_fail = ?11, error = ?12, warn = ?13,
         waived = ?14, pass = ?15, skip = ?16, other = ?17, report = ?18, silent_alerted_at = NULL`,
    ).bind(
      id, rep.email, rep.host.hostname, rep.host.os, rep.host.arch, rep.version, rep.policy, ts, rep.time,
      counts.fail, counts.high_fail, counts.error, counts.warn, counts.waived, counts.pass, counts.skip, counts.other,
      text,
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
  if (prevMachine?.silent_alerted_at) {
    stmts.push(insAlert.bind("back", id, "", JSON.stringify({ ...who, last_seen: prevMachine.last_seen }), ts));
  }

  stmts.push(
    db.prepare(
      `INSERT INTO reports (install_id, received_at, version, fail, warn, error, waived, statuses)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(id, ts, rep.version, counts.fail, counts.warn, counts.error, counts.waived, JSON.stringify(statuses)),
  );
  stmts.push(
    db.prepare(
      `DELETE FROM reports WHERE install_id = ?1 AND id <= (
         SELECT id FROM reports WHERE install_id = ?1 ORDER BY id DESC LIMIT 1 OFFSET ?2)`,
    ).bind(id, cfg.historyPerMachine),
  );

  await db.batch(stmts); // one transaction
  return json({ ok: true, fail: counts.fail, warn: counts.warn });
}
