// Cloudflare Zero Trust device posture: a "Custom service provider"
// integration (Cloudflare One > Integrations > Service providers > Custom).
// Cloudflare polls POST /posture/cloudflare with the devices its client (WARP)
// knows, and this answers a score from 0 to 100 for each, from BorderCheck's
// view of that machine. Access, Gateway network and HTTP policies then
// require a score ("Passed device posture checks"), so a machine that is not
// enrolled, fails a check, shows signs of compromise, has gone silent or was
// revoked loses access.
//
// Request:  {"devices": [{"device_id", "email", "serial_number", "mac_address", "virtual_ipv4", "hostname"}, …]}
//           (at most 1,000 per request)
// Response: {"result": {"<device_id>": {"s2s_id": "", "score": 0-100}, …}}, one entry per device asked about.
//
// Access: the path sits behind its own self-hosted Access application whose
// only policy is Service Auth with the service token given to the
// integration. Cloudflare then calls through Access, and this checks the
// Access JWT: signed by ACCESS_TEAM_DOMAIN's keys, for POSTURE_ACCESS_AUD, a
// service token (not a person), and if POSTURE_CLIENT_ID is set, that token.
// Unset POSTURE_ACCESS_AUD: 404 like any unknown path.
//
// Matching: by hardware serial number (the client sends it from v0.5.19);
// a device whose serial matches no machine is matched by email and short
// hostname instead. Several machines matching: the lowest score wins.
//
// Scores: 100 compliant; POSTURE_SCORE_ATTENTION (80) warnings or errors only;
// POSTURE_SCORE_FAILING (50) a check fails; 0 signs of compromise, silent for
// SILENT_DAYS, revoked, never reported, not enrolled, or unknown. So a policy
// "score >= 60" blocks failing machines, ">= 90" also those needing attention.

import { accessClaims } from "./auth";
import { config, type Env, num } from "./env";
import { json, readLimited, TooLarge } from "./ingest";

export const MAX_POSTURE_DEVICES = 1000;
const MAX_POSTURE_BYTES = 1024 * 1024;

interface Device {
  device_id: string;
  email: string;
  serial: string;
  host: string;
}

interface Candidate {
  install_id: string;
  email: string;
  hostname: string | null;
  serial: string | null;
  revoked_at: string | null;
  last_seen: string | null;
  fail: number | null;
  warn: number | null;
  error: number | null;
  compromised_since: string | null;
}

const s = (v: unknown, max: number) => (typeof v === "string" ? v.trim().slice(0, max) : "");
// The short hostname: "Kiens-MacBook-Pro.local" and "kiens-macbook-pro" are the same machine.
export const shortHost = (h: string | null | undefined) => (h ?? "").trim().toLowerCase().split(".")[0];

export function postureScore(c: Candidate, env: Env, now: Date): number {
  const silentIso = new Date(now.getTime() - config(env).silentDays * 86400_000).toISOString();
  if (c.revoked_at || !c.last_seen || c.compromised_since || c.last_seen < silentIso) return 0;
  if ((c.fail ?? 0) > 0) return Math.min(100, Math.floor(num(env.POSTURE_SCORE_FAILING, 50, 0)));
  if ((c.warn ?? 0) > 0 || (c.error ?? 0) > 0) return Math.min(100, Math.floor(num(env.POSTURE_SCORE_ATTENTION, 80, 0)));
  return 100;
}

export async function handlePosture(req: Request, env: Env, now = new Date()): Promise<Response> {
  if (!env.POSTURE_ACCESS_AUD || !env.ACCESS_TEAM_DOMAIN) return json({ error: "not found" }, 404);
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405, { allow: "POST" });
  const claims = await accessClaims(req, env, env.POSTURE_ACCESS_AUD, now.getTime());
  // Only a service token: a person's Access session must not read postures.
  const client = typeof claims?.common_name === "string" ? claims.common_name : "";
  if (!claims || !client || claims.email || (env.POSTURE_CLIENT_ID && client !== env.POSTURE_CLIENT_ID)) {
    return json({ error: "unauthorized" }, 401);
  }
  let body: unknown;
  try {
    body = JSON.parse(await readLimited(req, MAX_POSTURE_BYTES));
  } catch (e) {
    if (e instanceof TooLarge) return json({ error: "too large" }, 413);
    return json({ error: "bad request: JSON expected" }, 400);
  }
  const list = (body as { devices?: unknown })?.devices;
  if (!Array.isArray(list)) return json({ error: 'bad request: "devices" must be an array' }, 400);
  if (list.length > MAX_POSTURE_DEVICES) return json({ error: `bad request: at most ${MAX_POSTURE_DEVICES} devices` }, 400);
  const devices: Device[] = [];
  for (const d of list) {
    const o = (d && typeof d === "object" ? d : {}) as Record<string, unknown>;
    const id = s(o.device_id, 128);
    if (!id) continue;
    devices.push({ device_id: id, email: s(o.email, 254).toLowerCase(), serial: s(o.serial_number, 64).toUpperCase(), host: shortHost(s(o.hostname, 255)) });
  }

  const serials = [...new Set(devices.map((d) => d.serial).filter(Boolean))];
  const emails = [...new Set(devices.map((d) => d.email).filter(Boolean))];
  const rows = serials.length || emails.length
    ? (
        await env.DB.prepare(
          `SELECT e.install_id, e.email, COALESCE(m.hostname, e.hostname) AS hostname, COALESCE(m.serial, e.serial) AS serial,
                  e.revoked_at, m.last_seen, m.fail, m.warn, m.error, m.compromised_since
           FROM enrollments e LEFT JOIN machines m ON m.install_id = e.install_id
           WHERE upper(COALESCE(m.serial, e.serial)) IN (SELECT value FROM json_each(?1))
              OR lower(e.email) IN (SELECT value FROM json_each(?2))`,
        ).bind(JSON.stringify(serials), JSON.stringify(emails)).all<Candidate>()
      ).results
    : [];
  const bySerial = new Map<string, Candidate[]>();
  const byEmailHost = new Map<string, Candidate[]>();
  const add = (m: Map<string, Candidate[]>, k: string, c: Candidate) => m.set(k, [...(m.get(k) ?? []), c]);
  for (const c of rows) {
    if (c.serial) add(bySerial, c.serial.toUpperCase(), c);
    if (c.hostname) add(byEmailHost, `${c.email.toLowerCase()}\u0000${shortHost(c.hostname)}`, c);
  }

  const result: Record<string, { s2s_id: string; score: number }> = {};
  for (const d of devices) {
    const found = (d.serial && bySerial.get(d.serial)) || (d.email && d.host && byEmailHost.get(`${d.email}\u0000${d.host}`)) || [];
    const score = found.length ? Math.min(...found.map((c) => postureScore(c, env, now))) : 0;
    result[d.device_id] = { s2s_id: "", score };
  }
  return json({ result }, 200, { "cache-control": "no-store" });
}
