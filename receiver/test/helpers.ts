import { env as testEnv } from "cloudflare:test";
import type { Env } from "../src/env";
import worker from "../src/index";

export const env = testEnv as unknown as Env;
export const ADMIN_TOKEN = "test-admin-token-0123456789";
export const BASE = "https://bordercheck.example.com";

export function result(id: string, status: string, extra: Record<string, unknown> = {}) {
  return { id, title: `Check ${id}`, status, summary: `${id} is ${status}`, ...extra };
}

// A report as bordercheck sends it. install_id and email in the body are
// ignored by the receiver (they come from the machine token's enrollment);
// they are here because bordercheck sends them.
export function report(extra: Record<string, unknown> = {}, results?: unknown[]) {
  return {
    tool: "bordercheck",
    version: "v0.3.0",
    policy: "Acme",
    time: "2026-11-01T10:00:00Z",
    host: { os: "darwin", arch: "arm64", hostname: "an-mbp" },
    email: "an@acme.com",
    install_id: "4f1c0000aaaabbbbccccdddd",
    counts: { fail: 1, error: 0, warn: 0, pass: 1, skip: 0 },
    results: results ?? [result("firewall", "fail", { severity: "high", fix: "Turn it on." }), result("secrets", "pass")],
    ...extra,
  };
}

export function call(req: Request, e: Partial<Env> = {}) {
  return worker.fetch(req, { ...env, ...e } as Env);
}

export function reportRequest(body: unknown, token: string | null) {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;
  return new Request(`${BASE}/report`, { method: "POST", headers, body: typeof body === "string" ? body : JSON.stringify(body) });
}

// post sends a report to /report with a machine token (see enrolled()).
export function post(body: unknown, opts: { token: string | null; e?: Partial<Env> }) {
  return call(reportRequest(body, opts.token), opts.e);
}

export function adminGet(path: string, e: Partial<Env> = {}) {
  return call(new Request(BASE + path, { headers: { authorization: `Bearer ${ADMIN_TOKEN}` } }), e);
}

// ---- Enrollment, through the real endpoints ----

export const CODE_IN_PAGE = /\/i\/([A-Za-z0-9_-]{43})/g;

export function adminPost(path: string, fields: Record<string, string> = {}, e: Partial<Env> = {}) {
  return call(
    new Request(BASE + path, { method: "POST", headers: { authorization: `Bearer ${ADMIN_TOKEN}` }, body: new URLSearchParams(fields) }),
    e,
  );
}

export const DEV_POLICY = {
  name: "Acme dev",
  report: { interval: "24h" },
  update: { binary: true },
  checks: { listeners: { on_problem: "fail" } },
};

export async function makeRole(name = "Dev", policy: unknown = DEV_POLICY): Promise<number> {
  const res = await adminPost("/admin/roles", { name, policy: JSON.stringify(policy) });
  if (res.status !== 200) throw new Error(`role create ${res.status}: ${await res.text()}`);
  return (await env.DB.prepare("SELECT id FROM roles WHERE name = ?").bind(name).first<number>("id"))!;
}

export async function makeInvites(emails: string[], roleId: number, extra: Record<string, string> = {}): Promise<string[]> {
  const res = await adminPost("/admin/invites", { emails: emails.join("\n"), role_id: String(roleId), ...extra });
  const page = await res.text();
  if (res.status !== 200) throw new Error(`invite create ${res.status}: ${page}`);
  return [...new Set([...page.matchAll(CODE_IN_PAGE)].map((m) => m[1]))];
}

export function enroll(body: unknown, ip = "203.0.113.7", e: Partial<Env> = {}) {
  return call(
    new Request(`${BASE}/enroll`, {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": ip },
      body: typeof body === "string" ? body : JSON.stringify(body),
    }),
    e,
  );
}

export const HOST = { os: "darwin", arch: "arm64", hostname: "an-mbp" };

// Each helper enrollment comes from its own address, so tests that set up
// several machines stay clear of the per-IP enrollment rate limit.
let enrollIp = 0;

// enrolled invites `email` into `roleName` (created if missing) and enrolls a
// machine with the code, as bordercheck does. Its token is what reports use.
export async function enrolled(email = "an@acme.com", roleName = "Dev", host = HOST) {
  const roleId = (await env.DB.prepare("SELECT id FROM roles WHERE name = ?").bind(roleName).first<number>("id")) ?? (await makeRole(roleName));
  const [code] = await makeInvites([email], roleId);
  const ip = `198.18.${(enrollIp >> 8) & 255}.${enrollIp++ & 255}`;
  const res = await enroll({ code, host, version: "v0.4.0" }, ip);
  if (res.status !== 200) throw new Error(`enroll ${res.status}: ${await res.text()}`);
  return { roleId, code, ...(await res.json<{ install_id: string; email: string; role: string; token: string; policy_url: string; report_url: string }>()) };
}

export function getPolicy(token: string, e: Partial<Env> = {}) {
  return call(new Request(`${BASE}/policy`, { headers: { authorization: `Bearer ${token}` } }), e);
}
