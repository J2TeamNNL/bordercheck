import { env as testEnv } from "cloudflare:test";
import type { Env } from "../src/env";
import worker from "../src/index";

export const env = testEnv as unknown as Env;
export const REPORT_TOKEN = "test-report-token-0123456789";
export const ADMIN_TOKEN = "test-admin-token-0123456789";
export const BASE = "https://bordercheck.example.com";

export function result(id: string, status: string, extra: Record<string, unknown> = {}) {
  return { id, title: `Check ${id}`, status, summary: `${id} is ${status}`, ...extra };
}

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

export function post(body: unknown, opts: { token?: string | null; e?: Partial<Env> } = {}) {
  const headers: Record<string, string> = { "content-type": "application/json" };
  const token = opts.token === undefined ? REPORT_TOKEN : opts.token;
  if (token) headers.authorization = `Bearer ${token}`;
  return call(
    new Request(`${BASE}/report`, { method: "POST", headers, body: typeof body === "string" ? body : JSON.stringify(body) }),
    opts.e,
  );
}

export function adminGet(path: string, e: Partial<Env> = {}) {
  return call(new Request(BASE + path, { headers: { authorization: `Bearer ${ADMIN_TOKEN}` } }), e);
}
