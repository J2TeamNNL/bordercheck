// Helpers for enrollment-portal tests.
import { ADMIN_TOKEN, BASE, call, env } from "./helpers";
import type { Env } from "../src/env";

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

export async function enrolled(email = "an@acme.com", roleName = "Dev") {
  const roleId = (await env.DB.prepare("SELECT id FROM roles WHERE name = ?").bind(roleName).first<number>("id")) ?? (await makeRole(roleName));
  const [code] = await makeInvites([email], roleId);
  const res = await enroll({ code, host: HOST, version: "v0.4.0" });
  if (res.status !== 200) throw new Error(`enroll ${res.status}: ${await res.text()}`);
  return { roleId, code, ...(await res.json<{ install_id: string; email: string; role: string; token: string; policy_url: string; report_url: string }>()) };
}

export function getPolicy(token: string, e: Partial<Env> = {}) {
  return call(new Request(`${BASE}/policy`, { headers: { authorization: `Bearer ${token}` } }), e);
}
