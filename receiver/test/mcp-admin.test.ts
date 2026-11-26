import { describe, expect, it } from "vitest";
import type { Env } from "../src/env";
import { ADMIN_TOKEN, BASE, call, enrolled, env, post, report, result } from "./helpers";

// A named admin's own MCP token: made on the Admins page, scoped to the roles
// the admin manages, audited under their name.

const MCP_RE = /bcp_[A-Za-z0-9_-]{43}/;
const ADMIN_RE = /bca_[A-Za-z0-9_-]{43}/;
const OWNER = { authorization: `Bearer ${ADMIN_TOKEN}` };
let seq = 0;

function form(path: string, headers: Record<string, string>, fields: [string, string][] = []) {
  return call(new Request(BASE + path, { method: "POST", headers, body: new URLSearchParams(fields) }));
}

async function addAdmin(name: string, roles: number[]) {
  const res = await form("/admin/admins", OWNER, [["name", name], ...roles.map((r): [string, string] => ["role", String(r)])]);
  const token = ADMIN_RE.exec(await res.text())![0];
  const id = (await env.DB.prepare("SELECT id FROM admins WHERE name = ?").bind(name).first<number>("id"))!;
  return { id, token };
}

async function mcpToken(id: number, as: Record<string, string>, access: "read" | "write") {
  const res = await form(`/admin/admins/${id}/mcp`, as, [["access", access]]);
  const page = await res.text();
  return { status: res.status, page, token: MCP_RE.exec(page)?.[0] ?? "" };
}

// tool: a legacy-era tools/call (no _meta), enough here.
async function tool(token: string, name: string, args: Record<string, unknown> = {}, e: Partial<Env> = {}) {
  const res = await call(
    new Request(`${BASE}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++seq, method: "tools/call", params: { name, arguments: args } }),
    }),
    e,
  );
  if (res.status !== 200) return { status: res.status, isError: true, data: null as any };
  const b = await res.json<any>();
  return { status: 200, isError: b.result?.isError as boolean, data: b.result?.structuredContent };
}

async function twoRoles() {
  const dev = await enrolled("dev@domain.com", "Dev");
  const ops = await enrolled("ops@domain.com", "Ops", { os: "linux", arch: "amd64", hostname: "ops-box" });
  for (const m of [dev, ops]) expect((await post(report({ install_id: m.install_id }, [result("firewall", "fail")]), { token: m.token })).status).toBe(200);
  return { dev, ops };
}

describe("admin MCP tokens", () => {
  it("see only the admin's roles, and work with no deployment MCP token set", async () => {
    const { dev, ops } = await twoRoles();
    const kien = await addAdmin("Kien", [dev.roleId]);
    const { token, page } = await mcpToken(kien.id, { authorization: `Bearer ${kien.token}` }, "read");
    expect(token).toMatch(MCP_RE);
    expect(page).toContain("claude mcp add");
    // Only the hash is kept.
    const row = await env.DB.prepare("SELECT mcp_hash, mcp_write FROM admins WHERE id = ?").bind(kien.id).first<{ mcp_hash: string; mcp_write: number }>();
    expect(row!.mcp_hash).not.toContain(token);
    expect(row!.mcp_write).toBe(0);

    const machines = await tool(token, "list_machines");
    expect(machines.isError).toBe(false);
    expect(machines.data.machines.map((m: any) => m.install_id)).toEqual([dev.install_id]);
    expect((await tool(token, "get_machine", { install_id: ops.install_id })).isError).toBe(true);
    expect((await tool(token, "get_machine", { install_id: dev.install_id })).isError).toBe(false);
    expect((await tool(token, "list_roles")).data.roles.map((r: any) => r.name)).toEqual(["Dev"]);
    expect((await tool(token, "get_role", { role_id: ops.roleId })).isError).toBe(true);
    const sum = await tool(token, "fleet_summary");
    expect(sum.data.machines.reporting).toBe(1);
    expect(sum.data.roles).toBe(1);
    expect((await tool(token, "list_invites", { status: "all" })).data.invites.map((i: any) => i.email)).toEqual(["dev@domain.com"]);
    expect((await tool(token, "check_stats")).data.checks.find((c: any) => c.check_id === "firewall").fail).toBe(1);

    // Read only: writes refused, and recorded under the admin's name.
    const w = await tool(token, "revoke_machine", { install_id: dev.install_id });
    expect(w.isError).toBe(true);
    const refused = await env.DB.prepare("SELECT who FROM audit WHERE action = 'mcp.refused'").first<string>("who");
    expect(refused).toBe("Kien");
  });

  it("write tokens change only what is in scope, audited under the admin's name", async () => {
    const { dev, ops } = await twoRoles();
    const kien = await addAdmin("Kien", [dev.roleId]);
    const { token } = await mcpToken(kien.id, OWNER, "write"); // the owner can make one for them
    expect((await tool(token, "revoke_machine", { install_id: ops.install_id })).data.error).toBe("No such machine.");
    expect((await tool(token, "change_machine_role", { install_id: dev.install_id, role_id: ops.roleId })).isError).toBe(true);
    expect((await tool(token, "update_role", { role_id: ops.roleId, name: "Mine" })).isError).toBe(true);
    expect((await tool(token, "create_invites", { emails: ["x@domain.com"], role_id: ops.roleId })).isError).toBe(true);
    const opsInvite = await env.DB.prepare("SELECT i.id FROM invites i WHERE i.role_id = ?").bind(ops.roleId).first<number>("id");
    expect((await tool(token, "revoke_invite", { invite_id: opsInvite })).isError).toBe(true);
    expect(await env.DB.prepare("SELECT revoked_at FROM enrollments WHERE install_id = ?").bind(ops.install_id).first("revoked_at")).toBeNull();
    await env.DB.prepare("INSERT INTO waiver_requests (install_id, check_id, until, reason, accept_risk, created_at) VALUES (?, 'firewall', '2099-01-01', 'r', 1, '2026-01-01')").bind(ops.install_id).run();
    const opsRequest = await env.DB.prepare("SELECT id FROM waiver_requests").first<number>("id");
    expect((await tool(token, "reject_waiver_request", { install_id: ops.install_id, request_id: opsRequest })).data.error).toBe("No such machine.");
    expect(await env.DB.prepare("SELECT status FROM waiver_requests").first("status")).toBe("pending");

    const ok = await tool(token, "revoke_machine", { install_id: dev.install_id });
    expect(ok.isError).toBe(false);
    // A role it creates joins the admin's scope.
    const made = await tool(token, "create_role", { name: "Kien team", policy: { report: { interval: "24h" } } });
    expect(made.isError).toBe(false);
    expect((await tool(token, "list_roles")).data.roles.map((r: any) => r.name)).toEqual(["Dev", "Kien team"]);

    const rows = (await env.DB.prepare("SELECT who, action, detail FROM audit WHERE action IN ('machine.revoke', 'role.create') ORDER BY id").all<{ who: string; action: string; detail: string }>()).results;
    expect(rows.filter((r) => r.who === "Kien").map((r) => r.action)).toEqual(["machine.revoke", "role.create"]);
    expect(JSON.parse(rows.at(-1)!.detail).via).toBe("mcp");
    // The admin's audit, through MCP: only their own entries.
    const audit = await tool(token, "list_audit");
    expect(audit.data.entries.every((e: any) => e.who === "Kien")).toBe(true);
    // The owner's "MCP only" filter includes them.
    const page = await (await call(new Request(`${BASE}/admin/audit?who=mcp`, { headers: OWNER }))).text();
    expect(page).toContain("machine.revoke");
  });

  it("only the owner or the admin themself makes one; a new one or removal ends the old", async () => {
    const { dev } = await twoRoles();
    const a = await addAdmin("Kien", [dev.roleId]);
    const b = await addAdmin("Lan", [dev.roleId]);
    expect((await mcpToken(a.id, { authorization: `Bearer ${b.token}` }, "read")).status).toBe(403);
    // The panel under the table posts the admin's id in the form.
    expect((await form("/admin/admins/mcp", { authorization: `Bearer ${b.token}` }, [["admin", String(a.id)], ["access", "read"]])).status).toBe(403);
    const viaPanel = await form("/admin/admins/mcp", OWNER, [["admin", String(b.id)], ["access", "read"]]);
    expect(MCP_RE.test(await viaPanel.text())).toBe(true);
    const listing = await (await call(new Request(`${BASE}/admin/admins`, { headers: OWNER }))).text();
    expect(listing).toContain('action="/admin/admins/mcp"');
    const first = (await mcpToken(a.id, { authorization: `Bearer ${a.token}` }, "read")).token;
    const second = (await mcpToken(a.id, { authorization: `Bearer ${a.token}` }, "write")).token;
    expect((await tool(first, "list_roles")).status).toBe(401);
    expect((await tool(second, "list_roles")).isError).toBe(false);
    // The sign-in token is no MCP token, and the MCP token signs nobody in.
    expect((await tool(a.token, "list_roles")).status).toBe(404); // no deployment token: /mcp exists only for bcp_
    expect((await tool(a.token, "list_roles", {}, { MCP_TOKEN: "test-mcp-token-0123456789abcdef" })).status).toBe(401);
    expect((await call(new Request(`${BASE}/admin`, { headers: { authorization: `Bearer ${second}` } }))).status).not.toBe(200);
    expect((await form(`/admin/admins/${a.id}/mcp-delete`, OWNER)).status).toBe(200);
    expect((await tool(second, "list_roles")).status).toBe(401);
    const actions = (await env.DB.prepare("SELECT action FROM audit WHERE action LIKE 'admin.mcp%' ORDER BY id").all<{ action: string }>()).results.map((r) => r.action);
    expect(actions).toEqual(["admin.mcp_token", "admin.mcp_token", "admin.mcp_token", "admin.mcp_remove"]);
  });

  it("removing the admin ends the token; without any token /mcp is still 404", async () => {
    const { dev } = await twoRoles();
    const a = await addAdmin("Kien", [dev.roleId]);
    const { token } = await mcpToken(a.id, OWNER, "read");
    expect((await form(`/admin/admins/${a.id}/delete`, OWNER)).status).toBe(200);
    expect((await tool(token, "list_roles")).status).toBe(401);
    expect((await tool("whatever", "list_roles")).status).toBe(404);
  });

  it("the MCP page shows a named admin their own token, not wrangler commands", async () => {
    const { dev } = await twoRoles();
    const a = await addAdmin("Kien", [dev.roleId]);
    const as = { authorization: `Bearer ${a.token}` };
    let page = await (await call(new Request(`${BASE}/admin/mcp`, { headers: as }))).text();
    expect(page).not.toContain("wrangler secret put");
    expect(page).toContain("/admin/admins");
    await mcpToken(a.id, as, "write");
    page = await (await call(new Request(`${BASE}/admin/mcp`, { headers: as }))).text();
    expect(page).toContain("read and write");
    const owner = await (await call(new Request(`${BASE}/admin/mcp`, { headers: OWNER }))).text();
    expect(owner).toContain('action="/admin/mcp/token"');
    expect(owner).toContain("wrangler secret put MCP_TOKEN"); // folded away, still there
    // A named admin cannot make the owner's token.
    expect((await form("/admin/mcp/token", as, [["access", "write"]])).status).toBe(403);
  });

  it("the owner makes an MCP token on the MCP page: the whole fleet, audited as mcp", async () => {
    const { dev, ops } = await twoRoles();
    const res = await form("/admin/mcp/token", OWNER, [["access", "write"]]);
    expect(res.status).toBe(200);
    const token = MCP_RE.exec(await res.text())![0];
    const ids = (await tool(token, "list_machines")).data.machines.map((m: any) => m.install_id).sort();
    expect(ids).toEqual([dev.install_id, ops.install_id].sort());
    expect((await tool(token, "revoke_machine", { install_id: ops.install_id })).isError).toBe(false);
    expect(await env.DB.prepare("SELECT who FROM audit WHERE action = 'machine.revoke'").first("who")).toBe("mcp");
    // A new one ends the old; removing ends it.
    const second = MCP_RE.exec(await (await form("/admin/mcp/token", OWNER, [["access", "read"]])).text())![0];
    expect((await tool(token, "list_roles")).status).toBe(401);
    expect((await tool(second, "revoke_machine", { install_id: dev.install_id })).isError).toBe(true);
    expect((await form("/admin/mcp/token-delete", OWNER)).status).toBe(200);
    expect((await tool(second, "list_roles")).status).toBe(401);
  });
});
