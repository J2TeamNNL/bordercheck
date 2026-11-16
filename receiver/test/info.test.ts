import { describe, expect, it } from "vitest";
import { ADMIN_TOKEN, adminGet, BASE, call, enrolled, env, post, report, result } from "./helpers";

// Info: worth knowing, not a problem. Counted per machine for the filter,
// shown as a pill, never part of the state.

const info = [{ key: "secrets.keystoreInfo", params: { n: 2 } }];

describe("Info", () => {
  it("is stored, filtered on and shown, without changing the state", async () => {
    const m = await enrolled("an@domain.com", "Dev");
    const res = await post(report({ install_id: m.install_id }, [result("secrets", "pass", { info }), result("firewall", "pass")]), { token: m.token });
    expect(res.status).toBe(200);
    const row = await env.DB.prepare("SELECT info, fail, warn FROM machines WHERE install_id = ?").bind(m.install_id).first<{ info: number; fail: number; warn: number }>();
    expect(row).toEqual({ info: 1, fail: 0, warn: 0 });

    const list = await (await adminGet("/admin?filter=info")).text();
    expect(list).toContain(m.install_id);
    expect(list).toContain("ℹ Info");
    const page = await (await adminGet(`/admin/machine/${m.install_id}`)).text();
    expect(page).toContain('class="pill s-info"');

    // A later report without it: gone from the filter.
    await post(report({ install_id: m.install_id }, [result("secrets", "pass")]), { token: m.token });
    expect(await (await adminGet("/admin?filter=info")).text()).not.toContain(m.install_id);
  });

  it("reaches MCP as message keys BorderCheck knows", async () => {
    const m = await enrolled("an@domain.com", "Dev");
    await post(report({ install_id: m.install_id }, [result("secrets", "pass", { info: [...info, { key: "made.up", params: {} }] })]), { token: m.token });
    const call1 = (name: string, args: Record<string, unknown>) =>
      call(
        new Request(`${BASE}/mcp`, {
          method: "POST",
          headers: { "content-type": "application/json", authorization: "Bearer test-mcp-token-0123456789abcdef" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
        }),
        { MCP_TOKEN: "test-mcp-token-0123456789abcdef" },
      ).then((r) => r.json<any>());
    const got = (await call1("get_machine", { install_id: m.install_id })).result.structuredContent;
    expect(got.passing_checks.find((c: any) => c.check_id === "secrets").info).toEqual(["secrets.keystoreInfo"]);
    const listed = (await call1("list_machines", { filter: "info" })).result.structuredContent;
    expect(listed.machines[0].info_checks).toBe(1);
    expect(ADMIN_TOKEN).toBeTruthy();
  });
});
