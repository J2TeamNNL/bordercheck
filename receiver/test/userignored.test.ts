// Secrets the person at the machine marked as not sensitive (bordercheck
// ignore): the result's user_ignored list, from parsing to every page.
import { describe, expect, it } from "vitest";
import { machineDetail } from "../src/fleet";
import { MAX_USER_IGNORED, parseReport } from "../src/report";
import { validateRolePolicy } from "../src/roles";
import { ADMIN_TOKEN, adminGet, BASE, call, enrolled, env, post, report, result } from "./helpers";

const ignored = [
  { path: "~/app/.env", name: "POSTGRES_PASSWORD", kind: "Secret-looking variable", reason: "local docker db", since: "2026-11-11" },
  { path: "~/app/c.p12", kind: "certificate bundle", reason: "test cert" },
];

describe("user_ignored in a report", () => {
  it("is parsed, bounded and cleaned; anything malformed is dropped", () => {
    const long = "x".repeat(5000);
    const r = parseReport(
      report({}, [
        result("secrets", "warn", {
          user_ignored: [
            ...ignored,
            { path: "~/a\n.env", kind: "k", reason: long, since: "2026-11-11", extra: { nested: true } },
            { path: "", reason: "no path" },
            { path: "~/b", reason: "" },
            { path: 5, reason: "not a string" },
            { path: "~/c", reason: "r", name: ["x"] },
            "a string",
            null,
          ],
        }),
      ]),
    );
    const ui = r.results[0].user_ignored!;
    expect(ui).toHaveLength(3);
    expect(ui[0]).toEqual({ ...ignored[0] });
    expect(ui[1]).toEqual({ path: "~/app/c.p12", name: "", kind: "certificate bundle", reason: "test cert", since: "" });
    expect(ui[2].path).toBe("~/a .env");
    expect(ui[2].reason.length).toBeLessThanOrEqual(201);
    expect(ui[2]).not.toHaveProperty("extra");

    const many = Array.from({ length: 1000 }, (_, i) => ({ path: `~/f${i}/.env`, kind: "k", reason: "r" }));
    expect(parseReport(report({}, [result("secrets", "pass", { user_ignored: many })])).results[0].user_ignored).toHaveLength(MAX_USER_IGNORED);
    // Not an array: ignored, the report still parses.
    expect(parseReport(report({}, [result("secrets", "pass", { user_ignored: { path: "~/x" } })])).results[0].user_ignored).toBeUndefined();
  });

  it("is absent from an older client's report, which parses as before", () => {
    const r = parseReport(report());
    expect(r.results.every((x) => x.user_ignored === undefined)).toBe(true);
  });
});

describe("pages and the API", () => {
  const hostile = { path: "~/<script>alert(1)</script>/.env", name: "A&B", kind: "<b>kind</b>", reason: `"><img src=x onerror=alert(1)>`, since: "2026-11-11" };

  it("the machine page lists them, escaped, under a failing and under a passing check", async () => {
    const an = await enrolled("ign-an@acme.com");
    await post(report({}, [result("secrets", "warn", { severity: "medium", user_ignored: [ignored[0], hostile] })]), { token: an.token });
    const body = await (await adminGet(`/admin/machine/${an.install_id}`)).text();
    expect(body).toContain("Ignored by the user (2)");
    expect(body).toContain("~/app/.env  Secret-looking variable (POSTGRES_PASSWORD)");
    expect(body).toContain("local docker db");
    expect(body).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(body).toContain("A&amp;B");
    expect(body).toContain("&lt;b&gt;kind&lt;/b&gt;");
    expect(body).not.toContain("<img src=x");
    expect(body).not.toContain("<b>kind</b>");

    const bo = await enrolled("ign-bo@acme.com");
    await post(report({}, [result("secrets", "pass", { user_ignored: [ignored[1]] })]), { token: bo.token });
    const passing = await (await adminGet(`/admin/machine/${bo.install_id}`)).text();
    expect(passing).toContain("Ignored by the user (1)");
    expect(passing).toContain("test cert");

    // In Vietnamese and Chinese too.
    for (const [lang, want] of [["vi", "Người dùng đã bỏ qua (1)"], ["zh", "用户已忽略（1）"]]) {
      const res = await call(new Request(`${BASE}/admin/machine/${bo.install_id}`, { headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "accept-language": lang } }));
      expect(await res.text()).toContain(want);
    }
  });

  it("the report page shows only the count, no paths or reasons", async () => {
    const m = await enrolled("ign-cy@acme.com");
    const res = await post(report({}, [result("firewall", "fail", { severity: "high" }), result("secrets", "pass", { user_ignored: [ignored[0], hostile] })]), { token: m.token });
    const { report_url } = await res.json<{ report_url: string }>();
    const page = await (await call(new Request(report_url.replace("https://bordercheck.example.com", BASE)))).text();
    expect(page).toContain("<b>2</b> ignored by you");
    expect(page).not.toContain("POSTGRES_PASSWORD");
    expect(page).not.toContain("app/.env");
    expect(page).not.toContain("local docker db");
    expect(page).not.toContain("alert(1)");
    // An older client's report: no chip.
    const old = await enrolled("ign-dee@acme.com");
    const r2 = await post(report(), { token: old.token });
    const p2 = await (await call(new Request((await r2.json<{ report_url: string }>()).report_url.replace("https://bordercheck.example.com", BASE)))).text();
    expect(p2).not.toContain("ignored by you");
  });

  it("MCP/API machine detail: the count always, the items with evidence, under untrusted", async () => {
    const m = await enrolled("ign-ed@acme.com");
    await post(report({}, [result("secrets", "pass", { user_ignored: [ignored[0], hostile] })]), { token: m.token });
    const plain = await machineDetail(env, m.install_id, {}, new Date());
    const d = plain.ok ? (plain.data as Record<string, unknown>) : {};
    expect(d.user_ignored_count).toBe(2);
    expect(d.user_ignored).toBeUndefined();
    expect(JSON.stringify(d)).not.toContain("POSTGRES_PASSWORD");

    const full = await machineDetail(env, m.install_id, { evidence: true }, new Date());
    const items = (full.ok ? (full.data as Record<string, unknown>) : {}).user_ignored as { check_id: string; untrusted: Record<string, string> }[];
    expect(items).toHaveLength(2);
    expect(items[0]).toEqual({ check_id: "secrets", untrusted: { path: "~/app/.env", name: "POSTGRES_PASSWORD", kind: "Secret-looking variable", reason: "local docker db", since: "2026-11-11" } });

    const old = await enrolled("ign-fay@acme.com");
    await post(report(), { token: old.token });
    const o = await machineDetail(env, old.install_id, { evidence: true }, new Date());
    expect((o.ok ? (o.data as Record<string, unknown>) : {}).user_ignored_count).toBe(0);
  });
});

describe("role policies", () => {
  it("accept user_ignore on secrets, ai-agents and ssh-keys as a boolean only", () => {
    const off = { user_ignore: false };
    expect(validateRolePolicy({ checks: { secrets: off, "ai-agents": off, "ssh-keys": off } }, new Date())).toEqual([]);
    for (const id of ["secrets", "ai-agents", "ssh-keys"]) {
      const errs = validateRolePolicy({ checks: { [id]: { user_ignore: "no" } } }, new Date());
      expect(errs.map((m) => m.key)).toEqual(["v.mustBool"]);
      expect(JSON.stringify(errs)).toContain(`checks.${id}.user_ignore`);
    }
  });
});

describe("ai-agents and ssh-keys", () => {
  it("each check's list shows under that check, and the report page counts each", async () => {
    const m = await enrolled("ign-gus@acme.com");
    const res = await post(
      report({}, [
        result("ai-agents", "fail", {
          severity: "high",
          evidence: [`~/.codex/config.toml  sandbox_mode = "danger-full-access"  Codex: commands run without a sandbox`],
          user_ignored: [{ path: "~/.claude.json", name: "mcpServers.mcp-trinh.headers.Authorization", kind: "Claude Code: Token in an HTTP header in plain text", reason: "local MCP server", since: "2026-11-11" }],
        }),
        result("ssh-keys", "pass", { user_ignored: [{ path: "~/.ssh/aur", kind: "no passphrase (OpenSSH ssh-ed25519)", reason: "AUR upload key", since: "2026-11-10" }] }),
        result("secrets", "pass", { user_ignored: [ignored[0]] }),
      ]),
      { token: m.token },
    );
    const body = await (await adminGet(`/admin/machine/${m.install_id}`)).text();
    expect(body.match(/Ignored by the user \(1\)/g)).toHaveLength(3);
    expect(body).toContain("mcpServers.mcp-trinh.headers.Authorization");
    expect(body).toContain("~/.ssh/aur  no passphrase (OpenSSH ssh-ed25519)");
    // Each list sits with its own check: the AI token after the ai-agents title, before ssh-keys.
    expect(body.indexOf("local MCP server")).toBeGreaterThan(body.indexOf("ai-agents"));

    const { report_url } = await res.json<{ report_url: string }>();
    const page = await (await call(new Request(report_url.replace("https://bordercheck.example.com", BASE)))).text();
    expect(page).toContain("<b>3</b> ignored by you"); // the chip: every check
    expect(page).toContain("<b>1</b> ignored by you"); // under the failing ai-agents check
    expect(page).not.toContain(".ssh/aur");
    expect(page).not.toContain("local MCP server");

    const d = await machineDetail(env, m.install_id, { evidence: true }, new Date());
    const items = (d.ok ? (d.data as Record<string, unknown>) : {}).user_ignored as { check_id: string }[];
    expect(items.map((i) => i.check_id).sort()).toEqual(["ai-agents", "secrets", "ssh-keys"]);
  });
});
