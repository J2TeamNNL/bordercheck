import { afterEach, describe, expect, it, vi } from "vitest";
import { runCron } from "../src/alerts";
import type { Env } from "../src/env";
import { adminPost, BASE, call, enrolled, env, post as postWith, report, result } from "./helpers";

// Reports in these tests come from An's enrolled machine unless a token is given.
let an: { install_id: string; token: string } | undefined;
async function anMachine() {
  if (!an || !(await env.DB.prepare("SELECT 1 FROM enrollments WHERE install_id = ?").bind(an.install_id).first())) an = await enrolled();
  return an;
}
const post = async (body: unknown, opts: { token?: string; e?: Partial<Env> } = {}) =>
  postWith(body, { token: opts.token ?? (await anMachine()).token, e: opts.e });

const open = (url: string, ip = "203.0.113.50", e = {}) =>
  call(new Request(url.replace("https://bordercheck.example.com", BASE), { headers: { "cf-connecting-ip": ip } }), e);

async function reportUrl(res: Response): Promise<string> {
  expect(res.status).toBe(200);
  const body = await res.json<{ ok: boolean; fail: number; warn: number; report_url: string }>();
  expect(body.ok).toBe(true);
  expect(body.report_url).toMatch(new RegExp(`^${BASE}/r/[A-Za-z0-9_-]{32}$`));
  return body.report_url;
}

describe("login-free report links", () => {
  afterEach(() => vi.restoreAllMocks());

  it("returns report_url and shows that machine's own results without login", async () => {
    const url = await reportUrl(
      await post(
        report({}, [
          result("firewall", "fail", { severity: "high", fix: "Turn it on.", evidence: ["/Users/an/secret-path", "port 5432"] }),
          result("docker", "waived", { waived: { until: "2026-12-01", reason: "migration" } }),
          result("secrets", "pass"),
        ]),
      ),
    );
    const res = await open(url);
    expect(res.status).toBe(200);
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
    expect(res.headers.get("x-robots-tag")).toContain("noindex");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("content-security-policy")).toContain("default-src 'none'");
    const body = await res.text();
    expect(body).toContain("an@acme.com");
    expect(body).toContain("an-mbp");
    expect(body).toContain("Turn it on.");
    expect(body).toContain("[high]");
    expect(body).toContain("Until 2026-12-01");
    expect(body).not.toContain("secret-path"); // no evidence
    expect(body).not.toContain("5432");
    expect(body).not.toContain("/admin"); // no admin nav or controls
    expect(body).not.toContain("<form");
  });

  it("cannot reach another machine, and unknown ids get one uniform 404", async () => {
    const urlA = await reportUrl(await post(report()));
    const bo = await enrolled("bo@acme.com");
    await post(report({ host: { os: "linux", arch: "amd64", hostname: "bo-box" } }), { token: bo.token });
    const a = await (await open(urlA)).text();
    expect(a).not.toContain("bo@acme.com");
    const r1 = await open(`${BASE}/r/${"A".repeat(32)}`);
    const r2 = await open(`${BASE}/r/short`);
    expect(r1.status).toBe(404);
    expect(r2.status).toBe(404);
    expect(await r1.text()).toBe(await r2.text());
  });

  it("a revoked machine's link stops working, and restoring does not bring it back", async () => {
    const m = await enrolled();
    const url = await reportUrl(await post(report(), { token: m.token }));
    expect((await open(url)).status).toBe(200);
    await adminPost(`/admin/machine/${m.install_id}/revoke`);
    expect((await open(url)).status).toBe(404);
    await adminPost(`/admin/machine/${m.install_id}/restore`);
    expect((await open(url)).status).toBe(404);
    const fresh = await reportUrl(await post(report(), { token: m.token }));
    expect((await open(fresh)).status).toBe(200);
    await adminPost(`/admin/machine/${m.install_id}/reset-link`);
    expect((await open(fresh)).status).toBe(404);
  });

  it("keeps a few links per machine, and links expire", async () => {
    const m = await enrolled();
    const urls = [];
    for (let i = 0; i < 4; i++) urls.push(await reportUrl(await post(report(), { token: m.token })));
    expect((await open(urls[0])).status).toBe(404);
    for (const u of urls.slice(1)) expect((await open(u)).status).toBe(200);

    await env.DB.prepare("UPDATE report_links SET expires_at = '2000-01-01T00:00:00.000Z'").run();
    expect((await open(urls[3])).status).toBe(404);
  });

  it("forget removes links; the feature can be switched off", async () => {
    const url = await reportUrl(await post(report()));
    await adminPost(`/admin/machine/${(await anMachine()).install_id}/forget`);
    expect((await open(url)).status).toBe(404);

    const off = { REPORT_LINKS: "off" };
    const res = await post(report(), { e: off });
    expect(await res.json()).toEqual({ ok: true, fail: 1, warn: 0 });
    const url2 = await reportUrl(await post(report()));
    expect((await open(url2, undefined, off)).status).toBe(404);
  });

  it("rate-limits lookups", async () => {
    const url = await reportUrl(await post(report()));
    const e = { PAGE_RATE_LIMIT: "2" };
    expect((await open(url, "192.0.2.77", e)).status).toBe(200);
    expect((await open(url, "192.0.2.77", e)).status).toBe(200);
    expect((await open(url, "192.0.2.77", e)).status).toBe(429);
    expect((await open(url, "192.0.2.78", e)).status).toBe(200);
  });

  it("escapes everything from the report", async () => {
    const evil = "<script>alert(1)</script>";
    const url = await reportUrl(
      await post(report({ email: `x"><img src=x>@acme.com`, host: { os: "darwin", arch: "arm64", hostname: evil } }, [
        result("firewall", "fail", { severity: evil, title: evil, summary: evil, fix: evil }),
        result("docker", "waived", { waived: { until: evil, reason: evil } }),
      ])),
    );
    const body = await (await open(url)).text();
    expect(body).not.toContain("<script>");
    expect(body).not.toContain("<img");
    expect(body).toContain("&lt;script&gt;");
  });

  it("never writes the id to logs, alerts or the audit trail", async () => {
    const spies = (["log", "info", "warn", "error", "debug"] as const).map((k) => vi.spyOn(console, k));
    const m = await enrolled();
    const url = await reportUrl(await post(report(), { token: m.token }));
    const id = url.split("/r/")[1];
    await open(url);
    await adminPost(`/admin/machine/${m.install_id}/reset-link`);
    await runCron(env, new Date(), async () => {});
    for (const s of spies) for (const call of s.mock.calls) expect(JSON.stringify(call)).not.toContain(id);
    const tables = await Promise.all(
      ["alerts", "audit", "report_links", "machines", "reports"].map((t) => env.DB.prepare(`SELECT * FROM ${t}`).all().then((r) => JSON.stringify(r.results))),
    );
    for (const t of tables) expect(t).not.toContain(id);
  });
});
