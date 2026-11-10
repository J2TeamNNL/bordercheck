import { describe, expect, it } from "vitest";
import { composePolicy, goDuration, validateRolePolicy } from "../src/roles";
import { ADMIN_TOKEN, adminGet, BASE, call, env, post, REPORT_TOKEN, report } from "./helpers";
import { adminPost, DEV_POLICY, enroll, enrolled, getPolicy, HOST, makeInvites, makeRole } from "./portal";

const sha = async (s: string) =>
  [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))].map((b) => b.toString(16).padStart(2, "0")).join("");

describe("invites and enrollment", () => {
  it("enrolls with a code: per-machine token, server-assigned identity, nothing secret stored", async () => {
    const roleId = await makeRole("Dev");
    const [code] = await makeInvites(["An@Acme.com"], roleId, { note: "new starter" });
    expect(code).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const res = await enroll({ code, host: HOST, version: "v0.4.0" });
    expect(res.status).toBe(200);
    const body = await res.json<Record<string, string>>();
    expect(Object.keys(body).sort()).toEqual(["email", "install_id", "policy_url", "report_url", "role", "token"]);
    expect(body.install_id).toMatch(/^[0-9a-f]{32}$/);
    expect(body.email).toBe("an@acme.com");
    expect(body.role).toBe("Dev");
    expect(body.policy_url).toBe(`${BASE}/policy`);
    expect(body.report_url).toBe(`${BASE}/report`);
    expect(body.token).toMatch(/^bcm_[A-Za-z0-9_-]{43}$/);

    // Only hashes at rest.
    const dump = JSON.stringify(
      await Promise.all(
        ["invites", "enrollments", "audit", "roles"].map((t) => env.DB.prepare(`SELECT * FROM ${t}`).all().then((r) => r.results)),
      ),
    );
    expect(dump).not.toContain(code);
    expect(dump).not.toContain(body.token);
    expect(dump).toContain(await sha(code));
    expect(dump).toContain(await sha(body.token));

    const e = await env.DB.prepare("SELECT * FROM enrollments").first<Record<string, unknown>>();
    expect(e).toMatchObject({ install_id: body.install_id, email: "an@acme.com", hostname: "an-mbp", os: "darwin", version: "v0.4.0" });
    const audit = await env.DB.prepare("SELECT action FROM audit ORDER BY id").all<{ action: string }>();
    expect(audit.results.map((a) => a.action)).toEqual(["role.create", "invite.create", "machine.enroll"]);
  });

  it("fails with each machine-readable error", async () => {
    const roleId = await makeRole("Dev");
    const [a, b, c] = await makeInvites(["a@acme.com", "b@acme.com", "c@acme.com"], roleId);
    const err = async (r: Response) => ({ status: r.status, ...(await r.json<{ error: string; message: string }>()) });

    expect(await err(await enroll({ code: "A".repeat(43) }))).toMatchObject({ status: 404, error: "invalid_code" });
    expect(await err(await enroll({ code: "short" }))).toMatchObject({ status: 404, error: "invalid_code" });
    expect(await err(await enroll("{not json"))).toMatchObject({ status: 400, error: "bad_request" });
    expect(await err(await enroll({ nocode: 1 }))).toMatchObject({ status: 400, error: "bad_request" });
    expect(await err(await enroll({ code: a, host: "x" }))).toMatchObject({ status: 400, error: "bad_request" });

    expect((await enroll({ code: a, host: HOST })).status).toBe(200);
    const used = await err(await enroll({ code: a, host: HOST }));
    expect(used).toMatchObject({ status: 409, error: "used" });
    expect(used.message).toBeTruthy();

    const bId = (await env.DB.prepare("SELECT id FROM invites WHERE email = 'b@acme.com'").first<number>("id"))!;
    expect((await adminPost(`/admin/invites/${bId}/revoke`)).status).toBe(200);
    expect(await err(await enroll({ code: b }))).toMatchObject({ status: 410, error: "revoked" });

    await env.DB.prepare("UPDATE invites SET expires_at = '2000-01-01T00:00:00.000Z' WHERE email = 'c@acme.com'").run();
    expect(await err(await enroll({ code: c }))).toMatchObject({ status: 410, error: "expired" });
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM enrollments").first<number>("n")).toBe(1);
  });

  it("consumes a code exactly once under concurrency", async () => {
    const [code] = await makeInvites(["an@acme.com"], await makeRole("Dev"));
    const rs = await Promise.all(Array.from({ length: 6 }, (_, i) => enroll({ code, host: { ...HOST, hostname: `h${i}` } }, `198.51.100.${i}`)));
    const statuses = rs.map((r) => r.status).sort();
    expect(statuses).toEqual([200, 409, 409, 409, 409, 409]);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM enrollments").first<number>("n")).toBe(1);
  });

  it("rate-limits enrollment per client IP", async () => {
    const e = { ENROLL_RATE_LIMIT: "3" };
    for (let i = 0; i < 3; i++) expect((await enroll({ code: "x" }, "192.0.2.1", e)).status).toBe(404);
    const limited = await enroll({ code: "x" }, "192.0.2.1", e);
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toMatch(/^\d+$/);
    expect((await limited.json<{ error: string }>()).error).toBe("rate_limited");
    // Another address is unaffected; IPs are stored hashed.
    expect((await enroll({ code: "x" }, "192.0.2.2", e)).status).toBe(404);
    const keys = await env.DB.prepare("SELECT key FROM rate_limits").all<{ key: string }>();
    expect(JSON.stringify(keys.results)).not.toContain("192.0.2");
  });

  it("bulk-creates invites, refuses bad emails and other domains, re-issues", async () => {
    const roleId = await makeRole("Support");
    const codes = await makeInvites(["a@acme.com", "b@acme.com, c@acme.com", "a@acme.com"], roleId);
    expect(codes).toHaveLength(3);
    const bad = await adminPost("/admin/invites", { emails: "a@acme.com\nnot-an-email", role_id: String(roleId) });
    expect(bad.status).toBe(400);
    expect(await bad.text()).toContain("not-an-email");
    const outside = await adminPost("/admin/invites", { emails: "x@other.example", role_id: String(roleId) }, { ALLOWED_EMAIL_DOMAINS: "acme.com" });
    expect(outside.status).toBe(400);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM invites").first<number>("n")).toBe(3);

    const list = await (await adminGet("/admin/invites")).text();
    expect(list).toContain("b@acme.com");
    for (const c of codes) expect(list).not.toContain(c); // codes are shown once only

    const id = (await env.DB.prepare("SELECT id FROM invites WHERE email = 'b@acme.com'").first<number>("id"))!;
    const re = await adminPost(`/admin/invites/${id}/reissue`);
    expect(re.status).toBe(200);
    const newCode = [...(await re.text()).matchAll(/\/i\/([A-Za-z0-9_-]{43})/g)][0][1];
    expect(newCode).not.toBe(codes[1]);
    expect((await enroll({ code: codes[1] })).status).toBe(410); // old one revoked
    expect((await adminPost(`/admin/invites/${id}/reissue`)).status).toBe(409); // only once
    const enr = await enroll({ code: newCode, host: HOST });
    expect(enr.status).toBe(200);
    expect((await enr.json<{ email: string; role: string }>())).toMatchObject({ email: "b@acme.com", role: "Support" });

    const used = await (await adminGet("/admin/invites?status=used")).text();
    expect(used).toContain("b@acme.com");
    const revoked = await (await adminGet("/admin/invites?status=revoked")).text();
    expect(revoked).toContain(`re-issued as #`);
  });

  it("the invite page shows the install commands without consuming the code", async () => {
    const [code] = await makeInvites(["an@acme.com"], await makeRole("Dev"));
    const res = await call(new Request(`${BASE}/i/${code}`, { headers: { "cf-connecting-ip": "203.0.113.9" } }));
    expect(res.status).toBe(200);
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
    expect(res.headers.get("x-robots-tag")).toContain("noindex");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("content-security-policy")).toContain("default-src 'none'");
    const body = await res.text();
    expect(body).toContain(`curl -fsSL https://raw.githubusercontent.com/ptrinh/bordercheck/main/install.sh | sh -s -- ${BASE}/i/${code}`);
    expect(body).toContain(`&amp; ([scriptblock]::Create((irm https://raw.githubusercontent.com/ptrinh/bordercheck/main/install.ps1))) ${BASE}/i/${code}`);
    expect(body).not.toContain("an@acme.com");
    expect(body).not.toContain("<script");
    expect((await enroll({ code, host: HOST })).status).toBe(200);
    const after = await call(new Request(`${BASE}/i/${code}`));
    expect(after.status).toBe(404);
    expect(await after.text()).toContain("already been used");
    expect((await call(new Request(`${BASE}/i/nope`))).status).toBe(404);
  });

  it("uses INSTALL_SH_URL / INSTALL_PS1_URL, ignoring values that are unsafe in a shell", async () => {
    const roleId = await makeRole("Dev");
    const res = await adminPost("/admin/invites", { emails: "a@acme.com", role_id: String(roleId) }, {
      INSTALL_SH_URL: "https://bordercheck.acme.com/install.sh",
      INSTALL_PS1_URL: "https://evil.example/x.ps1; rm -rf ~",
    });
    const body = await res.text();
    expect(body).toContain("curl -fsSL https://bordercheck.acme.com/install.sh | sh -s -- ");
    expect(body).toContain("irm https://raw.githubusercontent.com/ptrinh/bordercheck/main/install.ps1");
    expect(body).not.toContain("rm -rf");
  });
});

describe("GET /policy", () => {
  it("serves the role's policy pointed at this deployment, with no token", async () => {
    const m = await enrolled();
    const res = await getPolicy(m.token);
    expect(res.status).toBe(200);
    const p = await res.json<any>();
    expect(p.name).toBe("Acme dev");
    expect(p.report.url).toBe(`${BASE}/report`);
    expect(p.report.headers).toEqual({});
    expect(p.update.policy_url).toBe(`${BASE}/policy`);
    expect(p.update.binary).toBe(true);
    expect(p.checks.listeners.on_problem).toBe("fail");
    expect(p.waivers).toEqual([]);
    expect(JSON.stringify(p)).not.toContain(m.token);
    expect(JSON.stringify(p)).not.toContain(REPORT_TOKEN);
  });

  it("401s unknown and revoked tokens, distinguishably", async () => {
    expect((await getPolicy("bcm_" + "A".repeat(43))).status).toBe(401);
    expect(await (await getPolicy("whatever")).json()).toEqual({ error: "unauthorized" });
    expect((await call(new Request(`${BASE}/policy`))).status).toBe(401);
    // The shared report token is not a machine token.
    expect((await getPolicy(REPORT_TOKEN)).status).toBe(401);

    const m = await enrolled();
    expect((await adminPost(`/admin/machine/${m.install_id}/revoke`)).status).toBe(303);
    const r = await getPolicy(m.token);
    expect(r.status).toBe(401);
    expect(await r.json()).toEqual({ error: "revoked" });
    // Restore: the same token works again.
    expect((await adminPost(`/admin/machine/${m.install_id}/restore`)).status).toBe(303);
    expect((await getPolicy(m.token)).status).toBe(200);
  });

  it("reflects a role change", async () => {
    const m = await enrolled();
    const sales = await makeRole("Sales", { name: "Acme sales", checks: { tailscale: { enabled: false } } });
    expect((await adminPost(`/admin/machine/${m.install_id}/role`, { role_id: String(sales) })).status).toBe(303);
    const p = await (await getPolicy(m.token)).json<any>();
    expect(p.name).toBe("Acme sales");
    expect(p.checks.tailscale.enabled).toBe(false);
    expect(p.report.url).toBe(`${BASE}/report`);
    const audit = await env.DB.prepare("SELECT detail FROM audit WHERE action = 'machine.change_role'").first<string>("detail");
    expect(JSON.parse(audit!)).toEqual({ from: "Dev", to: "Sales" });
  });

  it("composes waivers keyed by install_id, and the role's own waivers only for this machine", async () => {
    const until = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);
    await makeRole("Dev", {
      ...DEV_POLICY,
      waivers: [
        { check: "docker", email: "an@acme.com", until, reason: "migration" },
        { check: "docker", email: "someone-else@acme.com", until, reason: "not yours" },
      ],
    });
    const m = await enrolled();
    const add = (f: Record<string, string>) => adminPost(`/admin/machine/${m.install_id}/waivers`, f);
    expect((await add({ check: "listeners", until, reason: "Postgres on 5432" })).status).toBe(303);
    // Rejected: unknown check, past date, more than a year ahead, no reason.
    expect((await add({ check: "made-up", until, reason: "x" })).status).toBe(400);
    expect((await add({ check: "firewall", until: "2001-01-01", reason: "x" })).status).toBe(400);
    expect((await add({ check: "firewall", until: "2099-01-01", reason: "x" })).status).toBe(400);
    expect((await add({ check: "firewall", until, reason: "" })).status).toBe(400);

    const p = await (await getPolicy(m.token)).json<any>();
    expect(p.waivers).toEqual([
      { check: "docker", email: "an@acme.com", until, reason: "migration" },
      { check: "listeners", install_id: m.install_id, until, reason: "Postgres on 5432" },
    ]);
    const page = await (await adminGet(`/admin/machine/${m.install_id}`)).text();
    expect(page).toContain("Postgres on 5432");

    const wid = (await env.DB.prepare("SELECT id FROM machine_waivers").first<number>("id"))!;
    expect((await adminPost(`/admin/machine/${m.install_id}/waivers/${wid}/remove`)).status).toBe(303);
    const p2 = await (await getPolicy(m.token)).json<any>();
    expect(p2.waivers.map((w: any) => w.check)).toEqual(["docker"]);
    expect(await env.DB.prepare("SELECT removed_by FROM machine_waivers").first<string>("removed_by")).toBe("admin token");
  });
});

describe("reports from enrolled machines", () => {
  it("takes install_id and email from the token, ignoring the body", async () => {
    const m = await enrolled();
    const res = await post(report({ install_id: "spoofed-install-id-0001", email: "ceo@acme.com" }), { token: m.token });
    expect(res.status).toBe(200);
    const rows = await env.DB.prepare("SELECT install_id, email, report FROM machines").all<{ install_id: string; email: string; report: string }>();
    expect(rows.results).toHaveLength(1);
    expect(rows.results[0].install_id).toBe(m.install_id);
    expect(rows.results[0].email).toBe("an@acme.com");
    expect(JSON.parse(rows.results[0].report)).toMatchObject({ install_id: m.install_id, email: "an@acme.com" });
    // Even with no install_id in the body at all.
    const { install_id: _drop, ...noId } = report();
    expect((await post(noId, { token: m.token })).status).toBe(200);
  });

  it("refuses a revoked token, and keeps the history", async () => {
    const m = await enrolled();
    await post(report(), { token: m.token });
    await adminPost(`/admin/machine/${m.install_id}/revoke`);
    const res = await post(report(), { token: m.token });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "revoked" });
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM reports").first<number>("n")).toBe(1);
    const page = await (await adminGet(`/admin/machine/${m.install_id}`)).text();
    expect(page).toContain("revoked");
    const list = await (await adminGet("/admin?filter=revoked")).text();
    expect(list).toContain("an@acme.com");
  });

  it("does not let the shared token write to an enrolled machine", async () => {
    const m = await enrolled();
    const res = await post(report({ install_id: m.install_id, email: "evil@acme.com" }));
    expect(res.status).toBe(403);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM machines").first<number>("n")).toBe(0);
  });
});

describe("legacy mode", () => {
  it("is on by default: shared token and /policies.json work, machines show as legacy", async () => {
    expect((await post(report())).status).toBe(200);
    const list = await (await adminGet("/admin")).text();
    expect(list).toContain("legacy");
    const page = await (await adminGet(`/admin/machine/4f1c0000aaaabbbbccccdddd`)).text();
    expect(page).toContain("legacy");
    await call(new Request(`${BASE}/admin/policies.json`, { method: "PUT", headers: { authorization: `Bearer ${ADMIN_TOKEN}` }, body: "{}" }));
    expect((await call(new Request(`${BASE}/policies.json`))).status).toBe(200);
  });

  it("off: the shared token and /policies.json stop working; machine tokens still do", async () => {
    const off = { LEGACY_MODE: "off" };
    const m = await enrolled();
    expect((await post(report(), { e: off })).status).toBe(401);
    expect((await post(report(), { e: { ...off, REPORT_TOKEN: "" } })).status).toBe(401);
    expect((await call(new Request(`${BASE}/policies.json`), off)).status).toBe(410);
    expect((await post(report(), { token: m.token, e: off })).status).toBe(200);
    expect((await getPolicy(m.token, off)).status).toBe(200);
    // Machine tokens need no REPORT_TOKEN at all.
    expect((await post(report(), { token: m.token, e: { REPORT_TOKEN: "" } })).status).toBe(200);
  });
});

describe("admin portal", () => {
  const routes: [string, string][] = [
    ["GET", "/admin/roles"], ["POST", "/admin/roles"], ["GET", "/admin/roles/1"], ["POST", "/admin/roles/1"],
    ["POST", "/admin/roles/1/delete"], ["GET", "/admin/invites"], ["POST", "/admin/invites"],
    ["POST", "/admin/invites/1/revoke"], ["POST", "/admin/invites/1/reissue"], ["GET", "/admin/audit"],
    ["POST", "/admin/machine/abc/revoke"], ["POST", "/admin/machine/abc/restore"], ["POST", "/admin/machine/abc/role"],
    ["POST", "/admin/machine/abc/waivers"], ["POST", "/admin/machine/abc/waivers/1/remove"], ["POST", "/admin/machine/abc/reset-link"],
  ];

  it("needs admin auth on every route; machine and report tokens are not admin", async () => {
    const m = await enrolled();
    const before = await env.DB.prepare("SELECT COUNT(*) AS n FROM audit").first<number>("n");
    for (const [method, path] of routes) {
      for (const auth of [undefined, `Bearer ${REPORT_TOKEN}`, `Bearer ${m.token}`, "Bearer nope-nope-nope-nope"]) {
        const headers: Record<string, string> = auth ? { authorization: auth } : {};
        const res = await call(new Request(BASE + path, { method, headers, body: method === "POST" ? new URLSearchParams({}) : undefined }));
        expect([303, 401], `${method} ${path} ${auth}`).toContain(res.status);
        if (res.status === 303) expect(res.headers.get("location")).toBe("/admin/login");
      }
    }
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM audit").first<number>("n")).toBe(before);
    expect((await getPolicy(m.token)).status).toBe(200);
  });

  it("refuses cross-site posts with a session cookie", async () => {
    const login = await call(new Request(`${BASE}/admin/login`, { method: "POST", headers: { origin: BASE }, body: new URLSearchParams({ token: ADMIN_TOKEN }) }));
    const cookie = login.headers.get("set-cookie")!.split(";")[0];
    const m = await enrolled();
    const res = await call(new Request(`${BASE}/admin/machine/${m.install_id}/revoke`, { method: "POST", headers: { cookie, origin: "https://evil.example" } }));
    expect(res.status).toBe(403);
    expect((await getPolicy(m.token)).status).toBe(200);
    const ok = await call(new Request(`${BASE}/admin/machine/${m.install_id}/revoke`, { method: "POST", headers: { cookie, origin: BASE } }));
    expect(ok.status).toBe(303);
  });

  it("validates role policies", async () => {
    const bad = async (policy: string) => {
      const res = await adminPost("/admin/roles", { name: "X", policy });
      expect(res.status, policy).toBe(400);
      return res.text();
    };
    await bad("[1]");
    await bad("{nope");
    expect(await bad(JSON.stringify({ report: { headers: { Authorization: "Bearer {{REPORT_TOKEN}}" } } }))).toContain("no report token");
    expect(await bad(JSON.stringify({ reprot: {} }))).toContain("unknown field");
    expect(await bad(JSON.stringify({ checks: { firewal: {} } }))).toContain("unknown check");
    expect(await bad(JSON.stringify({ report: { interval: "5m" } }))).toContain("at least 15m");
    expect(await bad(JSON.stringify({ checks: { docker: { on_problem: "panic" } } }))).toContain("on_problem");
    expect(await bad(JSON.stringify({ waivers: [{ check: "docker", until: "2026-12-01", reason: "x" }] }))).toContain("email or install_id");
    await makeRole("Dev");
    const dup = await adminPost("/admin/roles", { name: "dev", policy: "{}" });
    expect(dup.status).toBe(400);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM roles").first<number>("n")).toBe(1);
  });

  it("edits and deletes roles, but not one in use", async () => {
    const id = await makeRole("Dev");
    expect((await adminPost(`/admin/roles/${id}`, { name: "Developers", policy: '{"name":"Acme devs"}' })).status).toBe(200);
    expect(await env.DB.prepare("SELECT name FROM roles WHERE id = ?").bind(id).first<string>("name")).toBe("Developers");
    await makeInvites(["a@acme.com"], id);
    expect((await adminPost(`/admin/roles/${id}/delete`)).status).toBe(409);
    const unused = await makeRole("Temp");
    expect((await adminPost(`/admin/roles/${unused}/delete`)).status).toBe(200);
    const audit = await (await adminGet("/admin/audit")).text();
    expect(audit).toContain("role.update");
    expect(audit).toContain("role.delete");
  });

  it("audits every write without codes or tokens", async () => {
    const m = await enrolled();
    await adminPost(`/admin/machine/${m.install_id}/reset-link`);
    await adminPost(`/admin/machine/${m.install_id}/revoke`);
    await adminPost(`/admin/machine/${m.install_id}/restore`);
    await adminPost(`/admin/machine/${m.install_id}/forget`);
    const rows = await env.DB.prepare("SELECT who, action, target, detail FROM audit ORDER BY id").all<Record<string, string>>();
    expect(rows.results.map((r) => r.action)).toEqual([
      "role.create", "invite.create", "machine.enroll", "machine.reset_link", "machine.revoke", "machine.restore", "machine.forget",
    ]);
    const all = JSON.stringify(rows.results);
    expect(all).not.toContain(m.code);
    expect(all).not.toContain(m.token);
    expect(rows.results[3].who).toBe("admin token");
  });

  it("escapes role names, notes, emails and hostnames everywhere", async () => {
    const evil = `<script>alert(1)</script>"'`;
    const roleId = await makeRole(`Dev ${evil}`, { name: evil });
    const [code] = await makeInvites(["an@acme.com"], roleId, { note: evil });
    const res = await enroll({ code, host: { os: evil, arch: evil, hostname: evil }, version: evil });
    const m = await res.json<{ install_id: string; token: string }>();
    await post(report({ host: { os: "darwin", arch: "arm64", hostname: evil } }), { token: m.token });
    for (const path of ["/admin", "/admin/roles", `/admin/roles/${roleId}`, "/admin/invites?status=all", "/admin/audit", `/admin/machine/${m.install_id}`]) {
      const res = await adminGet(path);
      expect(res.status, path).toBe(200);
      const body = await res.text();
      expect(body, path).not.toContain("<script>");
      expect(body, path).toContain("&lt;script&gt;");
    }
  });
});

describe("role policy helpers", () => {
  it("parses Go durations", () => {
    expect(goDuration("24h")).toBe(86400000);
    expect(goDuration("1h30m")).toBe(5400000);
    expect(goDuration("0")).toBe(0);
    expect(goDuration("15")).toBeNull();
    expect(goDuration("1d")).toBeNull();
  });

  it("accepts the README example structure", () => {
    const now = new Date("2026-11-10T00:00:00Z");
    expect(
      validateRolePolicy(
        {
          name: "Acme",
          report: { interval: "24h", include_evidence: false, email_domains: ["acme.com"] },
          update: { binary: true, interval: "24h", repo: "ptrinh/bordercheck", public_key: "" },
          notify: { enabled: true, statuses: ["fail"], severities: ["high", "medium"], remind_every: "24h" },
          waivers: [{ check: "listeners", email: "an@acme.com", until: "2026-12-01", reason: "Postgres" }],
          checks: { listeners: { on_problem: "fail", allow: [{ process: "rapportd" }] }, tailscale: { enabled: false } },
        },
        now,
      ),
    ).toEqual([]);
  });

  it("composePolicy strips tokens, drops stale waivers and other people's", () => {
    const now = new Date("2026-11-10T12:00:00Z");
    const p = composePolicy(
      {
        report: { headers: { Authorization: "Bearer x", "X-Other": "keep", "X-Leak": "{{REPORT_TOKEN}}" } },
        waivers: [
          { check: "docker", email: "AN@acme.com", until: "2026-12-01", reason: "ok" },
          { check: "docker", install_id: "other", until: "2026-12-01", reason: "no" },
          { check: "docker", email: "an@acme.com", until: "2020-01-01", reason: "stale" },
        ],
      },
      "Dev",
      { install_id: "abc", email: "an@acme.com" },
      [
        { check_id: "firewall", until: "2026-11-09", reason: "just ended" },
        { check_id: "made-up", until: "2026-12-01", reason: "unknown check" },
      ],
      "https://bordercheck.acme.com",
      now,
    );
    expect(p.name).toBe("Dev");
    expect((p.report as any).headers).toEqual({ "X-Other": "keep" });
    expect(p.waivers).toEqual([
      { check: "docker", email: "AN@acme.com", until: "2026-12-01", reason: "ok" },
      { check: "firewall", install_id: "abc", until: "2026-11-09", reason: "just ended" },
    ]);
  });
});

describe("sample policy", () => {
  it("is offered on the roles page, fills the box, and can be saved as it is", async () => {
    const plain = await (await adminGet("/admin/roles")).text();
    expect(plain).toContain("Paste sample policy");
    expect(plain).not.toContain("max_lock_minutes");
    const filled = await (await adminGet("/admin/roles?sample=1")).text();
    expect(filled).toContain("max_lock_minutes");
    expect(filled).toContain("&quot;ai-agents&quot;");
    const { SAMPLE_POLICY } = await import("../src/portal");
    expect(validateRolePolicy(JSON.parse(SAMPLE_POLICY), new Date())).toEqual([]);
    const res = await adminPost("/admin/roles", { name: "From sample", policy: SAMPLE_POLICY });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("created");
  });
});
