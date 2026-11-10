import { describe, expect, it } from "vitest";
import { ADMIN_TOKEN, adminGet, BASE, call, enrolled, env, post, report, result } from "./helpers";

const ID = "4f1c0000aaaabbbbccccdddd";

describe("dashboard auth", () => {
  it("is not public", async () => {
    const res = await call(new Request(`${BASE}/admin`));
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe("/admin/login");
    expect((await call(new Request(`${BASE}/admin/machine/${ID}`, { headers: { authorization: "Bearer nope-nope-nope-nope" } }))).status).toBe(401);
  });

  it("is off without Access or an admin token", async () => {
    expect((await call(new Request(`${BASE}/admin`), { ADMIN_TOKEN: "" })).status).toBe(503);
    expect((await call(new Request(`${BASE}/admin`), { ADMIN_TOKEN: "too-short" })).status).toBe(503);
  });

  it("does not accept a machine token", async () => {
    const m = await enrolled();
    const res = await call(new Request(`${BASE}/admin`, { headers: { authorization: `Bearer ${m.token}` } }));
    expect(res.status).toBe(401);
  });

  it("signs in with the admin token and a same-origin form post", async () => {
    const form = (token: string, origin = BASE) =>
      call(new Request(`${BASE}/admin/login`, { method: "POST", headers: { origin }, body: new URLSearchParams({ token }) }));
    expect((await form("wrong")).status).toBe(401);
    expect((await form(ADMIN_TOKEN, "https://evil.example")).status).toBe(403);
    const ok = await form(ADMIN_TOKEN);
    expect(ok.status).toBe(303);
    const cookie = ok.headers.get("set-cookie")!;
    expect(cookie).toMatch(/HttpOnly; Secure; SameSite=Strict/);
    const session = cookie.split(";")[0];
    expect((await call(new Request(`${BASE}/admin`, { headers: { cookie: session } }))).status).toBe(200);
    // A tampered session fails. (Not the last character: its low bits are
    // base64 padding, so A and B there can decode to the same signature.)
    const dot = session.indexOf(".") + 3;
    const bad = session.slice(0, dot) + (session[dot] === "A" ? "B" : "A") + session.slice(dot + 1);
    expect((await call(new Request(`${BASE}/admin`, { headers: { cookie: bad } }))).status).toBe(303);
    // Changing ADMIN_TOKEN signs everyone out.
    expect((await call(new Request(`${BASE}/admin`, { headers: { cookie: session } }), { ADMIN_TOKEN: "another-admin-token-xyz" })).status).toBe(303);
    // Cookie-authenticated writes need a same-origin request.
    const m = await enrolled();
    await post(report(), { token: m.token });
    const machines = () => env.DB.prepare("SELECT COUNT(*) AS n FROM machines").first<number>("n");
    const forget = (origin: string) =>
      call(new Request(`${BASE}/admin/machine/${m.install_id}/forget`, { method: "POST", headers: { cookie: session, origin } }));
    expect((await forget("https://evil.example")).status).toBe(403);
    expect(await machines()).toBe(1);
    expect((await forget(BASE)).status).toBe(303);
    expect(await machines()).toBe(0);
    // The enrollment stays, so the page now says no report has arrived.
    expect(await (await adminGet(`/admin/machine/${m.install_id}`)).text()).toContain("no report has arrived yet");
  });

  it("accepts a browser's form post, which says Origin: null under no-referrer", async () => {
    // What Chrome, Firefox and Safari send from a page with Referrer-Policy: no-referrer.
    const browser = (site: string) =>
      call(new Request(`${BASE}/admin/login`, {
        method: "POST",
        headers: { origin: "null", "sec-fetch-site": site },
        body: new URLSearchParams({ token: ADMIN_TOKEN }),
      }));
    expect((await browser("same-origin")).status).toBe(303);
    expect((await browser("cross-site")).status).toBe(403);
    expect((await browser("same-site")).status).toBe(403);
    // "null" with no Sec-Fetch-Site proves nothing.
    const bare = await call(new Request(`${BASE}/admin/login`, { method: "POST", headers: { origin: "null" }, body: new URLSearchParams({ token: ADMIN_TOKEN }) }));
    expect(bare.status).toBe(403);
    // The sign-in page really is served with no-referrer, which is what makes browsers do this.
    expect((await call(new Request(`${BASE}/admin/login`))).headers.get("referrer-policy")).toBe("no-referrer");
  });
});

describe("dashboard pages", () => {
  const evil = '<script>alert(1)</script>';
  it("escapes everything from the report", async () => {
    const m = await enrolled();
    const ID = m.install_id;
    const attr = `x"><img src=x onerror=alert(1)>`;
    await post(
      report({ version: attr, policy: evil, host: { os: attr, arch: evil, hostname: evil } }, [
        result("firewall", "fail", { severity: "high", title: evil, summary: evil, fix: evil, evidence: [evil, "a&b"] }),
        result(`<b>id</b>`, "warn", { title: attr, severity: attr }),
      ]),
      { token: m.token },
    );
    for (const path of ["/admin", `/admin/machine/${ID}`, "/admin/checks", "/admin/checks/firewall", "/admin/alerts"]) {
      const res = await adminGet(path);
      expect(res.status, path).toBe(200);
      expect(res.headers.get("content-security-policy")).toContain("default-src 'none'");
      const body = await res.text();
      expect(body, path).not.toContain("<script>");
      expect(body, path).not.toContain("<img");
      expect(body, path).not.toContain("<b>id</b>");
    }
    const body = await (await adminGet(`/admin/machine/${ID}`)).text();
    expect(body).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(body).toContain("a&amp;b");
  });

  it("lists machines, filters non-compliant, shows waivers and unknown statuses", async () => {
    const an = await enrolled("an@acme.com");
    const boM = await enrolled("bo@acme.com");
    await post(report(), { token: an.token });
    await post(
      report({ host: { os: "linux", arch: "amd64", hostname: "bo-box" } }, [
        result("os-updates", "waived", { severity: "high", waived: { until: "2099-01-31", reason: "Vendor patch due" } }),
        result("screen-lock", "brand-new-status"),
        result("firewall", "pass"),
      ]),
      { token: boM.token },
    );
    const all = await (await adminGet("/admin")).text();
    expect(all).toContain("an@acme.com");
    expect(all).toContain("bo@acme.com");
    const failing = await (await adminGet("/admin?filter=failing")).text();
    expect(failing).toContain("an@acme.com");
    expect(failing).not.toContain("bo@acme.com");
    const search = await (await adminGet("/admin?q=bo-b")).text();
    expect(search).toContain("bo@acme.com");
    expect(search).not.toContain("an@acme.com");

    const bo = await (await adminGet(`/admin/machine/${boM.install_id}`)).text();
    expect(bo).toContain("Waived until 2099-01-31");
    expect(bo).toContain("Vendor patch due");
    expect(bo).toContain("brand-new-status");
    expect(bo).not.toContain("Nothing failing");

    const checks = await (await adminGet("/admin/checks")).text();
    expect(checks.indexOf("firewall")).toBeLessThan(checks.indexOf("os-updates"));
    expect(checks).toContain("screen-lock");
    const fw = await (await adminGet("/admin/checks/firewall?status=fail")).text();
    expect(fw).toContain("an@acme.com");
    expect(fw).not.toContain("bo@acme.com");
  });

  it("shows when a check started failing", async () => {
    const m = await enrolled();
    await post(report(), { token: m.token });
    const body = await (await adminGet(`/admin/machine/${m.install_id}`)).text();
    expect(body).toMatch(/since \d{4}-\d{2}-\d{2}/);
    expect(body).toContain("Turn it on.");
  });

  it("returns 404 for unknown machines and paths", async () => {
    expect((await adminGet("/admin/machine/does-not-exist")).status).toBe(404);
    expect((await adminGet("/admin/nothing")).status).toBe(404);
    expect((await call(new Request(`${BASE}/nothing`))).status).toBe(404);
  });
});

describe("site icon", () => {
  it("is served without sign-in and linked from every page", async () => {
    for (const p of ["/favicon.svg", "/favicon.ico"]) {
      const res = await call(new Request(`${BASE}${p}`));
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toBe("image/svg+xml");
      expect(await res.text()).toContain("<svg");
    }
    expect(await (await call(new Request(`${BASE}/admin/login`))).text()).toContain('rel="icon" type="image/svg+xml" href="/favicon.svg"');
  });
});
