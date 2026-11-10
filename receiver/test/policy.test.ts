import { describe, expect, it } from "vitest";
import { ADMIN_TOKEN, BASE, call, env, REPORT_TOKEN } from "./helpers";

const policy = {
  name: "Acme",
  report: { url: `${BASE}/report`, headers: { Authorization: `Bearer ${REPORT_TOKEN}` }, interval: "24h" },
  update: { policy_url: `${BASE}/policies.json` },
};

const put = (body: string, e = {}) =>
  call(new Request(`${BASE}/admin/policies.json`, { method: "PUT", headers: { authorization: `Bearer ${ADMIN_TOKEN}` }, body }), e);

describe("policies.json", () => {
  it("404s until a policy is uploaded", async () => {
    expect((await call(new Request(`${BASE}/policies.json`))).status).toBe(404);
  });

  it("stores the token as a placeholder and fills it in when served", async () => {
    expect((await put(JSON.stringify(policy))).status).toBe(200);
    const stored = await env.DB.prepare("SELECT value FROM meta WHERE key = 'policies.json'").first<string>("value");
    expect(stored).not.toContain(REPORT_TOKEN);
    expect(stored).toContain("Bearer {{REPORT_TOKEN}}");

    const res = await call(new Request(`${BASE}/policies.json`));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(policy);

    // Rotating the secret changes what is served, no re-upload needed.
    const rotated = await (await call(new Request(`${BASE}/policies.json`), { REPORT_TOKEN: "rotated-token-0123456789" })).json<any>();
    expect(rotated.report.headers.Authorization).toBe("Bearer rotated-token-0123456789");
  });

  it("rejects bad uploads and needs admin auth", async () => {
    expect((await put("{nope")).status).toBe(400);
    expect((await put("[1]")).status).toBe(400);
    const anon = await call(new Request(`${BASE}/admin/policies.json`, { method: "PUT", body: "{}" }));
    expect(anon.status).toBe(401);
    const withReportToken = await call(
      new Request(`${BASE}/admin/policies.json`, { method: "PUT", headers: { authorization: `Bearer ${REPORT_TOKEN}` }, body: "{}" }),
    );
    expect(withReportToken.status).toBe(401);
  });

  it("needs ?key= when POLICY_KEY is set", async () => {
    await put(JSON.stringify(policy));
    const e = { POLICY_KEY: "policy-key-0123456789" };
    expect((await call(new Request(`${BASE}/policies.json`), e)).status).toBe(404);
    expect((await call(new Request(`${BASE}/policies.json?key=wrong`), e)).status).toBe(404);
    expect((await call(new Request(`${BASE}/policies.json?key=policy-key-0123456789`), e)).status).toBe(200);
  });

  it("the dashboard form escapes the stored policy", async () => {
    await put(JSON.stringify({ name: "</textarea><script>x</script>" }));
    const body = await (await call(new Request(`${BASE}/admin/policy`, { headers: { authorization: `Bearer ${ADMIN_TOKEN}` } }))).text();
    expect(body).not.toContain("<script");
    expect(body).toContain("&lt;/textarea&gt;");
  });
});
