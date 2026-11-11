import { describe, expect, it } from "vitest";
import { COPY_CSP, COPY_SCRIPT } from "../src/html";
import { ADMIN_TOKEN, adminPost, BASE, call, enrolled, env, post, report } from "./helpers";

const open = (url: string, ip: string) => call(new Request(url, { headers: { "cf-connecting-ip": ip } }));

describe("a public report link issued by an admin", () => {
  it("is shown once with a Copy button, opens that machine's report, and is audited", async () => {
    const m = await enrolled();
    const own = (await (await post(report(), { token: m.token })).json<{ report_url: string }>()).report_url;

    const res = await adminPost(`/admin/machine/${m.install_id}/report-link`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-security-policy")).toBe(COPY_CSP);
    const body = await res.text();
    const link = new RegExp(`id="report-link">(${BASE}/r/[A-Za-z0-9_-]{32})</code>`).exec(body)?.[1] ?? "";
    expect(link).not.toBe("");
    expect(link).not.toBe(own);
    expect(body).toMatch(/<button[^>]* hidden data-copy="report-link"/);
    expect(body.split("<script>").length).toBe(2);
    expect(body).toContain(`<script>${COPY_SCRIPT}</script>`);

    // It opens the machine's report without sign-in, and the machine's own link still works.
    const page = await open(link, "203.0.113.60");
    expect(page.status).toBe(200);
    expect(await page.text()).toContain("an@acme.com");
    expect((await open(own, "203.0.113.61")).status).toBe(200);

    // Only its hash is stored, and the audit trail says who made it.
    const stored = await env.DB.prepare("SELECT link_hash FROM report_links").all<{ link_hash: string }>();
    expect(stored.results.length).toBe(2);
    expect(JSON.stringify(stored.results)).not.toContain(link.split("/r/")[1]);
    const audit = await env.DB.prepare("SELECT who, target, detail FROM audit WHERE action = 'machine.issue_link'").first<{ who: string; target: string; detail: string }>();
    expect(audit?.target).toBe(m.install_id);
    expect(audit?.detail).not.toContain(link.split("/r/")[1]);

    // The machine page offers the button; resetting the links ends this one too.
    expect(await (await call(new Request(`${BASE}/admin/machine/${m.install_id}`, { headers: { authorization: `Bearer ${ADMIN_TOKEN}` } }))).text()).toContain(
      `action="/admin/machine/${m.install_id}/report-link"`,
    );
    expect((await adminPost(`/admin/machine/${m.install_id}/reset-link`)).status).toBe(303);
    expect((await open(link, "203.0.113.62")).status).toBe(404);
  });

  it("is refused for a machine that has not reported, a revoked one and an unknown one", async () => {
    const m = await enrolled("bo@acme.com");
    const none = await adminPost(`/admin/machine/${m.install_id}/report-link`);
    expect(none.status).toBe(409);
    expect(await none.text()).toContain("has not sent a report yet");

    await post(report(), { token: m.token });
    expect((await adminPost(`/admin/machine/${m.install_id}/revoke`)).status).toBe(303);
    const revoked = await adminPost(`/admin/machine/${m.install_id}/report-link`);
    expect(revoked.status).toBe(409);
    expect(await revoked.text()).toContain("revoked");

    expect((await adminPost("/admin/machine/ffffffffffffffffffffffffffffffff/report-link")).status).toBe(404);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM report_links").first<number>("n")).toBe(0);

    // Turned off for the whole portal.
    const off = await adminPost(`/admin/machine/${m.install_id}/report-link`, {}, { REPORT_LINKS: "off" });
    expect(off.status).toBe(409);
  });
});
