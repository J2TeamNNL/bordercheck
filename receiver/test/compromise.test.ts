// Signs of compromise: a report that says "compromised": true, from parsing to
// the pages, the API and an alert delivered at ingest.
import { describe, expect, it } from "vitest";
import { alertLine, runCron } from "../src/alerts";
import { machineRows } from "../src/dashboard";
import type { Env } from "../src/env";
import { alertItem, fleetSummary, machineDetail, machineSummary } from "../src/fleet";
import { handleReport } from "../src/ingest";
import { parseReport } from "../src/report";
import { validateRolePolicy } from "../src/roles";
import { ADMIN_TOKEN, adminGet, BASE, call, enrolled, env, post, report, reportRequest, result } from "./helpers";

const DISCORD = "https://discord.com/api/webhooks/123/abc";
const HOOK = "https://example.com/hook";
const day = (d: number, h = 10) => new Date(Date.UTC(2026, 10, d, h));

const sign = (key: string, detail?: string, params?: Record<string, string>) => ({ what: { key, ...(params ? { params } : {}) }, ...(detail ? { detail } : {}) });
const startupFail = (detail = "LaunchAgent ~/Library/LaunchAgents/com.x.plist (com.x)") =>
  result("startup-items", "fail", { severity: "high", compromise: [sign("compromise.startupDownloadRun", detail)] });

// A report from a newer client that shows signs of compromise.
const compromised = (detail?: string) =>
  report({ compromised: true, compromise_checks: ["startup-items"] }, [startupFail(detail), result("firewall", "pass")]);
const clean = () => report({}, [result("startup-items", "pass"), result("firewall", "pass")]);

function recorder(fail = false) {
  const calls: { url: string; body: any }[] = [];
  const send = async (url: string, body: unknown) => {
    if (fail) throw new Error("webhook answered 500");
    calls.push({ url, body });
  };
  return { calls, send };
}

async function alerts() {
  return (await env.DB.prepare("SELECT kind, sent_at, delivery, detail FROM alerts ORDER BY id").all<{ kind: string; sent_at: string | null; delivery: string; detail: string }>()).results;
}

describe("parsing", () => {
  it("reads the flag, the check ids and each sign, bounded; malformed parts are dropped", () => {
    const r = parseReport(
      report({ compromised: true, compromise_checks: ["startup-items", "startup-items", "has space", 7, "x".repeat(100)] }, [
        result("startup-items", "fail", {
          compromise: [
            sign("compromise.startupDownloadRun", "a\nb"),
            sign("compromise.kmsEmulator", "127.0.0.2:1688", { product: "Windows" }),
            { what: { key: "NOT A KEY" } },
            { what: "x" },
            { what: { key: "compromise.crackTool" }, detail: 5 },
            null,
          ],
        }),
        result("extensions", "pass", { compromise: [sign("compromise.blockedExtension")] }),
      ]),
    );
    expect(r.compromised).toBe(true);
    expect(r.compromiseChecks).toEqual(["startup-items", "x".repeat(64) + "…"]);
    expect(r.results[0].compromise).toEqual([
      { what: { key: "compromise.startupDownloadRun", params: {} }, detail: "a b" },
      { what: { key: "compromise.kmsEmulator", params: { product: "Windows" } }, detail: "127.0.0.2:1688" },
    ]);
    // Only a fail carries signs.
    expect(r.results[1].compromise).toBeUndefined();
  });

  it("an older client's report, or anything but true, is not compromised", () => {
    for (const v of [undefined, "true", 1, false, null, {}]) {
      const r = parseReport(report({ compromised: v, compromise_checks: ["startup-items"] }));
      expect(r.compromised, String(v)).toBe(false);
      expect(r.compromiseChecks).toEqual([]);
    }
    // The flag without a list: the checks come from the results' signs.
    expect(parseReport(report({ compromised: true }, [startupFail()])).compromiseChecks).toEqual(["startup-items"]);
  });

  it("role policies accept report.compromise_alert as a boolean only", () => {
    expect(validateRolePolicy({ report: { compromise_alert: false } }, new Date())).toEqual([]);
    expect(validateRolePolicy({ report: { compromise_alert: "no" } }, new Date()).map((m) => m.key)).toEqual(["v.mustBool"]);
  });
});

describe("migration 0004", () => {
  it("adds machines.compromised_since (NULL by default) and reports.compromised (0 by default)", async () => {
    const cols = async (t: string) => (await env.DB.prepare(`PRAGMA table_info(${t})`).all<{ name: string; dflt_value: string | null; notnull: number }>()).results;
    expect((await cols("machines")).find((c) => c.name === "compromised_since")).toMatchObject({ notnull: 0, dflt_value: null });
    expect((await cols("reports")).find((c) => c.name === "compromised")).toMatchObject({ notnull: 1, dflt_value: "0" });
  });
});

describe("ingest and alerts", () => {
  it("raises one alert per episode, delivers it to the webhook at once, and clears it", async () => {
    const m = await enrolled("comp-an@domain.com");
    const e: Env = { ...env, ALERT_WEBHOOK_URL: DISCORD, DASHBOARD_URL: "https://bordercheck.example.com" };
    const r = recorder();
    const req = (body: unknown) => reportRequest(body, m.token);

    await handleReport(req(clean()), e, day(1), undefined, { send: r.send });
    expect(r.calls).toHaveLength(0);

    // Compromised: delivered by the report itself, not the cron.
    const res = await handleReport(req(compromised()), e, day(2), undefined, { send: r.send });
    expect(res.status).toBe(200);
    expect(r.calls).toHaveLength(1);
    const content: string = r.calls[0].body.content;
    expect(content).toContain("SIGNS OF COMPROMISE in `startup-items`");
    expect(content).toContain("`comp-an@domain.com`");
    expect(content).toContain(`https://bordercheck.example.com/admin/machine/${m.install_id}`);
    expect(content).not.toContain("com.x.plist"); // which item stays on the machine page
    const row = await env.DB.prepare("SELECT compromised_since FROM machines WHERE install_id = ?").bind(m.install_id).first<string>("compromised_since");
    expect(row).toBe(day(2).toISOString());
    // The high-severity fail raised with it still waits for the cron.
    expect((await alerts()).map((a) => [a.kind, a.sent_at ? "sent" : "pending"])).toEqual([["high_fail", "pending"], ["compromised", "sent"]]);

    // Still compromised, even with another item: no new alert, the episode keeps its start.
    await handleReport(req(compromised("LaunchAgent ~/Library/LaunchAgents/com.y.plist (com.y)")), e, day(3), undefined, { send: r.send });
    expect(r.calls).toHaveLength(1);
    expect(await env.DB.prepare("SELECT compromised_since FROM machines WHERE install_id = ?").bind(m.install_id).first<string>("compromised_since")).toBe(day(2).toISOString());

    // Cleared: a note goes at once, and the machine is no longer compromised.
    await handleReport(req(clean()), e, day(4), undefined, { send: r.send });
    expect(r.calls).toHaveLength(2);
    expect(r.calls[1].body.content).toContain("no longer reports signs of compromise (reported since 2026-11-02)");
    expect(await env.DB.prepare("SELECT compromised_since FROM machines WHERE install_id = ?").bind(m.install_id).first("compromised_since")).toBeNull();

    // A new episode alerts again.
    await handleReport(req(compromised()), e, day(5), undefined, { send: r.send });
    expect(r.calls).toHaveLength(3);
    expect((await alerts()).filter((a) => a.kind.startsWith("compromise")).map((a) => a.kind)).toEqual(["compromised", "compromise_cleared", "compromised"]);

    // The cron sends the rest and never repeats these.
    await runCron({ ...e, DIGEST_HOURS: "0" }, day(5, 11), r.send);
    expect(r.calls.slice(3).map((c) => c.body.content).join("\n")).not.toContain("SIGNS OF COMPROMISE");
    // The history records which reports said so.
    const hist = (await env.DB.prepare("SELECT compromised FROM reports WHERE install_id = ? ORDER BY id").bind(m.install_id).all<{ compromised: number }>()).results;
    expect(hist.map((h) => h.compromised)).toEqual([0, 1, 1, 0, 1]);
  });

  it("goes after the response with waitUntil; a failed webhook leaves it for the cron", async () => {
    const m = await enrolled("comp-bo@domain.com");
    const e: Env = { ...env, ALERT_WEBHOOK_URL: HOOK, DIGEST_HOURS: "0" };
    const waits: Promise<unknown>[] = [];
    const down = recorder(true);
    const res = await handleReport(reportRequest(compromised(), m.token), e, day(1), undefined, { send: down.send, waitUntil: (p) => waits.push(p) });
    expect(res.status).toBe(200);
    expect(waits).toHaveLength(1);
    await Promise.all(waits);
    expect((await alerts()).find((a) => a.kind === "compromised")?.sent_at).toBeNull();

    const up = recorder();
    await runCron(e, day(1, 11), up.send);
    const body = up.calls[0].body;
    expect(body.text).toContain("SIGNS OF COMPROMISE");
    // The JSON payload carries the alert with its checks.
    expect(body.alerts.find((a: any) => a.kind === "compromised")).toMatchObject({ kind: "compromised", install_id: m.install_id, checks: "startup-items" });
  });

  it("without a webhook the alert is still listed on the Alerts page", async () => {
    const m = await enrolled("comp-cy@domain.com");
    const res = await post(compromised(), { token: m.token });
    expect(res.status).toBe(200);
    const a = (await alerts()).find((x) => x.kind === "compromised")!;
    expect(a.delivery).toBe("no webhook");
    const page = await (await adminGet("/admin/alerts")).text();
    expect(page).toContain("compromised");
    expect(page).toContain("<code>startup-items</code>");
    expect(alertItem({ id: 1, kind: "compromised", install_id: m.install_id, check_id: "", detail: a.detail, created_at: "x", sent_at: "y", delivery: "no webhook" }).untrusted).toMatchObject({ checks: "startup-items" });
  });

  it("webhook lines keep machine-supplied check ids inert", () => {
    const line = alertLine({ ...env, DASHBOARD_URL: "" } as Env, {
      id: 1, kind: "compromised", install_id: "x", check_id: "",
      detail: JSON.stringify({ email: "a@b", hostname: "h", checks: "@everyone, `x`\n[link](https://evil.example)" }), created_at: "",
    });
    expect(line).toContain("`@everyone`");
    expect(line).not.toContain("\n");
  });

  it("an older client's report never marks a machine compromised", async () => {
    const m = await enrolled("comp-dee@domain.com");
    await post(report({}, [result("startup-items", "fail", { severity: "high" })]), { token: m.token });
    expect((await alerts()).map((a) => a.kind)).toEqual(["high_fail"]);
    expect(await env.DB.prepare("SELECT compromised_since FROM machines WHERE install_id = ?").bind(m.install_id).first("compromised_since")).toBeNull();
  });
});

describe("pages", () => {
  const hostile = `<img src=x onerror=alert(1)> & "q"`;

  it("the overview has a Compromised tile and filter, sorts it first, and badges it", async () => {
    const ok = await enrolled("comp-ok@domain.com");
    await post(report({}, [result("firewall", "fail", { severity: "high" })]), { token: ok.token });
    const bad = await enrolled("comp-bad@domain.com");
    await post(compromised(), { token: bad.token });

    const all = await (await adminGet("/admin")).text();
    expect(all).toContain(`href="/admin?filter=compromised"`);
    expect(all).toContain("signs of compromise in the latest report");
    expect(all).toContain(`<span class="pill s-comp">compromised</span>`);
    expect(all.indexOf("comp-bad@domain.com")).toBeLessThan(all.indexOf("comp-ok@domain.com"));

    const only = await (await adminGet("/admin?filter=compromised")).text();
    expect(only).toContain("comp-bad@domain.com");
    expect(only).not.toContain("comp-ok@domain.com");
  });

  it("the machine page has a banner with each sign, escaped, and since when", async () => {
    const m = await enrolled("comp-ed@domain.com");
    await post(
      report({ compromised: true, compromise_checks: ["startup-items", "cracked-software"] }, [
        startupFail(hostile),
        result("cracked-software", "fail", { severity: "high", compromise: [sign("compromise.kmsEmulator", undefined, { product: "<b>Windows</b>" })] }),
      ]),
      { token: m.token },
    );
    const body = await (await adminGet(`/admin/machine/${m.install_id}`)).text();
    expect(body).toContain(`<div class="note s-comp" role="alert">`);
    expect(body).toContain("This machine may be compromised");
    expect(body).toContain("A program set to start automatically downloads code from the internet and runs it.");
    expect(body).toContain("&lt;img src=x onerror=alert(1)&gt; &amp; &quot;q&quot;");
    expect(body).toContain("&lt;b&gt;Windows&lt;/b&gt; is activated by a fake activation server");
    expect(body).toContain("which item it is was not sent");
    expect(body).not.toContain("<img src=x");
    expect(body).not.toContain("<b>Windows</b>");
    expect(body.indexOf("This machine may be compromised")).toBeLessThan(body.indexOf("Needs attention"));

    // In Vietnamese and Chinese too.
    for (const [lang, want] of [["vi", "Máy này có thể đã bị xâm nhập"], ["zh", "这台机器可能已被入侵"]]) {
      const res = await call(new Request(`${BASE}/admin/machine/${m.install_id}`, { headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "accept-language": lang } }));
      expect(await res.text()).toContain(want);
    }

    // Cleared: no banner.
    await post(clean(), { token: m.token });
    expect(await (await adminGet(`/admin/machine/${m.install_id}`)).text()).not.toContain("may be compromised");
  });

  it("the report page tells the person to stop and contact IT, with check titles only", async () => {
    const m = await enrolled("comp-fay@domain.com");
    const res = await post(compromised(hostile), { token: m.token });
    const { report_url } = await res.json<{ report_url: string }>();
    const page = await (await call(new Request(report_url.replace("https://bordercheck.example.com", BASE)))).text();
    expect(page).toContain("Stop: this computer may be compromised");
    expect(page).toContain("(Nothing unexpected starts at login)");
    expect(page).toContain("contact your IT team now");
    expect(page).not.toContain("onerror");
    expect(page).not.toContain("com.x");
    expect(page).not.toContain("bordercheck fix"); // no fix prompt: nothing is cleaned up before IT looks

    const old = await enrolled("comp-gus@domain.com");
    const r2 = await post(report(), { token: old.token });
    const p2 = await (await call(new Request((await r2.json<{ report_url: string }>()).report_url.replace("https://bordercheck.example.com", BASE)))).text();
    expect(p2).not.toContain("may be compromised");
  });
});

describe("MCP and REST", () => {
  it("machine summaries, detail and the fleet summary carry compromised and since", async () => {
    const m = await enrolled("comp-hal@domain.com");
    await post(
      report({ compromised: true, compromise_checks: ["startup-items"] }, [startupFail(), result("firewall", "pass")]),
      { token: m.token, e: {} },
    );
    const other = await enrolled("comp-ida@domain.com");
    await post(clean(), { token: other.token });

    const now = new Date();
    const silent = new Date(0).toISOString();
    const rows = await machineRows(env, { filter: "compromised", q: "", silentBefore: silent, limit: 10 });
    expect(rows.map((r) => r.install_id)).toEqual([m.install_id]);
    const s = machineSummary(env, rows[0], silent);
    expect(s.compromised).toBe(true);
    expect(typeof s.compromised_since).toBe("string");
    const o = machineSummary(env, (await machineRows(env, { filter: "all", q: "comp-ida", silentBefore: silent, limit: 10 }))[0], silent);
    expect(o).toMatchObject({ compromised: false, compromised_since: null });

    expect(((await fleetSummary(env, now)).machines as Record<string, number>).compromised).toBe(1);

    const plain = await machineDetail(env, m.install_id, {}, now);
    const d = (plain.ok ? plain.data : {}) as Record<string, any>;
    expect(d.compromise).toMatchObject({ checks: [{ check_id: "startup-items" }], signs: [{ check_id: "startup-items", sign: "compromise.startupDownloadRun", untrusted: {} }] });
    expect(JSON.stringify(d.compromise)).not.toContain("com.x");
    const full = await machineDetail(env, m.install_id, { evidence: true }, now);
    expect(((full.ok ? full.data : {}) as Record<string, any>).compromise.signs[0].untrusted.item).toBe("LaunchAgent ~/Library/LaunchAgents/com.x.plist (com.x)");
    const od = await machineDetail(env, other.install_id, {}, now);
    expect(((od.ok ? od.data : {}) as Record<string, any>).compromise).toBeUndefined();

    // Through the REST API.
    const API = "test-api-read-token-0123456789ab";
    const api = await call(new Request(`${BASE}/api/v1/machines?state=compromised`, { headers: { authorization: `Bearer ${API}` } }), { API_READ_TOKEN: API });
    expect(api.status).toBe(200);
    const list = await api.json<{ data: { install_id: string; compromised: boolean }[] }>();
    expect(list.data).toEqual([expect.objectContaining({ install_id: m.install_id, compromised: true })]);
    const sum = await call(new Request(`${BASE}/api/v1/summary`, { headers: { authorization: `Bearer ${API}` } }), { API_READ_TOKEN: API });
    expect((await sum.json<{ machines: { compromised: number } }>()).machines.compromised).toBe(1);
  });
});
