import { describe, expect, it } from "vitest";
import { handleReport } from "../src/ingest";
import { parseReport, statusRank } from "../src/report";
import { BASE, env, post, REPORT_TOKEN, report, result } from "./helpers";

const db = () => env.DB;

function req(body: unknown) {
  return new Request(`${BASE}/report`, {
    method: "POST",
    headers: { authorization: `Bearer ${REPORT_TOKEN}` },
    body: JSON.stringify(body),
  });
}

describe("auth", () => {
  it("refuses a missing or wrong token", async () => {
    expect((await post(report(), { token: null })).status).toBe(401);
    expect((await post(report(), { token: "wrong-token-but-long-enough" })).status).toBe(401);
    expect(await db().prepare("SELECT COUNT(*) n FROM machines").first("n")).toBe(0);
  });

  it("fails closed without a usable REPORT_TOKEN", async () => {
    expect((await post(report(), { e: { REPORT_TOKEN: "" } })).status).toBe(503);
    expect((await post(report(), { token: "short", e: { REPORT_TOKEN: "short" } })).status).toBe(503);
  });

  it("accepts the previous token while rotating", async () => {
    const e = { REPORT_TOKEN: "new-token-0123456789abcdef", REPORT_TOKEN_PREVIOUS: REPORT_TOKEN };
    expect((await post(report(), { e })).status).toBe(200);
    expect((await post(report(), { token: "new-token-0123456789abcdef", e })).status).toBe(200);
  });
});

describe("validation", () => {
  it("rejects non-JSON, wrong tool, missing install_id", async () => {
    expect((await post("{not json")).status).toBe(400);
    expect((await post(report({ tool: "other" }))).status).toBe(400);
    expect((await post(report({ install_id: undefined }))).status).toBe(400);
    expect((await post(report({ install_id: "../../etc" }))).status).toBe(400);
    expect((await post(report({ results: "nope" }))).status).toBe(400);
    expect((await post([1, 2])).status).toBe(400);
  });

  it("rejects oversized bodies", async () => {
    const big = report({ pad: "x".repeat(300_000) });
    expect((await post(big)).status).toBe(413);
    expect((await post(report(), { e: { MAX_REPORT_BYTES: "2000" } })).status).toBe(200);
    expect((await post(report({ pad: "x".repeat(3000) }), { e: { MAX_REPORT_BYTES: "2000" } })).status).toBe(413);
  });

  it("accepts unknown fields, check ids, statuses and OSes", async () => {
    const r = report(
      { future_field: { a: 1 }, host: { os: "linux", arch: "riscv64", hostname: "box" } },
      [
        result("ai-agents", "fail", { severity: "high", new_thing: true }),
        result("tunnels", "mystery-status"),
        result("os-updates", "waived", { severity: "medium", waived: { until: "2026-12-31", reason: "vendor patch" } }),
      ],
    );
    const res = await post(r);
    expect(res.status).toBe(200);
    const m = await db().prepare("SELECT * FROM machines").first<Record<string, unknown>>();
    expect(m).toMatchObject({ os: "linux", fail: 1, high_fail: 1, waived: 1, other: 1, warn: 0 });
    expect(JSON.parse(m!.report as string).future_field).toEqual({ a: 1 }); // raw report kept
  });

  it("enforces ALLOWED_EMAIL_DOMAINS", async () => {
    const e = { ALLOWED_EMAIL_DOMAINS: "acme.com, @acme.co.uk" };
    expect((await post(report({ email: "an@ACME.com" }), { e })).status).toBe(200);
    expect((await post(report({ email: "x@acme.co.uk" }), { e })).status).toBe(200);
    expect((await post(report({ email: "x@evil.example" }), { e })).status).toBe(403);
    expect((await post(report({ email: "" }), { e })).status).toBe(403);
  });

  it("caps the number of machines", async () => {
    const e = { MAX_MACHINES: "1" };
    expect((await post(report(), { e })).status).toBe(200);
    expect((await post(report(), { e })).status).toBe(200); // same machine again is fine
    expect((await post(report({ install_id: "another-install-id-1" }), { e })).status).toBe(403);
  });
});

describe("storage", () => {
  it("keeps the latest report per install and a history", async () => {
    await handleReport(req(report()), env, new Date("2026-11-01T10:00:00Z"));
    await handleReport(
      req(report({}, [result("firewall", "fail", { severity: "high" }), result("secrets", "fail", { severity: "medium" })])),
      env,
      new Date("2026-11-02T10:00:00Z"),
    );
    await handleReport(
      req(report({}, [result("firewall", "pass"), result("secrets", "fail", { severity: "medium" })])),
      env,
      new Date("2026-11-03T10:00:00Z"),
    );
    expect(await db().prepare("SELECT COUNT(*) n FROM machines").first("n")).toBe(1);
    expect(await db().prepare("SELECT COUNT(*) n FROM reports").first("n")).toBe(3);
    const checks = await db().prepare("SELECT check_id, status, since FROM checks ORDER BY check_id").all();
    expect(checks.results).toEqual([
      { check_id: "firewall", status: "pass", since: "2026-11-03T10:00:00.000Z" },
      { check_id: "secrets", status: "fail", since: "2026-11-02T10:00:00.000Z" }, // when it started failing
    ]);
    const m = await db().prepare("SELECT first_seen, last_seen, fail FROM machines").first();
    expect(m).toEqual({ first_seen: "2026-11-01T10:00:00.000Z", last_seen: "2026-11-03T10:00:00.000Z", fail: 1 });
  });

  it("raises a high-fail alert only when a check newly fails high", async () => {
    const t = (d: string) => new Date(`2026-11-${d}T10:00:00Z`);
    const high = [result("firewall", "fail", { severity: "high" })];
    await handleReport(req(report({}, high)), env, t("01"));
    await handleReport(req(report({}, high)), env, t("02")); // still failing: no new alert
    await handleReport(req(report({}, [result("firewall", "fail", { severity: "medium" })])), env, t("03"));
    await handleReport(req(report({}, [result("firewall", "waived", { severity: "high" })])), env, t("04"));
    await handleReport(req(report({}, high)), env, t("05")); // waiver expired: alert again
    const alerts = await db().prepare("SELECT kind, check_id, created_at FROM alerts ORDER BY id").all();
    expect(alerts.results).toEqual([
      { kind: "high_fail", check_id: "firewall", created_at: t("01").toISOString() },
      { kind: "high_fail", check_id: "firewall", created_at: t("05").toISOString() },
    ]);
  });

  it("bounds history per machine", async () => {
    const e = { ...env, HISTORY_PER_MACHINE: "3" };
    for (let i = 0; i < 5; i++) await handleReport(req(report()), e, new Date(Date.UTC(2026, 10, 1, i)));
    const rows = await db().prepare("SELECT received_at FROM reports ORDER BY id").all();
    expect(rows.results.map((r) => r.received_at)).toEqual([
      "2026-11-01T02:00:00.000Z",
      "2026-11-01T03:00:00.000Z",
      "2026-11-01T04:00:00.000Z",
    ]);
  });
});

describe("parseReport", () => {
  it("caps strings and strips control characters", () => {
    const r = parseReport(report({ host: { hostname: "a\u0007b" + "x".repeat(400) } }, [result("x", "FAIL", { summary: "s".repeat(5000) })]));
    expect(r.host.hostname.startsWith("abx")).toBe(true);
    expect(r.host.hostname.length).toBe(256);
    expect(r.results[0].status).toBe("fail");
    expect(r.results[0].summary.length).toBe(2001);
  });

  it("orders statuses worst first with unknown ones before pass", () => {
    const order = ["skip", "pass", "new", "waived", "warn", "error", "fail"].sort((a, b) => statusRank(a) - statusRank(b));
    expect(order).toEqual(["fail", "error", "warn", "waived", "new", "pass", "skip"]);
  });
});
