import { describe, expect, it } from "vitest";
import { machineDetail } from "../src/fleet";
import { adminGet, adminPost, BASE, call, enrolled, env, getPolicy, post, report } from "./helpers";

const day = (n: number) => new Date(Date.now() + n * 86400_000).toISOString().slice(0, 10);

function ask(token: string | null, body: unknown, method = "POST") {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;
  return call(new Request(`${BASE}/waiver-requests`, { method, headers, body: method === "GET" ? undefined : typeof body === "string" ? body : JSON.stringify(body) }));
}

const good = (o: Record<string, unknown> = {}) => ({ check: "listeners", until: day(30), reason: "Postgres for the billing project", accept_risk: true, ...o });

describe("waiver requests from a machine", () => {
  it("creates a pending request with the machine's token, and lists it back", async () => {
    const m = await enrolled();
    const res = await ask(m.token, good());
    expect(res.status).toBe(201);
    const body = await res.json<{ request_id: number; status: string }>();
    expect(body.status).toBe("pending");
    const row = await env.DB.prepare("SELECT * FROM waiver_requests WHERE id = ?").bind(body.request_id).first<Record<string, unknown>>();
    expect(row).toMatchObject({ install_id: m.install_id, check_id: "listeners", until: day(30), accept_risk: 1, status: "pending" });
    expect(await env.DB.prepare("SELECT action FROM audit WHERE action = 'waiver_request.create'").first("action")).toBe("waiver_request.create");

    const list = await (await ask(m.token, null, "GET")).json<{ data: { request_id: number; check: string; status: string }[] }>();
    expect(list.data).toEqual([expect.objectContaining({ request_id: body.request_id, check: "listeners", status: "pending" })]);
    // Nothing reaches the policy until IT approves it.
    expect((await (await getPolicy(m.token)).json<{ waivers: unknown[] }>()).waivers).toEqual([]);
  });

  it("refuses requests without a valid token, from a revoked machine, or with bad fields", async () => {
    const m = await enrolled();
    expect((await ask(null, good())).status).toBe(401);
    expect((await ask("bc_" + "x".repeat(43), good())).status).toBe(401);
    for (const [o, text] of [
      [{ check: "no-such-check" }, "Check must be one of"],
      [{ check: "*" }, "Check must be one of"],
      [{ until: "2001-01-01" }, "in the past"],
      [{ until: day(400) }, "365 days"],
      [{ until: "soon" }, "date like"],
      [{ reason: "  " }, "reason is required"],
      [{ reason: "x".repeat(301) }, "longer than 300"],
      [{ accept_risk: false }, "accept the risk"],
      [{ accept_risk: "yes" }, "accept the risk"],
    ] as const) {
      const res = await ask(m.token, good(o));
      expect(res.status, JSON.stringify(o)).toBe(400);
      expect((await res.json<{ message: string }>()).message).toContain(text);
    }
    expect((await ask(m.token, "[1]")).status).toBe(400);
    expect((await ask(m.token, "x".repeat(5000))).status).toBe(413);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM waiver_requests").first("n")).toBe(0);

    await adminPost(`/admin/machine/${m.install_id}/revoke`);
    const res = await ask(m.token, good());
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "revoked" });
  });

  it("allows one pending request per check", async () => {
    const m = await enrolled();
    expect((await ask(m.token, good())).status).toBe(201);
    const again = await ask(m.token, good({ reason: "again" }));
    expect(again.status).toBe(409);
    expect((await again.json<{ error: string }>()).error).toBe("already_requested");
    expect((await ask(m.token, good({ check: "firewall" }))).status).toBe(201);
  });
});

describe("deciding waiver requests", () => {
  it("approve adds the waiver through the usual path and delivers it in the policy", async () => {
    const m = await enrolled();
    const { request_id } = await (await ask(m.token, good())).json<{ request_id: number }>();
    const page = await (await adminGet(`/admin/machine/${m.install_id}`)).text();
    expect(page).toContain("Waiver requests");
    expect(page).toContain(`/waiver-requests/${request_id}/approve`);
    expect(await (await adminGet("/admin")).text()).toContain("1 waiver request is waiting for a decision.");

    const res = await adminPost(`/admin/machine/${m.install_id}/waiver-requests/${request_id}/approve`);
    expect(res.status).toBe(303);
    const row = await env.DB.prepare("SELECT status, decided_by, waiver_id FROM waiver_requests WHERE id = ?").bind(request_id).first<{ status: string; decided_by: string; waiver_id: number }>();
    expect(row).toMatchObject({ status: "approved", decided_by: "admin token" });
    const w = await env.DB.prepare("SELECT id, check_id, until, reason, created_by FROM machine_waivers").first<Record<string, unknown>>();
    expect(w).toMatchObject({ id: row!.waiver_id, check_id: "listeners", until: day(30), reason: "Postgres for the billing project" });
    expect(JSON.parse((await env.DB.prepare("SELECT detail FROM audit WHERE action = 'waiver.add'").first<string>("detail"))!)).toMatchObject({ request: request_id });
    expect((await (await getPolicy(m.token)).json<{ waivers: unknown[] }>()).waivers).toEqual([
      { check: "listeners", install_id: m.install_id, until: day(30), reason: "Postgres for the billing project" },
    ]);
    // Decided once only.
    expect((await adminPost(`/admin/machine/${m.install_id}/waiver-requests/${request_id}/approve`)).status).toBe(404);
    expect((await adminPost(`/admin/machine/${m.install_id}/waiver-requests/${request_id}/reject`)).status).toBe(404);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM machine_waivers").first("n")).toBe(1);
  });

  it("reject records the decision and its note, and adds no waiver", async () => {
    const m = await enrolled();
    const { request_id } = await (await ask(m.token, good())).json<{ request_id: number }>();
    expect((await adminPost(`/admin/machine/${m.install_id}/waiver-requests/${request_id}/reject`, { note: "Use the shared database instead" })).status).toBe(303);
    expect(await env.DB.prepare("SELECT status, decision_note FROM waiver_requests").first()).toEqual({ status: "rejected", decision_note: "Use the shared database instead" });
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM machine_waivers").first("n")).toBe(0);
    expect(await env.DB.prepare("SELECT action FROM audit WHERE action = 'waiver_request.reject'").first("action")).toBe("waiver_request.reject");
    const list = await (await ask(m.token, null, "GET")).json<{ data: { status: string; decision_note: string }[] }>();
    expect(list.data[0]).toMatchObject({ status: "rejected", decision_note: "Use the shared database instead" });
    // A new request for the same check is possible again.
    expect((await ask(m.token, good())).status).toBe(201);
  });

  it("an approval the waiver rules refuse leaves the request pending", async () => {
    const m = await enrolled();
    const { request_id } = await (await ask(m.token, good())).json<{ request_id: number }>();
    await env.DB.prepare("UPDATE waiver_requests SET until = '2001-01-01' WHERE id = ?").bind(request_id).run();
    const res = await adminPost(`/admin/machine/${m.install_id}/waiver-requests/${request_id}/approve`);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("in the past");
    expect(await env.DB.prepare("SELECT status, decided_at FROM waiver_requests").first()).toEqual({ status: "pending", decided_at: null });
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM machine_waivers").first("n")).toBe(0);
  });

  it("only decides a request of that machine", async () => {
    const a = await enrolled("an@domain.com");
    const b = await enrolled("binh@domain.com");
    const { request_id } = await (await ask(a.token, good())).json<{ request_id: number }>();
    expect((await adminPost(`/admin/machine/${b.install_id}/waiver-requests/${request_id}/approve`)).status).toBe(404);
    expect(await env.DB.prepare("SELECT status FROM waiver_requests").first("status")).toBe("pending");
  });

  it("escapes the requester's text in the dashboard and keeps it under untrusted in machine detail", async () => {
    const m = await enrolled();
    await ask(m.token, good({ reason: '<script>alert(1)</script> "x"' }));
    for (const path of [`/admin/machine/${m.install_id}`, "/admin"]) {
      const page = await (await adminGet(path)).text();
      expect(page).not.toContain("<script>alert(1)");
      expect(page).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    }
    const d = (await machineDetail(env, m.install_id, {}, new Date())) as unknown as { data: { waiver_requests: Record<string, unknown>[] } };
    expect(d.data.waiver_requests[0]).toMatchObject({ check_id: "listeners", status: "pending", untrusted: { reason: '<script>alert(1)</script> "x"' } });
    expect(d.data.waiver_requests[0]).not.toHaveProperty("reason");
  });

  it("the machine's report page says a waiver is pending for that check", async () => {
    const m = await enrolled();
    const sent = await post(report({}, [{ id: "listeners", title: "Listeners", status: "fail", severity: "high", summary: "5432 open" }]), { token: m.token });
    const url = (await sent.json<{ report_url: string }>()).report_url;
    await ask(m.token, good());
    const page = await (await call(new Request(url.replace("https://bordercheck.example.com", BASE)))).text();
    expect(page).toContain("You asked for a waiver until");
  });
});
