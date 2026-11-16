import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { resetAccessKeys } from "../src/auth";
import { adminPost, BASE, call, enrolled, env, post, report, result } from "./helpers";

// Cloudflare Zero Trust custom device posture: /posture/cloudflare.

const TEAM = "sample.cloudflareaccess.com";
const AUD = "posture-aud-5678";
const CLIENT = "abc123.access";
const E = { ACCESS_TEAM_DOMAIN: TEAM, POSTURE_ACCESS_AUD: AUD };

let keys: CryptoKeyPair;
let jwk: JsonWebKey;
const b64url = (b: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(b instanceof Uint8Array ? b : new Uint8Array(b))))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
const text = (o: unknown) => b64url(new TextEncoder().encode(JSON.stringify(o)));
async function jwt(claims: Record<string, unknown>) {
  const head = text({ alg: "RS256", kid: "k1", typ: "JWT" });
  const body = text(claims);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", keys.privateKey, new TextEncoder().encode(`${head}.${body}`));
  return `${head}.${body}.${b64url(sig)}`;
}
const service = (extra: Record<string, unknown> = {}) => ({
  aud: [AUD], iss: `https://${TEAM}`, exp: Math.floor(Date.now() / 1000) + 600, common_name: CLIENT, ...extra,
});

beforeAll(async () => {
  keys = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  jwk = (await crypto.subtle.exportKey("jwk", keys.publicKey)) as JsonWebKey;
});

const realFetch = globalThis.fetch;
function stubCerts() {
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = String(input instanceof Request ? input.url : input);
    if (url === `https://${TEAM}/cdn-cgi/access/certs`) return Response.json({ keys: [{ ...jwk, kid: "k1", alg: "RS256" }] });
    return realFetch(input, init);
  });
}
afterEach(() => {
  vi.restoreAllMocks();
  resetAccessKeys();
});

async function ask(devices: unknown[], claims = service(), e: Record<string, string> = E) {
  const res = await call(
    new Request(`${BASE}/posture/cloudflare`, {
      method: "POST",
      headers: { "content-type": "application/json", "cf-access-jwt-assertion": await jwt(claims) },
      body: JSON.stringify({ devices }),
    }),
    e,
  );
  return { status: res.status, body: res.status === 200 ? await res.json<any>() : null };
}

const dev = (id: string, o: Record<string, string> = {}) => ({ device_id: id, email: "", serial_number: "", mac_address: "", virtual_ipv4: "", hostname: "", ...o });
const host = (serial: string, hostname = "an-mbp") => ({ host: { os: "darwin", arch: "arm64", hostname, serial } });

describe("device posture for Cloudflare Zero Trust", () => {
  it("scores machines by serial, then by email and hostname", async () => {
    stubCerts();
    const ok = await enrolled("ok@domain.com", "Dev");
    const failing = await enrolled("fail@domain.com", "Dev");
    const warn = await enrolled("warn@domain.com", "Dev");
    const comp = await enrolled("comp@domain.com", "Dev");
    const revoked = await enrolled("rev@domain.com", "Dev");
    const silent = await enrolled("old@domain.com", "Dev");
    const byName = await enrolled("name@domain.com", "Dev");
    const send = (m: { token: string }, extra: Record<string, unknown>, results: unknown[]) => post(report(extra, results), { token: m.token });
    await send(ok, host("C02OK"), [result("firewall", "pass")]);
    await send(failing, host("C02FAIL"), [result("firewall", "fail", { severity: "high" })]);
    await send(warn, host("C02WARN"), [result("firewall", "warn")]);
    await send(comp, { ...host("C02COMP"), compromised: true, compromise_checks: ["startup"] }, [result("startup", "fail", { compromise: [{ what: { key: "compromise.startupDownloadRun" } }] })]);
    await send(revoked, host("C02REV"), [result("firewall", "pass")]);
    await send(silent, host("C02OLD"), [result("firewall", "pass")]);
    await send(byName, host("", "Name-MBP"), [result("firewall", "pass")]);
    await adminPost(`/admin/machine/${revoked.install_id}/revoke`);
    await env.DB.prepare("UPDATE machines SET last_seen = '2020-01-01T00:00:00Z' WHERE install_id = ?").bind(silent.install_id).run();

    const r = await ask([
      dev("d-ok", { serial_number: "c02ok" }), // case does not matter
      dev("d-fail", { serial_number: "C02FAIL" }),
      dev("d-warn", { serial_number: "C02WARN" }),
      dev("d-comp", { serial_number: "C02COMP" }),
      dev("d-rev", { serial_number: "C02REV" }),
      dev("d-old", { serial_number: "C02OLD" }),
      dev("d-name", { email: "Name@domain.com", hostname: "name-mbp.local" }),
      dev("d-unknown", { serial_number: "NOPE", email: "x@domain.com" }),
      dev("d-blank"),
    ]);
    expect(r.status).toBe(200);
    const score = Object.fromEntries(Object.entries(r.body.result).map(([k, v]: [string, any]) => [k, v.score]));
    // Fresh fail and warning: within their grace; compromised: never.
    expect(score).toEqual({ "d-ok": 100, "d-fail": 70, "d-warn": 90, "d-comp": 0, "d-rev": 0, "d-old": 0, "d-name": 100, "d-unknown": 0, "d-blank": 0 });
    expect(r.body.result["d-ok"].s2s_id).toBe("");

    // Past the grace (defaults: 3 days for a fail, 7 for a warning): 0.
    const back = (id: string, days: number) =>
      env.DB.prepare("UPDATE checks SET since = ? WHERE install_id = ?").bind(new Date(Date.now() - days * 86400_000).toISOString(), id).run();
    await back(failing.install_id, 2.9);
    await back(warn.install_id, 6.9);
    let s2 = (await ask([dev("f", { serial_number: "C02FAIL" }), dev("w", { serial_number: "C02WARN" })])).body.result;
    expect([s2.f.score, s2.w.score]).toEqual([70, 90]);
    await back(failing.install_id, 3.1);
    await back(warn.install_id, 7.1);
    s2 = (await ask([dev("f", { serial_number: "C02FAIL" }), dev("w", { serial_number: "C02WARN" })])).body.result;
    expect([s2.f.score, s2.w.score]).toEqual([0, 0]);
  });

  it("takes the grace periods from the role's access section", async () => {
    stubCerts();
    const m = await enrolled("an@domain.com", "Strict");
    await env.DB.prepare("UPDATE roles SET policy = ? WHERE id = ?")
      .bind(JSON.stringify({ access: { warn_grace: "720h", fail_grace: "0" } }), m.roleId).run();
    await post(report(host("C02S"), [result("firewall", "fail", { severity: "high" })]), { token: m.token });
    expect((await ask([dev("d", { serial_number: "C02S" })])).body.result.d.score).toBe(0); // no grace for a fail
    await post(report(host("C02S"), [result("firewall", "warn")]), { token: m.token });
    await env.DB.prepare("UPDATE checks SET since = ? WHERE install_id = ?").bind(new Date(Date.now() - 20 * 86400_000).toISOString(), m.install_id).run();
    expect((await ask([dev("d", { serial_number: "C02S" })])).body.result.d.score).toBe(90); // 30 days for a warning
  });

  it("the serial from enrollment counts before the first report: still 0 (never reported)", async () => {
    stubCerts();
    const m = await enrolled("an@domain.com", "Dev");
    await env.DB.prepare("UPDATE enrollments SET serial = 'C02NEW' WHERE install_id = ?").bind(m.install_id).run();
    expect((await ask([dev("d", { serial_number: "C02NEW" })])).body.result.d.score).toBe(0);
  });

  it("only a service token through the posture Access app gets an answer", async () => {
    stubCerts();
    expect((await ask([dev("d")], service(), {})).status).toBe(404); // not set up
    expect((await ask([dev("d")], service({ email: "someone@domain.com" }))).status).toBe(401); // a person
    expect((await ask([dev("d")], service({ aud: ["other"] }))).status).toBe(401);
    expect((await ask([dev("d")], service({ common_name: "other.access" }), { ...E, POSTURE_CLIENT_ID: CLIENT })).status).toBe(401);
    expect((await ask([dev("d")], service(), { ...E, POSTURE_CLIENT_ID: CLIENT })).status).toBe(200);
    const none = await call(new Request(`${BASE}/posture/cloudflare`, { method: "POST", body: "{}" }), E);
    expect(none.status).toBe(401);
    expect((await ask(Array.from({ length: 1001 }, (_, i) => dev(`d${i}`)))).status).toBe(400);
  });
});

describe("the access section of a role", () => {
  it("is validated, and never served to machines", async () => {
    const { validateRolePolicy } = await import("../src/roles");
    const now = new Date();
    expect(validateRolePolicy({ access: { warn_grace: "168h", fail_grace: "0" } }, now)).toEqual([]);
    for (const bad of [{ fail_grace: "3d" }, { warn_grace: "2161h" }, { extra: "1h" }]) {
      expect(validateRolePolicy({ access: bad }, now).length).toBeGreaterThan(0);
    }
    const m = await enrolled("an@domain.com", "Dev");
    await env.DB.prepare("UPDATE roles SET policy = ? WHERE id = ?").bind(JSON.stringify({ access: { fail_grace: "24h" } }), m.roleId).run();
    const { getPolicy } = await import("./helpers");
    const served = await (await getPolicy(m.token)).json<Record<string, unknown>>();
    expect(served.access).toBeUndefined();
    expect(served.report).toBeTruthy();
  });
});

describe("who may change the grace periods", () => {
  it("not MCP, not a named admin; spelling out the defaults is no change", async () => {
    const { MCP_ROLE_RULES, policyGuard } = await import("../src/fleet");
    expect(policyGuard({ access: { warn_grace: "168h", fail_grace: "72h" } }, {}, MCP_ROLE_RULES)).toEqual([]);
    expect(policyGuard({ access: { fail_grace: "720h" } }, {}, MCP_ROLE_RULES).join()).toContain("access");

    const { saveRole } = await import("../src/portal");
    const adminId = (await env.DB.prepare("INSERT INTO admins (name, token_hash, created_at, created_by) VALUES ('Kien', 'x', '2026-01-01', 'test') RETURNING id").first<number>("id"))!;
    const scope = { admin: adminId, roles: [] as number[] };
    const ok = await saveRole(env, "Kien", { name: "Mine", policyText: JSON.stringify({ access: { warn_grace: "168h" } }) }, {}, scope);
    expect(ok.ok).toBe(true);
    const longer = await saveRole(env, "Kien", { name: "Mine2", policyText: JSON.stringify({ access: { fail_grace: "720h" } }) }, {}, scope);
    expect(longer.ok).toBe(false);
    const owner = await saveRole(env, "admin token", { name: "Mine3", policyText: JSON.stringify({ access: { fail_grace: "720h" } }) });
    expect(owner.ok).toBe(true);
  });
});
