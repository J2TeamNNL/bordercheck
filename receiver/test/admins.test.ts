import { env as testEnv } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";
import { checkStats } from "../src/dashboard";
import { ADMIN_TOKEN, BASE, call, enrolled, env, makeInvites, makeRole, post, report, result } from "./helpers";

// Named admins and their role scopes, through the real routes.

const enc = new TextEncoder();
const HOST = new URL(BASE).hostname;
const TOKEN_RE = /bca_[A-Za-z0-9_-]{43}/;

type Auth = { cookie: string } | { bearer: string };
const headersOf = (a: Auth): Record<string, string> =>
  "cookie" in a ? { cookie: a.cookie, origin: BASE } : { authorization: `Bearer ${a.bearer}` };
const OWNER: Auth = { bearer: ADMIN_TOKEN };

const get = (path: string, a: Auth) => call(new Request(BASE + path, { headers: headersOf(a) }));
function send(path: string, a: Auth, fields: [string, string][] = []) {
  return call(new Request(BASE + path, { method: "POST", headers: headersOf(a), body: new URLSearchParams(fields) }));
}

const sessionOf = (res: Response) => res.headers.getSetCookie().find((c) => c.startsWith("bc_session="))?.split(";")[0] ?? null;

async function login(token: string) {
  return call(new Request(`${BASE}/admin/login`, { method: "POST", headers: { origin: BASE }, body: new URLSearchParams({ token }) }));
}

async function signIn(token: string): Promise<Auth> {
  const res = await login(token);
  expect(res.status).toBe(303);
  return { cookie: sessionOf(res)! };
}

// addAdmin adds one through the owner's form and returns its token from the page.
async function addAdmin(name: string, roles: number[] = []): Promise<{ id: number; token: string; page: string; res: Response }> {
  const res = await send("/admin/admins", OWNER, [["name", name], ...roles.map((r): [string, string] => ["role", String(r)])]);
  const page = await res.text();
  const token = TOKEN_RE.exec(page)?.[0] ?? "";
  const id = (await env.DB.prepare("SELECT id FROM admins WHERE name = ?").bind(name.trim()).first<number>("id")) ?? 0;
  return { id, token, page, res };
}

const audit = async () =>
  (await env.DB.prepare("SELECT who, action, target, detail FROM audit ORDER BY id").all<{ who: string; action: string; target: string; detail: string }>()).results;

// ---- A software authenticator (as in passkey.test.ts) ----

const b64url = (b: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(b instanceof Uint8Array ? b : new Uint8Array(b))))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
const sha256 = async (b: Uint8Array) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
const cat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) out.set(p, (i += p.length) - p.length);
  return out;
};
function rawToDer(raw: Uint8Array): Uint8Array {
  const int = (v: Uint8Array) => {
    let i = 0;
    while (i < v.length - 1 && v[i] === 0) i++;
    v = v.subarray(i);
    if (v[0] & 0x80) v = cat(new Uint8Array([0]), v);
    return cat(new Uint8Array([0x02, v.length]), v);
  };
  const body = cat(int(raw.subarray(0, 32)), int(raw.subarray(32)));
  return cat(new Uint8Array([0x30, body.length]), body);
}
class Authenticator {
  keys!: CryptoKeyPair;
  spki!: Uint8Array;
  id = crypto.getRandomValues(new Uint8Array(16));
  async init() {
    this.keys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    this.spki = new Uint8Array((await crypto.subtle.exportKey("spki", this.keys.publicKey)) as ArrayBuffer);
    return this;
  }
  async authData(flags: number, attested: boolean) {
    const parts = [await sha256(enc.encode(HOST)), new Uint8Array([flags]), new Uint8Array(4)];
    if (attested) parts.push(new Uint8Array(16), new Uint8Array([0, this.id.length]), this.id, new Uint8Array([0xa5, 1, 2]));
    return cat(...parts);
  }
  clientData(type: string, challenge: string) {
    return enc.encode(JSON.stringify({ type, challenge, origin: BASE, crossOrigin: false }));
  }
  async attest(challenge: string) {
    return {
      id: b64url(this.id),
      clientDataJSON: b64url(this.clientData("webauthn.create", challenge)),
      authenticatorData: b64url(await this.authData(0x01 | 0x04 | 0x40, true)),
      publicKey: b64url(this.spki),
      alg: -7,
      label: "Key",
    };
  }
  async assert(challenge: string) {
    const authData = await this.authData(0x01 | 0x04, false);
    const cd = this.clientData("webauthn.get", challenge);
    const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, this.keys.privateKey, cat(authData, await sha256(cd))));
    return { id: b64url(this.id), clientDataJSON: b64url(cd), authenticatorData: b64url(authData), signature: b64url(rawToDer(raw)) };
  }
}
const jsonPost = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  call(new Request(BASE + path, { method: "POST", headers: { origin: BASE, "content-type": "application/json", ...headers }, body: JSON.stringify(body) }));
async function registerKey(a: Authenticator, cookie: string) {
  const opts = await (await jsonPost("/admin/passkeys/options", {}, { cookie })).json<{ challenge: string; user: { id: string } }>();
  const res = await jsonPost("/admin/passkeys", await a.attest(opts.challenge), { cookie });
  return { res, opts };
}
async function passkeyLogin(a: Authenticator) {
  const { challenge } = await (await jsonPost("/admin/login/passkey/options", {})).json<{ challenge: string }>();
  return jsonPost("/admin/login/passkey", await a.assert(challenge));
}

// ---- Named admins ----

describe("named admins", () => {
  it("are added by the owner, sign in with their token, and show up by name in the header and audit", async () => {
    const roleA = await makeRole("A");
    const { id, token, page, res } = await addAdmin("  Linh Tran ", [roleA]);
    expect(res.status).toBe(200);
    // Shown once, with the Copy button and its CSP.
    expect(token).toMatch(TOKEN_RE);
    expect(res.headers.get("content-security-policy")).toContain("script-src 'sha256-");
    expect(page).toContain('data-copy="admin-token"');
    expect(page).toContain("Linh Tran added");
    // Only the hash is stored.
    const row = await env.DB.prepare("SELECT name, token_hash, gen, created_by FROM admins WHERE id = ?").bind(id).first<{ name: string; token_hash: string; gen: number; created_by: string }>();
    expect(row).toMatchObject({ name: "Linh Tran", gen: 1, created_by: "admin token" });
    expect(row!.token_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(await env.DB.prepare("SELECT * FROM admins").all())).not.toContain(token);
    expect((await audit()).find((a) => a.action === "admin.add")).toEqual({ who: "admin token", action: "admin.add", target: "Linh Tran", detail: '{"roles":["A"]}' });

    const before = await env.DB.prepare("SELECT last_used_at FROM admins WHERE id = ?").bind(id).first<string | null>("last_used_at");
    expect(before).toBeNull();
    const signed = await login(token);
    expect(signed.status).toBe(303);
    const cookie = sessionOf(signed)!;
    expect(cookie).toMatch(new RegExp(`^bc_session=\\d+a${id}g1\\.[A-Za-z0-9_-]+$`));
    expect(await env.DB.prepare("SELECT last_used_at FROM admins WHERE id = ?").bind(id).first<string>("last_used_at")).toBeTruthy();
    const home = await get("/admin", { cookie });
    expect(home.status).toBe(200);
    const html = await home.text();
    expect(html).toContain('<span class="id">Linh Tran</span>');
    expect(html).toContain("/admin/logout");
    expect(html).toContain('href="/admin/admins"');
    expect(html).toContain('href="/admin/passkeys"');

    // A change they make is audited under their name.
    expect((await send("/admin/roles", { cookie }, [["name", "Mine"], ["policy", JSON.stringify({ name: "x" })]])).status).toBe(200);
    expect((await audit()).some((a) => a.who === "Linh Tran" && a.action === "role.create")).toBe(true);
  });

  it("refuses wrong, removed and regenerated tokens with the same answer, and ends sessions at once", async () => {
    const a = await addAdmin("Bo");
    const b = await addAdmin("Cy");
    const bad = await login("bca_" + "A".repeat(43));
    expect(bad.status).toBe(401);
    expect(await bad.text()).toContain("Wrong token.");
    expect((await login("not even a token")).status).toBe(401);

    // Regenerate (owner): old token and old sessions refused, new token works.
    const oldSession = await signIn(a.token);
    const regen = await send(`/admin/admins/${a.id}/token`, OWNER);
    expect(regen.status).toBe(200);
    const fresh = TOKEN_RE.exec(await regen.text())![0];
    expect(fresh).not.toBe(a.token);
    expect(regen.headers.get("set-cookie")).toBeNull(); // the owner's own session is untouched
    expect((await login(a.token)).status).toBe(401);
    expect((await get("/admin", oldSession)).status).toBe(303);
    const s2 = await signIn(fresh);
    expect((await get("/admin", s2)).status).toBe(200);
    expect((await audit()).some((x) => x.action === "admin.token" && x.target === "Bo")).toBe(true);

    // Regenerating their own token keeps the admin signed in with a new session.
    const self = await send(`/admin/admins/${a.id}/token`, s2);
    expect(self.status).toBe(200);
    const s3 = sessionOf(self)!;
    expect(s3).toMatch(new RegExp(`a${a.id}g3\\.`));
    expect((await get("/admin", s2)).status).toBe(303);
    expect((await get("/admin", { cookie: s3 })).status).toBe(200);

    // Remove: their session stops on the next request, the token is refused.
    const sb = await signIn(b.token);
    expect((await get("/admin", sb)).status).toBe(200);
    const del = await send(`/admin/admins/${b.id}/delete`, OWNER);
    expect(del.status).toBe(200);
    expect(await del.text()).toContain("Cy removed.");
    expect((await get("/admin", sb)).status).toBe(303);
    expect((await login(b.token)).status).toBe(401);
    expect((await audit()).some((x) => x.action === "admin.delete" && x.target === "Cy" && x.who === "admin token")).toBe(true);
    expect((await send(`/admin/admins/${b.id}/delete`, OWNER)).status).toBe(404);
  });

  it("does not accept a forged or altered session", async () => {
    const a = await addAdmin("Dee");
    const s = (await signIn(a.token)) as { cookie: string };
    // Changing the admin id, the gen or the passkey marker breaks the signature.
    for (const forged of [s.cookie.replace(`a${a.id}g1`, `a${a.id + 1}g1`), s.cookie.replace("g1.", "g2."), s.cookie.replace(/=(\d+)a/, "=$1pa")]) {
      expect(forged).not.toBe(s.cookie);
      expect((await get("/admin", { cookie: forged })).status).toBe(303);
    }
  });

  it("validates names", async () => {
    const cases: [string, string, number][] = [
      ["", "Enter a name.", 400],
      ["   ", "Enter a name.", 400],
      ["x".repeat(41), "at most 40 characters", 400],
      ["-dash", "must start with a letter or digit", 400],
      ["a<b", "must start with a letter or digit", 400],
      ["Admin Token", "reserved", 400],
      ["admin passkey", "reserved", 400],
      ["MCP", "reserved", 400],
    ];
    for (const [name, text, status] of cases) {
      const r = await addAdmin(name);
      expect(r.res.status, name).toBe(status);
      expect(r.page, name).toContain(text);
      expect(r.token).toBe("");
    }
    expect((await addAdmin("Đức Anh")).res.status).toBe(200);
    expect((await addAdmin("x".repeat(40))).res.status).toBe(200);
    expect((await addAdmin("an.ng_1@acme-co")).res.status).toBe(200);
    // Duplicates, case-insensitively (ASCII and beyond).
    for (const dup of ["đức anh", "ĐỨC ANH", " Đức Anh "]) {
      const r = await addAdmin(dup);
      expect(r.res.status, dup).toBe(409);
      expect(r.page).toContain("There is already an admin with that name.");
    }
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM admins").first<number>("n")).toBe(3);
  });

  it("refuses owner-only actions to a named admin with a 403 page", async () => {
    const a = await addAdmin("Eve");
    const other = await addAdmin("Fay");
    const s = await signIn(a.token);
    for (const [path, fields] of [
      ["/admin/admins", [["name", "Mallory"]]],
      [`/admin/admins/${other.id}/delete`, []],
      [`/admin/admins/${other.id}/token`, []],
      [`/admin/admins/${a.id}/delete`, []],
      [`/admin/admins/${a.id}/roles`, [["role", "1"]]],
      ["/admin/passkeys/token-login", [["state", "on"]]],
    ] as [string, [string, string][]][]) {
      const r = await send(path, s, fields);
      expect(r.status, path).toBe(403);
      expect(await r.text(), path).toContain("Only the owner can do this");
    }
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM admins").first<number>("n")).toBe(2);
    // The list page shows only their own row, without the owner's controls.
    const list = await (await get("/admin/admins", s)).text();
    expect(list).toContain("Eve");
    expect(list).not.toContain("Fay");
    expect(list).not.toContain('action="/admin/admins"');
    expect(list).not.toContain("/delete");
    // Cross-site posts are refused before anything.
    const xs = await call(new Request(`${BASE}/admin/admins/${a.id}/token`, { method: "POST", headers: { cookie: (s as { cookie: string }).cookie, origin: "https://evil.example" } }));
    expect(xs.status).toBe(403);
  });

  it("accepts a named token as a bearer header on /admin", async () => {
    const a = await addAdmin("Gus");
    const res = await get("/admin", { bearer: a.token });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('<span class="id">Gus</span>');
    expect((await get("/admin", { bearer: "bca_" + "B".repeat(43) })).status).toBe(401);
    // Not a key to /api/v1 or MCP.
    expect((await call(new Request(`${BASE}/api/v1/summary`, { headers: { authorization: `Bearer ${a.token}` } }), { API_TOKEN: "test-api-token-0123456789abcdef" })).status).toBe(401);
  });

  it("with token sign-in off: named tokens refused everywhere, a named admin's passkey still signs in as them", async () => {
    const a = await addAdmin("Hal");
    const tokenSession = await signIn(a.token);
    // Hal registers a passkey from their token session.
    const key = await new Authenticator().init();
    const { res: reg, opts } = await registerKey(key, (tokenSession as { cookie: string }).cookie);
    expect(reg.status).toBe(200);
    expect(opts.user.id).toBe(b64url(enc.encode(`bordercheck-admin-${a.id}`)));
    expect(await env.DB.prepare("SELECT admin_id FROM passkeys").first<number>("admin_id")).toBe(a.id);
    expect((await audit()).some((x) => x.action === "passkey.add" && x.who === "Hal")).toBe(true);

    // The owner signs in with an owner passkey and switches tokens off.
    const ownerKey = await new Authenticator().init();
    const ownerToken = await signIn(ADMIN_TOKEN);
    expect((await registerKey(ownerKey, (ownerToken as { cookie: string }).cookie)).res.status).toBe(200);
    // Hal's own passkey list shows only Hal's; the owner's only the owner's.
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM passkeys").first<number>("n")).toBe(2);
    const ownerPk = { cookie: sessionOf(await passkeyLogin(ownerKey))! };
    const pkPage = await (await get("/admin/passkeys", ownerPk)).text();
    expect((pkPage.match(/\/admin\/passkeys\/\d+\/delete/g) ?? []).length).toBe(1);
    // One more admin without a passkey: the switch panel says so.
    await addAdmin("Ivy");
    expect(await (await get("/admin/passkeys", ownerPk)).text()).toContain("1 named admin has no passkey");
    expect((await send("/admin/passkeys/token-login", ownerPk, [["state", "off"]])).status).toBe(200);

    expect((await login(a.token)).status).toBe(401);
    expect((await get("/admin", { bearer: a.token })).status).toBe(401);
    expect((await get("/admin", tokenSession)).status).toBe(303);
    // Hal's passkey opens a session for Hal.
    const pk = await passkeyLogin(key);
    expect(pk.status).toBe(200);
    const halPk = { cookie: sessionOf(pk)! };
    expect(halPk.cookie).toMatch(new RegExp(`^bc_session=\\d+pa${a.id}g1\\.`));
    const home = await get("/admin", halPk);
    expect(home.status).toBe(200);
    expect(await home.text()).toContain('<span class="id">Hal</span>');
    // Hal cannot delete their own last passkey while tokens are off, nor the owner's.
    const halKeyId = await env.DB.prepare("SELECT id FROM passkeys WHERE admin_id = ?").bind(a.id).first<number>("id");
    const ownerKeyId = await env.DB.prepare("SELECT id FROM passkeys WHERE admin_id IS NULL").first<number>("id");
    expect((await send(`/admin/passkeys/${halKeyId}/delete`, halPk)).status).toBe(409);
    expect((await send(`/admin/passkeys/${ownerKeyId}/delete`, halPk)).status).toBe(404);
    // A named admin's passkey session cannot switch tokens back on.
    expect((await send("/admin/passkeys/token-login", halPk, [["state", "on"]])).status).toBe(403);

    // Removing Hal removes the passkey; it no longer signs in.
    expect((await send(`/admin/admins/${a.id}/delete`, ownerPk)).status).toBe(200);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM passkeys WHERE admin_id IS NOT NULL").first<number>("n")).toBe(0);
    expect((await get("/admin", halPk)).status).toBe(303);
    expect((await passkeyLogin(key)).status).toBe(400);
  });

  it("does not exist for Access-only deployments", async () => {
    const res = await call(new Request(`${BASE}/admin/admins`, { headers: { authorization: `Bearer ${ADMIN_TOKEN}` } }), {
      ADMIN_TOKEN: "",
      ACCESS_TEAM_DOMAIN: "acme.cloudflareaccess.com",
      ACCESS_AUD: "aud",
    });
    expect(res.status).toBe(401);
  });
});

// ---- Before migration 0006 ----

describe("without migration 0006", () => {
  const m = (testEnv as unknown as { TEST_MIGRATIONS: { name: string; queries: string[] }[] }).TEST_MIGRATIONS.find((x) => x.name.startsWith("0006"))!;
  afterEach(async () => {
    // Put the migration back for the other tests.
    if (!(await env.DB.prepare("SELECT 1 FROM sqlite_master WHERE name = 'admins'").first())) {
      for (const q of m.queries) await env.DB.prepare(q).run();
    }
  });

  it("the owner signs in with the token and a passkey, and named lookups find nobody", async () => {
    await env.DB.batch([
      env.DB.prepare("DROP TABLE admin_roles"),
      env.DB.prepare("DROP TABLE admins"),
      env.DB.prepare("DROP INDEX passkeys_admin"),
      env.DB.prepare("ALTER TABLE passkeys DROP COLUMN admin_id"),
    ]);
    const s = await signIn(ADMIN_TOKEN);
    expect((await get("/admin", s)).status).toBe(200);
    expect((await get("/admin", { bearer: "bca_" + "C".repeat(43) })).status).toBe(401);
    expect((await login("bca_" + "C".repeat(43))).status).toBe(401);
    const page = await get("/admin/admins", s);
    expect(page.status).toBe(200);
    expect(await page.text()).toContain("migrations applied first");
    expect((await send("/admin/admins", OWNER, [["name", "Zed"]])).status).toBe(409);
    // Passkeys keep working for the owner.
    const key = await new Authenticator().init();
    expect((await registerKey(key, (s as { cookie: string }).cookie)).res.status).toBe(200);
    const pk = await passkeyLogin(key);
    expect(pk.status).toBe(200);
    const pkS = { cookie: sessionOf(pk)! };
    const home = await (await get("/admin", pkS)).text();
    expect(home).toContain("admin passkey");
    expect(await (await get("/admin/passkeys", pkS)).text()).toContain("/delete");
    expect((await send("/admin/passkeys/token-login", pkS, [["state", "off"]])).status).toBe(200);
    expect((await send("/admin/passkeys/token-login", pkS, [["state", "on"]])).status).toBe(200);
    // Fleet pages still work.
    await makeRole("Dev");
    expect((await get("/admin/roles", s)).status).toBe(200);
    expect((await get("/admin/invites", s)).status).toBe(200);
    expect((await get("/admin/checks", s)).status).toBe(200);
  });
});

// ---- Role scopes ----

describe("sub-admin scopes", () => {
  let fleet: Awaited<ReturnType<typeof setup>>;

  async function setup() {
    const a1 = await enrolled("a1@acme.com", "A", { os: "darwin", arch: "arm64", hostname: "a1-mbp" });
    const b1 = await enrolled("b1@acme.com", "B", { os: "linux", arch: "amd64", hostname: "b1-box" });
    for (const m of [a1, b1]) {
      expect((await post(report({}, [result("firewall", "fail", { severity: "high", fix: "Turn it on." }), result("secrets", "pass")]), { token: m.token })).status).toBe(200);
    }
    // A machine that reported but never enrolled cannot exist through /report, so plant one.
    await env.DB.prepare(
      `INSERT INTO machines (install_id, email, hostname, os, arch, version, policy, first_seen, last_seen, fail, high_fail, error, warn, waived, pass, skip, other, report)
       VALUES ('ffffffffffffffffffffffffffffffff', 'loose@acme.com', 'loose', 'linux', 'amd64', 'v1', 'p', ?1, ?1, 0, 0, 0, 0, 0, 0, 0, 0, '{}')`,
    ).bind(new Date().toISOString()).run();
    await makeInvites(["a2@acme.com"], a1.roleId);
    await makeInvites(["b2@acme.com"], b1.roleId);
    const sub = await addAdmin("Sub", [a1.roleId]);
    const s = await signIn(sub.token);
    return { a1, b1, roleA: a1.roleId, roleB: b1.roleId, sub, s };
  }

  it("sees only role A's machines, invites, roles, alerts and checks", async () => {
    fleet = await setup();
    const { s, a1, b1 } = fleet;
    const home = await (await get("/admin", s)).text();
    expect(home).toContain("a1@acme.com");
    expect(home).not.toContain("b1@acme.com");
    expect(home).not.toContain("loose@acme.com");
    expect(home).toContain("1 reporting · 1 non-compliant");
    const inv = await (await get("/admin/invites?status=all", s)).text();
    expect(inv).toContain("a2@acme.com");
    expect(inv).not.toContain("b2@acme.com");
    expect(inv).toContain(`<option value="${fleet.roleA}"`);
    expect(inv).not.toContain(`<option value="${fleet.roleB}"`);
    const roles = await (await get("/admin/roles", s)).text();
    expect(roles).toContain(`/admin/roles/${fleet.roleA}`);
    expect(roles).not.toContain(`/admin/roles/${fleet.roleB}`);
    const alerts = await (await get("/admin/alerts", s)).text();
    expect(alerts).toContain(a1.install_id);
    expect(alerts).not.toContain(b1.install_id);
    const check = await (await get("/admin/checks/firewall", s)).text();
    expect(check).toContain("a1@acme.com");
    expect(check).not.toContain("b1@acme.com");
    expect((await checkStats(env, 10, { admin: fleet.sub.id, roles: [fleet.roleA] })).find((c) => c.check_id === "firewall")?.total).toBe(1);
    expect((await checkStats(env, 10)).find((c) => c.check_id === "firewall")?.total).toBe(2);

    // The owner still sees everything.
    const all = await (await get("/admin", OWNER)).text();
    for (const e of ["a1@acme.com", "b1@acme.com", "loose@acme.com"]) expect(all).toContain(e);
    expect(await (await get("/admin/invites?status=all", OWNER)).text()).toContain("b2@acme.com");
  });

  it("gets 404 on role B's machines and every action on them, and on machines never enrolled", async () => {
    fleet = await setup();
    const { s, a1, b1 } = fleet;
    expect((await get(`/admin/machine/${a1.install_id}`, s)).status).toBe(200);
    for (const id of [b1.install_id, "ffffffffffffffffffffffffffffffff", "0".repeat(32)]) {
      const r = await get(`/admin/machine/${id}`, s);
      expect(r.status, id).toBe(404);
      expect(await r.text()).toContain("No such machine");
    }
    const before = await audit();
    const until = new Date(Date.now() + 5 * 86400000).toISOString().slice(0, 10);
    for (const [action, fields] of [
      ["revoke", []],
      ["restore", []],
      ["role", [["role_id", String(fleet.roleA)]]],
      ["waivers", [["check", "firewall"], ["until", until], ["reason", "r"]]],
      ["waivers/1/remove", []],
      ["reset-link", []],
      ["report-link", []],
      ["forget", []],
    ] as [string, [string, string][]][]) {
      const r = await send(`/admin/machine/${b1.install_id}/${action}`, s, fields);
      expect(r.status, action).toBe(404);
    }
    expect(await audit()).toEqual(before);
    expect(await env.DB.prepare("SELECT revoked_at FROM enrollments WHERE install_id = ?").bind(b1.install_id).first("revoked_at")).toBeNull();
    // In scope, the same actions work.
    expect((await send(`/admin/machine/${a1.install_id}/revoke`, s)).status).toBe(303);
    expect((await send(`/admin/machine/${a1.install_id}/restore`, s)).status).toBe(303);
  });

  it("cannot move a machine to role B, invite into B, or touch role B and its invites", async () => {
    fleet = await setup();
    const { s, a1, roleA, roleB } = fleet;
    const page = await (await get(`/admin/machine/${a1.install_id}`, s)).text();
    expect(page).toContain(`<option value="${roleA}"`);
    expect(page).not.toContain(`<option value="${roleB}"`);
    const move = await send(`/admin/machine/${a1.install_id}/role`, s, [["role_id", String(roleB)]]);
    expect(move.status).toBe(400);
    expect(await env.DB.prepare("SELECT role_id FROM enrollments WHERE install_id = ?").bind(a1.install_id).first<number>("role_id")).toBe(roleA);

    const inv = await send("/admin/invites", s, [["emails", "x@acme.com"], ["role_id", String(roleB)]]);
    expect(inv.status).toBe(400);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM invites WHERE email = 'x@acme.com'").first<number>("n")).toBe(0);
    expect((await send("/admin/invites", s, [["emails", "x@acme.com"], ["role_id", String(roleA)]])).status).toBe(200);

    for (const [method, path] of [["GET", `/admin/roles/${roleB}`], ["POST", `/admin/roles/${roleB}`], ["POST", `/admin/roles/${roleB}/delete`]]) {
      const r = method === "GET" ? await get(path, s) : await send(path, s, [["name", "B2"], ["policy", "{}"]]);
      expect(r.status, `${method} ${path}`).toBe(404);
    }
    expect(await env.DB.prepare("SELECT name FROM roles WHERE id = ?").bind(roleB).first<string>("name")).toBe("B");
    const bInvite = await env.DB.prepare("SELECT id FROM invites WHERE email = 'b2@acme.com'").first<number>("id");
    for (const act of ["revoke", "reissue"]) expect((await send(`/admin/invites/${bInvite}/${act}`, s)).status, act).toBe(404);
    expect(await env.DB.prepare("SELECT revoked_at FROM invites WHERE id = ?").bind(bInvite).first("revoked_at")).toBeNull();
    const aInvite = await env.DB.prepare("SELECT id FROM invites WHERE email = 'a2@acme.com'").first<number>("id");
    expect((await send(`/admin/invites/${aInvite}/revoke`, s)).status).toBe(200);
  });

  it("creates role C, which lands in scope and can be used; deleting it leaves the scope", async () => {
    fleet = await setup();
    const { s, a1, sub } = fleet;
    const res = await send("/admin/roles", s, [["name", "C"], ["policy", JSON.stringify({ name: "C" })]]);
    expect(res.status).toBe(200);
    const roleC = (await env.DB.prepare("SELECT id FROM roles WHERE name = 'C'").first<number>("id"))!;
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM admin_roles WHERE admin_id = ? AND role_id = ?").bind(sub.id, roleC).first<number>("n")).toBe(1);
    expect(await res.text()).toContain(`/admin/roles/${roleC}`);
    expect((await get(`/admin/roles/${roleC}`, s)).status).toBe(200);
    expect((await send(`/admin/machine/${a1.install_id}/role`, s, [["role_id", String(roleC)]])).status).toBe(303);
    expect((await send("/admin/invites", s, [["emails", "c@acme.com"], ["role_id", String(roleC)]])).status).toBe(200);
    // Back to A, then delete C (no invites left in C after revoking).
    expect((await send(`/admin/machine/${a1.install_id}/role`, s, [["role_id", String(fleet.roleA)]])).status).toBe(303);
    await env.DB.prepare("DELETE FROM invites WHERE role_id = ?").bind(roleC).run();
    expect((await send(`/admin/roles/${roleC}/delete`, s)).status).toBe(200);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM admin_roles WHERE role_id = ?").bind(roleC).first<number>("n")).toBe(0);
  });

  it("may not set where reports go or where updates come from in a role; the owner may", async () => {
    fleet = await setup();
    const { s } = fleet;
    const elsewhere = { name: "D", update: { repo: "someone/else", public_key: "Q5Mw8yJQUgKSEtPNBVNnEP7HiSvhwT2y9Te4mEPOlcs=" } };
    // Creating a role with them: refused, nothing saved.
    let res = await send("/admin/roles", s, [["name", "D"], ["policy", JSON.stringify(elsewhere)]]);
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("update.repo");
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM roles WHERE name = 'D'").first<number>("n")).toBe(0);
    // Changing them on a role in scope: refused, the policy stays as it was.
    const before = await env.DB.prepare("SELECT policy FROM roles WHERE id = ?").bind(fleet.roleA).first<string>("policy");
    const next = { ...JSON.parse(before!), report: { ...(JSON.parse(before!).report ?? {}), url: "https://elsewhere.example/report" } };
    res = await send(`/admin/roles/${fleet.roleA}`, s, [["name", "A"], ["policy", JSON.stringify(next)]]);
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("report.url");
    expect(await env.DB.prepare("SELECT policy FROM roles WHERE id = ?").bind(fleet.roleA).first<string>("policy")).toBe(before);
    // Any other change to the same role goes through.
    const harmless = { ...JSON.parse(before!), notify: { enabled: false } };
    expect((await send(`/admin/roles/${fleet.roleA}`, s, [["name", "A"], ["policy", JSON.stringify(harmless)]])).status).toBe(200);
    // The owner is not held to this.
    expect((await send("/admin/roles", OWNER, [["name", "D"], ["policy", JSON.stringify(elsewhere)]])).status).toBe(200);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM roles WHERE name = 'D'").first<number>("n")).toBe(1);
  });

  it("follows the owner's changes on the next request, and an empty scope explains itself", async () => {
    fleet = await setup();
    const { s, sub, roleA, roleB, b1 } = fleet;
    // Owner switches the scope to B only.
    const r = await send(`/admin/admins/${sub.id}/roles`, OWNER, [["role", String(roleB)], ["role", "999999"]]);
    expect(r.status).toBe(200);
    expect(await r.text()).toContain("Roles saved for Sub.");
    expect((await audit()).find((x) => x.action === "admin.roles")).toEqual({ who: "admin token", action: "admin.roles", target: "Sub", detail: '{"roles":["B"]}' });
    expect((await get(`/admin/machine/${b1.install_id}`, s)).status).toBe(200);
    expect((await get(`/admin/machine/${fleet.a1.install_id}`, s)).status).toBe(404);
    expect((await get(`/admin/roles/${roleA}`, s)).status).toBe(404);
    // The list shows each admin's roles.
    expect(await (await get("/admin/admins", OWNER)).text()).toMatch(/<b>Sub<\/b><\/td><td class="wrap">B</);
    // No roles at all.
    await send(`/admin/admins/${sub.id}/roles`, OWNER, []);
    const empty = await (await get("/admin", s)).text();
    expect(empty).toContain("You do not manage any role yet");
    expect(empty).not.toContain("b1@acme.com");
    expect(await (await get("/admin/roles", s)).text()).toContain("Create one below");
    expect(await (await get("/admin/invites", s)).text()).toContain("You do not manage any role yet");
  });

  it("shows a sub-admin only their own audit entries", async () => {
    fleet = await setup();
    const { s, a1 } = fleet;
    await send(`/admin/machine/${a1.install_id}/revoke`, s);
    const page = await (await get("/admin/audit", s)).text();
    expect(page).toContain("machine.revoke");
    expect(page).not.toContain("admin.add"); // the owner's
    expect(page).not.toContain("role.create");
    expect(page).not.toContain("?who=mcp");
    const ownerPage = await (await get("/admin/audit", OWNER)).text();
    expect(ownerPage).toContain("admin.add");
    expect(ownerPage).toContain("machine.revoke");
  });

  it("leaves the REST API and MCP unscoped", async () => {
    fleet = await setup();
    const API = "test-api-token-0123456789abcdef";
    const MCP = "test-mcp-token-0123456789abcdef";
    const res = await call(new Request(`${BASE}/api/v1/machines`, { headers: { authorization: `Bearer ${API}` } }), { API_TOKEN: API });
    expect(res.status).toBe(200);
    const ids = ((await res.json()) as { data: { install_id: string }[] }).data.map((m) => m.install_id).sort();
    expect(ids).toEqual([fleet.a1.install_id, fleet.b1.install_id, "ffffffffffffffffffffffffffffffff"].sort());
    const mcp = await call(
      new Request(`${BASE}/mcp`, {
        method: "POST",
        headers: { authorization: `Bearer ${MCP}`, "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": "2025-06-18" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "list_machines", arguments: {} } }),
      }),
      { MCP_TOKEN: MCP },
    );
    expect(mcp.status).toBe(200);
    const out = (await mcp.json()) as { result: { structuredContent: { count: number } } };
    expect(out.result.structuredContent.count).toBe(3);
  });
});
