import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { resetAccessKeys } from "../src/auth";
import { PASSKEY_SCRIPT, PASSKEY_SCRIPT_HASH } from "../src/html";
import { derToRaw } from "../src/passkeys";
import { ADMIN_TOKEN, BASE, call, env } from "./helpers";

// A software authenticator: a P-256 key made here, authenticator data and
// clientDataJSON built by hand, as a browser and a passkey provider would.

const enc = new TextEncoder();
const HOST = new URL(BASE).hostname;
const BASE_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

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

// rawToDer: what a real authenticator sends for ES256.
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

const UP = 0x01, UV = 0x04, AT = 0x40;

class Authenticator {
  keys!: CryptoKeyPair;
  spki!: Uint8Array;
  id = crypto.getRandomValues(new Uint8Array(16));
  count = 0;
  async init() {
    this.keys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    this.spki = new Uint8Array((await crypto.subtle.exportKey("spki", this.keys.publicKey)) as ArrayBuffer);
    return this;
  }
  async authData(flags: number, count: number, attested: boolean, host = HOST) {
    const c = new Uint8Array(4);
    new DataView(c.buffer).setUint32(0, count);
    const parts = [await sha256(enc.encode(host)), new Uint8Array([flags]), c];
    // aaguid, id length, id, then a stand-in for the COSE key (we never parse it).
    if (attested) parts.push(new Uint8Array(16), new Uint8Array([0, this.id.length]), this.id, new Uint8Array([0xa5, 1, 2]));
    return cat(...parts);
  }
  clientData(type: string, challenge: string, origin = BASE) {
    return enc.encode(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  }
  async attest(challenge: string, o: { origin?: string; flags?: number; host?: string; label?: string } = {}) {
    return {
      id: b64url(this.id),
      clientDataJSON: b64url(this.clientData("webauthn.create", challenge, o.origin)),
      authenticatorData: b64url(await this.authData(o.flags ?? UP | UV | AT, 0, true, o.host)),
      publicKey: b64url(this.spki),
      alg: -7,
      label: o.label ?? "Test key",
    };
  }
  async assert(challenge: string, o: { origin?: string; flags?: number; count?: number; badSig?: boolean; type?: string } = {}) {
    const authData = await this.authData(o.flags ?? UP | UV, o.count ?? this.count, false);
    const cd = this.clientData(o.type ?? "webauthn.get", challenge, o.origin);
    const signed = cat(authData, await sha256(cd));
    if (o.badSig) signed[0] ^= 1;
    const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, this.keys.privateKey, signed));
    return { id: b64url(this.id), clientDataJSON: b64url(cd), authenticatorData: b64url(authData), signature: b64url(rawToDer(raw)) };
  }
}

// ---- Requests, as the page's script makes them ----

const jsonPost = (path: string, body: unknown, headers: Record<string, string> = {}, e = {}) =>
  call(new Request(BASE + path, { method: "POST", headers: { origin: BASE, "content-type": "application/json", ...headers }, body: JSON.stringify(body) }), e);

async function tokenSession(): Promise<string> {
  const res = await call(new Request(`${BASE}/admin/login`, { method: "POST", headers: { origin: BASE }, body: new URLSearchParams({ token: ADMIN_TOKEN }) }));
  return res.headers.get("set-cookie")!.split(";")[0];
}

async function registerKey(a: Authenticator, cookie: string, o: Parameters<Authenticator["attest"]>[1] = {}) {
  const opts = await (await jsonPost("/admin/passkeys/options", {}, { cookie })).json<{ challenge: string; exclude: string[]; rp: { id: string }; user: { id: string } }>();
  return jsonPost("/admin/passkeys", await a.attest(opts.challenge, o), { cookie });
}

async function loginChallenge(e = {}): Promise<string> {
  const res = await jsonPost("/admin/login/passkey/options", {}, {}, e);
  expect(res.status).toBe(200);
  return (await res.json<{ challenge: string }>()).challenge;
}

async function passkeyLogin(a: Authenticator, o: Parameters<Authenticator["assert"]>[1] = {}, challenge?: string) {
  return jsonPost("/admin/login/passkey", await a.assert(challenge ?? (await loginChallenge()), o));
}

const sessionOf = (res: Response) => res.headers.getSetCookie().find((c) => c.startsWith("bc_session="))!.split(";")[0];
const loginPage = (cookie = "", query = "") => call(new Request(`${BASE}/admin/login${query}`, { headers: cookie ? { cookie } : {} }));
const count = (sql: string) => env.DB.prepare(sql).first<number>("n");

let a: Authenticator;
beforeAll(async () => {
  a = await new Authenticator().init();
});
afterEach(() => {
  a.count = 0;
});

describe("passkeys", () => {
  it("registers from a signed-in session, then signs in and reaches /admin", async () => {
    const cookie = await tokenSession();
    const opts = await (await jsonPost("/admin/passkeys/options", {}, { cookie })).json<{ rp: { id: string }; exclude: string[] }>();
    expect(opts.rp.id).toBe(HOST);
    expect(opts.exclude).toEqual([]);
    const reg = await registerKey(a, cookie);
    expect(reg.status).toBe(200);
    expect(reg.headers.getSetCookie()).toContain("bc_pk=1; Path=/admin; Max-Age=31536000; HttpOnly; Secure; SameSite=Lax");
    // Stored: SPKI, alg, label; listed on the page; excluded next time.
    const row = await env.DB.prepare("SELECT * FROM passkeys").first<{ credential_id: string; public_key: string; alg: number; label: string }>();
    expect(row).toMatchObject({ credential_id: b64url(a.id), public_key: b64url(a.spki), alg: -7, label: "Test key" });
    const page = await call(new Request(`${BASE}/admin/passkeys`, { headers: { cookie } }));
    expect(await page.text()).toContain("Test key");
    const again = await (await jsonPost("/admin/passkeys/options", {}, { cookie })).json<{ exclude: string[] }>();
    expect(again.exclude).toEqual([b64url(a.id)]);
    expect(await count("SELECT COUNT(*) AS n FROM audit WHERE action = 'passkey.add' AND who = 'admin token'")).toBe(1);

    a.count = 5;
    const res = await passkeyLogin(a);
    expect(res.status).toBe(200);
    const cookies = res.headers.getSetCookie();
    expect(cookies.some((c) => /^bc_session=\d+p\.[A-Za-z0-9_-]+; Path=\/admin; Max-Age=43200; HttpOnly; Secure; SameSite=Strict$/.test(c))).toBe(true);
    expect(cookies).toContain("bc_pk=1; Path=/admin; Max-Age=31536000; HttpOnly; Secure; SameSite=Lax");
    const admin = await call(new Request(`${BASE}/admin`, { headers: { cookie: sessionOf(res) } }));
    expect(admin.status).toBe(200);
    expect(await admin.text()).toContain("admin passkey");
    const used = await env.DB.prepare("SELECT sign_count, last_used_at FROM passkeys").first<{ sign_count: number; last_used_at: string }>();
    expect(used!.sign_count).toBe(5);
    expect(used!.last_used_at).toBeTruthy();
  });

  it("refuses a registration with a wrong origin, a reused challenge, no UV or a mismatched id, and cross-site", async () => {
    const cookie = await tokenSession();
    expect((await registerKey(a, cookie, { origin: "https://evil.example" })).status).toBe(400);
    expect((await registerKey(a, cookie, { flags: UP | AT })).status).toBe(400);
    expect((await registerKey(a, cookie, { host: "evil.example" })).status).toBe(400);
    const opts = await (await jsonPost("/admin/passkeys/options", {}, { cookie })).json<{ challenge: string }>();
    const att = await a.attest(opts.challenge);
    expect((await jsonPost("/admin/passkeys", { ...att, id: b64url(new Uint8Array(16)) }, { cookie })).status).toBe(400);
    // That attempt used the challenge up.
    expect((await jsonPost("/admin/passkeys", att, { cookie })).status).toBe(400);
    // Cookie-borne writes need the same origin.
    const o2 = await (await jsonPost("/admin/passkeys/options", {}, { cookie })).json<{ challenge: string }>();
    expect((await jsonPost("/admin/passkeys", await a.attest(o2.challenge), { cookie, origin: "https://evil.example" })).status).toBe(403);
    // A login challenge is not a registration challenge.
    expect((await jsonPost("/admin/passkeys", await a.attest(await loginChallenge()), { cookie })).status).toBe(400);
    // Not signed in: nothing.
    expect((await jsonPost("/admin/passkeys/options", {})).status).toBe(401);
    expect(await count("SELECT COUNT(*) AS n FROM passkeys")).toBe(0);
    expect(await count("SELECT COUNT(*) AS n FROM audit")).toBe(0);
  });

  it("refuses every bad sign-in with one generic answer", async () => {
    const cookie = await tokenSession();
    expect((await registerKey(a, cookie)).status).toBe(200);
    const other = await new Authenticator().init();
    const failures: Response[] = [
      await passkeyLogin(a, { origin: "https://evil.example" }),
      await passkeyLogin(a, { badSig: true }),
      await passkeyLogin(a, { flags: UP }), // no UV
      await passkeyLogin(a, { flags: UV }), // no UP
      await passkeyLogin(a, { type: "webauthn.create" }),
      await passkeyLogin(other), // unknown credential
      await jsonPost("/admin/login/passkey", await a.assert(b64url(crypto.getRandomValues(new Uint8Array(32))))), // never issued
      await jsonPost("/admin/login/passkey", { id: "x" }),
      await jsonPost("/admin/login/passkey", "nonsense"),
    ];
    // Reused challenge: the first use succeeds, the second fails.
    const ch = await loginChallenge();
    const assertion = await a.assert(ch);
    expect((await jsonPost("/admin/login/passkey", assertion)).status).toBe(200);
    failures.push(await jsonPost("/admin/login/passkey", assertion));
    for (const r of failures) {
      expect(r.status).toBe(400);
      expect(await r.json()).toEqual({ error: "passkey sign-in failed" });
      expect(r.headers.get("set-cookie")).toBeNull();
    }
    // Cross-site requests are refused before anything else.
    expect((await jsonPost("/admin/login/passkey/options", {}, { origin: "https://evil.example" })).status).toBe(403);
  });

  it("refuses an expired challenge", async () => {
    const cookie = await tokenSession();
    await registerKey(a, cookie);
    const ch = await loginChallenge();
    await env.DB.prepare("UPDATE passkey_challenges SET expires_at = ?").bind(Date.now() - 1).run();
    expect((await passkeyLogin(a, {}, ch)).status).toBe(400);
    // Issuing a new challenge cleans expired ones up.
    await loginChallenge();
    expect(await count("SELECT COUNT(*) AS n FROM passkey_challenges")).toBe(1);
  });

  it("refuses a sign counter that does not move forward", async () => {
    const cookie = await tokenSession();
    await registerKey(a, cookie);
    expect((await passkeyLogin(a, { count: 10 })).status).toBe(200);
    expect((await passkeyLogin(a, { count: 10 })).status).toBe(400);
    expect((await passkeyLogin(a, { count: 3 })).status).toBe(400);
    expect((await passkeyLogin(a, { count: 11 })).status).toBe(200);
    expect(await count("SELECT sign_count AS n FROM passkeys")).toBe(11);
  });

  it("rate-limits the public sign-in endpoints per IP", async () => {
    const ip = { "cf-connecting-ip": "203.0.113.90" };
    let last = 0;
    for (let i = 0; i < 31; i++) last = (await jsonPost("/admin/login/passkey/options", {}, ip)).status;
    expect(last).toBe(429);
    expect((await jsonPost("/admin/login/passkey", {}, ip)).status).toBe(429);
    expect((await jsonPost("/admin/login/passkey/options", {}, { "cf-connecting-ip": "203.0.113.91" })).status).toBe(200);
  });

  it("auto-prompts on the sign-in page only with the cookie, a passkey, and not after signing out", async () => {
    const auto = async (cookie: string, query = "") => (await (await loginPage(cookie, query)).text()).includes('data-auto="1"');
    // No passkey: the plain page, no script, no button, even with the cookie.
    let res = await loginPage("bc_pk=1");
    let body = await res.text();
    expect(res.headers.get("content-security-policy")).toBe(BASE_CSP);
    expect(body).not.toContain("<script");
    expect(body).not.toContain('id="pk"');

    const cookie = await tokenSession();
    await registerKey(a, cookie);
    res = await loginPage();
    body = await res.text();
    expect(body).toContain("Sign in with a passkey");
    expect(body.indexOf('id="pk"')).toBeLessThan(body.indexOf('name="token"'));
    expect(body).not.toContain('data-auto="1"');
    expect(res.headers.get("content-security-policy")).toBe(`${BASE_CSP}; script-src '${PASSKEY_SCRIPT_HASH}'; connect-src 'self'`);
    expect(await auto("bc_pk=1")).toBe(true);
    expect(await auto("bc_lang=vi; bc_pk=1")).toBe(true);
    expect(await auto("bc_pk=0")).toBe(false);

    // Logout lands on a page that does not prompt.
    const out = await call(new Request(`${BASE}/admin/logout`, { method: "POST", headers: { origin: BASE, cookie } }));
    expect(out.status).toBe(303);
    const to = out.headers.get("location")!;
    expect(to).toBe("/admin/login?signed_out=1");
    expect(await auto("bc_pk=1", to.slice("/admin/login".length))).toBe(false);

    // Deleting the last passkey: back to the plain page.
    const id = await count("SELECT id AS n FROM passkeys");
    expect((await call(new Request(`${BASE}/admin/passkeys/${id}/delete`, { method: "POST", headers: { origin: BASE, cookie } }))).status).toBe(200);
    res = await loginPage("bc_pk=1");
    expect(res.headers.get("content-security-policy")).toBe(BASE_CSP);
    expect(await res.text()).not.toContain("<script");
  });

  it("deletes a passkey (same-origin only) and audits it", async () => {
    const cookie = await tokenSession();
    await registerKey(a, cookie, { label: "Laptop" });
    const id = await count("SELECT id AS n FROM passkeys");
    const del = (origin: string) => call(new Request(`${BASE}/admin/passkeys/${id}/delete`, { method: "POST", headers: { origin, cookie } }));
    expect((await del("https://evil.example")).status).toBe(403);
    expect(await count("SELECT COUNT(*) AS n FROM passkeys")).toBe(1);
    const res = await del(BASE);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Passkey deleted.");
    expect(await count("SELECT COUNT(*) AS n FROM passkeys")).toBe(0);
    const row = await env.DB.prepare("SELECT who, target FROM audit WHERE action = 'passkey.delete'").first<{ who: string; target: string }>();
    expect(row).toEqual({ who: "admin token", target: "Laptop" });
    expect((await del(BASE)).status).toBe(404);
    // The deleted passkey no longer signs in.
    expect((await passkeyLogin(a)).status).toBe(400);
  });
});

describe("switching off sign-in with the admin token", () => {
  const setToken = (cookie: string, state: string) =>
    call(new Request(`${BASE}/admin/passkeys/token-login`, { method: "POST", headers: { origin: BASE, cookie }, body: new URLSearchParams({ state }) }));
  const tokenLogin = () => call(new Request(`${BASE}/admin/login`, { method: "POST", headers: { origin: BASE }, body: new URLSearchParams({ token: ADMIN_TOKEN }) }));
  const off = () => env.DB.prepare("SELECT value FROM meta WHERE key = 'admin_token_login'").first<string>("value");

  it("cannot be switched off without a passkey, or from a token session", async () => {
    const cookie = await tokenSession();
    let res = await setToken(cookie, "off");
    expect(res.status).toBe(409);
    expect(await res.text()).toContain("Add a passkey first.");
    await registerKey(a, cookie);
    res = await setToken(cookie, "off");
    expect(res.status).toBe(409);
    expect(await res.text()).toContain("sign in with your passkey first");
    // Nor with the token as a bearer header.
    res = await call(new Request(`${BASE}/admin/passkeys/token-login`, { method: "POST", headers: { authorization: `Bearer ${ADMIN_TOKEN}` }, body: new URLSearchParams({ state: "off" }) }));
    expect(res.status).toBe(409);
    expect(await off()).toBeNull();
    // Cross-site: refused before anything.
    const pk = sessionOf(await passkeyLogin(a));
    res = await call(new Request(`${BASE}/admin/passkeys/token-login`, { method: "POST", headers: { origin: "https://evil.example", cookie: pk }, body: new URLSearchParams({ state: "off" }) }));
    expect(res.status).toBe(403);
    expect(await off()).toBeNull();
  });

  it("when off: token refused everywhere in the dashboard, passkeys work, the last passkey stays; on again restores the form", async () => {
    const tokenCookie = await tokenSession();
    await registerKey(a, tokenCookie);
    const pk = sessionOf(await passkeyLogin(a));
    let res = await setToken(pk, "off");
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Token sign-in is off.");
    expect(await off()).toBe("off");
    expect(await count("SELECT COUNT(*) AS n FROM audit WHERE action = 'token-login.off' AND who = 'admin passkey'")).toBe(1);

    // The sign-in page has only the passkey button.
    const body = await (await loginPage()).text();
    expect(body).toContain("Sign in with a passkey");
    expect(body).not.toContain('name="token"');
    // A correct token gets the wrong-token answer.
    const t = await tokenLogin();
    expect(t.status).toBe(401);
    expect(await t.text()).toContain("Wrong token.");
    expect(t.headers.get("set-cookie")).toBeNull();
    // Earlier token sessions and the bearer header open nothing.
    expect((await call(new Request(`${BASE}/admin`, { headers: { cookie: tokenCookie } }))).status).toBe(303);
    expect((await call(new Request(`${BASE}/admin`, { headers: { authorization: `Bearer ${ADMIN_TOKEN}` } }))).status).toBe(401);
    // A passkey still signs in.
    const pk2 = sessionOf(await passkeyLogin(a));
    expect((await call(new Request(`${BASE}/admin`, { headers: { cookie: pk2 } }))).status).toBe(200);

    // The last passkey cannot be deleted while the token is off.
    const id = await count("SELECT id AS n FROM passkeys");
    res = await call(new Request(`${BASE}/admin/passkeys/${id}/delete`, { method: "POST", headers: { origin: BASE, cookie: pk2 } }));
    expect(res.status).toBe(409);
    expect(await res.text()).toContain("Switch token sign-in back on first.");
    expect(await count("SELECT COUNT(*) AS n FROM passkeys")).toBe(1);

    // On again: the token form is back and the token signs in.
    res = await setToken(pk2, "on");
    expect(res.status).toBe(200);
    expect(await off()).toBeNull();
    expect(await (await loginPage()).text()).toContain('name="token"');
    expect((await tokenLogin()).status).toBe(303);
    expect((await call(new Request(`${BASE}/admin`, { headers: { cookie: tokenCookie } }))).status).toBe(200);
  });

  it("still rate-limits the token form when off", async () => {
    await env.DB.prepare("INSERT INTO meta (key, value) VALUES ('admin_token_login', 'off')").run();
    let last = 0;
    for (let i = 0; i < 31; i++) {
      last = (await call(new Request(`${BASE}/admin/login`, { method: "POST", headers: { origin: BASE, "cf-connecting-ip": "203.0.113.95" }, body: new URLSearchParams({ token: ADMIN_TOKEN }) }))).status;
    }
    expect(last).toBe(429);
  });
});

describe("passkeys and Cloudflare Access", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    resetAccessKeys();
  });

  it("do not exist for Access-only deployments or Access viewers", async () => {
    const accessOnly = { ADMIN_TOKEN: "", ACCESS_TEAM_DOMAIN: "sample.cloudflareaccess.com", ACCESS_AUD: "aud" };
    expect((await jsonPost("/admin/login/passkey/options", {}, {}, accessOnly)).status).toBe(404);
    expect((await jsonPost("/admin/login/passkey", {}, {}, accessOnly)).status).toBe(404);
    expect((await call(new Request(`${BASE}/admin/login`), accessOnly)).status).toBe(403);
    // A signed-in Access viewer: no Passkeys link, and the routes answer 404.
    const keys = (await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const jwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => Response.json({ keys: [{ ...jwk, kid: "k1", alg: "RS256" }] }));
    const part = (o: unknown) => b64url(enc.encode(JSON.stringify(o)));
    const head = part({ alg: "RS256", kid: "k1" });
    const claims = part({ aud: ["aud"], iss: "https://sample.cloudflareaccess.com", exp: Math.floor(Date.now() / 1000) + 600, email: "it@domain.com" });
    const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", keys.privateKey, enc.encode(`${head}.${claims}`));
    const jwt = `${head}.${claims}.${b64url(sig)}`;
    for (const e of [accessOnly, { ...accessOnly, ADMIN_TOKEN }]) {
      const h = { "cf-access-jwt-assertion": jwt };
      const home = await call(new Request(`${BASE}/admin`, { headers: h }), e);
      expect(home.status).toBe(200);
      expect(await home.text()).not.toContain("/admin/passkeys");
      expect((await call(new Request(`${BASE}/admin/passkeys`, { headers: h }), e)).status).toBe(404);
      expect((await call(new Request(`${BASE}/admin/passkeys/options`, { method: "POST", headers: { ...h, origin: BASE } }), e)).status).toBe(404);
      // Nor the named-admin pages.
      expect(await (await call(new Request(`${BASE}/admin`, { headers: h }), e)).text()).not.toContain("/admin/admins");
      expect((await call(new Request(`${BASE}/admin/admins`, { headers: h }), e)).status).toBe(404);
      expect((await call(new Request(`${BASE}/admin/admins`, { method: "POST", headers: { ...h, origin: BASE }, body: new URLSearchParams({ name: "x" }) }), e)).status).toBe(404);
    }
    // Switching the token off does not touch Access.
    await env.DB.prepare("INSERT INTO meta (key, value) VALUES ('admin_token_login', 'off')").run();
    expect((await call(new Request(`${BASE}/admin`, { headers: { "cf-access-jwt-assertion": jwt } }), { ...accessOnly, ADMIN_TOKEN })).status).toBe(200);
  });
});

describe("the passkey script", () => {
  it("is allowed by its hash, on the pages that carry it", async () => {
    const d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(PASSKEY_SCRIPT)));
    expect(PASSKEY_SCRIPT_HASH).toBe(`sha256-${btoa(String.fromCharCode(...d))}`);
    // The script is built from template strings, which drop a backslash before
    // most characters: a regex written /\\+/ would arrive as /+/ and not parse.
    expect(PASSKEY_SCRIPT).not.toContain("/+/");
    expect(PASSKEY_SCRIPT).not.toContain("///");
    expect(PASSKEY_SCRIPT).toContain('.replace(/[+]/g,"-").replace(/[/]/g,"_")');
    const cookie = await tokenSession();
    const res = await call(new Request(`${BASE}/admin/passkeys`, { headers: { cookie } }));
    const body = await res.text();
    const scripts = [...body.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)];
    expect(scripts.length).toBe(1);
    expect(scripts[0][1]).toBe(PASSKEY_SCRIPT);
    expect(res.headers.get("content-security-policy")).toBe(`${BASE_CSP}; script-src '${PASSKEY_SCRIPT_HASH}'; connect-src 'self'`);
    // Controls are hidden until the script finds WebAuthn; texts come from the server.
    expect(body).toMatch(/<div id="pk" data-mode="register" data-fail="The passkey was not added\. Try again\." hidden>/);
    const vi_ = await (await call(new Request(`${BASE}/admin/passkeys`, { headers: { cookie: `${cookie}; bc_lang=vi` } }))).text();
    expect(vi_).toContain("Thêm passkey");
    expect(vi_).toContain('data-fail="Chưa thêm được passkey. Hãy thử lại."');
  });

  it("derToRaw handles short and padded integers and rejects junk", () => {
    const r = new Uint8Array(32).fill(0x80), s = new Uint8Array(32);
    s[31] = 7;
    const raw = derToRaw(rawToDer(cat(r, s)))!;
    expect([...raw]).toEqual([...r, ...s]);
    expect(derToRaw(new Uint8Array([0x30, 2, 0x02, 0]))).toBeNull();
    expect(derToRaw(new Uint8Array(70))).toBeNull();
  });
});
