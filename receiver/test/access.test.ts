import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { accessIdentity, resetAccessKeys } from "../src/auth";
import { BASE, call, env } from "./helpers";

const TEAM = "sample.cloudflareaccess.com";
const AUD = "aud-tag-1234";
const e = { ...env, ACCESS_TEAM_DOMAIN: TEAM, ACCESS_AUD: AUD };

let keys: CryptoKeyPair;
let jwk: JsonWebKey;

const b64url = (b: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(b instanceof Uint8Array ? b : new Uint8Array(b))))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
const text = (o: unknown) => b64url(new TextEncoder().encode(JSON.stringify(o)));

async function jwt(claims: Record<string, unknown>, key = keys.privateKey, kid = "k1") {
  const head = text({ alg: "RS256", kid, typ: "JWT" });
  const body = text(claims);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(`${head}.${body}`));
  return `${head}.${body}.${b64url(sig)}`;
}

const now = Date.now();
const good = () => ({ aud: [AUD], iss: `https://${TEAM}`, exp: Math.floor(now / 1000) + 600, email: "it@domain.com" });

beforeAll(async () => {
  keys = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  jwk = (await crypto.subtle.exportKey("jwk", keys.publicKey)) as JsonWebKey;
});

function stubCerts() {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = String(input instanceof Request ? input.url : input);
    if (url === `https://${TEAM}/cdn-cgi/access/certs`) {
      return Response.json({ keys: [{ ...jwk, kid: "k1", alg: "RS256" }] });
    }
    return new Response("unexpected", { status: 500 });
  });
}

afterEach(() => {
  vi.restoreAllMocks();
  resetAccessKeys();
});

const withJwt = (token: string) => new Request(`${BASE}/admin`, { headers: { "cf-access-jwt-assertion": token } });

describe("Cloudflare Access", () => {
  it("accepts a valid JWT and shows the identity", async () => {
    stubCerts();
    const token = await jwt(good());
    expect(await accessIdentity(withJwt(token), e, now)).toBe("it@domain.com");
    const res = await call(withJwt(token), e);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("it@domain.com");
  });

  it("rejects wrong audience, issuer, expiry, signature and alg", async () => {
    stubCerts();
    const other = (await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const cases = [
      await jwt({ ...good(), aud: ["other-app"] }),
      await jwt({ ...good(), iss: "https://evil.cloudflareaccess.com" }),
      await jwt({ ...good(), exp: Math.floor(now / 1000) - 10 }),
      await jwt(good(), other.privateKey),
      await jwt(good(), keys.privateKey, "unknown-kid"),
      `${text({ alg: "none", kid: "k1" })}.${text(good())}.`,
      "garbage",
    ];
    for (const t of cases) expect(await accessIdentity(withJwt(t), e, now)).toBeNull();
  });

  it("falls back to the admin token without a JWT, and refuses without either", async () => {
    stubCerts();
    expect((await call(new Request(`${BASE}/admin`), e)).status).toBe(303); // to the token login
    const accessOnly = { ...e, ADMIN_TOKEN: "" };
    expect((await call(new Request(`${BASE}/admin`), accessOnly)).status).toBe(401);
    expect((await call(withJwt(await jwt(good())), accessOnly)).status).toBe(200);
    expect((await call(new Request(`${BASE}/admin/login`), accessOnly)).status).toBe(403);
  });
});
