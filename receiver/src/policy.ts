// Serving the organisation's policies.json. The stored copy never holds the
// report token: header values carry the placeholder {{REPORT_TOKEN}}, filled
// in from the Worker secret when the file is served.

import { safeEqual, usableToken } from "./auth";
import { config, type Env } from "./env";
import { html, layout, page } from "./html";
import { json } from "./ingest";

export const PLACEHOLDER = "{{REPORT_TOKEN}}";
const KEY = "policies.json";
const MAX_POLICY_BYTES = 256 * 1024;

type Obj = Record<string, unknown>;

function headersOf(p: Obj): Obj | null {
  const r = p.report;
  if (!r || typeof r !== "object") return null;
  const h = (r as Obj).headers;
  return h && typeof h === "object" && !Array.isArray(h) ? (h as Obj) : null;
}

function mapHeaders(p: Obj, fn: (v: string) => string): Obj {
  const copy = structuredClone(p);
  const h = headersOf(copy);
  if (h) for (const k of Object.keys(h)) if (typeof h[k] === "string") h[k] = fn(h[k] as string);
  return copy;
}

export async function servePolicy(req: Request, env: Env): Promise<Response> {
  if (!config(env).legacy) {
    return json({ error: "legacy_disabled", message: "This receiver only serves enrolled machines; install with an invite link." }, 410);
  }
  if (env.POLICY_KEY) {
    const key = new URL(req.url).searchParams.get("key") ?? "";
    if (!(await safeEqual(key, env.POLICY_KEY))) return json({ error: "not found" }, 404);
  }
  const stored = await env.DB.prepare("SELECT value FROM meta WHERE key = ?").bind(KEY).first<string>("value");
  if (!stored) return json({ error: "no policy has been uploaded" }, 404);
  const p = JSON.parse(stored) as Obj;
  if (stored.includes(PLACEHOLDER) && !usableToken(env.REPORT_TOKEN)) {
    return json({ error: "receiver has no REPORT_TOKEN set" }, 503);
  }
  const out = mapHeaders(p, (v) => v.split(PLACEHOLDER).join(env.REPORT_TOKEN ?? ""));
  return new Response(JSON.stringify(out, null, 2) + "\n", {
    headers: { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff" },
  });
}

// savePolicy checks the upload is a JSON object and swaps any literal report
// token for the placeholder, so the token is not stored in D1. The full policy
// rules are checked by bordercheck itself, which keeps its last good copy if
// this one is invalid; run `bordercheck -policy file -print-policy` first.
export async function savePolicy(env: Env, text: string): Promise<string | null> {
  if (text.length > MAX_POLICY_BYTES) return "policy is too large";
  let p: unknown;
  try {
    p = JSON.parse(text);
  } catch (e) {
    return `not valid JSON: ${(e as Error).message}`;
  }
  if (!p || typeof p !== "object" || Array.isArray(p)) return "policy must be a JSON object";
  const tokens = [env.REPORT_TOKEN, env.REPORT_TOKEN_PREVIOUS].filter(usableToken);
  const clean = mapHeaders(p as Obj, (v) => tokens.reduce((s, t) => s.split(t).join(PLACEHOLDER), v));
  await env.DB.prepare("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value")
    .bind(KEY, JSON.stringify(clean, null, 2))
    .run();
  return null;
}

export async function policyPage(env: Env, who: string, message = "", draft?: string): Promise<Response> {
  const stored = await env.DB.prepare("SELECT value FROM meta WHERE key = ?").bind(KEY).first<string>("value");
  const body = html`<h1>policies.json</h1>
<p class="muted">Served at <code>/policies.json</code>${env.POLICY_KEY ? html` (with <code>?key=</code>)` : ""} to every installed bordercheck.
Put <code>${PLACEHOLDER}</code> where the report token goes, e.g. <code>"Authorization": "Bearer ${PLACEHOLDER}"</code>;
it is filled in from the REPORT_TOKEN secret when served. Anyone who can fetch this file can read that token.</p>
${message ? html`<div class="note">${message}</div>` : ""}
<form method="post" action="/admin/policy"><textarea name="policy" spellcheck="false">${draft ?? stored ?? ""}</textarea>
<p><button>Save</button></p></form>`;
  return page(layout("Policy", who, body), message && draft !== undefined ? 400 : 200);
}
