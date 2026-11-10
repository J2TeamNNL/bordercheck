// The REST API at /api/v1: JSON in, JSON out, for scripts and other systems
// (onboarding creates invites, offboarding revokes a machine, a job exports
// the fleet, CI checks posture). English only, like MCP.
//
// Every route is one entry in ROUTES: method, path, the schemas of its path
// parameters, query and body, and its handler. The router, the input
// validation and the OpenAPI document (GET /api/v1/openapi.json) are all
// derived from that table, so the document can't drift from what is served.
//
// Handlers reach the data only through fleet.ts and the dashboard's shared
// operations, exactly as the MCP tools do: same validation, limits,
// atomicity and audit rows. Writes are audited as "api" with the method, the
// path and the arguments; refused writes as "api.refused".
//
// Access: bearer tokens API_TOKEN (reads and writes) and API_READ_TOKEN (GET
// only), separate from ADMIN_TOKEN and from the MCP tokens. A token equal to
// ADMIN_TOKEN is ignored, so the dashboard login never opens the API. With no
// usable token, /api/v1 answers 404 like any unknown path. Only the
// Authorization header is read (no cookies, so nothing for a cross-site
// request to ride on), a browser Origin other than this deployment's is
// refused, and requests are rate-limited per client IP before the token is
// checked.
//
// Deliberately absent, as in MCP: forgetting a machine, deleting roles, token
// or configuration changes, and anything that returns a machine token, a
// code/token hash or a report-link id. Invite codes appear only in the
// responses of POST /invites and POST /invites/{id}/reissue.

import { bearer, safeEqual, usableToken } from "./auth";
import { API_ACTOR, API_READ_ACTOR, audit } from "./audit";
import { alertRows, checkStats, FILTERS, type Filter, machineCount, machineRows, waitingCount, waitingRows } from "./dashboard";
import { publicOrigin } from "./enroll";
import type { Env } from "./env";
import {
  alertItem,
  API_ROLE_RULES,
  auditArgs,
  auditItem,
  checkStatItem,
  clean,
  createInvites,
  fleetSummary,
  INSTALL_ID_PATTERN,
  inviteItem,
  issuedItem,
  KNOWN_STATUSES,
  machineDetail,
  machineExists,
  machineSummary,
  machineWaivers,
  machineWrite,
  type Out,
  reissueInvite,
  revokeInvite,
  roleDetail,
  roleItem,
  type Schema,
  silentBefore,
  validate,
  waitingSummary,
  type Writer,
  writeRole,
} from "./fleet";
import { json, readLimited, TooLarge } from "./ingest";
import { originAllowed } from "./mcp";
import { type AuditFilter, auditRows, type InviteFilter, inviteRows, MAX_BULK, roleRows } from "./portal";
import { hit } from "./ratelimit";
import { POLICY_CHECKS } from "./roles";
import { b64url, sha256hex } from "./tokens";

export const API_BASE = "/api/v1";
// A role policy may be 256 KB; leave room for the rest of the body.
export const MAX_API_BYTES = 320 * 1024;
export const IDEMPOTENCY_HOURS = 24;
export const API_VERSION = "1.0.0";

const HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" };

// ---- Access ----

// A token is usable if it is long enough and is not the dashboard's admin token.
const usableApiToken = (env: Env, t: string | undefined): t is string => usableToken(t) && t !== env.ADMIN_TOKEN;

export function apiConfigured(env: Env): boolean {
  return usableApiToken(env, env.API_TOKEN) || usableApiToken(env, env.API_READ_TOKEN);
}

// apiAccess: "write", "read" or null. Both tokens are always compared, in
// constant time, so timing doesn't say which one (if any) matched.
export async function apiAccess(req: Request, env: Env): Promise<"write" | "read" | null> {
  const got = bearer(req);
  if (!got) return null;
  const [w, r] = await Promise.all([
    usableApiToken(env, env.API_TOKEN) ? safeEqual(got, env.API_TOKEN) : Promise.resolve(false),
    usableApiToken(env, env.API_READ_TOKEN) ? safeEqual(got, env.API_READ_TOKEN) : Promise.resolve(false),
  ]);
  return w ? "write" : r ? "read" : null;
}

// ---- Responses and errors ----

interface Reply {
  status: number;
  body: unknown;
  headers?: Record<string, string>;
}

// ApiError is thrown by handlers and turned into the one error shape:
// {"error": {"code", "message", "details"?}}.
export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: unknown[],
    public headers: Record<string, string> = {},
  ) {
    super(message);
  }
}

function reply(r: Reply): Response {
  return new Response(r.status === 204 ? null : JSON.stringify(r.body), { status: r.status, headers: { ...HEADERS, ...r.headers } });
}

function errorReply(e: ApiError): Response {
  const error: Record<string, unknown> = { code: e.code, message: e.message };
  if (e.details?.length) error.details = e.details;
  return reply({ status: e.status, body: { error }, headers: e.headers });
}

const invalid = (problems: string[]) =>
  new ApiError(400, "validation_failed", "The request is not valid.", problems.slice(0, 50).map((message) => ({ message })));

// Codes for conflicts the shared operations report, by their message key.
const CONFLICT_CODES: Record<string, string> = {
  "err.roleExists": "name_taken",
  "err.roleClash": "name_taken",
  "err.inviteUsedOrRevoked": "invite_not_pending",
  "err.inviteNotReissuable": "invite_not_reissuable",
  "err.inviteRaced": "invite_not_reissuable",
  "err.notEnrolled": "not_enrolled",
};

// failure turns a shared operation's failure into an ApiError: its status,
// a stable code, the English message and the validation problems.
function failure(o: { error: string; errors?: string[]; status?: number; key?: string }): ApiError {
  const status = o.status ?? 400;
  const code = status === 404 ? "not_found" : (o.key && CONFLICT_CODES[o.key]) || (status === 409 ? "conflict" : "validation_failed");
  return new ApiError(status, code, o.error, o.errors?.slice(0, 50).map((message) => ({ message })));
}

function must(o: Out): Record<string, unknown> {
  if (!o.ok) throw failure(o);
  return o.data;
}

// ---- Cursors ----

// A cursor is opaque to clients: base64url of "<kind>:<last key>". Lists are
// ordered by a unique, unchanging key (install_id, or an id newest first), so
// paging is stable while reports keep arriving.
function encodeCursor(kind: string, v: string | number): string {
  return b64url(new TextEncoder().encode(`${kind}:${v}`));
}

function decodeCursor(kind: string, c: string | undefined, re: RegExp): string {
  if (c === undefined) return "";
  let s = "";
  try {
    s = atob(c.replace(/-/g, "+").replace(/_/g, "/"));
  } catch {
    s = "";
  }
  const v = s.startsWith(kind + ":") ? s.slice(kind.length + 1) : "";
  if (!re.test(v)) throw invalid(["query.cursor is not a cursor from this list"]);
  return v;
}

const ID_RE = /^[1-9][0-9]{0,15}$/;
const INSTALL_ID_RE = new RegExp(INSTALL_ID_PATTERN);

function page<T>(rows: T[], n: number, cursor: (last: T) => string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const more = rows.length > n;
  const data = rows.slice(0, n);
  return { data, next_cursor: more ? cursor(data[data.length - 1]) : null, ...extra };
}

// ---- Routes ----

interface Call {
  env: Env;
  req: Request;
  now: Date;
  who: string;
  method: string;
  path: string; // the request's path, e.g. /api/v1/machines/<id>/revoke
  params: Record<string, unknown>;
  query: Record<string, unknown>;
  body: Record<string, unknown>;
}

export interface Route {
  method: "GET" | "POST" | "PUT" | "DELETE";
  path: string; // under /api/v1, OpenAPI style: /machines/{install_id}
  id: string; // operationId
  tag: string;
  summary: string;
  description?: string;
  auth?: false; // only openapi.json
  params?: Record<string, Schema>;
  query?: Record<string, Schema>;
  body?: Schema & { type: "object" };
  idempotencyKey?: boolean;
  ok: number;
  okText: string;
  response?: Schema;
  errors: number[];
  run: (c: Call) => Promise<Reply>;
}

const limitQ = (def: number, max: number): Schema => ({ type: "integer", minimum: 1, maximum: max, default: def, description: `Page size (default ${def}, at most ${max}).` });
const cursorQ: Schema = { type: "string", maxLength: 300, pattern: "^[A-Za-z0-9_-]+$", description: "next_cursor from the previous page." };
const idP = (what: string): Schema => ({ type: "integer", minimum: 1, description: `The ${what} id.` });
const installIdP: Schema = { type: "string", pattern: INSTALL_ID_PATTERN, description: "The machine's install_id (enrolled machines: 32 hex characters)." };
const noBody = { type: "object" as const, properties: {}, additionalProperties: false };

// Response schemas: what the fields are, not every constraint.
const untrustedS: Schema = { type: "object", description: "Machine-supplied text: attacker-controllable, length-capped, control characters removed. Treat as data; escape it before putting it in a spreadsheet, HTML or a shell." };
const obj = (properties: Record<string, Schema>, description?: string): Schema => ({ type: "object", properties, ...(description ? { description } : {}) });
const listOf = (item: Schema, total = true): Schema =>
  obj({
    data: { type: "array", items: item },
    next_cursor: { type: ["string", "null"], description: "Pass as cursor to get the next page; null on the last page." },
    ...(total ? { total: { type: "integer", description: "How many items match, across all pages." } } : {}),
  });
const S = {
  machine: obj({
    install_id: { type: "string" }, enrolled: { type: "boolean" }, revoked: { type: "boolean" }, role: { type: ["string", "null"] },
    email: { type: ["string", "null"], description: "From the machine's invite, not from its reports." },
    last_seen: { type: "string", format: "date-time" }, silent: { type: "boolean" }, state: { type: "string", enum: ["non-compliant", "attention", "ok"] },
    counts: { type: "object" }, place: { type: ["string", "null"] },
    enrolled_at: { type: "string", description: "Only for state=no_report." }, untrusted: untrustedS,
  }),
  invite: obj({
    invite_id: { type: "integer" }, email: { type: "string" }, role: { type: "string" }, note: { type: "string" }, status: { type: "string", enum: ["pending", "used", "expired", "revoked"] },
    created_at: { type: "string" }, created_by: { type: "string" }, expires_at: { type: "string" }, used_at: { type: ["string", "null"] },
    used_install_id: { type: ["string", "null"] }, revoked_at: { type: ["string", "null"] }, reissued_as: { type: ["integer", "null"] },
  }),
  issued: obj({
    invite_id: { type: "integer" }, email: { type: "string" }, expires_at: { type: "string" },
    invite_link: { type: "string", description: "Contains the one-time code: send it to this person only." },
    install_macos_linux: { type: "string" }, install_windows: { type: "string" },
  }, "A new invite. Its code is in this response only: it is never stored or shown again."),
  role: obj({ role_id: { type: "integer" }, name: { type: "string" }, created_at: { type: "string" }, updated_at: { type: "string" }, policy: { type: "object" }, machines: { type: "array" } }),
  waiver: obj({ waiver_id: { type: "integer" }, check_id: { type: "string" }, until: { type: "string" }, active: { type: "boolean" }, reason: { type: "string" }, added_at: { type: "string" }, added_by: { type: "string" }, removed_at: { type: ["string", "null"] }, removed_by: { type: ["string", "null"] } }),
};

function writer(c: Call): Writer {
  const args = { ...c.params, ...c.body };
  return {
    env: c.env,
    req: c.req,
    who: c.who,
    extra: { via: "api", method: c.method, path: c.path, args: auditArgs(args) },
    refuse: (errors) => refused(c, errors),
  };
}

async function refused(c: Call, errors: string[]) {
  await audit(c.env, c.who, "api.refused", `${c.method} ${clean(c.path, 150)}`, {
    via: "api",
    method: c.method,
    path: clean(c.path, 200),
    args: auditArgs({ ...c.params, ...c.body }),
    errors: errors.slice(0, 10).map((e) => clean(e, 300)),
  });
}

const ok = (body: unknown, status = 200, headers?: Record<string, string>): Reply => ({ status, body, headers });

// ---- Machines ----

async function listMachines(c: Call): Promise<Reply> {
  const q = c.query;
  const state = (q.state as string | undefined) ?? "all";
  const n = (q.limit as number | undefined) ?? 50;
  const search = String(q.search ?? "").trim();
  const roleId = q.role_id as number | undefined;
  if (q.check_status !== undefined && q.check === undefined) throw invalid(["query.check_status needs query.check"]);
  const after = decodeCursor("m", q.cursor as string | undefined, INSTALL_ID_RE);
  if (state === "no_report") {
    if (q.check !== undefined) throw invalid(["query.check can't be combined with state=no_report (those machines have no report)"]);
    const [rows, total] = await Promise.all([
      waitingRows(c.env, n + 1, { byId: true, after, q: search, roleId }),
      waitingCount(c.env, { q: search, roleId }),
    ]);
    return ok(page(rows.map(waitingSummary), n, (m) => encodeCursor("m", m.install_id), { total }));
  }
  const silentIso = silentBefore(c.env, c.now);
  const mq = {
    filter: state as Filter,
    q: search,
    silentBefore: silentIso,
    limit: n + 1,
    check: q.check as string | undefined,
    checkStatus: q.check !== undefined ? ((q.check_status as string | undefined) ?? "fail") : undefined,
    roleId,
    byId: true,
    after,
  };
  const [rows, total] = await Promise.all([machineRows(c.env, mq), machineCount(c.env, mq)]);
  return ok(page(rows.map((m) => machineSummary(c.env, m, silentIso)), n, (m) => encodeCursor("m", m.install_id), { total }));
}

async function getMachine(c: Call): Promise<Reply> {
  const include = String(c.query.include ?? "").split(",").filter(Boolean);
  const d = must(await machineDetail(c.env, c.params.install_id as string, {
    evidence: include.includes("evidence"),
    location: include.includes("location"),
    history: c.query.history as number | undefined,
  }, c.now));
  return ok(d);
}

async function machineChange(c: Call, action: "revoke" | "restore" | "reset-link"): Promise<Reply> {
  const d = must(await machineWrite(writer(c), c.params.install_id as string, action));
  if (action === "reset-link") return ok({ install_id: d.install_id, report_links_reset: true });
  return ok({ install_id: d.install_id, revoked: action === "revoke" });
}

// ---- Invites ----

// canonical: JSON with object keys sorted, so the same request always hashes the same.
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`).join(",")}}`;
  }
  return JSON.stringify(v);
}

// Idempotency-Key for POST /invites. The response to the first request holds
// one-time codes that are never stored, so it can't be replayed. A retry with
// the same key and the same body gets 409 already_created with the ids and
// emails of the invites made the first time (re-issue one to get a new code);
// the same key with a different body gets 422; a retry while the first is
// still running gets 409 request_in_progress. Only hashes of the key and of
// the body are stored, for IDEMPOTENCY_HOURS.
const IDEMPOTENCY_KEY_RE = /^[!-~]{1,255}$/;

async function claimKey(c: Call, key: string): Promise<string> {
  const keyHash = await sha256hex("bordercheck-idempotency:" + key);
  const reqHash = await sha256hex(canonical(c.body));
  const ts = c.now.toISOString();
  const expires = new Date(c.now.getTime() + IDEMPOTENCY_HOURS * 3600_000).toISOString();
  const res = await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM api_idempotency WHERE key_hash = ? AND expires_at <= ?").bind(keyHash, ts),
    c.env.DB.prepare(
      "INSERT INTO api_idempotency (key_hash, request_hash, state, invite_ids, created_at, expires_at) VALUES (?, ?, 'pending', '[]', ?, ?) ON CONFLICT (key_hash) DO NOTHING",
    ).bind(keyHash, reqHash, ts, expires),
  ]);
  if (res[1].meta.changes === 1) return keyHash;
  const row = await c.env.DB.prepare("SELECT request_hash, state, invite_ids FROM api_idempotency WHERE key_hash = ?")
    .bind(keyHash)
    .first<{ request_hash: string; state: string; invite_ids: string }>();
  if (row && row.request_hash !== reqHash) {
    throw new ApiError(422, "idempotency_key_reused", "This Idempotency-Key was already used with a different request body.");
  }
  if (!row || row.state !== "done") {
    throw new ApiError(409, "request_in_progress", "A request with this Idempotency-Key is still being processed; retry shortly.", undefined, { "retry-after": "2" });
  }
  const made = await c.env.DB.prepare("SELECT id, email FROM invites WHERE id IN (SELECT value FROM json_each(?)) ORDER BY id")
    .bind(row.invite_ids)
    .all<{ id: number; email: string }>();
  throw new ApiError(
    409,
    "already_created",
    "These invites were already created with this Idempotency-Key. Their codes are shown only once; re-issue an invite to get a new code.",
    made.results.map((i) => ({ invite_id: i.id, email: i.email })),
  );
}

async function postInvites(c: Call): Promise<Reply> {
  const b = c.body;
  if ((b.email === undefined) === (b.emails === undefined)) {
    await refused(c, ["give either email or emails"]);
    throw invalid(["body: give either email (one person) or emails (a list)"]);
  }
  const key = c.req.headers.get("idempotency-key");
  if (key !== null && !IDEMPOTENCY_KEY_RE.test(key)) throw invalid(["Idempotency-Key must be 1 to 255 visible ASCII characters"]);
  const claim = key === null ? null : await claimKey(c, key);
  const release = async () => {
    if (claim) await c.env.DB.prepare("DELETE FROM api_idempotency WHERE key_hash = ? AND state = 'pending'").bind(claim).run();
  };
  let r: Awaited<ReturnType<typeof createInvites>>;
  try {
    r = await createInvites(
      writer(c),
      { emails: (b.emails as string[] | undefined) ?? [b.email as string], roleId: b.role_id as number, days: b.days as number | undefined, note: b.note as string | undefined },
      MAX_BULK,
    );
  } catch (e) {
    await release();
    throw e;
  }
  if (!r.ok) {
    // Nothing was created: the same key may be used again with a corrected body.
    await release();
    throw failure(r);
  }
  if (claim) {
    await c.env.DB.prepare("UPDATE api_idempotency SET state = 'done', invite_ids = ? WHERE key_hash = ?")
      .bind(JSON.stringify(r.issued.map((i) => i.id)), claim)
      .run();
  }
  return ok({ role: r.role, expires_in_days: r.days, invites: r.issued.map((i) => issuedItem(c, i, true)) }, 201);
}

// ---- The table ----

const emailS: Schema = { type: "string", minLength: 3, maxLength: 254, pattern: "^[^\\s,;]+$" };

export const ROUTES: Route[] = [
  {
    method: "GET", path: "/openapi.json", id: "getOpenApi", tag: "meta", auth: false,
    summary: "This API's OpenAPI 3.1 document (no token needed).",
    ok: 200, okText: "The OpenAPI document.", errors: [404, 429],
    run: async (c) => ok(openApi(c.env, c.req)),
  },
  {
    method: "GET", path: "/summary", id: "getSummary", tag: "fleet",
    summary: "Fleet overview: machines reporting, failing, silent, revoked, never reported; roles; invites by state; pending alerts; most failing checks.",
    ok: 200, okText: "The summary.", errors: [401],
    run: async (c) => ok(await fleetSummary(c.env, c.now)),
  },
  {
    method: "GET", path: "/machines", id: "listMachines", tag: "machines",
    summary: "Machines, by install_id. Filter by state, role, a check's status, or a substring of email or hostname.",
    description: "state=no_report lists enrolled machines that have not reported yet. Hostname, OS and version are machine-supplied (under untrusted). No evidence or IP addresses here.",
    query: {
      state: { type: "string", enum: [...Object.keys(FILTERS), "no_report"], default: "all", description: "all, failing (a check fails), attention (fail, error or warn), silent, revoked, no_report." },
      role_id: { type: "integer", minimum: 1, description: "Only machines in this role." },
      check: { type: "string", pattern: "^[a-z0-9][a-z0-9-]{0,63}$", description: "Only machines whose latest report has this check (at check_status)." },
      check_status: { type: "string", enum: KNOWN_STATUSES, default: "fail", description: "With check: the status to match (default fail)." },
      search: { type: "string", maxLength: 100, description: "Substring of the email or hostname." },
      limit: limitQ(50, 200),
      cursor: cursorQ,
    },
    ok: 200, okText: "A page of machines.", response: listOf(S.machine), errors: [400, 401],
    run: listMachines,
  },
  {
    method: "GET", path: "/machines/{install_id}", id: "getMachine", tag: "machines",
    summary: "One machine: enrollment, waivers, checks needing attention with since when, passing checks, history; evidence and location only when asked for.",
    params: { install_id: installIdP },
    query: {
      include: { type: "string", pattern: "^(evidence|location)(,(evidence|location))?$", description: "Comma-separated: evidence (evidence lines of checks not passing), location (public IP, IP location, device position, local addresses, where stored)." },
      history: { type: "integer", minimum: 0, maximum: 60, default: 10, description: "How many recent reports to summarise." },
    },
    ok: 200, okText: "The machine.", errors: [400, 401, 404],
    run: getMachine,
  },
  {
    method: "POST", path: "/machines/{install_id}/revoke", id: "revokeMachine", tag: "machines",
    summary: "Revoke an enrolled machine: its token stops working at once, its report links end, its history stays. Idempotent.",
    params: { install_id: installIdP },
    ok: 200, okText: "Revoked.", response: obj({ install_id: { type: "string" }, revoked: { type: "boolean" } }), errors: [400, 401, 403, 404, 409],
    run: (c) => machineChange(c, "revoke"),
  },
  {
    method: "POST", path: "/machines/{install_id}/restore", id: "restoreMachine", tag: "machines",
    summary: "Undo a revoke: the same token works again (old report links stay ended). Idempotent.",
    params: { install_id: installIdP },
    ok: 200, okText: "Restored.", response: obj({ install_id: { type: "string" }, revoked: { type: "boolean" } }), errors: [400, 401, 403, 404, 409],
    run: (c) => machineChange(c, "restore"),
  },
  {
    method: "PUT", path: "/machines/{install_id}/role", id: "setMachineRole", tag: "machines",
    summary: "Move an enrolled machine to another role; it gets the policy at its next hourly refresh. Idempotent.",
    params: { install_id: installIdP },
    body: { type: "object", properties: { role_id: { type: "integer", minimum: 1 } }, required: ["role_id"], additionalProperties: false },
    ok: 200, okText: "The machine's role.", response: obj({ install_id: { type: "string" }, role: { type: "string" }, previous_role: { type: "string" } }), errors: [400, 401, 403, 404, 409],
    async run(c) {
      const d = must(await machineWrite(writer(c), c.params.install_id as string, "role", { role_id: c.body.role_id as number }));
      return ok({ install_id: d.install_id, role: d.to, previous_role: d.from });
    },
  },
  {
    method: "GET", path: "/machines/{install_id}/waivers", id: "listMachineWaivers", tag: "machines",
    summary: "A machine's waivers (at most 100), active ones first.",
    params: { install_id: installIdP },
    ok: 200, okText: "The waivers.", response: obj({ data: { type: "array", items: S.waiver } }), errors: [400, 401, 404],
    async run(c) {
      const id = c.params.install_id as string;
      if (!(await machineExists(c.env, id))) throw new ApiError(404, "not_found", "No such machine.");
      return ok({ data: await machineWaivers(c.env, id, c.now) });
    },
  },
  {
    method: "POST", path: "/machines/{install_id}/waivers", id: "addMachineWaiver", tag: "machines",
    summary: "Waive one check on one enrolled machine until a date (today to a year ahead), with a reason. Delivered at the next hourly policy refresh.",
    params: { install_id: installIdP },
    body: {
      type: "object",
      properties: {
        check: { type: "string", enum: POLICY_CHECKS },
        until: { type: "string", pattern: "^\\d{4}-\\d{2}-\\d{2}$", description: "Last day, YYYY-MM-DD." },
        reason: { type: "string", minLength: 1, maxLength: 300 },
      },
      required: ["check", "until", "reason"],
      additionalProperties: false,
    },
    ok: 201, okText: "The waiver.", response: obj({ install_id: { type: "string" }, waiver_id: { type: "integer" }, check: { type: "string" }, until: { type: "string" }, reason: { type: "string" } }),
    errors: [400, 401, 403, 404, 409],
    async run(c) {
      const d = must(await machineWrite(writer(c), c.params.install_id as string, "waivers", { check: c.body.check as string, until: c.body.until as string, reason: c.body.reason as string }));
      return ok(d, 201);
    },
  },
  {
    method: "DELETE", path: "/machines/{install_id}/waivers/{waiver_id}", id: "removeMachineWaiver", tag: "machines",
    summary: "End one machine waiver now (the record stays, marked removed).",
    params: { install_id: installIdP, waiver_id: idP("waiver") },
    ok: 200, okText: "Removed.", response: obj({ install_id: { type: "string" }, waiver_id: { type: "integer" }, removed: { type: "boolean" } }), errors: [400, 401, 403, 404, 409],
    async run(c) {
      must(await machineWrite(writer(c), c.params.install_id as string, "remove-waiver", { waiver_id: c.params.waiver_id as number }));
      return ok({ install_id: c.params.install_id, waiver_id: c.params.waiver_id, removed: true });
    },
  },
  {
    method: "POST", path: "/machines/{install_id}/report-links/reset", id: "resetReportLinks", tag: "machines",
    summary: "End every login-free report link issued so far for one machine; the next report gets a new one.",
    params: { install_id: installIdP },
    ok: 200, okText: "Reset.", response: obj({ install_id: { type: "string" }, report_links_reset: { type: "boolean" } }), errors: [400, 401, 403, 404],
    run: (c) => machineChange(c, "reset-link"),
  },
  {
    method: "GET", path: "/roles", id: "listRoles", tag: "roles",
    summary: "Roles by id, with active machines and pending invites.",
    query: { limit: limitQ(100, 200), cursor: cursorQ },
    ok: 200, okText: "A page of roles.", response: listOf(obj({ role_id: { type: "integer" }, name: { type: "string" }, machines: { type: "integer" }, pending_invites: { type: "integer" }, updated_at: { type: "string" } })),
    errors: [400, 401],
    async run(c) {
      const n = (c.query.limit as number | undefined) ?? 100;
      const after = Number(decodeCursor("r", c.query.cursor as string | undefined, ID_RE) || 0);
      const all = (await roleRows(c.env)).sort((a, b) => a.id - b.id);
      return ok(page(all.filter((r) => r.id > after).slice(0, n + 1).map(roleItem), n, (r) => encodeCursor("r", r.role_id), { total: all.length }));
    },
  },
  {
    method: "POST", path: "/roles", id: "createRole", tag: "roles",
    summary: "Create a role. The policy is validated as the dashboard does; every problem is returned at once.",
    description: "Through the API a role may not set report.url, report.headers, update.policy_url, update.repo or update.public_key (they are filled in per machine, or decide where binary updates come from: do that in the dashboard). Everything else, including include_evidence, include_ips, include_location, check_interval and role-level waivers, is allowed.",
    body: {
      type: "object",
      properties: { name: { type: "string", minLength: 1, maxLength: 64 }, policy: { type: ["object", "string"], description: "The policy JSON (an object, or its text), same shape as policies.json." } },
      required: ["name", "policy"],
      additionalProperties: false,
    },
    ok: 201, okText: "The new role.", response: S.role, errors: [400, 401, 403, 409, 413],
    async run(c) {
      const w = must(await writeRole(writer(c), { name: c.body.name as string, policy: c.body.policy }, API_ROLE_RULES, c.now));
      const d = must(await roleDetail(c.env, w.role_id as number));
      return ok(d, 201, { location: `${API_BASE}/roles/${w.role_id}` });
    },
  },
  {
    method: "GET", path: "/roles/{role_id}", id: "getRole", tag: "roles",
    summary: "One role: its policy and its machines (at most 200).",
    params: { role_id: idP("role") },
    ok: 200, okText: "The role.", response: S.role, errors: [400, 401, 404],
    run: async (c) => ok(must(await roleDetail(c.env, c.params.role_id as number))),
  },
  {
    method: "PUT", path: "/roles/{role_id}", id: "updateRole", tag: "roles",
    summary: "Rename a role and/or replace its whole policy (each field given replaces that field; omitted fields are kept). Machines pick it up at their next hourly refresh.",
    params: { role_id: idP("role") },
    body: {
      type: "object",
      properties: { name: { type: "string", minLength: 1, maxLength: 64 }, policy: { type: ["object", "string"], description: "The complete new policy." } },
      additionalProperties: false,
    },
    ok: 200, okText: "The role.", response: S.role, errors: [400, 401, 403, 404, 409, 413],
    async run(c) {
      if (c.body.name === undefined && c.body.policy === undefined) throw invalid(["body: give name, policy, or both"]);
      const w = must(await writeRole(writer(c), { id: c.params.role_id as number, name: c.body.name as string | undefined, policy: c.body.policy }, API_ROLE_RULES, c.now));
      const d = must(await roleDetail(c.env, w.role_id as number));
      return ok({ ...d, policy_changed: w.policy_changed });
    },
  },
  {
    method: "GET", path: "/invites", id: "listInvites", tag: "invites",
    summary: "Invites, newest first, with counts per state. Codes are never shown again after creation.",
    query: {
      status: { type: "string", enum: ["all", "pending", "used", "expired", "revoked"], default: "all" },
      email: { type: "string", maxLength: 254, description: "Only this person's invites (exact, case-insensitive)." },
      limit: limitQ(50, 200),
      cursor: cursorQ,
    },
    ok: 200, okText: "A page of invites.", response: { ...listOf(S.invite), description: "total is given unless email is set; counts are per state, over all invites." },
    errors: [400, 401],
    async run(c) {
      const status = ((c.query.status as string | undefined) ?? "all") as InviteFilter;
      const n = (c.query.limit as number | undefined) ?? 50;
      const before = Number(decodeCursor("i", c.query.cursor as string | undefined, ID_RE) || 0);
      const email = c.query.email as string | undefined;
      const { rows, counts } = await inviteRows(c.env, status, n + 1, { before, email });
      const total = email ? undefined : status === "all" ? Object.values(counts).reduce((a, b) => a + b, 0) : counts[status] ?? 0;
      return ok(page(rows.map(inviteItem), n, (i) => encodeCursor("i", i.invite_id), { ...(total === undefined ? {} : { total }), counts }));
    },
  },
  {
    method: "POST", path: "/invites", id: "createInvites", tag: "invites",
    summary: `Invite one person (email) or several (emails, at most ${MAX_BULK}) to enroll one machine each in a role. All or nothing.`,
    description: "Returns each invite's link and install commands, which contain the one-time code: shown only in this response, never stored. Send an Idempotency-Key header to make retries safe: a repeat with the same key and body gets 409 already_created with the invite ids (no codes), not a second invite.",
    idempotencyKey: true,
    body: {
      type: "object",
      properties: {
        email: emailS,
        emails: { type: "array", minItems: 1, maxItems: MAX_BULK, items: emailS },
        role_id: { type: "integer", minimum: 1 },
        days: { type: "integer", minimum: 1, maximum: 90, description: "Days until the invites expire (default INVITE_DAYS)." },
        note: { type: "string", maxLength: 200, description: "A note for admins." },
      },
      required: ["role_id"],
      additionalProperties: false,
    },
    ok: 201, okText: "The invites, with their codes (once).", response: obj({ role: { type: "string" }, expires_in_days: { type: "integer" }, invites: { type: "array", items: S.issued } }),
    errors: [400, 401, 403, 409, 413, 422],
    run: postInvites,
  },
  {
    method: "POST", path: "/invites/{invite_id}/revoke", id: "revokeInvite", tag: "invites",
    summary: "Revoke a pending invite: its code stops working. A used or already revoked invite gives 409 invite_not_pending.",
    params: { invite_id: idP("invite") },
    ok: 200, okText: "Revoked.", response: obj({ invite_id: { type: "integer" }, email: { type: "string" }, status: { type: "string" } }), errors: [400, 401, 403, 404, 409],
    run: async (c) => ok(must(await revokeInvite(writer(c), c.params.invite_id as number))),
  },
  {
    method: "POST", path: "/invites/{invite_id}/reissue", id: "reissueInvite", tag: "invites",
    summary: "Replace an unused invite (pending, expired or revoked) with a new one for the same email and role; the old code stops working. Returns the new code once.",
    params: { invite_id: idP("invite") },
    ok: 201, okText: "The new invite.", response: obj({ replaced_invite_id: { type: "integer" }, invite: S.issued }), errors: [400, 401, 403, 404, 409],
    async run(c) {
      const r = await reissueInvite(writer(c), c.params.invite_id as number);
      if (!r.ok) throw failure(r);
      return ok({ replaced_invite_id: c.params.invite_id, invite: issuedItem(c, r.issued, true) }, 201);
    },
  },
  {
    method: "GET", path: "/checks", id: "listChecks", tag: "fleet",
    summary: "Per check, across every machine's latest report: failing, failing at high severity, error, warn, waived, pass, reporting. Most failing first. Not paged.",
    query: { limit: limitQ(100, 1000) },
    ok: 200, okText: "The checks.", response: obj({ data: { type: "array", items: obj({ check_id: { type: ["string", "null"] }, fail: { type: "integer" }, high: { type: "integer" }, untrusted: untrustedS }) }, next_cursor: { type: "null" } }),
    errors: [400, 401],
    run: async (c) => ok({ data: (await checkStats(c.env, (c.query.limit as number | undefined) ?? 100)).map(checkStatItem), next_cursor: null }),
  },
  {
    method: "GET", path: "/alerts", id: "listAlerts", tag: "fleet",
    summary: "Alerts (high_fail, silent, back, new_country), newest first.",
    query: { pending: { type: "boolean", default: false, description: "Only alerts not yet delivered to the webhook." }, limit: limitQ(50, 200), cursor: cursorQ },
    ok: 200, okText: "A page of alerts.", response: listOf(obj({ alert_id: { type: "integer" }, kind: { type: "string" }, install_id: { type: "string" }, check_id: { type: ["string", "null"] }, raised_at: { type: "string" }, delivered_at: { type: ["string", "null"] }, untrusted: untrustedS }), false),
    errors: [400, 401],
    async run(c) {
      const n = (c.query.limit as number | undefined) ?? 50;
      const before = Number(decodeCursor("a", c.query.cursor as string | undefined, ID_RE) || 0);
      const rows = await alertRows(c.env, n + 1, c.query.pending === true, before);
      return ok(page(rows.map(alertItem), n, (a) => encodeCursor("a", a.alert_id)));
    },
  },
  {
    method: "GET", path: "/audit", id: "listAudit", tag: "fleet",
    summary: "The audit trail, newest first. actor=api keeps what was done through this API, actor=mcp through the MCP server.",
    query: { actor: { type: "string", enum: ["all", "api", "mcp"], default: "all" }, limit: limitQ(50, 200), cursor: cursorQ },
    ok: 200, okText: "A page of audit entries.", response: listOf(obj({ id: { type: "integer" }, at: { type: "string" }, who: { type: "string" }, action: { type: "string" }, target: { type: "string" }, untrusted: untrustedS }), false),
    errors: [400, 401],
    async run(c) {
      const n = (c.query.limit as number | undefined) ?? 50;
      const before = Number(decodeCursor("u", c.query.cursor as string | undefined, ID_RE) || 0);
      const rows = await auditRows(c.env, n + 1, ((c.query.actor as string | undefined) ?? "all") as AuditFilter, before);
      return ok(page(rows.map(auditItem), n, (a) => encodeCursor("u", a.id)));
    },
  },
];

// ---- Matching and input ----

const compiled = ROUTES.map((r) => ({
  route: r,
  names: [...r.path.matchAll(/\{(\w+)\}/g)].map((m) => m[1]),
  re: new RegExp("^" + r.path.replace(/[.]/g, "[.]").replace(/\{\w+\}/g, "([^/]+)") + "$"),
}));

// match finds the route for a path under /api/v1: the route and its raw path
// parameters, or the methods the path allows (405), or nothing (404).
export function match(method: string, path: string): { route: Route; raw: Record<string, string> } | { allow: string[] } | null {
  const allow: string[] = [];
  for (const c of compiled) {
    const m = c.re.exec(path);
    if (!m) continue;
    if (c.route.method !== method) {
      allow.push(c.route.method);
      continue;
    }
    const raw: Record<string, string> = {};
    c.names.forEach((n, i) => {
      try {
        raw[n] = decodeURIComponent(m[i + 1]);
      } catch {
        raw[n] = m[i + 1];
      }
    });
    return { route: c.route, raw };
  }
  return allow.length ? { allow } : null;
}

// coerce turns a query or path string into what its schema expects, where it
// plainly is one; anything else is left for validate to refuse.
function coerce(s: Schema, v: string): unknown {
  const t = Array.isArray(s.type) ? s.type[0] : s.type;
  if (t === "integer" && /^-?[0-9]{1,15}$/.test(v)) return Number(v);
  if (t === "boolean" && (v === "true" || v === "false")) return v === "true";
  return v;
}

function readParams(r: Route, raw: Record<string, string>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(raw)) out[k] = coerce(r.params?.[k] ?? {}, v);
  const errs = validate({ type: "object", properties: r.params ?? {}, additionalProperties: false }, out, "path");
  if (errs.length) throw invalid(errs);
  return out;
}

function readQuery(r: Route, url: URL): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const errs: string[] = [];
  for (const k of new Set(url.searchParams.keys())) {
    const s = r.query?.[k];
    if (!s) {
      errs.push(`query: unknown parameter "${clean(k, 40)}"`);
      continue;
    }
    const all = url.searchParams.getAll(k);
    if (all.length > 1) errs.push(`query.${k} is given more than once`);
    out[k] = coerce(s, all[0]);
  }
  errs.push(...validate({ type: "object", properties: r.query ?? {}, additionalProperties: true }, out, "query"));
  if (errs.length) throw invalid(errs);
  return out;
}

async function readBody(req: Request): Promise<Record<string, unknown>> {
  let text: string;
  try {
    text = await readLimited(req, MAX_API_BYTES);
  } catch (e) {
    if (e instanceof TooLarge) throw new ApiError(413, "payload_too_large", `The body is larger than ${MAX_API_BYTES / 1024} KB.`);
    throw e;
  }
  if (text.trim() === "") return {};
  if (!(req.headers.get("content-type") ?? "").toLowerCase().startsWith("application/json")) {
    throw new ApiError(415, "unsupported_media_type", "Send the body as JSON, with Content-Type: application/json.");
  }
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    throw new ApiError(400, "invalid_json", "The body is not valid JSON.");
  }
  if (!v || typeof v !== "object" || Array.isArray(v)) throw new ApiError(400, "invalid_json", "The body must be a JSON object.");
  return v as Record<string, unknown>;
}

// ---- The handler ----

export async function handleApi(req: Request, env: Env, now = new Date()): Promise<Response> {
  // Off: indistinguishable from any unknown path.
  if (!apiConfigured(env)) return json({ error: "not found" }, 404);
  try {
    return await serve(req, env, now);
  } catch (e) {
    if (e instanceof ApiError) return errorReply(e);
    console.error("api:", (e as Error)?.message ?? "error");
    return errorReply(new ApiError(500, "internal_error", "Something went wrong on the server."));
  }
}

async function serve(req: Request, env: Env, now: Date): Promise<Response> {
  if (!originAllowed(req, env)) throw new ApiError(403, "origin_not_allowed", "Requests from other sites' pages are refused.");
  // Counted before the token check, so guessing tokens is throttled too.
  const rl = await hit(env, req, "api", now.getTime());
  if (!rl.ok) throw new ApiError(429, "rate_limited", "Too many requests; retry later.", undefined, { "retry-after": String(rl.retryAfter) });

  const url = new URL(req.url);
  const path = url.pathname.slice(API_BASE.length).replace(/\/+$/, "") || "/";
  const m = match(req.method, path);
  if (!m) throw new ApiError(404, "unknown_endpoint", "No such endpoint. See /api/v1/openapi.json.");
  if ("allow" in m) throw new ApiError(405, "method_not_allowed", "Method not allowed here.", undefined, { allow: m.allow.join(", ") });
  const { route, raw } = m;

  let access: "write" | "read" | null = "read";
  if (route.auth !== false) {
    access = await apiAccess(req, env);
    if (!access) {
      throw new ApiError(401, "unauthorized", "Send Authorization: Bearer <API token>.", undefined, { "www-authenticate": 'Bearer realm="bordercheck-api"' });
    }
  }
  const c: Call = {
    env, req, now,
    who: access === "write" ? API_ACTOR : API_READ_ACTOR,
    method: req.method,
    path: url.pathname,
    params: {},
    query: {},
    body: {},
  };
  const writes = route.method !== "GET";
  if (writes && access !== "write") {
    await refused(c, ["read-only token"]);
    throw new ApiError(403, "read_only_token", "This API token is read-only; writes need API_TOKEN.");
  }
  try {
    c.params = readParams(route, raw);
    c.query = readQuery(route, url);
    if (writes) {
      c.body = await readBody(req);
      const errs = validate(route.body ?? noBody, c.body, "body");
      if (errs.length) throw invalid(errs);
    }
  } catch (e) {
    if (writes && e instanceof ApiError && e.status === 400) await refused(c, (e.details ?? []).map((d) => String((d as { message?: string }).message ?? e.message)));
    throw e;
  }
  return reply(await route.run(c));
}

// ---- OpenAPI ----

const ERROR_TEXT: Record<number, string> = {
  400: "Invalid request: validation_failed (details lists every problem), invalid_json.",
  401: "Missing or wrong token: unauthorized.",
  403: "read_only_token (a write with API_READ_TOKEN) or origin_not_allowed.",
  404: "not_found (no such machine, role, invite or waiver) or unknown_endpoint.",
  405: "method_not_allowed; the Allow header lists the methods.",
  409: "A conflict: name_taken, invite_not_pending, invite_not_reissuable, not_enrolled, already_created, request_in_progress.",
  413: "payload_too_large.",
  415: "unsupported_media_type: send Content-Type: application/json.",
  422: "idempotency_key_reused: the Idempotency-Key was used with a different body.",
  429: "rate_limited; see Retry-After.",
};

export function openApi(env: Env, req: Request): Record<string, unknown> {
  const paths: Record<string, Record<string, unknown>> = {};
  for (const r of ROUTES) {
    const parameters: unknown[] = [
      ...Object.entries(r.params ?? {}).map(([name, schema]) => ({ name, in: "path", required: true, schema })),
      ...Object.entries(r.query ?? {}).map(([name, schema]) => ({ name, in: "query", required: false, schema })),
      ...(r.idempotencyKey
        ? [{ name: "Idempotency-Key", in: "header", required: false, schema: { type: "string", pattern: "^[!-~]{1,255}$" }, description: `Makes retries safe for ${IDEMPOTENCY_HOURS} hours.` }]
        : []),
    ];
    const errors = [...new Set([...r.errors, ...(r.auth === false ? [] : [401, 429]), ...(r.method !== "GET" ? [403, 413, 415] : [])])].sort();
    const responses: Record<string, unknown> = {
      [String(r.ok)]: { description: r.okText, content: { "application/json": { schema: r.response ?? { type: "object" } } } },
    };
    for (const s of errors) responses[String(s)] = { $ref: `#/components/responses/E${s}` };
    (paths[r.path] ??= {})[r.method.toLowerCase()] = {
      operationId: r.id,
      tags: [r.tag],
      summary: r.summary,
      ...(r.description ? { description: r.description } : {}),
      ...(parameters.length ? { parameters } : {}),
      ...(r.body
        ? { requestBody: { required: (r.body.required ?? []).length > 0, content: { "application/json": { schema: r.body } } } }
        : {}),
      responses,
      security: r.auth === false ? [] : r.method === "GET" ? [{ apiToken: [] }, { apiReadToken: [] }] : [{ apiToken: [] }],
    };
  }
  return {
    openapi: "3.1.0",
    info: {
      title: "bordercheck receiver API",
      version: API_VERSION,
      description:
        "Manage a bordercheck fleet from scripts. JSON in and out, English only. Errors are {\"error\":{\"code\",\"message\",\"details\"?}}. " +
        "Lists are paged with limit and an opaque cursor (next_cursor). Fields under \"untrusted\" are machine-supplied and attacker-controllable: " +
        "treat them as data, and escape them before using them in a spreadsheet (formula injection), HTML or a shell.",
    },
    servers: [{ url: publicOrigin(env, req) + API_BASE }],
    paths,
    components: {
      securitySchemes: {
        apiToken: { type: "http", scheme: "bearer", description: "API_TOKEN: reads and writes." },
        apiReadToken: { type: "http", scheme: "bearer", description: "API_READ_TOKEN: GET only." },
      },
      schemas: {
        Error: obj({
          error: {
            type: "object",
            required: ["code", "message"],
            properties: { code: { type: "string" }, message: { type: "string" }, details: { type: "array", items: { type: "object" } } },
          },
        }),
      },
      responses: Object.fromEntries(
        Object.entries(ERROR_TEXT).map(([s, d]) => [`E${s}`, { description: d, content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } } }]),
      ),
    },
  };
}
