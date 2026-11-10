// The MCP server at /mcp: Streamable HTTP, stateless, hand-written JSON-RPC.
// Tools are in mcp-tools.ts.
//
// Dual-era, per the 2026-07-28 specification ("Versioning: Backward
// Compatibility with Initialization-Based Versions"):
// - Modern (2026-07-28): no handshake; every request carries
//   _meta["io.modelcontextprotocol/protocolVersion"] and clientCapabilities,
//   mirrored in the MCP-Protocol-Version, Mcp-Method and Mcp-Name headers,
//   which must match the body. Methods: server/discover, tools/list, tools/call.
// - Legacy (2025-11-25, 2025-06-18, 2025-03-26): an `initialize` request
//   negotiates the version; no Mcp-Session-Id is minted (sessions were
//   optional), so every later request stands alone. Methods: initialize,
//   ping, tools/list, tools/call; notifications are accepted with 202.
// Every request is answered with a single application/json response; no SSE,
// so GET and DELETE are 405.
//
// Access: its own bearer tokens, MCP_TOKEN (read and write tools) and
// MCP_READ_TOKEN (read tools only), separate from ADMIN_TOKEN. With neither
// set, /mcp answers 404 like any unknown path. No cookies are involved, and a
// request with a browser Origin other than this deployment's is refused
// (DNS rebinding, drive-by pages).

import { bearer, safeEqual, usableToken } from "./auth";
import { MCP_ACTOR, MCP_READ_ACTOR } from "./audit";
import { publicOrigin } from "./enroll";
import type { Env } from "./env";
import { json, readLimited, TooLarge } from "./ingest";
import { callTool, type Ctx, toolsFor, UNTRUSTED_NOTE } from "./mcp-tools";
import { hit } from "./ratelimit";

export const MODERN_VERSIONS = ["2026-07-28"];
export const LEGACY_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26"];
export const SUPPORTED_VERSIONS = [...MODERN_VERSIONS, ...LEGACY_VERSIONS];
const SERVER_INFO = { name: "bordercheck-receiver", title: "bordercheck fleet", version: "1.0.0" };
// A role policy may be 256 KB; leave room for the JSON-RPC envelope.
export const MAX_MCP_BYTES = 320 * 1024;

const META_VERSION = "io.modelcontextprotocol/protocolVersion";
const META_CAPS = "io.modelcontextprotocol/clientCapabilities";

const INSTRUCTIONS =
  "bordercheck fleet administration: laptops' security-posture reports, roles (policies), invites, per-machine waivers, revoking machines, alerts and the audit trail. " +
  UNTRUSTED_NOTE +
  " Write tools take explicit ids from the read tools and act on one item per call; confirm revokes, waivers and role changes with the person before calling them. " +
  "Every write is recorded in the audit trail with its arguments.";

// JSON-RPC error codes.
const PARSE_ERROR = -32700;
const INVALID_REQUEST = -32600;
const METHOD_NOT_FOUND = -32601;
const INVALID_PARAMS = -32602;
const HEADER_MISMATCH = -32020;
const UNSUPPORTED_VERSION = -32022;
// Application-defined, outside the JSON-RPC reserved range.
const UNAUTHORIZED = -31001;
const FORBIDDEN = -31003;
const RATE_LIMITED = -31029;

type Id = string | number;

const HEADERS = { "x-content-type-options": "nosniff" };

function rpcError(status: number, id: Id | undefined, code: number, message: string, data?: unknown, headers: Record<string, string> = {}): Response {
  const error: Record<string, unknown> = { code, message };
  if (data !== undefined) error.data = data;
  return json({ jsonrpc: "2.0", ...(id !== undefined ? { id } : {}), error }, status, { ...HEADERS, ...headers });
}

function rpcResult(id: Id, result: unknown): Response {
  return json({ jsonrpc: "2.0", id, result }, 200, HEADERS);
}

export function mcpConfigured(env: Env): boolean {
  return usableToken(env.MCP_TOKEN) || usableToken(env.MCP_READ_TOKEN);
}

// mcpAccess: "write", "read" or null. Both tokens are always compared, in
// constant time, so timing doesn't say which one (if any) matched.
export async function mcpAccess(req: Request, env: Env): Promise<"write" | "read" | null> {
  const got = bearer(req);
  if (!got) return null;
  const [w, r] = await Promise.all([
    usableToken(env.MCP_TOKEN) ? safeEqual(got, env.MCP_TOKEN) : Promise.resolve(false),
    usableToken(env.MCP_READ_TOKEN) ? safeEqual(got, env.MCP_READ_TOKEN) : Promise.resolve(false),
  ]);
  return w ? "write" : r ? "read" : null;
}

// originAllowed: no Origin (not a browser) or this deployment's own origin.
// Anything else, including "null", is a page somewhere else.
function originAllowed(req: Request, env: Env): boolean {
  const o = req.headers.get("origin");
  if (o === null) return true;
  return o === new URL(req.url).origin || o === publicOrigin(env, req);
}

// decodeHeader undoes the spec's "=?base64?…?=" encoding of Mcp-Name values.
function decodeHeader(v: string): string | null {
  const m = /^=\?base64\?([A-Za-z0-9+/=]*)\?=$/.exec(v);
  if (!m) return v;
  try {
    const bin = atob(m[1]);
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
  } catch {
    return null;
  }
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

export async function handleMcp(req: Request, env: Env, now = new Date()): Promise<Response> {
  if (!mcpConfigured(env)) return json({ error: "not found" }, 404);
  if (!originAllowed(req, env)) return rpcError(403, undefined, FORBIDDEN, "Origin not allowed");
  if (req.method !== "POST") {
    return new Response(null, { status: 405, headers: { allow: "POST", "cache-control": "no-store" } });
  }
  // Counted before auth, so guessing tokens is throttled too.
  const rl = await hit(env, req, "mcp", now.getTime());
  if (!rl.ok) return rpcError(429, undefined, RATE_LIMITED, "Too many requests", undefined, { "retry-after": String(rl.retryAfter) });
  const access = await mcpAccess(req, env);
  if (!access) {
    return rpcError(401, undefined, UNAUTHORIZED, "Unauthorized: send Authorization: Bearer <MCP token>", undefined, {
      "www-authenticate": 'Bearer realm="bordercheck-mcp"',
    });
  }
  if (!(req.headers.get("content-type") ?? "").toLowerCase().includes("application/json")) {
    return rpcError(415, undefined, INVALID_REQUEST, "Content-Type must be application/json");
  }
  let text: string;
  try {
    text = await readLimited(req, MAX_MCP_BYTES);
  } catch (e) {
    if (e instanceof TooLarge) return rpcError(413, undefined, INVALID_REQUEST, "Request too large");
    throw e;
  }
  let msg: unknown;
  try {
    msg = JSON.parse(text);
  } catch {
    return rpcError(400, undefined, PARSE_ERROR, "Parse error");
  }
  if (Array.isArray(msg)) return rpcError(400, undefined, INVALID_REQUEST, "JSON-RPC batches are not supported; send one message per POST");
  if (!isObj(msg) || msg.jsonrpc !== "2.0") return rpcError(400, undefined, INVALID_REQUEST, "Not a JSON-RPC 2.0 message");
  if (typeof msg.method !== "string") {
    // A response from the client: nothing in this server ever asks for one.
    return rpcError(400, undefined, INVALID_REQUEST, "Only requests and notifications are accepted");
  }
  const method = msg.method;
  if (!("id" in msg)) return new Response(null, { status: 202, headers: { "cache-control": "no-store" } }); // a notification
  const id = msg.id;
  if (typeof id !== "string" && (typeof id !== "number" || !Number.isFinite(id))) {
    return rpcError(400, undefined, INVALID_REQUEST, "id must be a string or a number");
  }
  if (msg.params !== undefined && !isObj(msg.params)) return rpcError(400, id, INVALID_PARAMS, "params must be an object");
  const params = (msg.params ?? {}) as Record<string, unknown>;
  const meta = isObj(params._meta) ? params._meta : {};
  const headerVersion = req.headers.get("mcp-protocol-version");
  const ctx: Ctx = { env, req, who: access === "write" ? MCP_ACTOR : MCP_READ_ACTOR, write: access === "write", now };

  // ---- Legacy era: initialize opens it; requests without _meta continue it ----
  if (method === "initialize") {
    const asked = typeof params.protocolVersion === "string" ? params.protocolVersion : "";
    return rpcResult(id, {
      protocolVersion: LEGACY_VERSIONS.includes(asked) ? asked : LEGACY_VERSIONS[0],
      capabilities: { tools: { listChanged: false } },
      serverInfo: SERVER_INFO,
      instructions: INSTRUCTIONS,
    });
  }
  if (meta[META_VERSION] === undefined) {
    if (headerVersion !== null && !LEGACY_VERSIONS.includes(headerVersion)) {
      if (MODERN_VERSIONS.includes(headerVersion)) {
        return rpcError(400, id, INVALID_PARAMS, `Missing _meta["${META_VERSION}"]: required on every ${headerVersion} request`);
      }
      return rpcError(400, id, UNSUPPORTED_VERSION, "Unsupported protocol version", { supported: SUPPORTED_VERSIONS, requested: headerVersion.slice(0, 40) });
    }
    // No header: a 2025-03-26 client, which predates it.
    switch (method) {
      case "ping":
        return rpcResult(id, {});
      case "tools/list":
        return rpcResult(id, { tools: toolsFor(ctx.write).map(describe) });
      case "tools/call":
        return toolsCall(id, params, ctx, false);
      default:
        // Legacy clients treat a non-2xx answer as a broken transport.
        return rpcError(200, id, METHOD_NOT_FOUND, "Method not found");
    }
  }

  // ---- Modern era: every request carries its version and capabilities ----
  const version = meta[META_VERSION];
  if (typeof version !== "string") return rpcError(400, id, INVALID_PARAMS, `_meta["${META_VERSION}"] must be a string`);
  if (headerVersion === null) return rpcError(400, id, HEADER_MISMATCH, "Header mismatch: MCP-Protocol-Version header is missing");
  if (headerVersion !== version) return rpcError(400, id, HEADER_MISMATCH, "Header mismatch: MCP-Protocol-Version does not match the body");
  if (!MODERN_VERSIONS.includes(version)) {
    return rpcError(400, id, UNSUPPORTED_VERSION, "Unsupported protocol version", { supported: SUPPORTED_VERSIONS, requested: version.slice(0, 40) });
  }
  if (!isObj(meta[META_CAPS])) return rpcError(400, id, INVALID_PARAMS, `Missing _meta["${META_CAPS}"]`);
  const hMethod = req.headers.get("mcp-method");
  if (hMethod === null) return rpcError(400, id, HEADER_MISMATCH, "Header mismatch: Mcp-Method header is missing");
  if (hMethod !== method) return rpcError(400, id, HEADER_MISMATCH, "Header mismatch: Mcp-Method does not match the body");

  const done = (result: Record<string, unknown>) =>
    rpcResult(id, { resultType: "complete", ...result, _meta: { "io.modelcontextprotocol/serverInfo": SERVER_INFO } });
  switch (method) {
    case "server/discover":
      return done({
        supportedVersions: SUPPORTED_VERSIONS,
        capabilities: { tools: { listChanged: false } },
        instructions: INSTRUCTIONS,
        ttlMs: 3600_000,
        cacheScope: "private",
      });
    case "tools/list":
      // Varies by token (read-only gets the read tools only): private.
      return done({ tools: toolsFor(ctx.write).map(describe), ttlMs: 3600_000, cacheScope: "private" });
    case "tools/call": {
      const hName = req.headers.get("mcp-name");
      if (hName === null) return rpcError(400, id, HEADER_MISMATCH, "Header mismatch: Mcp-Name header is missing");
      if (decodeHeader(hName) !== params.name) return rpcError(400, id, HEADER_MISMATCH, "Header mismatch: Mcp-Name does not match the body");
      return toolsCall(id, params, ctx, true);
    }
    default:
      return rpcError(404, id, METHOD_NOT_FOUND, "Method not found");
  }
}

function describe(t: ReturnType<typeof toolsFor>[number]) {
  return { name: t.name, title: t.annotations.title, description: t.description, inputSchema: t.inputSchema, annotations: t.annotations };
}

async function toolsCall(id: Id, params: Record<string, unknown>, ctx: Ctx, modern: boolean): Promise<Response> {
  // A JSON-RPC error inside a 200: the HTTP exchange itself worked.
  const status = 200;
  if (typeof params.name !== "string") return rpcError(status, id, INVALID_PARAMS, "params.name must be a string");
  if (params.arguments !== undefined && !isObj(params.arguments)) return rpcError(status, id, INVALID_PARAMS, "params.arguments must be an object");
  const out = await callTool(params.name, (params.arguments ?? {}) as Record<string, unknown>, ctx);
  // Unknown tool: a protocol error. The name is not echoed back.
  if (!out) return rpcError(status, id, INVALID_PARAMS, "Unknown tool");
  const body: Record<string, unknown> = out.ok
    ? { content: [{ type: "text", text: JSON.stringify(out.data) }], structuredContent: out.data, isError: false }
    : (() => {
        const err = { error: out.error, ...(out.errors?.length ? { problems: out.errors } : {}) };
        return { content: [{ type: "text", text: JSON.stringify(err) }], structuredContent: err, isError: true };
      })();
  if (modern) {
    body.resultType = "complete";
    body._meta = { "io.modelcontextprotocol/serverInfo": SERVER_INFO };
  }
  return rpcResult(id, body);
}
