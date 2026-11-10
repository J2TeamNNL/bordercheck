// Fixed-window rate limits for the unauthenticated endpoints (/enroll, /i/,
// /r/), counted in D1 per client IP. The IP is hashed before it is used as a
// key. One upsert per request: the count and the window move together, so
// concurrent requests can't both see a fresh window.

import { config, type Env } from "./env";
import { sha256hex } from "./tokens";

// clientIP is Cloudflare's view of the connecting address. Other headers
// (X-Forwarded-For, X-Real-IP…) are set by the client and never trusted.
export function clientIP(req: Request): string {
  return (req.headers.get("cf-connecting-ip") ?? "").trim();
}

export async function hit(env: Env, req: Request, bucket: "enroll" | "page" | "mcp" | "api", nowMs = Date.now()): Promise<{ ok: boolean; retryAfter: number }> {
  const cfg = config(env);
  const limit = { enroll: cfg.enrollRateLimit, mcp: cfg.mcpRateLimit, api: cfg.apiRateLimit, page: cfg.pageRateLimit }[bucket];
  const win = Math.floor(nowMs / 1000 / cfg.rateWindow);
  const key = `${bucket}:${(await sha256hex("bordercheck-rl:" + (clientIP(req) || "unknown"))).slice(0, 32)}`;
  const count = await env.DB.prepare(
    `INSERT INTO rate_limits (key, win, count) VALUES (?1, ?2, 1)
     ON CONFLICT (key) DO UPDATE SET count = CASE WHEN win = ?2 THEN count + 1 ELSE 1 END, win = ?2
     RETURNING count`,
  )
    .bind(key, win)
    .first<number>("count");
  const retryAfter = Math.max(1, Math.ceil((win + 1) * cfg.rateWindow - nowMs / 1000));
  return { ok: (count ?? 0) <= limit, retryAfter };
}

export async function pruneRateLimits(env: Env, nowMs: number): Promise<void> {
  const win = Math.floor(nowMs / 1000 / config(env).rateWindow);
  await env.DB.prepare("DELETE FROM rate_limits WHERE win < ?").bind(win - 1).run();
}
