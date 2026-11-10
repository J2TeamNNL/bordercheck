// The audit trail: who did what, when. Callers pass only identifiers that are
// safe to show (invite numbers, install IDs, role names, emails); never codes,
// tokens or report-link ids.

import type { Env } from "./env";

function values(who: string, action: string, target: string, detail: Record<string, unknown>, at: Date): unknown[] {
  return [at.toISOString(), who.slice(0, 200), action, target.slice(0, 200), JSON.stringify(detail)];
}

// auditStmt is an INSERT to put in a batch with the change it records.
export function auditStmt(env: Env, who: string, action: string, target: string, detail: Record<string, unknown> = {}, at = new Date()) {
  return env.DB.prepare("INSERT INTO audit (at, who, action, target, detail) VALUES (?, ?, ?, ?, ?)").bind(...values(who, action, target, detail, at));
}

// auditStmtIf inserts only if the statement just before it in the batch
// changed a row and `exists` (a SELECT) returns a row: for a change in the
// same batch that may turn out to be a no-op. (`exists` alone is not enough:
// a repeat of the same change within the same millisecond matches it too.)
export function auditStmtIf(env: Env, exists: { sql: string; binds: unknown[] }, who: string, action: string, target: string, detail: Record<string, unknown> = {}, at = new Date()) {
  return env.DB.prepare(`INSERT INTO audit (at, who, action, target, detail) SELECT ?, ?, ?, ?, ? WHERE changes() > 0 AND EXISTS (${exists.sql})`).bind(
    ...values(who, action, target, detail, at),
    ...exists.binds,
  );
}

export async function audit(env: Env, who: string, action: string, target: string, detail: Record<string, unknown> = {}) {
  await auditStmt(env, who, action, target, detail).run();
}

// MCP actors. Only these two names are ever written for MCP calls, so the
// audit page can filter on them.
export const MCP_ACTOR = "mcp";
export const MCP_READ_ACTOR = "mcp (read-only)";
