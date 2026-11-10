// The audit trail: who did what, when. Callers pass only identifiers that are
// safe to show (invite numbers, install IDs, role names, emails); never codes,
// tokens or report-link ids.

import type { Env } from "./env";

export function auditStmt(env: Env, who: string, action: string, target: string, detail: Record<string, unknown> = {}, at = new Date()) {
  return env.DB.prepare("INSERT INTO audit (at, who, action, target, detail) VALUES (?, ?, ?, ?, ?)").bind(
    at.toISOString(),
    who.slice(0, 200),
    action,
    target.slice(0, 200),
    JSON.stringify(detail),
  );
}

export async function audit(env: Env, who: string, action: string, target: string, detail: Record<string, unknown> = {}) {
  await auditStmt(env, who, action, target, detail).run();
}
