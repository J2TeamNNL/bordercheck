// A named admin's scope: the roles they manage (table admin_roles). The
// dashboard routes pass Viewer.scope to the query helpers here and in
// dashboard.ts / portal.ts; undefined means everything (the owner, Access
// viewers, and always /api/v1 and MCP, which have their own tokens).
//
// In SQL the scope is one parameter, the admin's id, and a subquery on
// admin_roles (never one parameter per role: D1 caps bound parameters). An
// unscoped query keeps the parameter but only as "?n = 0", so it does not
// touch admin_roles and works before migration 0006 is applied.

import type { Env } from "./env";

export interface Scope {
  admin: number; // admins.id
  roles: number[]; // role ids, loaded once per request (auth.ts viewer())
}

// The value to bind for the scope parameter: 0 when unscoped (ids start at 1).
export const scopeBind = (s?: Scope): number => s?.admin ?? 0;

// roleIn: the role in column `col` is in scope (?n bound to scopeBind).
export function roleIn(col: string, n: number, s?: Scope): string {
  return s ? `${col} IN (SELECT role_id FROM admin_roles WHERE admin_id = ?${n})` : `?${n} = 0`;
}

// machineIn: the machine in column `col` (an install_id) is enrolled in a role
// in scope. Machines that were never enrolled are in nobody's scope.
export function machineIn(col: string, n: number, s?: Scope): string {
  return s
    ? `${col} IN (SELECT se.install_id FROM enrollments se WHERE se.role_id IN (SELECT role_id FROM admin_roles WHERE admin_id = ?${n}))`
    : `?${n} = 0`;
}

export const roleAllowed = (s: Scope | undefined, roleId: number): boolean => !s || s.roles.includes(roleId);

// machineVisible: may this viewer see (and act on) the machine? Unscoped: yes
// (whether it exists is for the page to find out, as before).
export async function machineVisible(env: Env, id: string, s?: Scope): Promise<boolean> {
  if (!s) return true;
  return !!(await env.DB.prepare(`SELECT 1 FROM enrollments e WHERE e.install_id = ?1 AND ${roleIn("e.role_id", 2, s)}`).bind(id, scopeBind(s)).first());
}

export async function inviteVisible(env: Env, id: number, s?: Scope): Promise<boolean> {
  if (!s) return true;
  return !!(await env.DB.prepare(`SELECT 1 FROM invites i WHERE i.id = ?1 AND ${roleIn("i.role_id", 2, s)}`).bind(id, scopeBind(s)).first());
}
