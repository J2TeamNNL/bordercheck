// Waiver requests: the person at an enrolled machine asks for a waiver
// (`bordercheck waiver request`, POST /waiver-requests with the machine's
// token, like /report), and sees their requests (GET /waiver-requests). An
// admin approves one, which adds the waiver through machineAction exactly as
// the dashboard's form does, or rejects it. The reason is the requester's
// text: escaped in HTML, under "untrusted" in MCP and API results.

import { audit } from "./audit";
import { bearer } from "./auth";
import { machineByToken } from "./enroll";
import type { Env } from "./env";
import { Html, html, note, pill } from "./html";
import { checkTitle, english, type I18n, type Msg, msg } from "./i18n";
import { json } from "./ingest";
import { type AuditExtra, cleanLine, machineAction, machineLink } from "./portal";
import { CHECK_ID_RE, POLICY_CHECKS, waiverDateError } from "./roles";
import { machineIn, type Scope, scopeBind } from "./scope";

export const MAX_REQUEST_REASON = 300;
// Pending requests one machine may have at once.
export const MAX_PENDING = 20;
const MAX_BODY = 4 * 1024;

export type RequestStatus = "pending" | "approved" | "rejected";

export interface WaiverRequestRow {
  id: number;
  install_id: string;
  check_id: string;
  until: string;
  reason: string;
  accept_risk: number;
  status: RequestStatus;
  created_at: string;
  decided_at: string | null;
  decided_by: string | null;
  decision_note: string;
  waiver_id: number | null;
}

const bad = (message: string, status = 400, error = "bad_request") => json({ error, message }, status);

// handleWaiverRequests: POST creates a request for the token's machine, GET
// lists that machine's latest requests. Answers are for bordercheck, in English.
export async function handleWaiverRequests(req: Request, env: Env, now = new Date()): Promise<Response> {
  if (req.method !== "POST" && req.method !== "GET") return bad("POST a waiver request here, or GET your requests", 405);
  const m = await machineByToken(env, bearer(req));
  if (!m) return json({ error: "unauthorized" }, 401, { "www-authenticate": "Bearer" });
  if (m.revoked_at) return json({ error: "revoked" }, 401, { "www-authenticate": "Bearer" });
  if (req.method === "GET") {
    const rows = await env.DB.prepare(
      "SELECT id, check_id, until, reason, status, created_at, decided_at, decision_note FROM waiver_requests WHERE install_id = ? ORDER BY id DESC LIMIT 50",
    ).bind(m.install_id).all<WaiverRequestRow>();
    return json({
      data: rows.results.map((r) => ({
        request_id: r.id, check: r.check_id, until: r.until, reason: r.reason, status: r.status,
        requested_at: r.created_at, decided_at: r.decided_at, decision_note: r.decision_note,
      })),
    });
  }

  if (Number(req.headers.get("content-length") ?? "0") > MAX_BODY) return bad("The request is too large.", 413);
  let body: Record<string, unknown>;
  try {
    const text = await req.text();
    if (text.length > MAX_BODY) return bad("The request is too large.", 413);
    const v = JSON.parse(text);
    if (!v || typeof v !== "object" || Array.isArray(v)) throw new SyntaxError();
    body = v as Record<string, unknown>;
  } catch {
    return bad("The request body must be a JSON object.");
  }
  const check = typeof body.check === "string" ? body.check : "";
  const until = typeof body.until === "string" ? body.until : "";
  const reason = typeof body.reason === "string" ? cleanLine(body.reason, MAX_REQUEST_REASON + 1) : "";
  if (!CHECK_ID_RE.test(check) || !POLICY_CHECKS.includes(check)) return bad(english(msg("err.waiverCheck", { list: POLICY_CHECKS.join(", ") })));
  const dateErr = waiverDateError(until, now);
  if (dateErr) return bad(english(dateErr));
  if (!reason) return bad("A reason is required.");
  if (reason.length > MAX_REQUEST_REASON) return bad(`The reason is longer than ${MAX_REQUEST_REASON} characters.`);
  if (body.accept_risk !== true) return bad("A waiver request must say that you accept the risk (accept_risk: true).");

  const db = env.DB;
  const ts = now.toISOString();
  // One statement: the limits and the insert cannot race another request.
  const row = await db.prepare(
    `INSERT INTO waiver_requests (install_id, check_id, until, reason, accept_risk, status, created_at)
     SELECT ?1, ?2, ?3, ?4, 1, 'pending', ?5
     WHERE NOT EXISTS (SELECT 1 FROM waiver_requests WHERE install_id = ?1 AND check_id = ?2 AND status = 'pending')
       AND (SELECT COUNT(*) FROM waiver_requests WHERE install_id = ?1 AND status = 'pending') < ?6
     RETURNING id`,
  ).bind(m.install_id, check, until, reason, ts, MAX_PENDING).first<{ id: number }>();
  if (!row) {
    const dup = await db.prepare("SELECT 1 FROM waiver_requests WHERE install_id = ? AND check_id = ? AND status = 'pending'").bind(m.install_id, check).first();
    return dup
      ? bad(`A waiver of ${check} is already waiting for IT's decision.`, 409, "already_requested")
      : bad(`This machine already has ${MAX_PENDING} waiver requests waiting for IT's decision.`, 409, "too_many");
  }
  await audit(env, "machine", "waiver_request.create", m.install_id, { request: row.id, check, until });
  return json({ request_id: row.id, check, until, status: "pending" }, 201);
}

export type Decision = "approve" | "reject";

// decideWaiverRequest approves or rejects a pending request of machine `id`.
// The request is claimed first, so two admins cannot both approve it; an
// approval that machineAction refuses (an end date now in the past, say)
// puts it back to pending.
export async function decideWaiverRequest(
  env: Env,
  who: string,
  id: string,
  requestId: number,
  decision: Decision,
  decisionNote: string,
  extra: AuditExtra = {},
  now = new Date(),
): Promise<{ status: number; error?: Msg; detail?: Record<string, unknown> }> {
  const db = env.DB;
  const ts = now.toISOString();
  const noteText = cleanLine(decisionNote, 300);
  const claimed = await db.prepare(
    `UPDATE waiver_requests SET status = ?1, decided_at = ?2, decided_by = ?3, decision_note = ?4
     WHERE id = ?5 AND install_id = ?6 AND status = 'pending' RETURNING check_id, until, reason`,
  ).bind(decision === "approve" ? "approved" : "rejected", ts, who.slice(0, 200), noteText, requestId, id)
    .first<{ check_id: string; until: string; reason: string }>();
  if (!claimed) return { status: 404, error: msg("err.noSuchWaiverRequest") };
  if (decision === "reject") {
    await audit(env, who, "waiver_request.reject", id, { request: requestId, check: claimed.check_id, until: claimed.until, note: noteText, ...extra });
    return { status: 200, detail: { request_id: requestId, status: "rejected", check: claimed.check_id, until: claimed.until } };
  }
  const r = await machineAction(env, who, id, "waivers", { check: claimed.check_id, until: claimed.until, reason: claimed.reason }, { request: requestId, ...extra });
  if (r.error) {
    await db.prepare("UPDATE waiver_requests SET status = 'pending', decided_at = NULL, decided_by = NULL, decision_note = '' WHERE id = ?").bind(requestId).run();
    return r;
  }
  const waiverId = Number(r.detail?.waiver_id ?? 0) || null;
  await db.prepare("UPDATE waiver_requests SET waiver_id = ? WHERE id = ?").bind(waiverId, requestId).run();
  return { status: 200, detail: { request_id: requestId, status: "approved", check: claimed.check_id, until: claimed.until, waiver_id: waiverId } };
}

export async function machineWaiverRequests(env: Env, id: string): Promise<WaiverRequestRow[]> {
  return (await env.DB.prepare(
    "SELECT * FROM waiver_requests WHERE install_id = ? ORDER BY status <> 'pending', id DESC LIMIT 50",
  ).bind(id).all<WaiverRequestRow>()).results;
}

// For MCP get_machine and GET /api/v1/machines/{id}: the requester's reason under "untrusted".
export async function waiverRequestsDetail(env: Env, id: string) {
  return (await machineWaiverRequests(env, id)).map((r) => ({
    request_id: r.id,
    check_id: r.check_id,
    until: r.until,
    status: r.status,
    requested_at: r.created_at,
    decided_at: r.decided_at,
    decided_by: r.decided_by,
    decision_note: r.decision_note,
    waiver_id: r.waiver_id,
    untrusted: { reason: r.reason },
  }));
}

export async function pendingCheckIds(env: Env, id: string): Promise<Map<string, string>> {
  const rows = await env.DB.prepare("SELECT check_id, until FROM waiver_requests WHERE install_id = ? AND status = 'pending'").bind(id).all<{ check_id: string; until: string }>();
  return new Map(rows.results.map((r) => [r.check_id, r.until]));
}

const statusPill = (L: I18n, s: RequestStatus) =>
  pill(s === "pending" ? "s-warn" : s === "approved" ? "s-pass" : "s-fail", L.t(s === "pending" ? "wr.pending" : s === "approved" ? "wr.approved" : "wr.rejected"));

// waiverRequestsSection: a machine's requests on its dashboard page, pending
// ones with Approve and Reject. Nothing when it has none.
export function waiverRequestsSection(L: I18n, id: string, rows: WaiverRequestRow[]): Html | string {
  if (rows.length === 0) return "";
  const pending = rows.filter((r) => r.status === "pending").length;
  const base = `${machineLink(id)}/waiver-requests`;
  return html`<h2 id="waiver-requests">${L.t("wr.title")}${pending ? html` <span class="muted">${L.t("wr.pendingN", { n: pending })}</span>` : ""}</h2>
<p class="muted">${L.t("wr.text")}</p>
<div class="panel flush"><div class="scroll"><table><thead><tr><th>${L.t("common.check")}</th><th>${L.t("enr.thUntil")}</th><th>${L.t("enr.thReason")}</th><th>${L.t("wr.thRequested")}</th><th>${L.t("wr.thStatus")}</th></tr></thead><tbody>
${rows.map(
    (r) => html`<tr${r.status === "pending" ? "" : html` class="off"`}><td><code>${r.check_id}</code><span class="sub">${checkTitle(L, r.check_id)}</span></td><td class="nowrap">${L.day(r.until)}</td>
<td class="wrap">${r.reason}${r.accept_risk ? html`<span class="sub">${L.t("wr.acceptedRisk")}</span>` : ""}</td><td class="nowrap">${L.when(r.created_at)}</td>
<td>${statusPill(L, r.status)}${r.decided_at ? html`<span class="sub">${L.t("wr.decidedBy", { when: L.when(r.decided_at), who: r.decided_by ?? "?" })}</span>` : ""}${r.decision_note ? html`<span class="sub">${r.decision_note}</span>` : ""}${
      r.status === "pending"
        ? html`<div class="actions"><form method="post" action="${base}/${r.id}/approve"><button class="sm">${L.t("wr.approve")}</button></form>
<form method="post" action="${base}/${r.id}/reject" class="row"><input name="note" maxlength="300" placeholder="${L.s("wr.notePlaceholder")}" aria-label="${L.s("wr.notePlaceholder")}"><button class="sm danger">${L.t("wr.reject")}</button></form></div>`
        : ""
    }</td></tr>`,
  )}</tbody></table></div></div>`;
}

// pendingRequests: the requests waiting for a decision on machines in scope, oldest first.
export async function pendingRequests(env: Env, limit: number, scope?: Scope) {
  return (await env.DB.prepare(
    `SELECT w.id, w.install_id, w.check_id, w.until, w.reason, w.created_at, e.email, e.hostname
     FROM waiver_requests w JOIN enrollments e ON e.install_id = w.install_id
     WHERE w.status = 'pending' AND ${machineIn("w.install_id", 1, scope)} ORDER BY w.id LIMIT ?2`,
  ).bind(scopeBind(scope), limit).all<{ id: number; install_id: string; check_id: string; until: string; reason: string; created_at: string; email: string; hostname: string }>()).results;
}

export function pendingRequestsNote(L: I18n, n: number): Html | string {
  return n ? note(html`<a href="#waiver-requests">${L.t("wr.waitingNote", { n })}</a>`, "s-warn") : "";
}

// pendingRequestsSection: the machines page's list of requests waiting for a decision.
export function pendingRequestsSection(L: I18n, rows: Awaited<ReturnType<typeof pendingRequests>>, now: number): Html | string {
  if (rows.length === 0) return "";
  return html`<section id="waiver-requests"><h2>${L.t("wr.listTitle", { n: rows.length })}</h2>
<div class="panel flush"><div class="scroll"><table><thead><tr><th>${L.t("common.personMachine")}</th><th>${L.t("common.check")}</th><th>${L.t("enr.thUntil")}</th><th>${L.t("enr.thReason")}</th><th>${L.t("wr.thRequested")}</th></tr></thead><tbody>
${rows.map(
    (r) => html`<tr><td class="who-cell"><a href="${machineLink(r.install_id)}#waiver-requests">${r.email}</a><span class="sub">${r.hostname}</span></td><td><code>${r.check_id}</code></td>
<td class="nowrap">${L.day(r.until)}</td><td class="wrap">${r.reason}</td><td class="nowrap" title="${L.when(r.created_at)}">${L.ago(r.created_at, now)}</td></tr>`,
  )}</tbody></table></div></div></section>`;
}
