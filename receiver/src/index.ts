import { runCron } from "./alerts";
import {
  dashboardConfigured,
  newSession,
  sameOrigin,
  safeEqual,
  sessionCookie,
  usableToken,
  viewer,
} from "./auth";
import { alertsPage, checkPage, checksPage, forgetMachine, machinePage, machinesPage } from "./dashboard";
import type { Env } from "./env";
import { FAVICON, html, layout, MARK, note, page } from "./html";
import { forRequest, type I18n, isLang, type Key, langCookie, safeNext } from "./i18n";
import { handleReport, json } from "./ingest";
import { audit } from "./audit";
import { handleEnroll, invitePage, serveMachinePolicy } from "./enroll";
import {
  auditPage,
  createInvites,
  createRole,
  deleteRole,
  invitesPage,
  type MachineAction,
  machineAction,
  machineParams,
  reissueInvite,
  revokeInvite,
  rolePage,
  rolesPage,
  updateRole,
} from "./portal";
import { selfReportPage } from "./selfreport";
import { handleMcp } from "./mcp";

const MAX_FORM_BYTES = 512 * 1024;

async function formOf(req: Request): Promise<FormData> {
  if (Number(req.headers.get("content-length") ?? "0") > MAX_FORM_BYTES) return new FormData();
  try {
    return await req.formData();
  } catch {
    return new FormData();
  }
}

function loginPage(L: I18n, message?: Key, status = 200): Response {
  const body = html`<div class="center-card"><span class="mark lg">${MARK}</span><p class="eyebrow">${L.t("login.eyebrow")}</p><h1>${L.t("login.title")}</h1>
<p class="lead">${L.t("login.lead")}</p>
${message ? note(L.t(message), status >= 400 ? "s-fail" : "") : ""}
<form method="post" action="/admin/login"><div class="panel"><label for="token">${L.t("login.token")}</label><input id="token" class="full" type="password" name="token" placeholder="${L.s("login.placeholder")}" autocomplete="current-password" autofocus>
<div class="actions"><button class="primary">${L.t("login.button")}</button></div></div></form></div>`;
  return page(layout(L, L.s("login.title"), null, body), status);
}

const redirect = (to: string, headers: Record<string, string> = {}) =>
  new Response(null, { status: 303, headers: { location: to, "cache-control": "no-store", ...headers } });

async function admin(req: Request, env: Env, url: URL, L: I18n): Promise<Response> {
  const path = url.pathname.replace(/\/+$/, "") || "/admin";
  const now = Date.now();
  if (!dashboardConfigured(env)) {
    return page(
      layout(L, L.s("off.title"), null, html`<div class="center-card"><span class="mark lg">${MARK}</span><h1>${L.t("off.h1")}</h1><p class="lead">${L.t("off.lead")}</p></div>`),
      503,
    );
  }

  if (path === "/admin/login") {
    if (!usableToken(env.ADMIN_TOKEN)) return loginPage(L, "login.off", 403);
    if (req.method === "GET") return loginPage(L);
    if (req.method !== "POST") return new Response("method not allowed", { status: 405 });
    if (!sameOrigin(req)) return new Response("cross-site request refused", { status: 403 });
    const form = await req.formData();
    const token = String(form.get("token") ?? "");
    if (!(await safeEqual(token, env.ADMIN_TOKEN))) return loginPage(L, "login.wrong", 401);
    return redirect("/admin", { "set-cookie": sessionCookie(await newSession(env, now)) });
  }

  const v = await viewer(req, env, now);
  if (!v) {
    if (req.method === "GET" && !req.headers.get("authorization")) {
      if (usableToken(env.ADMIN_TOKEN)) return redirect("/admin/login");
      return page(layout(L, L.s("login.title"), null, html`<div class="center-card"><span class="mark lg">${MARK}</span><h1>${L.t("access.h1")}</h1><p class="lead">${L.t("access.lead")}</p></div>`), 401);
    }
    return json({ error: "unauthorized" }, 401);
  }
  // Cookie-borne credentials (Access, our session) need a same-origin check on writes.
  if (req.method !== "GET" && req.method !== "HEAD" && v.via !== "bearer" && !sameOrigin(req)) {
    return new Response("cross-site request refused", { status: 403 });
  }

  if (path === "/admin/logout" && req.method === "POST") {
    return redirect(usableToken(env.ADMIN_TOKEN) ? "/admin/login" : "/admin", { "set-cookie": sessionCookie("", 0) });
  }
  if (path === "/admin" && req.method === "GET") return machinesPage(env, url, v.who, now, L);
  if (path === "/admin/checks" && req.method === "GET") return checksPage(env, v.who, L);
  if (path === "/admin/alerts" && req.method === "GET") return alertsPage(env, v.who, L);

  let m = /^\/admin\/checks\/([^/]+)$/.exec(path);
  if (m && req.method === "GET") return checkPage(env, decodeURIComponent(m[1]), url, v.who, now, L);
  m = /^\/admin\/machine\/([A-Za-z0-9_-]+)$/.exec(path);
  if (m && req.method === "GET") return machinePage(env, m[1], v.who, now, L);
  m = /^\/admin\/machine\/([A-Za-z0-9_-]+)\/forget$/.exec(path);
  if (m && req.method === "POST") {
    await forgetMachine(env, m[1]);
    await audit(env, v.who, "machine.forget", m[1]);
    return redirect("/admin");
  }
  m = /^\/admin\/machine\/([A-Za-z0-9_-]+)\/(revoke|restore|role|waivers|reset-link|waivers\/(\d+)\/remove)$/.exec(path);
  if (m && req.method === "POST") {
    const action = (m[3] ? "remove-waiver" : m[2]) as MachineAction;
    const form = await formOf(req);
    const r = await machineAction(env, v.who, m[1], action, machineParams(form, Number(m[3] ?? 0)));
    if (r.error) {
      return page(
        layout(L, L.s("notDone.title"), v.who, html`<p class="eyebrow">${L.t("nav.machines")}</p><h1>${L.t("notDone.title")}</h1>${note(L.m(r.error), "s-fail")}<div class="actions"><a class="btn" href="/admin/machine/${m[1]}">${L.t("notDone.back")}</a></div>`),
        r.status,
      );
    }
    return redirect(`/admin/machine/${m[1]}`);
  }

  if (path === "/admin/roles" && req.method === "GET") return rolesPage(env, v.who, L);
  if (path === "/admin/roles" && req.method === "POST") return createRole(env, v.who, await formOf(req), L);
  m = /^\/admin\/roles\/(\d{1,12})$/.exec(path);
  if (m && req.method === "GET") return rolePage(env, Number(m[1]), v.who, L);
  if (m && req.method === "POST") return updateRole(env, Number(m[1]), v.who, await formOf(req), L);
  m = /^\/admin\/roles\/(\d{1,12})\/delete$/.exec(path);
  if (m && req.method === "POST") return deleteRole(env, Number(m[1]), v.who, L);

  if (path === "/admin/invites" && req.method === "GET") return invitesPage(env, url, v.who, L);
  if (path === "/admin/invites" && req.method === "POST") return createInvites(env, req, url, v.who, await formOf(req), L);
  m = /^\/admin\/invites\/(\d{1,12})\/(revoke|reissue)$/.exec(path);
  if (m && req.method === "POST") {
    return m[2] === "revoke" ? revokeInvite(env, url, v.who, Number(m[1]), L) : reissueInvite(env, req, url, v.who, Number(m[1]), L);
  }
  if (path === "/admin/audit" && req.method === "GET") return auditPage(env, url, v.who, L);
  return page(layout(L, L.s("common.notFound"), v.who, html`<h1>${L.t("common.notFound")}</h1><p class="lead">${L.t("notFound.lead")}</p><div class="actions"><a class="btn" href="/admin">${L.t("nav.machines")}</a></div>`), 404);
}

// The language switcher. POST /lang sets the bc_lang cookie and goes back to
// `next` (a same-origin path only, never an open redirect). POST to a
// capability page (/i/<code>, /r/<id>) does the same and goes back to that
// very path, taken from the request URL. Either way nothing else happens: no
// page is rendered, nothing is looked up, no invite is touched.
async function switchLanguage(req: Request, url: URL, back?: string): Promise<Response> {
  if (req.method !== "POST") return new Response("method not allowed", { status: 405, headers: { allow: "POST" } });
  if (!sameOrigin(req)) return new Response("cross-site request refused", { status: 403 });
  const form = await formOf(req);
  const lang = form.get("lang");
  if (!isLang(lang)) return new Response("unknown language", { status: 400 });
  const to = back ?? safeNext(String(form.get("next") ?? ""), url.origin);
  return redirect(to, { "set-cookie": langCookie(lang) });
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;
    if (path === "/report") {
      if (req.method !== "POST") return json({ error: "POST a bordercheck report here" }, 405, { allow: "POST" });
      return handleReport(req, env);
    }
    if (path === "/enroll") {
      if (req.method !== "POST") return json({ error: "bad_request", message: "POST an enrollment here" }, 405, { allow: "POST" });
      return handleEnroll(req, env);
    }
    if (path === "/policy") {
      if (req.method !== "GET") return json({ error: "bad_request", message: "GET your policy here" }, 405, { allow: "GET" });
      return serveMachinePolicy(req, env);
    }
    if (path === "/lang") return switchLanguage(req, url);
    const L = forRequest(req, url);
    // Capability URLs. The code or id is never logged by this Worker.
    let cap = /^\/i\/([^/]{1,200})$/.exec(path);
    if (cap && req.method === "GET") return invitePage(req, env, cap[1], undefined, L);
    if (cap && req.method === "POST") return switchLanguage(req, url, path);
    cap = /^\/r\/([^/]{1,200})$/.exec(path);
    if (cap && req.method === "GET") return selfReportPage(req, env, cap[1], undefined, L);
    if (cap && req.method === "POST") return switchLanguage(req, url, path);
    if (path === "/mcp") return handleMcp(req, env);
    if (path === "/healthz") return new Response("ok\n", { headers: { "cache-control": "no-store" } });
    if ((path === "/favicon.svg" || path === "/favicon.ico") && (req.method === "GET" || req.method === "HEAD")) {
      return new Response(FAVICON, {
        headers: { "content-type": "image/svg+xml", "cache-control": "public, max-age=86400", "x-content-type-options": "nosniff" },
      });
    }
    if (path === "/" || path === "") return redirect("/admin");
    if (path === "/admin" || path.startsWith("/admin/")) return admin(req, env, url, L);
    return json({ error: "not found" }, 404);
  },

  async scheduled(controller: ScheduledController, env: Env): Promise<void> {
    const r = await runCron(env, new Date(controller.scheduledTime));
    console.log("cron", JSON.stringify(r));
  },
} satisfies ExportedHandler<Env>;
