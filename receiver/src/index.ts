import { runCron } from "./alerts";
import { addAdmin, adminsPage, deleteAdmin, newToken, setRoles } from "./admins";
import {
  adminByToken,
  dashboardConfigured,
  newSession,
  sameOrigin,
  safeEqual,
  sessionCookie,
  tokenLoginOn,
  usableToken,
  viewer,
} from "./auth";
import { alertsPage, checkPage, checksPage, forgetMachine, machinePage, machinesPage } from "./dashboard";
import type { Env } from "./env";
import { FAVICON, html, layout, MARK, note, page, PASSKEY_HEADERS } from "./html";
import { forRequest, type I18n, isLang, type Key, langCookie, msg, safeNext } from "./i18n";
import { handleReport, json } from "./ingest";
import { audit } from "./audit";
import { handleEnroll, invitePage, serveMachinePolicy } from "./enroll";
import {
  auditPage,
  createInvites,
  createRole,
  deleteRole,
  invitesPage,
  issuedLinkPage,
  noSuchRole,
  issueReportLink,
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
import { API_BASE, handleApi } from "./api";
import {
  autoPrompt,
  deletePasskey,
  loginOptions,
  loginVerify,
  passkeyCount,
  passkeysPage,
  register,
  registerOptions,
  setTokenLogin,
  SIGNED_OUT,
} from "./passkeys";
import { hit } from "./ratelimit";
import { inviteVisible, machineVisible, roleAllowed } from "./scope";

const MAX_FORM_BYTES = 512 * 1024;

async function formOf(req: Request): Promise<FormData> {
  if (Number(req.headers.get("content-length") ?? "0") > MAX_FORM_BYTES) return new FormData();
  try {
    return await req.formData();
  } catch {
    return new FormData();
  }
}

// The sign-in page. With at least one passkey it has the passkey button (and
// PASSKEY_SCRIPT) above the token form, and starts the prompt by itself when
// autoPrompt says so (data-auto). With token sign-in switched off there is no
// token form. Without passkeys it is the plain, script-free page.
async function loginPage(req: Request, env: Env, url: URL, L: I18n, message?: Key, status = 200): Promise<Response> {
  const passkeys = await passkeyCount(env);
  const tokenOn = await tokenLoginOn(env);
  const pk = passkeys
    ? html`<div id="pk" data-mode="login" data-fail="${L.s("login.passkeyFail")}"${autoPrompt(req, url, passkeys) ? html` data-auto="1"` : ""} hidden><div class="panel"><div class="actions" style="margin-top:0"><button type="button" id="pk-go" class="primary">${L.t("login.passkey")}</button></div><p id="pk-msg" class="small" role="status" aria-live="polite"></p></div></div>
${tokenOn ? "" : html`<p id="pk-unsupported" class="muted">${L.t("login.passkeyUnsupported")}</p>`}`
    : "";
  const form = tokenOn
    ? html`${passkeys ? html`<p class="muted small" style="margin:18px 0 8px">${L.t("login.orToken")}</p>` : ""}<form method="post" action="/admin/login"><input type="text" name="username" value="admin" autocomplete="username" readonly hidden><div class="panel"><label for="token">${L.t("login.token")}</label><input id="token" class="full" type="password" name="token" placeholder="${L.s("login.placeholder")}" autocomplete="current-password"${passkeys ? "" : html` autofocus`}>
<div class="actions"><button class="primary">${L.t("login.button")}</button></div></div></form>`
    : "";
  const body = html`<div class="center-card"><span class="mark lg">${MARK}</span><p class="eyebrow">${L.t("login.eyebrow")}</p><h1>${L.t("login.title")}</h1>
<p class="lead">${L.t("login.lead")}</p>
${message ? note(L.t(message), status >= 400 ? "s-fail" : "") : ""}
${pk}${form}</div>`;
  return page(layout(L, L.s("login.title"), null, body, undefined, { passkey: !!passkeys }), status, passkeys ? PASSKEY_HEADERS : {});
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
    if (!usableToken(env.ADMIN_TOKEN)) return loginPage(req, env, url, L, "login.off", 403);
    if (req.method === "GET") return loginPage(req, env, url, L);
    if (req.method !== "POST") return new Response("method not allowed", { status: 405 });
    if (!sameOrigin(req)) return new Response("cross-site request refused", { status: 403 });
    if (!(await hit(env, req, "login", now)).ok) return loginPage(req, env, url, L, "login.slow", 429);
    const form = await req.formData();
    const token = String(form.get("token") ?? "");
    // The owner's ADMIN_TOKEN first (constant time), then a named admin's
    // token by its hash. Token sign-in switched off, or anything else wrong:
    // the same answer as a wrong token.
    const owner = await safeEqual(token, env.ADMIN_TOKEN);
    const named = owner ? null : await adminByToken(env, token);
    if ((!owner && !named) || !(await tokenLoginOn(env))) return loginPage(req, env, url, L, "login.wrong", 401);
    if (named) await env.DB.prepare("UPDATE admins SET last_used_at = ? WHERE id = ?").bind(new Date(now).toISOString(), named.id).run();
    return redirect("/admin", { "set-cookie": sessionCookie(await newSession(env, now, "token", named ? { id: named.id, gen: named.gen } : undefined)) });
  }
  // Passkey sign-in: public, so only a challenge and a verdict. Part of the
  // token/session sign-in: absent (404) when ADMIN_TOKEN is not set.
  if (path === "/admin/login/passkey/options" || path === "/admin/login/passkey") {
    if (!usableToken(env.ADMIN_TOKEN)) return json({ error: "not found" }, 404);
    if (req.method !== "POST") return json({ error: "method not allowed" }, 405, { allow: "POST" });
    if (!sameOrigin(req)) return json({ error: "cross-site request refused" }, 403);
    const rl = await hit(env, req, "login", now);
    if (!rl.ok) return json({ error: "rate_limited" }, 429, { "retry-after": String(rl.retryAfter) });
    return path.endsWith("/options") ? loginOptions(env, req, now) : loginVerify(env, req, now);
  }

  const v = await viewer(req, env, now);
  if (!v) {
    if (req.method === "GET" && !req.headers.get("authorization")) {
      if (usableToken(env.ADMIN_TOKEN)) return redirect("/admin/login");
      return page(layout(L, L.s("login.title"), null, html`<div class="center-card"><span class="mark lg">${MARK}</span><h1>${L.t("access.h1")}</h1><p class="lead">${L.t("access.lead")}</p></div>`), 401);
    }
    return json({ error: "unauthorized" }, 401);
  }
  // Header, Sign out, Passkeys and Admins follow the viewer, not their name.
  L.ownSignIn = v.via !== "access";
  // A named admin's scope (scope.ts): list pages take it, and every route on
  // one machine, role or invite checks it below before anything runs.
  const scope = v.scope;
  const machineGone = () =>
    page(layout(L, L.s("common.notFound"), v.who, html`<p class="eyebrow">${L.t("nav.machines")}</p><h1>${L.t("machine.noSuch")}</h1><p><a href="/admin">${L.t("machine.back")}</a></p>`, "Machines"), 404);
  // Cookie-borne credentials (Access, our session) need a same-origin check on writes.
  if (req.method !== "GET" && req.method !== "HEAD" && v.via !== "bearer" && !sameOrigin(req)) {
    return new Response("cross-site request refused", { status: 403 });
  }

  if (path === "/admin/logout" && req.method === "POST") {
    // The flag keeps the sign-in page from starting the passkey prompt right away.
    return redirect(usableToken(env.ADMIN_TOKEN) ? `/admin/login?${SIGNED_OUT}=1` : "/admin", { "set-cookie": sessionCookie("", 0) });
  }
  if (path === "/admin" && req.method === "GET") return machinesPage(env, url, v.who, now, L, scope);
  if (path === "/admin/checks" && req.method === "GET") return checksPage(env, v.who, L, scope);
  if (path === "/admin/alerts" && req.method === "GET") return alertsPage(env, v.who, L, scope);

  let m = /^\/admin\/checks\/([^/]+)$/.exec(path);
  if (m && req.method === "GET") return checkPage(env, decodeURIComponent(m[1]), url, v.who, now, L, scope);
  // Every machine route: out of scope answers exactly like an unknown machine.
  m = /^\/admin\/machine\/([A-Za-z0-9_-]+)(\/.*)?$/.exec(path);
  if (m && !(await machineVisible(env, m[1], scope))) return machineGone();
  m = /^\/admin\/machine\/([A-Za-z0-9_-]+)$/.exec(path);
  if (m && req.method === "GET") return machinePage(env, m[1], v.who, now, L, scope);
  m = /^\/admin\/machine\/([A-Za-z0-9_-]+)\/forget$/.exec(path);
  if (m && req.method === "POST") {
    await forgetMachine(env, m[1]);
    await audit(env, v.who, "machine.forget", m[1]);
    return redirect("/admin");
  }
  // A new login-free report link for the admin to pass on: shown once, on the page this returns.
  m = /^\/admin\/machine\/([A-Za-z0-9_-]+)\/report-link$/.exec(path);
  if (m && req.method === "POST") {
    const r = await issueReportLink(env, v.who, m[1], url.origin);
    if (r.error || !r.url || !r.expires) {
      return page(
        layout(L, L.s("notDone.title"), v.who, html`<p class="eyebrow">${L.t("nav.machines")}</p><h1>${L.t("notDone.title")}</h1>${note(L.m(r.error ?? { key: "err.unknownAction" }), "s-fail")}<div class="actions"><a class="btn" href="/admin/machine/${m[1]}">${L.t("notDone.back")}</a></div>`),
        r.status,
      );
    }
    return issuedLinkPage(L, v.who, m[1], r.url, r.expires);
  }
  m = /^\/admin\/machine\/([A-Za-z0-9_-]+)\/(revoke|restore|role|waivers|reset-link|waivers\/(\d+)\/remove)$/.exec(path);
  if (m && req.method === "POST") {
    const action = (m[3] ? "remove-waiver" : m[2]) as MachineAction;
    const form = await formOf(req);
    const params = machineParams(form, Number(m[3] ?? 0));
    // Moving a machine: the target role must be in scope too (the current one is, or it would be 404 above).
    const r = action === "role" && !roleAllowed(scope, Number(params.role_id))
      ? { status: 400, error: msg("err.noSuchRole") }
      : await machineAction(env, v.who, m[1], action, params);
    if (r.error) {
      return page(
        layout(L, L.s("notDone.title"), v.who, html`<p class="eyebrow">${L.t("nav.machines")}</p><h1>${L.t("notDone.title")}</h1>${note(L.m(r.error), "s-fail")}<div class="actions"><a class="btn" href="/admin/machine/${m[1]}">${L.t("notDone.back")}</a></div>`),
        r.status,
      );
    }
    return redirect(`/admin/machine/${m[1]}`);
  }

  if (path === "/admin/roles" && req.method === "GET") return rolesPage(env, v.who, L, "", undefined, 200, scope);
  // Creating a role is open to named admins; the new role joins their scope.
  if (path === "/admin/roles" && req.method === "POST") return createRole(env, v.who, await formOf(req), L, scope);
  // Every route on one role: out of scope answers like an unknown role.
  m = /^\/admin\/roles\/(\d{1,12})(\/.*)?$/.exec(path);
  if (m && !roleAllowed(scope, Number(m[1]))) return noSuchRole(L, v.who);
  m = /^\/admin\/roles\/(\d{1,12})$/.exec(path);
  if (m && req.method === "GET") return rolePage(env, Number(m[1]), v.who, L);
  if (m && req.method === "POST") return updateRole(env, Number(m[1]), v.who, await formOf(req), L, scope);
  m = /^\/admin\/roles\/(\d{1,12})\/delete$/.exec(path);
  if (m && req.method === "POST") return deleteRole(env, Number(m[1]), v.who, L, scope);

  if (path === "/admin/invites" && req.method === "GET") return invitesPage(env, url, v.who, L, "", 200, scope);
  if (path === "/admin/invites" && req.method === "POST") return createInvites(env, req, url, v.who, await formOf(req), L, scope);
  m = /^\/admin\/invites\/(\d{1,12})\/(revoke|reissue)$/.exec(path);
  if (m && req.method === "POST") {
    // Out of scope answers like an unknown invite.
    if (!(await inviteVisible(env, Number(m[1]), scope))) return invitesPage(env, url, v.who, L, L.m(msg("err.noSuchInvite")), 404, scope);
    return m[2] === "revoke" ? revokeInvite(env, url, v.who, Number(m[1]), L, scope) : reissueInvite(env, req, url, v.who, Number(m[1]), L, scope);
  }
  if (path === "/admin/audit" && req.method === "GET") return auditPage(env, url, v.who, L, scope);

  // Passkeys: for the token/session sign-in only. Under Cloudflare Access (or
  // without ADMIN_TOKEN) these routes do not exist, like Sign out.
  if ((path === "/admin/passkeys" || path.startsWith("/admin/passkeys/")) && usableToken(env.ADMIN_TOKEN) && v.via !== "access") {
    if (path === "/admin/passkeys" && req.method === "GET") return passkeysPage(env, req, v, L);
    if (path === "/admin/passkeys/options" && req.method === "POST") return registerOptions(env, req, v, now);
    if (path === "/admin/passkeys" && req.method === "POST") return register(env, req, v, now);
    if (path === "/admin/passkeys/token-login" && req.method === "POST") return setTokenLogin(env, req, v, await formOf(req), L);
    m = /^\/admin\/passkeys\/(\d{1,12})\/delete$/.exec(path);
    if (m && req.method === "POST") return deletePasskey(env, req, v, Number(m[1]), L);
  }
  // Named admins (admins.ts): like the passkey pages, only for the portal's
  // own sign-in. Who may do what is checked there (owner, or the admin themself).
  if ((path === "/admin/admins" || path.startsWith("/admin/admins/")) && usableToken(env.ADMIN_TOKEN) && v.via !== "access") {
    if (path === "/admin/admins" && req.method === "GET") return adminsPage(env, v, L);
    if (path === "/admin/admins" && req.method === "POST") return addAdmin(env, v, await formOf(req), L, now);
    m = /^\/admin\/admins\/(\d{1,12})\/(token|delete|roles)$/.exec(path);
    if (m && req.method === "POST") {
      const id = Number(m[1]);
      if (m[2] === "token") return newToken(env, v, id, L, now);
      if (m[2] === "delete") return deleteAdmin(env, v, id, L);
      return setRoles(env, v, id, await formOf(req), L);
    }
  }
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
  async fetch(req: Request, env: Env, ctx?: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;
    if (path === "/report") {
      if (req.method !== "POST") return json({ error: "POST a bordercheck report here" }, 405, { allow: "POST" });
      return handleReport(req, env, undefined, undefined, ctx ? { waitUntil: (p) => ctx.waitUntil(p) } : {});
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
    if (path === API_BASE || path.startsWith(API_BASE + "/")) return handleApi(req, env);
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
