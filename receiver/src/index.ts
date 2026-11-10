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
import { html, layout, page } from "./html";
import { handleReport, json } from "./ingest";
import { policyPage, savePolicy, servePolicy } from "./policy";

function loginPage(message = "", status = 200): Response {
  const body = html`<h1>Sign in</h1>
${message ? html`<div class="note">${message}</div>` : ""}
<form method="post" action="/admin/login"><p><input type="password" name="token" placeholder="Admin token" autocomplete="current-password" size="40" autofocus>
<button>Sign in</button></p></form>`;
  return page(layout("Sign in", null, body), status);
}

const redirect = (to: string, headers: Record<string, string> = {}) =>
  new Response(null, { status: 303, headers: { location: to, "cache-control": "no-store", ...headers } });

async function admin(req: Request, env: Env, url: URL): Promise<Response> {
  const path = url.pathname.replace(/\/+$/, "") || "/admin";
  const now = Date.now();
  if (!dashboardConfigured(env)) {
    return page(
      layout("Dashboard off", null, html`<h1>Dashboard is off</h1><p>Set Cloudflare Access (ACCESS_TEAM_DOMAIN and ACCESS_AUD) or an ADMIN_TOKEN secret of at least 16 characters.</p>`),
      503,
    );
  }

  if (path === "/admin/login") {
    if (!usableToken(env.ADMIN_TOKEN)) return loginPage("Sign-in with a token is off; use Cloudflare Access.", 403);
    if (req.method === "GET") return loginPage();
    if (req.method !== "POST") return new Response("method not allowed", { status: 405 });
    if (!sameOrigin(req)) return new Response("cross-site request refused", { status: 403 });
    const form = await req.formData();
    const token = String(form.get("token") ?? "");
    if (!(await safeEqual(token, env.ADMIN_TOKEN))) return loginPage("Wrong token.", 401);
    return redirect("/admin", { "set-cookie": sessionCookie(await newSession(env, now)) });
  }

  const v = await viewer(req, env, now);
  if (!v) {
    if (req.method === "GET" && !req.headers.get("authorization")) {
      if (usableToken(env.ADMIN_TOKEN)) return redirect("/admin/login");
      return page(layout("Sign in", null, html`<h1>Sign in through Cloudflare Access</h1><p>This request did not carry a valid Access token.</p>`), 401);
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
  if (path === "/admin" && req.method === "GET") return machinesPage(env, url, v.who, now);
  if (path === "/admin/checks" && req.method === "GET") return checksPage(env, v.who);
  if (path === "/admin/alerts" && req.method === "GET") return alertsPage(env, v.who);

  let m = /^\/admin\/checks\/([^/]+)$/.exec(path);
  if (m && req.method === "GET") return checkPage(env, decodeURIComponent(m[1]), url, v.who, now);
  m = /^\/admin\/machine\/([A-Za-z0-9_-]+)$/.exec(path);
  if (m && req.method === "GET") return machinePage(env, m[1], v.who, now);
  m = /^\/admin\/machine\/([A-Za-z0-9_-]+)\/forget$/.exec(path);
  if (m && req.method === "POST") {
    await forgetMachine(env, m[1]);
    return redirect("/admin");
  }

  if (path === "/admin/policy" && req.method === "GET") return policyPage(env, v.who);
  if ((path === "/admin/policy" && req.method === "POST") || (path === "/admin/policies.json" && req.method === "PUT")) {
    const isForm = (req.headers.get("content-type") ?? "").includes("form");
    const text = isForm ? String((await req.formData()).get("policy") ?? "") : await req.text();
    const err = await savePolicy(env, text);
    if (!isForm) return err ? json({ error: err }, 400) : json({ ok: true });
    return err ? policyPage(env, v.who, err, text) : policyPage(env, v.who, "Saved.");
  }
  return page(layout("Not found", v.who, html`<h1>Not found</h1>`), 404);
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;
    if (path === "/report") {
      if (req.method !== "POST") return json({ error: "POST a bordercheck report here" }, 405, { allow: "POST" });
      return handleReport(req, env);
    }
    if (path === "/policies.json" && (req.method === "GET" || req.method === "HEAD")) return servePolicy(req, env);
    if (path === "/healthz") return new Response("ok\n", { headers: { "cache-control": "no-store" } });
    if (path === "/" || path === "") return redirect("/admin");
    if (path === "/admin" || path.startsWith("/admin/")) return admin(req, env, url);
    return json({ error: "not found" }, 404);
  },

  async scheduled(controller: ScheduledController, env: Env): Promise<void> {
    const r = await runCron(env, new Date(controller.scheduledTime));
    console.log("cron", JSON.stringify(r));
  },
} satisfies ExportedHandler<Env>;
