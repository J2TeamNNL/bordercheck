import { describe, expect, it } from "vitest";
import { COPY_SCRIPT, html } from "../src/html";
import { english, fromAcceptLanguage, fromCookie, i18n, type Lang, LANGS, msg, negotiate, safeNext } from "../src/i18n";
import { en } from "../src/i18n/en";
import { vi } from "../src/i18n/vi";
import { zh } from "../src/i18n/zh";
import { ADMIN_TOKEN, BASE, call, enrolled, env, makeInvites, makeRole, post, report, result } from "./helpers";

const CATALOGS = { en, zh, vi } as const;
const keys = Object.keys(en) as (keyof typeof en)[];

// ---- Negotiation ----

describe("choosing the language", () => {
  it("parses Accept-Language with q-values", () => {
    expect(fromAcceptLanguage("vi")).toBe("vi");
    expect(fromAcceptLanguage("vi-VN,vi;q=0.9,en;q=0.8")).toBe("vi");
    expect(fromAcceptLanguage("en;q=0.5, vi;q=0.8")).toBe("vi");
    expect(fromAcceptLanguage("fr-FR,fr;q=0.9,vi;q=0.4,en;q=0.3")).toBe("vi");
    expect(fromAcceptLanguage("de, en-GB;q=0.7")).toBe("en");
    expect(fromAcceptLanguage("vi;q=0, en;q=0.1")).toBe("en"); // q=0 means "not this"
    expect(fromAcceptLanguage("en;q=0.9, zh;q=0.9")).toBe("en"); // a tie keeps header order
    expect(fromAcceptLanguage("vi;q=2, en;q=0.5")).toBe("en"); // q above 1 is malformed
    expect(fromAcceptLanguage("vi;q=abc, en")).toBe("en");
    expect(fromAcceptLanguage("*")).toBeNull();
    expect(fromAcceptLanguage("fr, de;q=0.9")).toBeNull();
    expect(fromAcceptLanguage("<script>, vi")).toBe("vi");
    expect(fromAcceptLanguage("")).toBeNull();
    expect(fromAcceptLanguage(null)).toBeNull();
  });

  it("sends every Chinese variant to Simplified Chinese", () => {
    for (const tag of ["zh", "zh-CN", "zh-Hans", "zh-SG", "zh-Hans-CN", "zh-TW", "zh-HK", "zh-Hant", "zh-Hant-TW", "ZH-cn"]) {
      expect(fromAcceptLanguage(`${tag},en;q=0.5`), tag).toBe("zh");
    }
  });

  it("reads only a supported language from the cookie", () => {
    expect(fromCookie("a=1; bc_lang=vi; b=2")).toBe("vi");
    expect(fromCookie("bc_lang=zh")).toBe("zh");
    expect(fromCookie("bc_lang=fr")).toBeNull();
    expect(fromCookie("bc_lang=vi<script>")).toBeNull();
    expect(fromCookie("other_bc_lang=vi")).toBeNull();
    expect(fromCookie(null)).toBeNull();
  });

  it("prefers the cookie, then the header, then English", () => {
    const req = (h: Record<string, string>) => new Request(BASE, { headers: h });
    expect(negotiate(req({ cookie: "bc_lang=zh", "accept-language": "vi" }))).toBe("zh");
    expect(negotiate(req({ cookie: "bc_lang=xx", "accept-language": "vi" }))).toBe("vi");
    expect(negotiate(req({ "accept-language": "ja, ko" }))).toBe("en");
    expect(negotiate(req({}))).toBe("en");
  });

  it("only goes back to same-origin paths", () => {
    const o = "https://bordercheck.example.com";
    expect(safeNext("/admin/machine/abc?x=1", o)).toBe("/admin/machine/abc?x=1");
    expect(safeNext("/i/AAAA", o)).toBe("/i/AAAA");
    for (const bad of ["https://evil.example/", "//evil.example/x", "/\\evil.example", "\\\\evil", "javascript:alert(1)", "", "admin", "/\n/evil", " /admin"]) {
      expect(safeNext(bad, o), JSON.stringify(bad)).toBe("/");
    }
  });
});

// ---- The catalogue ----

const placeholders = (e: unknown) => {
  const forms = typeof e === "string" ? [e] : Object.values(e as Record<string, string>);
  return [...new Set(forms.flatMap((f) => [...f.matchAll(/\{(\w+)\}/g)].map((m) => m[1])))].sort();
};

describe("catalogue", () => {
  it("has the same keys in every language", () => {
    for (const lang of LANGS) expect(Object.keys(CATALOGS[lang]).sort(), lang).toEqual([...keys].sort());
  });

  it("uses the same parameters as English, balanced markup and no raw HTML", () => {
    for (const lang of LANGS) {
      for (const k of keys) {
        const e = CATALOGS[lang][k];
        const where = `${lang} ${k}`;
        // The same parameters as English's "other" form ("one" may spell the count out).
        const ref = en[k] as string | { other: string };
        expect(placeholders(e), where).toEqual(placeholders(typeof ref === "string" ? ref : ref.other));
        for (const form of typeof e === "string" ? [e] : Object.values(e)) {
          expect(form, where).not.toMatch(/[<>]/);
          for (const tag of ["b", "code", "kbd"]) {
            expect(form.split(`[${tag}]`).length, `${where} [${tag}]`).toBe(form.split(`[/${tag}]`).length);
          }
          expect(form.trim(), where).not.toBe("");
        }
      }
    }
  });

  it("escapes parameters and the translation text, in every language", () => {
    for (const lang of LANGS) {
      const L = i18n(lang);
      const out = L.t("rep.for", { email: `<img src=x onerror=alert(1)>`, host: `"><script>alert(1)</script>`, when: "&" }).value;
      expect(out, lang).not.toContain("<img");
      expect(out, lang).not.toContain("<script");
      expect(out, lang).toContain("&lt;img src=x onerror=alert(1)&gt;");
      expect(out, lang).toContain("&amp;");
      expect(out, lang).toMatch(/<b>.*&lt;img/); // the translation's own [b] became <b>
      // An Html parameter is inserted as is; a message parameter is translated and escaped.
      expect(L.t("invites.needRole", { link: html`<a href="/admin/roles">x</a>` }).value).toContain('<a href="/admin/roles">x</a>');
      expect(L.m(msg("err.waiverNotAdded", { problem: msg("v.unknownCheck", { id: "<b>" }) })).value).toContain("&lt;b&gt;");
      // Plain text has no markup at all.
      expect(L.s("inv.single"), lang).not.toMatch(/\[|</);
    }
  });

  it("chooses plural forms per language", () => {
    const E = i18n("en");
    expect(E.s("rep.toFixHeadline", { n: 1 })).toBe("One thing to fix");
    expect(E.s("rep.toFixHeadline", { n: 2 })).toBe("2 things to fix");
    expect(E.s("tile.silentSub", { n: 1 })).toBe("no report for 1+ day");
    expect(E.s("tile.silentSub", { n: 7 })).toBe("no report for 7+ days");
    expect(E.s("issued.many", { n: 1234 })).toBe("1,234 invites created");
    expect(i18n("zh").s("rep.toFixHeadline", { n: 1 })).toBe("有 1 项需要处理");
    expect(i18n("zh").s("rep.toFixHeadline", { n: 2 })).toBe("有 2 项需要处理");
    expect(i18n("vi").s("rep.toFixHeadline", { n: 1 })).toBe("1 điều cần khắc phục");
    expect(i18n("vi").s("issued.many", { n: 1234 })).toBe("Đã tạo 1.234 lời mời");
    // Ids are not grouped.
    expect(E.s("invites.revoked", { id: 12345 })).toBe("Invite #12345 revoked.");
  });

  it("formats relative times, ages and dates per language", () => {
    const now = Date.parse("2026-11-20T12:00:00Z");
    const at = (ms: number) => new Date(now - ms).toISOString();
    const cases: Record<Lang, string[]> = {
      en: ["just now", "3m ago", "5h ago", "17d ago", "17 days", "in 5d", "today", "2026-11-01 10:05 UTC", "2026-12-01"],
      zh: ["刚刚", "3分钟前", "5小时前", "17天前", "17天", "5天后", "今天", "2026/11/01 10:05 UTC", "2026/12/01"],
      vi: ["vừa xong", "3 phút trước", "5 giờ trước", "17 ngày trước", "17 ngày", "sau 5 ngày nữa", "hôm nay", "10:05 01/11/2026 UTC", "01/12/2026"],
    };
    for (const lang of LANGS) {
      const L = i18n(lang);
      expect([
        L.ago(at(30_000), now),
        L.ago(at(3 * 60_000), now),
        L.ago(at(5 * 3600_000), now),
        L.ago(at(17 * 86400_000), now),
        L.age(at(17 * 86400_000), now),
        L.inDays(new Date(now + 4.5 * 86400_000).toISOString(), now),
        L.inDays(new Date(now - 1000).toISOString(), now),
        L.when("2026-11-01T10:05:42.123Z"),
        L.day("2026-12-01"),
      ], lang).toEqual(cases[lang]);
      expect(L.ago(null, now)).toBe(L.s("time.never"));
      expect(L.status("brand-new-status")).toBe("brand-new-status"); // unknown statuses as received
    }
    expect(i18n("zh").status("fail")).toBe("未通过");
    expect(i18n("vi").severity("high")).toBe("cao");
  });

  it("keeps machine-facing messages in English", () => {
    expect(english(msg("err.waiverNotAdded", { problem: msg("v.untilFar", { n: 365 }) }))).toBe(
      "Waiver not added: until is more than 365 days ahead; waivers are temporary.",
    );
  });
});

// ---- Pages in every language ----

const COOKIE = (lang: Lang) => ({ cookie: `bc_lang=${lang}` });
const adminGet = (path: string, h: Record<string, string> = {}) =>
  call(new Request(BASE + path, { headers: { authorization: `Bearer ${ADMIN_TOKEN}`, ...h } }));
const publicGet = (path: string, h: Record<string, string> = {}) =>
  call(new Request(BASE + path, { headers: { "cf-connecting-ip": "203.0.113.90", ...h } }));
const HTML_LANG: Record<Lang, string> = { en: "en", zh: "zh-Hans", vi: "vi" };

// Text a page should never show: a {param} left unfilled, a [b] left
// unconverted, or a catalogue key printed instead of its text.
function assertTranslated(body: string, lang: Lang, where: string) {
  const text = body.replace(/<style>[\s\S]*?<\/style>/, "").replace(/<textarea[\s\S]*?<\/textarea>/g, "");
  expect(text, where).toContain(`<html lang="${HTML_LANG[lang]}">`);
  expect(text, where).not.toMatch(/\{[a-z]\w*\}/i);
  expect(text, where).not.toMatch(/\[\/?(b|code|kbd)\]/);
  // A key printed instead of its text (as `>nav.machines<` or `"nav.machines"`).
  for (const k of keys) expect(text, `${where} ${k}`).not.toMatch(new RegExp(`[>"]${k.replace(/\./g, "\\.")}[<"]`));
}

async function seed() {
  const roleId = await makeRole("Dev");
  const m = await enrolled("an@domain.com", "Dev");
  const res = await post(
    report({}, [
      result("firewall", "fail", { severity: "high", fix: "Turn it on." }),
      result("os-updates", "waived", { severity: "medium", waived: { until: "2099-01-31", reason: "Vendor patch due" } }),
      result("screen-lock", "warn"),
      result("secrets", "pass"),
    ]),
    { token: m.token },
  );
  const reportUrl = (await res.json<{ report_url: string }>()).report_url.replace("https://bordercheck.example.com", "");
  const [code] = await makeInvites(["bo@domain.com"], roleId);
  await env.DB.prepare("INSERT INTO alerts (kind, install_id, check_id, detail, created_at) VALUES ('high_fail', ?, 'firewall', '{}', ?)")
    .bind(m.install_id, new Date().toISOString()).run();
  return { roleId, m, reportUrl, code };
}

describe("pages in every language", () => {
  it("render with the right <html lang>, no missing text, and the switcher", async () => {
    const { roleId, m, reportUrl, code } = await seed();
    const admin = ["/admin", `/admin/machine/${m.install_id}`, "/admin/checks", "/admin/checks/firewall", "/admin/checks/firewall?status=fail", "/admin/alerts",
      "/admin/roles", `/admin/roles/${roleId}`, "/admin/invites", "/admin/invites?status=all", "/admin/audit", "/admin/passkeys", "/admin/nothing-here"];
    const pub = ["/admin/login", `/i/${code}`, `/i/${"A".repeat(43)}`, reportUrl, `/r/${"A".repeat(32)}`];
    for (const lang of LANGS) {
      for (const path of admin) {
        const res = await adminGet(path, COOKIE(lang));
        const body = await res.text();
        assertTranslated(body, lang, `${lang} ${path}`);
        expect(res.headers.get("vary"), path).toBe("Accept-Language, Cookie");
        expect(res.headers.get("cache-control"), path).toBe("no-store");
        expect(res.headers.get("content-security-policy"), path).toContain("default-src 'none'");
        expect(body, path).toContain(`<input type="hidden" name="next" value="${path.replace(/&/g, "&amp;")}">`);
        expect(body).toContain(`value="${lang}" lang="${HTML_LANG[lang]}" title=`);
      }
      for (const path of pub) {
        const res = await publicGet(path, COOKIE(lang));
        const body = await res.text();
        assertTranslated(body, lang, `${lang} ${path}`);
        if (path.startsWith("/i/") || path.startsWith("/r/")) {
          // Posts to itself: no action, no copy of the code in a field.
          expect(body).toContain(`<form class="langs" method="post" role="group"`);
          expect(body).not.toContain('name="next"');
        }
      }
    }
    // A sample of real text, so the test cannot pass on an all-English page.
    expect(await (await adminGet("/admin", COOKIE("zh"))).text()).toContain("全部设备");
    expect(await (await adminGet("/admin", COOKIE("vi"))).text()).toContain("Tất cả các máy");
    expect(await (await publicGet(`/i/${code}`, { "accept-language": "vi-VN,vi;q=0.9" })).text()).toContain("Cài đặt bordercheck");
    expect(await (await publicGet(reportUrl, { "accept-language": "zh-TW" })).text()).toContain("你的 bordercheck 报告");
    // No header, no cookie: English, and the English text the other tests rely on.
    const plain = await (await publicGet(reportUrl)).text();
    expect(plain).toContain(`<html lang="en">`);
    expect(plain).toContain("Your bordercheck report");
  });

  it("escapes report text in every language", async () => {
    const m = await enrolled();
    const evil = '<script>alert(1)</script>';
    const attr = `x"><img src=x onerror=alert(1)>`;
    const res = await post(
      report({ version: attr, policy: evil, host: { os: attr, arch: evil, hostname: evil } }, [
        result("firewall", "fail", { severity: "high", title: evil, summary: evil, fix: evil, evidence: [evil] }),
        result(`<b>id</b>`, "warn", { title: attr, severity: attr }),
        result("docker", "waived", { title: evil, waived: { until: attr, reason: evil } }),
      ]),
      { token: m.token },
    );
    const reportUrl = (await res.json<{ report_url: string }>()).report_url.replace("https://bordercheck.example.com", "");
    for (const lang of LANGS) {
      for (const path of ["/admin", `/admin/machine/${m.install_id}`, "/admin/checks", "/admin/checks/firewall", "/admin/alerts", `/admin/machine/${m.install_id}?q=${encodeURIComponent(evil)}`, `/admin?q=${encodeURIComponent(evil)}`]) {
        const body = await (await adminGet(path, COOKIE(lang))).text();
        expect(body, `${lang} ${path}`).not.toContain("<script>");
        expect(body, `${lang} ${path}`).not.toContain("<img");
        expect(body, `${lang} ${path}`).not.toContain("<b>id</b>");
      }
      // The report page's one script is the hashed Copy script, there for the fix prompt.
      const body = (await (await publicGet(reportUrl, COOKIE(lang))).text()).replace(`<script>${COPY_SCRIPT}</script>`, "");
      expect(body, lang).not.toContain("<script>");
      expect(body, lang).not.toContain("<img");
      expect(body, lang).toContain("&lt;script&gt;");
    }
  });
});

// ---- The switcher ----

const switchTo = (path: string, fields: Record<string, string>, h: Record<string, string> = { origin: BASE }) =>
  call(new Request(BASE + path, { method: "POST", headers: h, body: new URLSearchParams(fields) }));

describe("language switcher", () => {
  it("sets a strict cookie and goes back to the page", async () => {
    const res = await switchTo("/lang", { lang: "vi", next: "/admin/invites?status=all" });
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe("/admin/invites?status=all");
    expect(res.headers.get("set-cookie")).toBe("bc_lang=vi; Path=/; Max-Age=31536000; Secure; HttpOnly; SameSite=Lax");
    expect(res.headers.get("cache-control")).toBe("no-store");
    // A browser's same-origin form post (Origin: null under no-referrer).
    const b = await switchTo("/lang", { lang: "zh", next: "/admin" }, { origin: "null", "sec-fetch-site": "same-origin" });
    expect(b.status).toBe(303);
  });

  it("is not an open redirect and accepts only known languages", async () => {
    for (const next of ["https://evil.example/", "//evil.example", "/\\evil.example", "javascript:alert(1)", "http:/evil.example"]) {
      const res = await switchTo("/lang", { lang: "vi", next });
      expect(res.headers.get("location"), next).toBe("/");
    }
    expect((await switchTo("/lang", { lang: "fr", next: "/admin" })).status).toBe(400);
    expect((await switchTo("/lang", { lang: "vi; Path=/x", next: "/admin" })).status).toBe(400);
    expect((await switchTo("/lang", { lang: "vi" }, { origin: "https://evil.example" })).status).toBe(403);
    expect((await switchTo("/lang", { lang: "vi" }, { origin: "null", "sec-fetch-site": "cross-site" })).status).toBe(403);
    expect((await call(new Request(`${BASE}/lang`))).status).toBe(405);
  });

  it("works on an invite page without consuming the invite or copying the code", async () => {
    const roleId = await makeRole("Dev");
    const [code] = await makeInvites(["bo@domain.com"], roleId);
    const res = await switchTo(`/i/${code}`, { lang: "zh" });
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe(`/i/${code}`);
    expect(res.headers.get("set-cookie")).toContain("bc_lang=zh;");
    // Cross-site posts to the page are refused like any other.
    expect((await switchTo(`/i/${code}`, { lang: "zh" }, { origin: "https://evil.example" })).status).toBe(403);
    // The page now speaks Chinese, and the invite still works.
    const page = await (await publicGet(`/i/${code}`, { cookie: "bc_lang=zh" })).text();
    expect(page).toContain("安装 bordercheck");
    expect(page.split(code).length - 1).toBe(2); // only in the two install commands
    const inv = await env.DB.prepare("SELECT used_at, revoked_at FROM invites WHERE email = 'bo@domain.com'").first();
    expect(inv).toEqual({ used_at: null, revoked_at: null });
    const enrolledRes = await call(new Request(`${BASE}/enroll`, {
      method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": "198.51.100.77" },
      body: JSON.stringify({ code, host: { os: "darwin", arch: "arm64", hostname: "bo-mbp" } }),
    }));
    expect(enrolledRes.status).toBe(200);
  });

  it("works on a report link and keeps it uniform for unknown ids", async () => {
    const m = await enrolled();
    const res = await post(report(), { token: m.token });
    const path = (await res.json<{ report_url: string }>()).report_url.replace("https://bordercheck.example.com", "");
    const sw = await switchTo(path, { lang: "vi" });
    expect(sw.status).toBe(303);
    expect(sw.headers.get("location")).toBe(path);
    expect(await (await publicGet(path, { cookie: "bc_lang=vi" })).text()).toContain("Báo cáo bordercheck của bạn");
    // Unknown ids: the same 404 body whatever the id, in each language.
    for (const lang of LANGS) {
      const a = await (await publicGet(`/r/${"A".repeat(32)}`, COOKIE(lang))).text();
      const b = await (await publicGet(`/r/${"B".repeat(32)}`, COOKIE(lang))).text();
      expect(a).toBe(b);
    }
  });

  it("hides the switcher where switching would lose one-time codes", async () => {
    const roleId = await makeRole("Dev");
    const res = await call(new Request(`${BASE}/admin/invites`, {
      method: "POST", headers: { authorization: `Bearer ${ADMIN_TOKEN}`, cookie: "bc_lang=vi" },
      body: new URLSearchParams({ emails: "c@domain.com", role_id: String(roleId) }),
    }));
    const body = await res.text();
    expect(body).toContain("Hãy sao chép ngay.");
    expect(body).not.toContain('class="langs"');
  });
});
