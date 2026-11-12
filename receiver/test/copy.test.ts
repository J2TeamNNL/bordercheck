import { describe, expect, it } from "vitest";
import { ADMIN_TOKEN, BASE, call, enrolled, makeRole, post, report } from "./helpers";

// The script-free CSP every page had before the Copy buttons, byte for byte.
const BASE_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

async function sha256b64(s: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
  let bin = "";
  for (const b of d) bin += String.fromCharCode(b);
  return btoa(bin);
}

// The page's scripts, and the CSP it must then carry.
async function checkScriptPage(res: Response) {
  const body = await res.text();
  const scripts = [...body.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)];
  expect(scripts.length).toBe(1);
  expect(scripts[0][0].startsWith("<script>")).toBe(true); // no src, no attributes
  const hash = await sha256b64(scripts[0][1]);
  expect(res.headers.get("content-security-policy")).toBe(`${BASE_CSP}; script-src 'sha256-${hash}'`);
  // Buttons are inert and hidden without the script, and only point at ids we made.
  const buttons = [...body.matchAll(/<button[^>]*data-copy="([^"]*)"[^>]*>/g)];
  for (const b of buttons) expect(b[0]).toMatch(/ hidden /);
  return { body, targets: buttons.map((b) => b[1]) };
}

const issue = (fields: Record<string, string>, lang = "en") =>
  call(new Request(`${BASE}/admin/invites`, {
    method: "POST",
    headers: { authorization: `Bearer ${ADMIN_TOKEN}`, cookie: `bc_lang=${lang}` },
    body: new URLSearchParams(fields),
  }));

describe("copy buttons", () => {
  it("on the issued page: one hashed script, one row of buttons per person, a message in the admin's language", async () => {
    const evil = `</script><script>alert(1)</script>" data-copy="x`;
    const roleId = await makeRole(evil);
    const res = await issue({ emails: "an@domain.com\nbo@domain.com", role_id: String(roleId), note: evil });
    expect(res.status).toBe(200);
    const { body, targets } = await checkScriptPage(res);
    const ids = [...body.matchAll(/<h2>(\S+@domain\.com) <span class="muted">#(\d+)<\/span><\/h2>/g)].map((m) => m[2]);
    expect(ids.length).toBe(2);
    expect(targets).toEqual(ids.flatMap((id) => ["link", "sh", "ps1", "msg"].map((k) => `inv-${id}-${k}`)));
    for (const t of targets) expect(body).toContain(` id="${t}">`);
    expect(body).not.toContain("alert(1)</script>");
    expect(body).toContain("Copy message");
    expect(body).toMatch(/Hi, please install bordercheck[^<]*\/i\/[A-Za-z0-9_-]{43}\nThe link works once, for one computer, until \d{4}-\d{2}-\d{2}\./);
    expect(body).toContain('data-done="Copied"');
    expect(body).toContain('aria-live="polite"');
    // Without scripts the commands are still there to select.
    expect(body.match(/<code tabindex="0"/g)?.length).toBe(8);

    for (const [lang, word, msg] of [["zh", "复制消息", "你好，请在你的工作电脑上安装 bordercheck"], ["vi", "Sao chép tin nhắn", "Chào bạn, vui lòng cài bordercheck"]]) {
      const r = await issue({ emails: `c-${lang}@domain.com`, role_id: String(roleId) }, lang);
      const { body: b } = await checkScriptPage(r);
      expect(b).toContain(word);
      expect(b).toContain(msg);
      expect(b).toContain(`data-label="${word}"`);
    }
  });

  it("on the re-issue page too", async () => {
    const roleId = await makeRole("Dev");
    await issue({ emails: "an@domain.com", role_id: String(roleId) });
    const id = (await (await call(new Request(`${BASE}/admin/invites`, { headers: { authorization: `Bearer ${ADMIN_TOKEN}` } }))).text())
      .match(/\/admin\/invites\/(\d+)\/reissue/)![1];
    const res = await call(new Request(`${BASE}/admin/invites/${id}/reissue`, { method: "POST", headers: { authorization: `Bearer ${ADMIN_TOKEN}` } }));
    const { targets } = await checkScriptPage(res);
    expect(targets.length).toBe(4);
  });

  it("on the invite page, for the commands shown", async () => {
    const roleId = await makeRole("Dev");
    const page = await (await issue({ emails: "an@domain.com", role_id: String(roleId) })).text();
    const code = page.match(/\/i\/([A-Za-z0-9_-]{43})/)![1];
    for (const ua of ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "curl/8"]) {
      const res = await call(new Request(`${BASE}/i/${code}`, { headers: { "user-agent": ua, "cf-connecting-ip": "203.0.113.61" } }));
      const { targets } = await checkScriptPage(res);
      expect(targets.length).toBe(2);
      expect(res.headers.get("x-robots-tag")).toContain("noindex");
    }
  });

  it("leaves every other page script-free, with the same CSP", async () => {
    const m = await enrolled();
    const r = await post(report(), { token: m.token });
    const reportPath = (await r.json<{ report_url: string }>()).report_url.replace("https://bordercheck.example.com", "");
    const admin = ["/admin", `/admin/machine/${m.install_id}`, "/admin/checks", "/admin/alerts", "/admin/roles", "/admin/invites", "/admin/audit"];
    for (const path of admin) {
      const res = await call(new Request(BASE + path, { headers: { authorization: `Bearer ${ADMIN_TOKEN}` } }));
      expect(res.headers.get("content-security-policy"), path).toBe(BASE_CSP);
      expect(await res.text(), path).not.toContain("<script");
    }
    for (const path of ["/admin/login", reportPath, `/r/${"A".repeat(32)}`, `/i/${"A".repeat(43)}`]) {
      const res = await call(new Request(BASE + path, { headers: { "cf-connecting-ip": "203.0.113.62" } }));
      expect(res.headers.get("content-security-policy"), path).toBe(BASE_CSP);
      expect(await res.text(), path).not.toContain("<script");
    }
  });
});
