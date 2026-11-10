import { describe, expect, it } from "vitest";
import { type CheckKey, duration, fixHtml, MAX_PARAM_LENGTH, MAX_PARTS, parseParts, type Part, placeholders, renderParts, summaryHtml } from "../src/checktext";
import { i18n, type Lang, LANGS } from "../src/i18n";
import checksEn from "../src/i18n/checks.en.json";
import { checksVi } from "../src/i18n/checks.vi";
import { checksZh } from "../src/i18n/checks.zh";
import type { Entry } from "../src/i18n/en";
import { parseReport } from "../src/report";
import { ADMIN_TOKEN, BASE, call, enrolled, env, post, report } from "./helpers";

const CATALOGS = { en: checksEn as Record<CheckKey, Entry>, vi: checksVi, zh: checksZh };
const keys = Object.keys(checksEn) as CheckKey[];
const L = Object.fromEntries(LANGS.map((l) => [l, i18n(l)])) as Record<Lang, ReturnType<typeof i18n>>;

const part = (key: string, params: Record<string, string | number> = {}): Part => ({ key, params });
const text = (h: { value: string } | null) =>
  (h?.value ?? "")
    .replace(/<[^>]*>/g, "")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, "&");
const forms = (e: Entry) => (typeof e === "string" ? [e] : [e.other, ...(e.one ? [e.one] : [])]);

describe("check message catalogues", () => {
  it("have the same keys and the same parameters (names and types) in every language", () => {
    for (const lang of ["vi", "zh"] as const) {
      expect(Object.keys(CATALOGS[lang]).sort()).toEqual([...keys].sort());
      for (const k of keys) {
        expect([...placeholders(CATALOGS[lang][k])].sort(), `${lang} ${k}`).toEqual([...placeholders(CATALOGS.en[k])].sort());
      }
    }
  });

  it("carry only balanced [code]/[kbd] markup, no [b] (it is the fix label's style) and no tags", () => {
    for (const lang of ["en", "vi", "zh"] as const) {
      for (const k of keys) {
        for (const f of forms(CATALOGS[lang][k])) {
          expect(f.trim(), `${lang} ${k}`).not.toBe("");
          expect(f, `${lang} ${k}`).not.toMatch(/\[\/?b\]/);
          expect(f.replace(/<key>/g, ""), `${lang} ${k}`).not.toMatch(/[<>]/);
          const tokens = f.match(/\[\/?(?:code|kbd)\]/g) ?? [];
          for (let i = 0; i < tokens.length; i += 2) {
            expect(tokens[i + 1], `${lang} ${k}`).toBe(tokens[i].replace("[", "[/"));
          }
        }
      }
    }
  });

  it("keep commands and URLs exactly as the English has them", () => {
    for (const k of keys) {
      const en = forms(CATALOGS.en[k]).join(" ");
      const code = en.match(/\[code\][\s\S]*?\[\/code\]/g) ?? [];
      const urls = en.match(/https:\/\/[^\s),]+/g) ?? [];
      for (const lang of ["vi", "zh"] as const) {
        const t = forms(CATALOGS[lang][k]).join(" ");
        for (const c of code) expect(t, `${lang} ${k}`).toContain(c);
        for (const u of urls) expect(t, `${lang} ${k}`).toContain(u);
      }
    }
  });

  it("Chinese sentences end in full-width punctuation, since parts join without spaces", () => {
    for (const k of keys) {
      const t = forms(CATALOGS.zh[k]).join("");
      if (/[一-鿿]/.test(t) && !/^\[code\]/.test(t) && !["firewall.win.noProfiles", "tailscale.badPrefs", "disk.mac.partial"].includes(k)) {
        expect(t, k).toMatch(/[。）]$|\[\/code\]$/);
      }
    }
  });
});

describe("rendering parts", () => {
  const listeners = [part("listeners.exposed", { n: 3 }), part("check.moreAllowed", { n: 2 }), part("listeners.note.mac")];

  it("renders a multi-part summary in each language, joined as the language joins sentences", () => {
    expect(text(renderParts(L.en, listeners))).toBe(
      "3 ports can be reached from other machines (LAN, Wi-Fi, Tailscale). 2 more allowed by policy. Only your own processes are visible; run with sudo to include system services.",
    );
    expect(text(renderParts(L.vi, listeners))).toBe(
      "3 cổng có thể được truy cập từ máy khác (LAN, Wi-Fi, Tailscale). Còn 2 mục khác được policy cho phép. Chỉ thấy được tiến trình của bạn; chạy với sudo để thấy cả service hệ thống.",
    );
    expect(text(renderParts(L.zh, listeners))).toBe(
      "3 个端口可被其他设备访问（局域网、Wi-Fi、Tailscale）。另有 2 项为策略所允许。只能看到你自己的进程；用 sudo 运行可包含系统服务。",
    );
  });

  it("chooses English plural forms by n", () => {
    expect(text(renderParts(L.en, [part("listeners.exposed", { n: 1 })]))).toBe("1 port can be reached from other machines (LAN, Wi-Fi, Tailscale).");
    expect(text(renderParts(L.en, [part("sshkeys.noPassphrase", { n: 1 }), part("sshkeys.readable", { n: 2 })]))).toBe(
      "1 private key has no passphrase. 2 keys are readable by other users.",
    );
    expect(text(renderParts(L.vi, [part("sshkeys.noPassphrase", { n: 1 })]))).toBe("1 private key không có passphrase.");
  });

  it("formats durations, days ago and dates as the client's English does, and in each language", () => {
    const lock = [part("screenlock.tooLate", { after: 900, max: 300 })];
    expect(text(renderParts(L.en, lock))).toBe("The screen locks only after 15 minutes idle (policy: 5 minutes).");
    expect(text(renderParts(L.vi, lock))).toBe("Màn hình chỉ khoá sau 15 phút không hoạt động (policy: 5 phút).");
    expect(text(renderParts(L.zh, lock))).toBe("闲置 15 分钟后屏幕才会锁定（策略：5 分钟）。");
    expect(duration("en", 90)).toBe("1.5 minutes");
    expect(duration("vi", 90)).toBe("1,5 phút");
    expect(duration("en", 1)).toBe("1 second");
    expect(text(renderParts(L.en, [part("updates.paused", { until: "2026-12-01" })]))).toBe("Updates are paused until 1 Dec 2026.");
    expect(text(renderParts(L.vi, [part("updates.paused", { until: "2026-12-01" })]))).toBe("Cập nhật đang tạm dừng đến 01/12/2026.");
    const stale = (ago: number) => [part("updates.checkStale", { ago, max: 14 })];
    expect(text(renderParts(L.en, stale(1)))).toBe("The OS last checked for updates 1 day ago (policy: every 14 days).");
    expect(text(renderParts(L.en, stale(0)))).toBe("The OS last checked for updates today (policy: every 14 days).");
    expect(text(renderParts(L.zh, stale(40)))).toBe("系统上次检查更新：40 天前（策略：每 14 天一次）。");
  });

  it("shows numbers as sent, without digit grouping (ports, counts)", () => {
    expect(text(renderParts(L.en, [part("docker.problems", { n: 2, containers: 12345 })]))).toBe("2 problems in 12345 running container(s).");
  });

  it("turns [code] into <code> and keeps trusted links clickable in a translated fix", () => {
    const fix = fixHtml(L.vi, { summary: "", fix: "English", fix_parts: [part("outbound.fix.mac")] }).value;
    expect(fix).toContain('<a href="https://objective-see.org/products/lulu.html" target="_blank" rel="noopener noreferrer">');
    expect(fix).toContain("Cài một tường lửa chiều đi");
    const zh = fixHtml(L.zh, { summary: "", fix: "English", fix_parts: [part("cracked.fixAlternatives"), part("cracked.alt.adobe")] }).value;
    expect(zh).toContain('<a href="https://getartcraft.com" target="_blank"');
    expect(zh).toContain("PhotoCraft 替代 Photoshop");
    const code = fixHtml(L.vi, { summary: "", fix: "English", fix_parts: [part("firewall.mac.off.fix")] }).value;
    expect(code).toContain("<code>sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on</code>");
    // A link in a parameter is linked only when its host is trusted.
    const p = (service: string) => fixHtml(L.en, { summary: "", fix: "x", fix_parts: [part("remote.fix.macSharing", { service })] }).value;
    expect(p("https://evil.example.com/x")).not.toContain("<a ");
    expect(p("https://github.com/acme/x")).toContain('<a href="https://github.com/acme/x"');
  });

  it("falls back to the English text when a key is unknown or the parameters are wrong", () => {
    const r = (summary_parts: Part[]) => summaryHtml(L.vi, { summary: "The English <text>", fix: "", summary_parts }).value;
    const english = "The English &lt;text&gt;";
    expect(r([part("no.such.key")])).toBe(english);
    expect(r([part("listeners.exposed", { n: 3 }), part("no.such.key")])).toBe(english); // one bad part spoils the lot
    expect(r([part("listeners.exposed")])).toBe(english); // missing n
    expect(r([part("listeners.exposed", { n: 3, extra: "x" })])).toBe(english); // extra parameter
    expect(r([part("listeners.exposed", { n: "3" })])).toBe(english); // n must be a count
    expect(r([part("listeners.exposed", { n: -1 })])).toBe(english);
    expect(r([part("listeners.exposed", { n: 1.5 })])).toBe(english);
    expect(r([part("screenlock.passIdle", { after: "15 minutes" })])).toBe(english); // a duration is seconds
    expect(r([part("updates.paused", { until: "next week" })])).toBe(english); // a date is YYYY-MM-DD
    expect(r([part("toString")])).toBe(english);
    expect(r([])).toBe(english);
    expect(summaryHtml(L.vi, { summary: "Old client", fix: "" }).value).toBe("Old client");
    expect(fixHtml(L.zh, { summary: "", fix: "See https://github.com/x and https://evil.example.com" }).value).toBe(
      'See <a href="https://github.com/x" target="_blank" rel="noopener noreferrer">https://github.com/x</a> and https://evil.example.com',
    );
  });

  it("renders hostile parameters inert", () => {
    const evil = '<img src=x onerror="alert(1)"> [b]bold[/b] [code]x[/code] {n} &amp;';
    for (const lang of LANGS) {
      const h = renderParts(L[lang], [part("remote.on", { service: evil })])!.value;
      expect(h).not.toContain("<img");
      expect(h).not.toContain("<b>");
      expect(h).not.toContain("<code>");
      expect(h).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt; [b]bold[/b] [code]x[/code] {n} &amp;amp;");
      const f = fixHtml(L[lang], { summary: "", fix: "", fix_parts: [part("remote.fix.macSharing", { service: evil })] }).value;
      expect(f).not.toContain("<img");
      expect(f).not.toContain("<b>");
    }
  });
});

describe("parsing parts from a report", () => {
  it("keeps well-formed parts and cleans their strings", () => {
    expect(parseParts([{ key: "listeners.exposed", params: { n: 3 } }, { key: "listeners.note.mac" }])).toEqual([
      { key: "listeners.exposed", params: { n: 3 } },
      { key: "listeners.note.mac", params: {} },
    ]);
    const [p] = parseParts([{ key: "remote.on", params: { service: "a\u0000b\nc\td\u001b[31m" } }])!;
    expect(p.params.service).toBe("a b c d [31m");
    const [long] = parseParts([{ key: "remote.on", params: { service: "x".repeat(MAX_PARAM_LENGTH + 50) } }])!;
    expect((long.params.service as string).length).toBe(MAX_PARAM_LENGTH + 1);
  });

  it("drops the whole field when anything is malformed", () => {
    const bad: unknown[] = [
      "listeners.exposed",
      {},
      [],
      [null],
      [{ key: 3 }],
      [{ key: "Listeners.Exposed" }],
      [{ key: "a.b<script>" }],
      [{ key: "x".repeat(81) + ".y" }],
      [{ key: "remote.on", params: [] }],
      [{ key: "remote.on", params: { service: { nested: 1 } } }],
      [{ key: "remote.on", params: { service: ["a"] } }],
      [{ key: "remote.on", params: { service: true } }],
      [{ key: "remote.on", params: { service: null } }],
      [{ key: "remote.on", params: { n: Number.POSITIVE_INFINITY } }],
      [{ key: "remote.on", params: { n: 1e15 } }],
      [{ key: "remote.on", params: { "Bad-Name": "x" } }],
      JSON.parse('[{"key": "remote.on", "params": {"__proto__": "x", "service": "y"}}]'),
      [{ key: "remote.on", params: { service: "x".repeat(MAX_PARAM_LENGTH * 4 + 1) } }],
      [{ key: "remote.on", params: Object.fromEntries(Array.from({ length: 9 }, (_, i) => [`p${i}`, i])) }],
      Array.from({ length: MAX_PARTS + 1 }, () => ({ key: "listeners.note.mac" })),
    ];
    for (const v of bad) expect(parseParts(v), JSON.stringify(v)?.slice(0, 80)).toBeUndefined();
  });

  it("is additive in parseReport: other unknown result fields are ignored, not rejected", () => {
    const r = parseReport(
      report({}, [
        {
          id: "listeners",
          title: "Nothing listens beyond localhost",
          status: "warn",
          summary: "3 ports can be reached from other machines (LAN, Wi-Fi, Tailscale).",
          summary_parts: [{ key: "listeners.exposed", params: { n: 3 } }],
          fix_parts: "not a list",
          something_new: { anything: true },
        },
      ]),
    ).results[0];
    expect(r.summary_parts).toEqual([{ key: "listeners.exposed", params: { n: 3 } }]);
    expect(r.fix_parts).toBeUndefined();
    expect(r).not.toHaveProperty("something_new");
  });
});

describe("pages show summaries and fixes in the reader's language", () => {
  const results = [
    {
      id: "firewall",
      title: "Firewall is on",
      status: "fail",
      severity: "high",
      summary: "The macOS firewall is off.",
      summary_parts: [{ key: "firewall.mac.off" }],
      fix: "System Settings → Network → Firewall → turn it on. Or: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
      fix_parts: [{ key: "firewall.mac.off.fix" }],
    },
    {
      id: "listeners",
      title: "Nothing listens beyond localhost",
      status: "warn",
      severity: "medium",
      summary: "1 port can be reached <b>from</b> other machines (LAN, Wi-Fi, Tailscale).",
      summary_parts: [{ key: "listeners.exposed", params: { n: 1 } }, { key: "listeners.v9.somethingNew" }],
      fix: "Old English fix.",
    },
  ];

  it("on the report page, the admin machine page, and in the stored report", async () => {
    const m = await enrolled();
    const res = await post(report({}, results), { token: m.token });
    expect(res.status).toBe(200);
    const { report_url } = await res.json<{ report_url: string }>();

    const page = async (lang: string) =>
      (await call(new Request(report_url, { headers: { cookie: `bc_lang=${lang}`, "cf-connecting-ip": "203.0.113.60" } }))).text();
    const vi = await page("vi");
    expect(vi).toContain("Tường lửa macOS đang tắt.");
    expect(vi).toContain("Mở System Settings → Network → Firewall rồi bật lên.");
    // A key this portal does not know: the whole summary falls back to the English, escaped.
    expect(vi).toContain("1 port can be reached &lt;b&gt;from&lt;/b&gt; other machines");
    const zh = await page("zh");
    expect(zh).toContain("macOS 防火墙已关闭。");
    expect(zh).toContain("前往 系统设置 → 网络 → 防火墙（System Settings → Network → Firewall），打开防火墙。");

    const admin = await (
      await call(new Request(`${BASE}/admin/machine/${m.install_id}`, { headers: { authorization: `Bearer ${ADMIN_TOKEN}`, cookie: "bc_lang=zh" } }))
    ).text();
    expect(admin).toContain("macOS 防火墙已关闭。");
    expect(admin).toContain("<code>sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on</code>");
    const en = await (await call(new Request(`${BASE}/admin/machine/${m.install_id}`, { headers: { authorization: `Bearer ${ADMIN_TOKEN}` } }))).text();
    expect(en).toContain("The macOS firewall is off.");

    const stored = await env.DB.prepare("SELECT report FROM machines WHERE install_id = ?").bind(m.install_id).first<{ report: string }>();
    expect(JSON.parse(stored!.report).results[0].summary_parts).toEqual([{ key: "firewall.mac.off" }]);
  });
});
