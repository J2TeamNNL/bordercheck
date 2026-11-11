import { type I18n, type Key, LANG_NAME, LANG_SHORT, LANGS } from "./i18n";

// A tiny HTML template: every interpolated value is escaped unless it is
// itself the output of html``. Report contents (hostnames, emails, summaries,
// evidence) are attacker-controlled, so nothing reaches the page unescaped.

export class Html {
  constructor(readonly value: string) {}
  toString() {
    return this.value;
  }
}

export function escape(s: unknown): string {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function render(v: unknown): string {
  if (v instanceof Html) return v.value;
  if (Array.isArray(v)) return v.map(render).join("");
  if (v === null || v === undefined || v === false) return "";
  return escape(v);
}

export function html(strings: TemplateStringsArray, ...values: unknown[]): Html {
  let out = strings[0];
  for (let i = 0; i < values.length; i++) out += render(values[i]) + strings[i + 1];
  return new Html(out);
}

// Hosts that fix text may link to. Fix text comes from the machine, so a link
// in it is only made clickable when it points at one of the places
// bordercheck's own advice names; any other URL stays plain text.
const LINK_HOSTS = new Set([
  "github.com", "objective-see.org", "getartcraft.com", "support.apple.com", "support.microsoft.com",
  "learn.microsoft.com", "tailscale.com", "docs.docker.com", "developers.cloudflare.com",
]);

// linkify escapes text and turns https links to LINK_HOSTS into anchors.
export function linkify(text: unknown): Html {
  const s = String(text ?? "");
  let out = "";
  let last = 0;
  for (const m of s.matchAll(/https:\/\/[A-Za-z0-9.-]+(?:\/[A-Za-z0-9._~%\/#?=&+@:-]*)?/g)) {
    let url = m[0].replace(/[.,:;?]+$/, ""); // sentence punctuation is not part of the link
    let host = "";
    try {
      const u = new URL(url);
      if (u.protocol === "https:" && !u.username && !u.password && !u.port) host = u.hostname.replace(/^www\./, "");
    } catch {
      host = "";
    }
    if (!LINK_HOSTS.has(host)) continue;
    out += escape(s.slice(last, m.index)) + `<a href="${escape(url)}" target="_blank" rel="noopener noreferrer">${escape(url)}</a>`;
    last = m.index + url.length;
  }
  return new Html(out + escape(s.slice(last)));
}

// Content-Security-Policy: no scripts at all, inline styles only, forms post
// to this origin, never framed.
const CSP =
  "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

// The portal's one script: Copy buttons, on exactly three pages (the admin page
// showing freshly issued invites, the invite page /i/<code>, and a report page
// /r/<id> that offers the fix prompt). Every other
// page is served with CSP above and runs no script at all.
//
// What it does: on a click on an element with data-copy="<id>", copy that
// element's textContent with navigator.clipboard (falling back to selecting
// the text), and show the button's data-done label for two seconds. Buttons
// are rendered `hidden` and un-hidden by the script, so without scripts they
// are simply absent and the one-click-select code blocks still work. It reads
// only text the server rendered; it builds no HTML, loads nothing, sends
// nothing anywhere.
//
// It is allowed by its SHA-256 hash, and only on the pages that include it
// (COPY_CSP). Changing one byte of it means updating COPY_SCRIPT_HASH; a test
// recomputes the hash from the page as served.
export const COPY_SCRIPT =
  `(function(){var live=document.getElementById("copy-status");` +
  `function sel(el){var r=document.createRange();r.selectNodeContents(el);var s=window.getSelection();if(s){s.removeAllRanges();s.addRange(r)}}` +
  `document.addEventListener("click",function(e){var b=e.target instanceof Element?e.target.closest("[data-copy]"):null;if(!b)return;` +
  `var el=document.getElementById(b.getAttribute("data-copy")||"");if(!el)return;` +
  `var label=b.getAttribute("data-label")||"",done=b.getAttribute("data-done")||"";` +
  `function ok(){b.textContent=done;if(live)live.textContent=done;setTimeout(function(){b.textContent=label;if(live)live.textContent=""},2000)}` +
  `function no(){sel(el)}` +
  `if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(el.textContent||"").then(ok,no)}else{no()}});` +
  `var bs=document.querySelectorAll("[data-copy]");for(var i=0;i<bs.length;i++)bs[i].hidden=false})();`;
export const COPY_SCRIPT_HASH = "sha256-fRZPvsKfmsR0Pg84Bsxw4Mc+qbaPX7EyEGpbV66f3vQ=";
export const COPY_CSP = `${CSP}; script-src '${COPY_SCRIPT_HASH}'`;
export const COPY_HEADERS = { "content-security-policy": COPY_CSP };

export function page(body: Html, status = 200, headers: Record<string, string> = {}): Response {
  return new Response("<!doctype html>" + body.value, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": CSP,
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "cache-control": "no-store",
      // The language comes from these two headers.
      vary: "Accept-Language, Cookie",
      ...headers,
    },
  });
}

// The stylesheet. Dark only, in the manner of tvOS: a black canvas lit by soft
// colour fields, glass surfaces with a top highlight instead of borders, large
// tight type in the system font, and focus/hover that lifts and brightens.
// Sections: tokens, base, chrome (header/nav), type, surfaces (panel, tile,
// card, table), status (pill, numbers, bar), results, forms, buttons, commands,
// public pages, responsive, reduced motion. The select chevron and the search
// glyph are data: SVGs, which img-src allows.
const STYLE = `
:root{color-scheme:dark;--bg:#000;--text:#f5f5f7;--dim:#a1a1a6;--faint:#8d8d93;
--glass:rgba(255,255,255,.06);--glass-2:rgba(255,255,255,.09);--glass-hi:rgba(255,255,255,.14);--line:rgba(255,255,255,.08);--hl:inset 0 1px 0 rgba(255,255,255,.08);
--fail:#ff453a;--warn:#ff9f0a;--err:#bf5af2;--ok:#30d158;--waived:#64d2ff;--skip:#98989d;--other:#e0b07a;--accent:#0a84ff;
--r:22px;--r-sm:14px;--ease:cubic-bezier(.2,.8,.2,1);
--font:-apple-system,BlinkMacSystemFont,"SF Pro Text","SF Pro Display","Helvetica Neue","Segoe UI",system-ui,Roboto,sans-serif;
--mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}
[hidden]{display:none!important}
.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
html{-webkit-text-size-adjust:100%}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font:400 15px/1.5 var(--font);-webkit-font-smoothing:antialiased;overflow-x:hidden}
body::before{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;background:
radial-gradient(70vmax 50vmax at 0% -10%,rgba(43,92,255,.26),transparent 62%),
radial-gradient(60vmax 50vmax at 105% 0%,rgba(138,43,226,.15),transparent 60%),
radial-gradient(60vmax 40vmax at 50% 115%,rgba(0,194,168,.09),transparent 60%)}
a{color:inherit;text-decoration:none}
p a,dd a,li a,.note a,td a.u{text-decoration:underline;text-decoration-color:rgba(255,255,255,.3);text-underline-offset:3px}
p a:hover,dd a:hover,li a:hover,td a.u:hover{text-decoration-color:currentColor}
code,.mono{font-family:var(--mono);font-size:.88em}
:focus-visible{outline:2px solid var(--text);outline-offset:3px;border-radius:8px}
::selection{background:rgba(10,132,255,.5)}

.top{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:20px;flex-wrap:wrap;padding:14px clamp(16px,4vw,48px);
background:rgba(0,0,0,.62);-webkit-backdrop-filter:saturate(180%) blur(22px);backdrop-filter:saturate(180%) blur(22px);box-shadow:0 1px 0 var(--line)}
.brand{display:inline-flex;align-items:center;gap:10px;font-weight:700;font-size:16px;letter-spacing:-.01em;padding:4px 8px 4px 4px;margin-left:-4px;border-radius:12px;transition:background .25s,color .25s}
a.brand:hover{background:var(--glass-hi)}
.mark{display:inline-grid;place-items:center;width:30px;height:30px;border-radius:9px;background:linear-gradient(140deg,#3a7bff,#7b4dff 55%,#1fc8b0);box-shadow:inset 0 1px 0 rgba(255,255,255,.35),0 6px 18px rgba(43,92,255,.35)}
.mark svg{width:18px;height:18px}
.mark.lg{width:64px;height:64px;border-radius:18px;margin-bottom:22px}.mark.lg svg{width:36px;height:36px}
.nav{display:flex;gap:2px;padding:4px;border-radius:999px;background:var(--glass);box-shadow:var(--hl);overflow-x:auto;scrollbar-width:none}
.nav::-webkit-scrollbar{display:none}
.nav a{padding:7px 15px;border-radius:999px;font-size:14px;font-weight:600;color:var(--dim);white-space:nowrap;transition:background .25s var(--ease),color .25s}
.nav a.on{background:var(--glass-hi);color:var(--text)}
.nav a:hover,.nav a:focus-visible{background:var(--text);color:#000;outline:none}
.who{margin-left:auto;display:flex;align-items:center;gap:12px;color:var(--faint);font-size:13px}
.who form{margin:0}
.langs{display:inline-flex;gap:2px;padding:3px;margin:0;border-radius:999px;background:var(--glass);box-shadow:var(--hl)}
.langs button{padding:5px 10px;font-size:12.5px;font-weight:600;border-radius:999px;background:transparent;box-shadow:none;color:var(--dim)}
.langs button:hover,.langs button:focus-visible{transform:none}
.langs button.on{background:var(--glass-hi);color:var(--text)}
body.public .langs{margin-left:auto}

main{max-width:1280px;margin:0 auto;padding:clamp(24px,5vh,48px) clamp(16px,4vw,48px) 96px}
.eyebrow{color:var(--dim);font-size:13px;font-weight:650;letter-spacing:.07em;text-transform:uppercase;margin:0 0 8px}
h1{font-size:clamp(32px,4.6vw,52px);line-height:1.05;letter-spacing:-.035em;font-weight:800;margin:0 0 12px;overflow-wrap:anywhere}
h2{font-size:22px;letter-spacing:-.02em;font-weight:700;margin:52px 0 16px}
h3{font-size:17px;letter-spacing:-.01em;font-weight:650;margin:0 0 6px}
.lead{color:var(--dim);font-size:clamp(16px,1.6vw,19px);max-width:760px;margin:0 0 28px}
.muted{color:var(--faint)}.dim{color:var(--dim)}.small{font-size:13px}
.hero{margin-bottom:28px}
.hero .lead{margin-bottom:14px}
.shelf{display:flex;align-items:baseline;justify-content:space-between;gap:16px;margin:48px 0 16px}
.shelf h2{margin:0}.shelf a{color:var(--dim);font-size:14px;font-weight:600}.shelf a:hover{color:var(--text)}
.chips{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.chip{display:inline-flex;align-items:center;gap:6px;padding:5px 12px;border-radius:999px;background:var(--glass-2);color:var(--dim);font-size:13px;font-weight:600;max-width:100%;overflow-wrap:anywhere}
.chip b{color:var(--text);font-weight:650}

.panel{background:var(--glass);border-radius:var(--r);box-shadow:var(--hl);padding:22px 24px}
.panel+.panel{margin-top:16px}
.cols>.panel+.panel{margin-top:0}
aside.panel{position:sticky;top:96px}
.panel.flush{padding:0;overflow:hidden}
.panel h2:first-child,.panel h3:first-child{margin-top:0}
.panel>p:first-child{margin-top:0}.panel>p:last-child{margin-bottom:0}
.cols{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(0,1fr);gap:20px;align-items:start}

.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(168px,1fr));gap:14px}
.tile{--c:var(--text);position:relative;display:flex;flex-direction:column;gap:2px;min-height:132px;padding:18px 20px;border-radius:var(--r);
background:radial-gradient(130% 120% at 0% 0%,color-mix(in srgb,var(--c) 16%,transparent),transparent 60%),var(--glass);box-shadow:var(--hl);
transition:transform .35s var(--ease),box-shadow .35s var(--ease),background-color .3s}
.tile .n{margin-top:auto;font-size:44px;line-height:1;font-weight:750;letter-spacing:-.04em;font-variant-numeric:tabular-nums;color:var(--c)}
.tile .l{font-weight:650;font-size:15px}
.tile .s{color:var(--faint);font-size:12.5px}
.tile.zero{--c:var(--dim);background:var(--glass)}
a.tile:hover,a.tile:focus-visible{transform:scale(1.04);background-color:var(--glass-2);box-shadow:var(--hl),0 24px 50px rgba(0,0,0,.6),0 0 0 1px rgba(255,255,255,.14);outline:none;z-index:1}
.t-fail{--c:var(--fail)}.t-err{--c:var(--err)}.t-warn{--c:var(--warn)}.t-skip{--c:var(--skip)}.t-ok{--c:var(--ok)}.t-accent{--c:var(--waived)}

.health{margin:22px 0 0}
.bar{display:flex;height:10px;border-radius:999px;overflow:hidden;background:var(--glass-2);gap:2px}
.bar i{display:block;min-width:4px}
.b-fail{--c:var(--fail)}.b-warn{--c:var(--warn)}.b-ok{--c:var(--ok)}.b-waived{--c:var(--waived)}.b-err{--c:var(--err)}.b-skip{--c:var(--skip)}
.bar i{background:var(--c)}
.legend{display:flex;gap:6px 18px;flex-wrap:wrap;margin-top:10px;color:var(--dim);font-size:13px}
.legend span::before{content:"";display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;background:var(--c);vertical-align:1px}
.minibar{display:flex;height:6px;width:140px;border-radius:999px;overflow:hidden;background:var(--glass-2);gap:1px;margin-top:6px}
.minibar i{display:block;background:var(--c)}

.shelf-row{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:14px}
.card{--c:var(--fail);display:flex;flex-direction:column;gap:4px;padding:18px 20px;border-radius:var(--r);background:var(--glass);box-shadow:var(--hl);transition:transform .35s var(--ease),box-shadow .35s var(--ease),background-color .3s;min-width:0}
.card .t{font-weight:650;font-size:15.5px;line-height:1.3;overflow-wrap:anywhere}
.card .meta{display:flex;align-items:baseline;gap:8px;margin-top:auto;padding-top:12px;color:var(--dim);font-size:13px}
.card .big{font-size:30px;font-weight:750;letter-spacing:-.03em;color:var(--c);font-variant-numeric:tabular-nums}
.card .big.plain{color:var(--text)}
a.card:hover,a.card:focus-visible{transform:scale(1.04);background-color:var(--glass-2);box-shadow:var(--hl),0 24px 50px rgba(0,0,0,.6),0 0 0 1px rgba(255,255,255,.14);outline:none}

.toolbar{display:flex;gap:12px;flex-wrap:wrap;align-items:center;justify-content:space-between;margin:0 0 14px}
.seg{display:inline-flex;flex-wrap:wrap;gap:2px;padding:4px;border-radius:999px;background:var(--glass);box-shadow:var(--hl)}
.seg a{padding:7px 14px;border-radius:999px;font-size:13.5px;font-weight:600;color:var(--dim);white-space:nowrap;transition:background .25s var(--ease),color .25s}
.seg a .c{margin-left:6px;color:var(--faint);font-variant-numeric:tabular-nums}
.seg a.on{background:var(--glass-hi);color:var(--text)}.seg a.on .c{color:var(--dim)}
.seg a:hover,.seg a:focus-visible{background:var(--text);color:#000;outline:none}.seg a:hover .c,.seg a:focus-visible .c{color:#444}
.search{display:flex;gap:8px;align-items:center}
.search input{width:min(300px,62vw);padding-left:38px;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' fill='none' stroke='%238d8d93' stroke-width='2' stroke-linecap='round'%3E%3Ccircle cx='7' cy='7' r='5.2'/%3E%3Cpath d='m11 11 3.5 3.5'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:14px 50%}

.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;font-size:14px}
th{text-align:left;font-size:11.5px;font-weight:650;letter-spacing:.06em;text-transform:uppercase;color:var(--faint);padding:14px 14px 10px;white-space:nowrap}
td{padding:11px 14px;border-top:1px solid var(--line);vertical-align:top}
th:first-child,td:first-child{padding-left:22px}th:last-child,td:last-child{padding-right:22px}
tbody tr{transition:background-color .2s}
tbody tr:hover{background:rgba(255,255,255,.035)}
tr.off td{opacity:.55}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
td .sub{display:block;color:var(--faint);font-size:12.5px;margin-top:1px;overflow-wrap:anywhere}
td .sub.mono{font-size:12px;white-space:nowrap}
td.who-cell{min-width:200px;max-width:340px}
td.who-cell a,a.strong{font-weight:600;overflow-wrap:anywhere}
td.who-cell a:hover,a.strong:hover{text-decoration:underline;text-underline-offset:3px}
.nowrap{white-space:nowrap}
td.wrap{overflow-wrap:anywhere;min-width:160px}
.ev{font-family:var(--mono);font-size:12px;overflow-wrap:anywhere;color:var(--dim)}
.zero{color:var(--faint)}
.empty{padding:28px 22px;color:var(--faint);text-align:center;margin:0}

.pill{--c:var(--other);display:inline-flex;align-items:center;gap:6px;padding:3px 10px 3px 8px;border-radius:999px;font-size:12px;font-weight:650;line-height:1.5;white-space:nowrap;
color:var(--c);background:color-mix(in srgb,var(--c) 15%,transparent);box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--c) 30%,transparent)}
.pill::before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor;box-shadow:0 0 8px currentColor;flex:none}
.pill+.pill{margin-left:4px}
.num-fail{color:var(--fail);font-weight:650}.num-warn{color:var(--warn);font-weight:650}.num-error{color:var(--err);font-weight:650}.num-waived{color:var(--waived);font-weight:650}
.sev{display:inline-block;padding:2px 9px;border-radius:7px;font-size:11.5px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;background:var(--glass-hi);color:var(--dim)}
.sev-high{background:color-mix(in srgb,var(--fail) 22%,transparent);color:#ff8a82}
.sev-medium{background:color-mix(in srgb,var(--warn) 20%,transparent);color:#ffc062}

.result{--c:var(--other);position:relative;padding:20px 22px 20px 26px;border-radius:var(--r);
background:radial-gradient(90% 140% at 0% 0%,color-mix(in srgb,var(--c) 13%,transparent),transparent 55%),var(--glass);box-shadow:var(--hl),inset 3px 0 0 var(--c)}
.result+.result{margin-top:12px}
.result .head{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:6px}
.result h3{margin:0;font-size:17px;overflow-wrap:anywhere}
.result .body{color:var(--dim);overflow-wrap:anywhere;white-space:pre-line}
.result .since{color:var(--faint);font-size:13px}
.result ul.evidence{margin:12px 0 0;padding:12px 16px;list-style:none;border-radius:12px;background:rgba(0,0,0,.4);box-shadow:inset 0 0 0 1px var(--line)}
.result ul.evidence li+li{margin-top:4px}
.result p.prod{margin:14px 0 0}.result ul.evidence li{overflow-wrap:anywhere;padding:2px 0}.fix a{color:inherit;text-decoration:underline;text-underline-offset:3px}
.fix{margin-top:12px;padding:12px 16px;border-radius:var(--r-sm);background:var(--glass-2)}
.fix b{display:block;font-size:11.5px;letter-spacing:.07em;text-transform:uppercase;color:var(--faint);margin-bottom:2px}
.fix span{overflow-wrap:anywhere;white-space:pre-line}
.waiver{margin-top:10px;color:var(--waived);font-size:14px;overflow-wrap:anywhere}
.waiver .body{color:var(--dim);white-space:normal}
.compact{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px}
.compact>div{display:flex;gap:12px;align-items:flex-start;padding:12px 14px;border-radius:var(--r-sm);background:var(--glass);box-shadow:var(--hl);min-width:0}
.compact .t{font-weight:600;overflow-wrap:anywhere}.compact .sub{color:var(--faint);font-size:12.5px;overflow-wrap:anywhere}

dl.facts{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:18px 24px;margin:0}
dl.facts dt{color:var(--faint);font-size:12px;font-weight:650;letter-spacing:.06em;text-transform:uppercase;margin-bottom:3px}
dl.facts dd{margin:0;overflow-wrap:anywhere}
dl.facts .wide{grid-column:1/-1}

.note{--c:var(--accent);display:flex;gap:12px;align-items:flex-start;padding:14px 18px;border-radius:var(--r-sm);margin:0 0 20px;
background:color-mix(in srgb,var(--c) 12%,var(--glass));box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--c) 28%,transparent);overflow-wrap:anywhere}
.note::before{content:"i";flex:none;display:grid;place-items:center;width:20px;height:20px;margin-top:1px;border-radius:50%;background:var(--c);color:#000;font:700 12px/1 var(--font)}
.note.s-warn::before,.note.s-fail::before{content:"!"}.note.s-pass::before{content:"\\2713"}
.note>div{min-width:0}.note ul{margin:6px 0 0;padding-left:18px}

label{display:block;font-size:13px;font-weight:650;color:var(--dim);margin:0 0 6px}
input,select,textarea{font:inherit;color:var(--text);background:rgba(255,255,255,.065);border:0;border-radius:12px;padding:10px 14px;
box-shadow:inset 0 0 0 1px var(--line);transition:box-shadow .25s var(--ease),background-color .25s;max-width:100%}
input:focus,select:focus,textarea:focus{outline:none;background:rgba(255,255,255,.09);box-shadow:inset 0 0 0 2px var(--accent)}
input::placeholder,textarea::placeholder{color:#7c7c82}
select{-webkit-appearance:none;appearance:none;padding-right:38px;cursor:pointer;
background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' fill='none' stroke='%23a1a1a6' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m1 1.5 5 5 5-5'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 14px center}
option{background:#1c1c1e;color:var(--text)}
input[type=date]{color-scheme:dark}
input[type=number]{width:7em}
textarea{display:block;width:100%;resize:vertical}
textarea.code{font:13px/1.6 var(--mono);tab-size:2;min-height:max(560px,70vh);padding:16px 18px;background:rgba(0,0,0,.45);white-space:pre;overflow:auto}
textarea.emails{min-height:140px;font:14px/1.6 var(--mono)}
.field{margin:0 0 16px}
.row{display:flex;gap:14px;flex-wrap:wrap;align-items:flex-end}
.row>.field{margin:0}
.grow{flex:1 1 220px;min-width:0}
.grow input,.grow select,.full{width:100%}
.w-name{width:min(420px,100%)}
.actions{display:flex;gap:12px;flex-wrap:wrap;align-items:center;margin-top:18px}
form.inline{display:inline-block;margin:0}

button,.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;font:600 14px/1.2 var(--font);color:var(--text);background:var(--glass-hi);border:0;border-radius:12px;padding:11px 18px;cursor:pointer;white-space:nowrap;
box-shadow:var(--hl);transition:transform .3s var(--ease),background-color .2s,color .2s,box-shadow .3s var(--ease)}
button:hover,button:focus-visible,.btn:hover,.btn:focus-visible{background:var(--text);color:#000;transform:scale(1.04);box-shadow:0 14px 34px rgba(0,0,0,.6),0 0 0 1px rgba(255,255,255,.25);outline:none}
button.primary,.btn.primary{background:var(--text);color:#000}
button.danger{color:#ff7b72;background:color-mix(in srgb,var(--fail) 16%,transparent);box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--fail) 35%,transparent)}
button.danger:hover,button.danger:focus-visible{background:var(--fail);color:#1a0000}
button.sm{padding:6px 12px;font-size:13px;border-radius:10px}
button.ghost{background:transparent;box-shadow:inset 0 0 0 1px var(--line);color:var(--dim)}
.danger-zone{box-shadow:var(--hl),inset 0 0 0 1px color-mix(in srgb,var(--fail) 22%,transparent)}

.cmd{border-radius:16px;background:rgba(0,0,0,.55);box-shadow:inset 0 0 0 1px rgba(255,255,255,.1);overflow:hidden}
.cmd+.cmd,.cmd+p{margin-top:14px}
.cmd-h{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:10px 16px;font-size:12px;font-weight:650;letter-spacing:.04em;color:var(--faint);background:rgba(255,255,255,.04);box-shadow:0 1px 0 var(--line)}
.cmd-h b{color:var(--dim);letter-spacing:0;font-size:13px}
.cmd-h{align-items:center}.cmd-h .copy{margin:-4px -6px -4px auto;padding:5px 12px;font-size:12.5px;letter-spacing:0}
.cmd code.msg{font:14px/1.6 var(--font);word-break:normal;overflow-wrap:anywhere}
.cmd code{display:block;padding:16px 18px;font:13.5px/1.6 var(--mono);color:#e8e8ed;white-space:pre-wrap;word-break:break-all;-webkit-user-select:all;user-select:all;cursor:text}
.cmd code:focus-visible{outline:2px solid var(--accent);outline-offset:-2px;border-radius:0}
.cmd.fixp{margin:22px 0 4px}
.cmd.big code{font-size:15px;padding:20px 22px}

body.public main{max-width:780px;padding-top:clamp(28px,7vh,72px)}
.status-mark{--c:var(--ok);display:grid;place-items:center;width:72px;height:72px;border-radius:22px;margin-bottom:22px;
background:radial-gradient(circle at 30% 20%,color-mix(in srgb,var(--c) 70%,#fff),var(--c) 55%,color-mix(in srgb,var(--c) 60%,#000));box-shadow:0 18px 50px color-mix(in srgb,var(--c) 40%,transparent),inset 0 1px 0 rgba(255,255,255,.4)}
.status-mark svg{width:36px;height:36px}
.steps{counter-reset:s;list-style:none;margin:0 0 20px;padding:0;display:grid;gap:12px}
.steps li{counter-increment:s;display:flex;gap:14px;align-items:flex-start;color:var(--dim)}
.steps li::before{content:counter(s);flex:none;display:grid;place-items:center;width:28px;height:28px;margin-top:-2px;border-radius:50%;background:var(--glass-hi);color:var(--text);font-weight:700;font-size:13px}
.steps li b{color:var(--text)}
kbd{font:600 12px/1 var(--font);padding:3px 7px;border-radius:6px;background:var(--glass-hi);box-shadow:inset 0 -1px 0 rgba(0,0,0,.5);color:var(--text)}
footer.credit{margin:48px auto 28px;padding:0 24px;text-align:center;font-size:12px;color:var(--dim);opacity:.7}
details.adder{margin-top:28px}
details.adder>summary{list-style:none}details.adder>summary::-webkit-details-marker{display:none}
details.adder>summary::before{content:"+";font-weight:700;font-size:16px;line-height:1}
details.adder[open]>summary{background:var(--glass-hi);color:var(--text)}details.adder[open]>summary::before{content:"−"}
details.alt{margin-top:16px;border-radius:var(--r);background:var(--glass);box-shadow:var(--hl)}
details.alt summary{cursor:pointer;list-style:none;padding:18px 22px;font-weight:650;display:flex;justify-content:space-between;align-items:center;border-radius:var(--r);transition:background-color .2s}
details.alt summary::-webkit-details-marker{display:none}
details.alt summary::after{content:"";width:9px;height:9px;border-right:2px solid var(--dim);border-bottom:2px solid var(--dim);transform:rotate(45deg) translate(-2px,-2px);transition:transform .3s var(--ease)}
details.alt[open] summary::after{transform:rotate(225deg) translate(-2px,-2px)}
details.alt summary:hover{background:var(--glass)}
details.alt>div{padding:0 22px 22px}
.foot{margin-top:40px;color:var(--faint);font-size:13.5px}
.center-card{max-width:460px;margin:clamp(16px,8vh,80px) auto 0}

/* Chinese: no uppercase or letter-spacing (they do nothing useful for Han
   characters and space them apart), a little more line height. Vietnamese
   keeps uppercase labels (the system fonts render its stacked diacritics) but
   with less tracking. */
:lang(zh) .eyebrow,:lang(zh) th,:lang(zh) dl.facts dt,:lang(zh) .fix b,:lang(zh) .sev,:lang(zh) .cmd-h{text-transform:none;letter-spacing:0}
:lang(zh) body{line-height:1.6}
:lang(zh) h1{line-height:1.15;letter-spacing:0}:lang(zh) h2,:lang(zh) h3{letter-spacing:0}
:lang(vi) .eyebrow,:lang(vi) th,:lang(vi) dl.facts dt,:lang(vi) .fix b,:lang(vi) .sev{letter-spacing:.02em}
:lang(vi) h1{line-height:1.15}

/* Status tones last, so they override each component's default --c. */
.s-fail{--c:var(--fail)}.s-warn{--c:var(--warn)}.s-error{--c:var(--err)}.s-pass{--c:var(--ok)}.s-skip{--c:var(--skip)}.s-waived{--c:var(--waived)}.s-other{--c:var(--other)}
@media (max-width:860px){.cols{grid-template-columns:minmax(0,1fr)}}
@media (max-width:640px){
.top{gap:10px 12px;padding:10px 16px}
.nav{order:3;width:100%}
.who .id{display:none}
.langs button{padding:5px 8px}
main{padding:22px 16px 72px}
h2{margin-top:40px}
.tiles{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.tile{min-height:112px;padding:14px 16px}.tile .n{font-size:34px}
.panel{padding:18px}
th:first-child,td:first-child{padding-left:16px}th:last-child,td:last-child{padding-right:16px}
.result{padding:16px 16px 16px 20px}
.search{flex:1}.search input{width:100%}
.cmd code,.cmd.big code{font-size:13px;padding:14px 16px}
.status-mark,.mark.lg{width:60px;height:60px;border-radius:18px}
}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{transition:none!important}
a.tile:hover,a.tile:focus-visible,a.card:hover,a.card:focus-visible,button:hover,button:focus-visible,.btn:hover,.btn:focus-visible{transform:none}}
`;

// The site icon: the mark on its gradient tile. Served at /favicon.svg (and
// /favicon.ico, which browsers ask for unprompted); img-src 'self' allows it.
export const FAVICON = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#3a7bff"/><stop offset=".55" stop-color="#7b4dff"/><stop offset="1" stop-color="#1fc8b0"/></linearGradient></defs><rect width="64" height="64" rx="15" fill="url(#g)"/><g transform="translate(13 13) scale(1.58)" fill="none"><path d="M12 2.8 4.5 5.6v5.7c0 4.6 3.1 8.6 7.5 9.9 4.4-1.3 7.5-5.3 7.5-9.9V5.6L12 2.8Z" fill="rgba(255,255,255,.18)" stroke="#fff" stroke-width="1.6" stroke-linejoin="round"/><path d="m8.6 12.1 2.4 2.4 4.5-4.7" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></g></svg>`;

// The bordercheck mark: a shield with a check, drawn inline (no request).
export const MARK = new Html(
  `<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 2.8 4.5 5.6v5.7c0 4.6 3.1 8.6 7.5 9.9 4.4-1.3 7.5-5.3 7.5-9.9V5.6L12 2.8Z" fill="rgba(255,255,255,.18)" stroke="#fff" stroke-width="1.6" stroke-linejoin="round"/><path d="m8.6 12.1 2.4 2.4 4.5-4.7" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
);

export type NavItem = "Machines" | "Checks" | "Alerts" | "Roles" | "Invites" | "Audit";

const NAV: [NavItem, string, Key][] = [
  ["Machines", "/admin", "nav.machines"],
  ["Checks", "/admin/checks", "nav.checks"],
  ["Alerts", "/admin/alerts", "nav.alerts"],
  ["Roles", "/admin/roles", "nav.roles"],
  ["Invites", "/admin/invites", "nav.invites"],
  ["Audit", "/admin/audit", "nav.audit"],
];

// switcher is the language choice: a POST form with one button per language
// (no script).
// - "lang" (admin and sign-in pages): posts to /lang with the page's path in
//   `next`; /lang sets the cookie and goes back there, validated as a
//   same-origin path.
// - "self" (the capability pages /i/<code> and /r/<id>): no action, so the
//   form posts to the page's own URL, which sets the cookie and redirects to
//   that same path. The code or id is not copied into the page, another URL
//   or a form field, and the GET that follows never consumes an invite.
function switcher(L: I18n, mode: "lang" | "self"): Html {
  return html`<form class="langs" method="post"${mode === "lang" ? html` action="/lang"` : ""} role="group" aria-label="${L.s("lang.label")}">${
    mode === "lang" ? html`<input type="hidden" name="next" value="${L.path}">` : ""
  }${LANGS.map(
    (l) => html`<button name="lang" value="${l}" lang="${l === "zh" ? "zh-Hans" : l}" title="${LANG_NAME[l]}" aria-label="${LANG_NAME[l]}"${l === L.lang ? html` class="on" aria-current="true"` : ""}>${LANG_SHORT[l]}</button>`,
  )}</form>`;
}

export interface LayoutOptions {
  // "self" on the capability pages (see switcher); false on pages that exist
  // only as the answer to a POST (codes shown once): going "back" there would
  // lose them.
  switcher?: false | "self";
  // Include COPY_SCRIPT. The response must then carry COPY_HEADERS.
  copy?: boolean;
}

// copyButton copies the text of the element with id `target`. Hidden until
// the script runs. Its labels are rendered here, escaped; the script only
// moves them between data- attributes and textContent.
export function copyButton(L: I18n, target: string, label: Key): Html {
  return html`<button type="button" class="sm copy" hidden data-copy="${target}" data-label="${L.s(label)}" data-done="${L.s("copy.done")}">${L.t(label)}</button>`;
}

// layout wraps a page. With `who` (a signed-in admin) it has the portal's
// navigation; without, it is a public page (sign-in, invite, report link)
// with only the name and no links into /admin.
export function layout(L: I18n, title: string, who: string | null, body: Html, active?: NavItem, opts: LayoutOptions = {}): Html {
  const langs = opts.switcher === false ? "" : switcher(L, opts.switcher === "self" ? "self" : "lang");
  return html`<html lang="${L.htmlLang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="dark"><meta name="theme-color" content="#000000">
<link rel="icon" type="image/svg+xml" href="/favicon.svg"><meta name="theme-color" content="#000000">
<title>${title} · bordercheck</title><style>${new Html(STYLE)}</style></head><body class="${who ? "admin" : "public"}">
<header class="top">${
    who
      ? html`<a class="brand" href="/admin"><span class="mark">${MARK}</span>bordercheck</a><nav class="nav" aria-label="${L.s("nav.sections")}">${NAV.map(
          ([item, href, key]) => html`<a href="${href}"${item === active ? html` class="on" aria-current="page"` : ""}>${L.t(key)}</a>`,
        )}</nav>
<div class="who">${langs}<span class="id">${who}</span>${
          who === "admin token"
            ? html`<form method="post" action="/admin/logout"><button class="sm ghost">${L.t("nav.signOut")}</button></form>`
            : ""
        }</div>`
      : html`<span class="brand"><span class="mark">${MARK}</span>bordercheck</span>${langs}`
  }</header>
<main>${body}</main><footer class="credit">© Phil Trinh - SENPRINTS</footer>${
    opts.copy ? html`<span id="copy-status" class="sr-only" aria-live="polite"></span><script>${new Html(COPY_SCRIPT)}</script>` : ""
  }</body></html>`;
}

export function statusClass(s: string): string {
  return ["fail", "warn", "error", "pass", "skip", "waived"].includes(s) ? `s-${s}` : "s-other";
}

// badge is a status pill: colour, a dot and the status word, so it never
// relies on colour alone. Known statuses are translated; anything else (a
// status from a newer bordercheck) is shown as received.
export function badge(L: I18n, s: string): Html {
  return html`<span class="pill ${statusClass(s)}">${L.status(s)}</span>`;
}

// pill is a coloured label with fixed text, e.g. "non-compliant", "revoked".
export function pill(cls: string, text: string | Html): Html {
  return html`<span class="pill ${cls}">${text}</span>`;
}

// sev is a severity chip; only the known severities get a colour class and a
// translation.
export function sev(L: I18n, s: string): Html | string {
  if (!s) return "";
  const known = ["high", "medium", "low", "info"].includes(s) ? ` sev-${s}` : "";
  return html`<span class="sev${known}">${L.severity(s)}</span>`;
}

// count renders a number, coloured when it is not zero.
export function count(L: I18n, n: number, cls: string): Html {
  return n ? html`<span class="${cls}">${L.num(n)}</span>` : html`<span class="zero">${L.num(0)}</span>`;
}

export function note(m: string | Html, cls = ""): Html | string {
  return m ? html`<div class="note ${cls}"><div>${m}</div></div>` : "";
}

// pct is a share as a CSS width; numbers only, never text from a report.
export function pct(part: number, whole: number): string {
  if (!whole || !part) return "0%";
  return `${Math.max(0, Math.min(100, (part / whole) * 100)).toFixed(2)}%`;
}
