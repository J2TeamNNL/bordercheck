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

function render(v: unknown): string {
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

// Content-Security-Policy: no scripts at all, inline styles only, forms post
// to this origin, never framed.
const CSP =
  "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

export function page(body: Html, status = 200, headers: Record<string, string> = {}): Response {
  return new Response("<!doctype html>" + body.value, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": CSP,
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "cache-control": "no-store",
      ...headers,
    },
  });
}

const STYLE = `
:root{--bg:#fbfbfa;--fg:#1d1d1b;--muted:#6b6b66;--line:#e4e3df;--card:#fff;--fail:#c0362c;--warn:#b7791f;--err:#8e44ad;--ok:#2f7d4f;--waived:#3d6ea8;--other:#666}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe7;--muted:#9a9993;--line:#2d2d2a;--card:#1e1e1c;--fail:#ef6b5f;--warn:#e0a84a;--err:#c18ae0;--ok:#5fc08a;--waived:#7fa8dd;--other:#aaa}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
header{display:flex;gap:16px;align-items:center;flex-wrap:wrap;padding:12px 16px;border-bottom:1px solid var(--line)}
header b{font-size:15px}header nav{display:flex;gap:12px;flex-wrap:wrap}header .who{margin-left:auto;color:var(--muted)}
main{padding:16px;max-width:1200px;margin:0 auto}a{color:inherit}h1{font-size:20px;margin:4px 0 12px}h2{font-size:16px;margin:24px 0 8px}
.muted{color:var(--muted)}.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;background:var(--card)}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{font-weight:600;color:var(--muted);white-space:nowrap}
td.n{text-align:right;font-variant-numeric:tabular-nums}.filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.filters a{padding:3px 10px;border:1px solid var(--line);border-radius:12px;text-decoration:none}.filters a.on{background:var(--fg);color:var(--bg)}
.badge{display:inline-block;padding:0 7px;border-radius:9px;font-size:12px;font-weight:600;border:1px solid currentColor;white-space:nowrap}
.s-fail{color:var(--fail)}.s-warn{color:var(--warn)}.s-error{color:var(--err)}.s-pass{color:var(--ok)}.s-skip{color:var(--muted)}.s-waived{color:var(--waived)}.s-other{color:var(--other)}
.result{background:var(--card);border:1px solid var(--line);border-left:4px solid currentColor;border-radius:4px;padding:10px 12px;margin:8px 0}
.result .body{color:var(--fg)}.result ul{margin:6px 0;padding-left:20px}.result code,.ev{font:12px ui-monospace,Menlo,monospace;word-break:break-all}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0}dt{color:var(--muted)}dd{margin:0;word-break:break-word}
input,textarea,button,select{font:inherit}textarea{width:100%;min-height:360px;font:12px ui-monospace,Menlo,monospace}
textarea.cmd{min-height:0;background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:4px;padding:6px}
button{padding:5px 12px;border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:4px;cursor:pointer}
.danger{color:var(--fail)}.note{padding:8px 12px;border:1px solid var(--line);background:var(--card);border-radius:4px;margin:8px 0}
`;

export function layout(title: string, who: string | null, body: Html): Html {
  return html`<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} · bordercheck</title><style>${new Html(STYLE)}</style></head><body>
<header><b>bordercheck</b>${
    who
      ? html`<nav><a href="/admin">Machines</a><a href="/admin/checks">Checks</a><a href="/admin/alerts">Alerts</a><a href="/admin/roles">Roles</a><a href="/admin/invites">Invites</a><a href="/admin/audit">Audit</a></nav>
<span class="who">${who}${
          who === "admin token"
            ? html` · <form method="post" action="/admin/logout" style="display:inline"><button>Sign out</button></form>`
            : ""
        }</span>`
      : ""
  }</header>
<main>${body}</main></body></html>`;
}

export function statusClass(s: string): string {
  return ["fail", "warn", "error", "pass", "skip", "waived"].includes(s) ? `s-${s}` : "s-other";
}

export function badge(s: string): Html {
  return html`<span class="badge ${statusClass(s)}">${s}</span>`;
}

export function ago(iso: string | null | undefined, now: number): string {
  if (!iso) return "never";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "?";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 90) return "just now";
  if (s < 90 * 60) return `${Math.round(s / 60)} min ago`;
  if (s < 36 * 3600) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

export function when(iso: string | null | undefined): string {
  if (!iso) return "";
  return iso.replace("T", " ").replace(/\.\d+Z$|Z$/, " UTC");
}
