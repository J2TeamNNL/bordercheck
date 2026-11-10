// Languages for the HTML pages (admin and public). Machine interfaces (the
// JSON of /enroll, /policy, /report; the MCP server; webhook payloads) stay in
// English: see README "Languages".
//
// How a request's language is chosen: the bc_lang cookie set by the switcher
// (POST /lang), else the best supported match in Accept-Language, else English.

import { escape, Html } from "../html";
import { type Catalog, en, type Entry, type Key } from "./en";
import { vi } from "./vi";
import { zh } from "./zh";

export type { Key } from "./en";

export const LANGS = ["en", "zh", "vi"] as const;
export type Lang = (typeof LANGS)[number];
export const DEFAULT_LANG: Lang = "en";

const CATALOGS: Record<Lang, Catalog> = { en, zh, vi };
// BCP 47 tags: for <html lang> and for Intl.
const HTML_LANG: Record<Lang, string> = { en: "en", zh: "zh-Hans", vi: "vi" };
const LOCALE: Record<Lang, string> = { en: "en", zh: "zh-CN", vi: "vi" };
// The switcher's labels, each in its own language.
export const LANG_SHORT: Record<Lang, string> = { en: "EN", zh: "中文", vi: "VI" };
export const LANG_NAME: Record<Lang, string> = { en: "English", zh: "简体中文", vi: "Tiếng Việt" };

export const LANG_COOKIE = "bc_lang";
const COOKIE_MAX_AGE = 365 * 24 * 3600;

export const isLang = (s: unknown): s is Lang => typeof s === "string" && (LANGS as readonly string[]).includes(s);

// langOfTag maps one language tag to a supported language. Every Chinese tag
// goes to Simplified Chinese, the only Chinese catalogue: zh, zh-CN, zh-SG,
// zh-Hans, and also zh-TW, zh-HK and zh-Hant (a reader of Traditional is
// better served by Simplified than by English).
function langOfTag(tag: string): Lang | null {
  const primary = tag.trim().toLowerCase().split(/[-_]/)[0];
  if (primary === "en") return "en";
  if (primary === "zh") return "zh";
  if (primary === "vi") return "vi";
  return null;
}

// fromAcceptLanguage returns the supported language with the highest q-value
// (ties keep header order), or null. q=0 means "not this one"; malformed
// entries are skipped; "*" carries no preference here.
export function fromAcceptLanguage(header: string | null | undefined): Lang | null {
  if (!header) return null;
  const prefs: { lang: Lang; q: number; i: number }[] = [];
  header.slice(0, 1000).split(",").forEach((part, i) => {
    const [tag, ...params] = part.split(";");
    if (!/^\s*[A-Za-z]{1,8}(-[A-Za-z0-9]{1,8})*\s*$/.test(tag)) return;
    let q = 1;
    for (const p of params) {
      const m = /^\s*q\s*=\s*([0-9](?:\.[0-9]{0,3})?)\s*$/i.exec(p);
      if (m) q = Number(m[1]);
      else if (/^\s*q\s*=/i.test(p)) q = -1;
    }
    if (!(q > 0 && q <= 1)) return;
    const lang = langOfTag(tag);
    if (lang) prefs.push({ lang, q, i });
  });
  prefs.sort((a, b) => b.q - a.q || a.i - b.i);
  return prefs[0]?.lang ?? null;
}

// fromCookie reads bc_lang, accepted only if it names a supported language.
export function fromCookie(header: string | null | undefined): Lang | null {
  if (!header) return null;
  for (const part of header.split(";")) {
    const [k, v] = part.split("=", 2).map((s) => s?.trim());
    if (k === LANG_COOKIE && isLang(v)) return v;
  }
  return null;
}

export function negotiate(req: Request): Lang {
  return fromCookie(req.headers.get("cookie")) ?? fromAcceptLanguage(req.headers.get("accept-language")) ?? DEFAULT_LANG;
}

export function langCookie(lang: Lang): string {
  return `${LANG_COOKIE}=${lang}; Path=/; Max-Age=${COOKIE_MAX_AGE}; Secure; HttpOnly; SameSite=Lax`;
}

// safeNext turns the switcher's "next" field into a same-origin path to go
// back to. Anything else (absolute URLs, //host, backslashes, control
// characters) goes to "/".
export function safeNext(next: string, origin: string): string {
  if (!next.startsWith("/") || next.startsWith("//") || /[\\\u0000-\u001f\u007f]/.test(next) || next.length > 2048) return "/";
  try {
    const u = new URL(next, origin);
    if (u.origin !== origin) return "/";
    return u.pathname + u.search;
  } catch {
    return "/";
  }
}

// ---- Messages ----

export type Params = Record<string, unknown>;

// A Msg is a message to show later, in whatever language the reader has:
// shared operations (portal.ts, roles.ts) return these, the dashboard renders
// them in the request's language and the MCP server in English.
export interface Msg {
  key: Key;
  p?: Params;
}
export const msg = (key: Key, p?: Params): Msg => (p ? { key, p } : { key });
const isMsg = (v: unknown): v is Msg => !!v && typeof v === "object" && typeof (v as Msg).key === "string" && (v as Msg).key in en;

// The only markup a translation can carry.
const MARKUP: Record<string, string> = { "[b]": "<b>", "[/b]": "</b>", "[code]": "<code>", "[/code]": "</code>", "[kbd]": "<kbd>", "[/kbd]": "</kbd>" };
const MARKUP_RE = /\[\/?(?:b|code|kbd)\]/g;

const pluralRules = new Map<Lang, Intl.PluralRules>();
const numberFormats = new Map<Lang, Intl.NumberFormat>();

function plural(lang: Lang): Intl.PluralRules {
  let r = pluralRules.get(lang);
  if (!r) pluralRules.set(lang, (r = new Intl.PluralRules(LOCALE[lang])));
  return r;
}

function numberFormat(lang: Lang): Intl.NumberFormat {
  let f = numberFormats.get(lang);
  if (!f) numberFormats.set(lang, (f = new Intl.NumberFormat(LOCALE[lang])));
  return f;
}

function template(lang: Lang, key: Key, p: Params | undefined): string {
  const entry: Entry = CATALOGS[lang][key] ?? en[key];
  if (typeof entry === "string") return entry;
  const n = Number(p?.n ?? 0);
  const cat = plural(lang).select(n) as "one" | "other";
  return entry[cat] ?? entry.other;
}

function param(lang: Lang, name: string, v: unknown, asHtml: boolean): string {
  if (v === undefined) return escape(`{${name}}`); // visible, so tests catch it
  if (v instanceof Html) return asHtml ? v.value : v.value.replace(/<[^>]*>/g, "");
  if (isMsg(v)) return format(lang, v.key, v.p, asHtml);
  // Ids (#123) are not quantities: no grouping.
  const s = typeof v === "number" && name !== "id" ? numberFormat(lang).format(v) : String(v);
  return asHtml ? escape(s) : s;
}

function format(lang: Lang, key: Key, p: Params | undefined, asHtml: boolean): string {
  const parts = template(lang, key, p).split(/\{(\w+)\}/);
  let out = "";
  for (let i = 0; i < parts.length; i++) {
    if (i % 2) out += param(lang, parts[i], p?.[parts[i]], asHtml);
    else out += asHtml ? escape(parts[i]).replace(MARKUP_RE, (t) => MARKUP[t]) : parts[i].replace(MARKUP_RE, "");
  }
  return out;
}

// ---- Per-request formatter ----

export interface I18n {
  lang: Lang;
  htmlLang: string;
  // The path and query of the page being rendered: where the switcher returns to.
  path: string;
  // t renders a message as HTML: the translation's text escaped, its [b] etc.
  // turned into tags, parameters escaped unless they are Html.
  t(key: Key, p?: Params): Html;
  // s renders it as plain text (for <title>, attributes via html``, MCP).
  s(key: Key, p?: Params): string;
  m(m: Msg): Html;
  ms(m: Msg): string;
  num(n: number): string;
  status(s: string): string;
  severity(s: string): string;
  // ago: "3m ago" / "3分钟前" / "3 phút trước"; age: "3 days" / "3天" / "3 ngày".
  ago(iso: string | null | undefined, now: number): string;
  age(iso: string | null | undefined, now: number): string;
  inDays(iso: string, now: number): string;
  // when: a timestamp, UTC. day: a YYYY-MM-DD date.
  when(iso: string | null | undefined): string;
  day(ymd: string | null | undefined): string;
}

// checkTitle is the name of a check in the reader's language: the built-in
// checks have translated titles; for any other ID the title the machine sent
// (untrusted, escaped by the template) is shown.
export function checkTitle(L: I18n, id: string, sent?: string | null): string {
  const key = `checkTitle.${id}`;
  return Object.hasOwn(en, key) ? L.s(key as Key) : sent || id;
}

const STATUS_KEYS: Record<string, Key> = {
  fail: "status.fail", warn: "status.warn", error: "status.error", pass: "status.pass", skip: "status.skip", waived: "status.waived",
};
const SEV_KEYS: Record<string, Key> = { high: "sev.high", medium: "sev.medium", low: "sev.low", info: "sev.info" };

const DAY_MS = 24 * 3600 * 1000;

export function i18n(lang: Lang, path = "/"): I18n {
  const locale = LOCALE[lang];
  const rtf = new Intl.RelativeTimeFormat(locale, { style: "narrow", numeric: "always" });
  const unit = (u: "minute" | "hour" | "day", n: number) =>
    new Intl.NumberFormat(locale, { style: "unit", unit: u, unitDisplay: "short" }).format(n);
  const s = (key: Key, p?: Params) => format(lang, key, p, false);
  const span = (iso: string | null | undefined, now: number) => {
    if (!iso) return null;
    const t = Date.parse(iso);
    if (Number.isNaN(t)) return undefined;
    const sec = Math.max(0, Math.round((now - t) / 1000));
    if (sec < 90) return { u: "now" as const, n: 0 };
    if (sec < 90 * 60) return { u: "minute" as const, n: Math.round(sec / 60) };
    if (sec < 36 * 3600) return { u: "hour" as const, n: Math.round(sec / 3600) };
    return { u: "day" as const, n: Math.round(sec / 86400) };
  };
  // English keeps ISO 8601 dates (unambiguous for an international team, and
  // what the portal always showed); Chinese and Vietnamese get their own
  // numeric order from Intl. All times are UTC and say so.
  const dt = lang === "en" ? null : new Intl.DateTimeFormat(locale, {
    year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23", timeZone: "UTC",
  });
  const d = lang === "en" ? null : new Intl.DateTimeFormat(locale, { year: "numeric", month: "2-digit", day: "2-digit", timeZone: "UTC" });
  return {
    lang,
    htmlLang: HTML_LANG[lang],
    path,
    t: (key, p) => new Html(format(lang, key, p, true)),
    s,
    m: (m) => new Html(format(lang, m.key, m.p, true)),
    ms: (m) => format(lang, m.key, m.p, false),
    num: (n) => numberFormat(lang).format(n),
    status: (st) => (STATUS_KEYS[st] ? s(STATUS_KEYS[st]) : st),
    severity: (sv) => (SEV_KEYS[sv] ? s(SEV_KEYS[sv]) : sv),
    ago(iso, now) {
      const a = span(iso, now);
      if (a === null) return s("time.never");
      if (a === undefined) return "?";
      return a.u === "now" ? s("time.justNow") : rtf.format(-a.n, a.u);
    },
    age(iso, now) {
      const a = span(iso, now);
      if (a === null) return s("time.never");
      if (a === undefined) return "?";
      // A duration is never "just now": under 90 seconds it is one minute.
      return a.u === "now" ? unit("minute", 1) : unit(a.u, a.n);
    },
    inDays(iso, now) {
      const n = Math.ceil((Date.parse(iso) - now) / DAY_MS);
      return Number.isNaN(n) ? "" : n <= 0 ? s("time.today") : rtf.format(n, "day");
    },
    when(iso) {
      if (!iso) return "";
      const t = Date.parse(iso);
      if (!dt || Number.isNaN(t)) return iso.replace("T", " ").replace(/:\d\d(\.\d+)?Z$/, " UTC").replace(/Z$/, " UTC");
      return `${dt.format(t)} UTC`;
    },
    day(ymd) {
      if (!ymd) return "";
      const t = Date.parse(ymd.length === 10 ? ymd + "T00:00:00Z" : ymd);
      if (!d || Number.isNaN(t)) return ymd;
      return d.format(t);
    },
  };
}

export function forRequest(req: Request, url = new URL(req.url)): I18n {
  return i18n(negotiate(req), url.pathname + url.search);
}

// English, for the MCP server and anything else that is not a page.
export const EN = i18n("en");
export const english = (m: Msg): string => EN.ms(m);
