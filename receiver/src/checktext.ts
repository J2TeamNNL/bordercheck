// A result's summary and fix in the reader's language.
//
// bordercheck 0.4+ sends each result's summary and fix twice: as English text
// ("summary", "fix") and as parts ("summary_parts", "fix_parts"): message keys
// with named parameters, in the order the English joins them. The keys and
// their English come from the client's table (internal/msg/catalog.go),
// exported to i18n/checks.en.json; checks.zh.ts and checks.vi.ts translate
// the same keys. When every part of a field has a known key and exactly the
// parameters that key takes, with the right types, the parts are rendered
// in the reader's language; otherwise the English text the machine sent is
// shown, as it always was (older clients send no parts).
//
// Parts come from the machine and are untrusted like everything else in a
// report: parseParts caps and type-checks them, parameters are escaped (never
// read as markup), and a translation can only carry the [b] [code] [kbd]
// markup every catalogue may. Fix text keeps linkify: only https links to
// the hosts html.ts trusts become anchors, in the template and in parameters.

import { escape, Html, linkify } from "./html";
import type { I18n, Lang } from "./i18n";
import checksEn from "./i18n/checks.en.json";
import { checksVi } from "./i18n/checks.vi";
import { checksZh } from "./i18n/checks.zh";
import type { Entry } from "./i18n/en";

export type CheckKey = keyof typeof checksEn;
// A translation of every check message: a key missing (or extra) is a compile error.
export type CheckCatalog = Record<CheckKey, Entry>;

export type ParamValue = string | number;
export interface Part {
  key: string;
  params: Record<string, ParamValue>;
}

const CATALOGS: Record<Lang, CheckCatalog> = { en: checksEn as CheckCatalog, zh: checksZh, vi: checksVi };

// ---- Parsing (report.ts) ----

export const MAX_PARTS = 24;
export const MAX_PARAMS = 8;
export const MAX_PARAM_LENGTH = 300;
const KEY_RE = /^[a-z][A-Za-z0-9]*(?:\.[a-z][A-Za-z0-9]*){1,5}$/;
const NAME_RE = /^[a-z][A-Za-z0-9_]{0,31}$/;

// parseParts validates summary_parts / fix_parts. Anything malformed (not an
// array, too many parts or parameters, a bad key or name, a value that is not
// a short string or a finite number) drops the whole field, so the English
// text is shown instead.
export function parseParts(v: unknown): Part[] | undefined {
  if (!Array.isArray(v) || v.length === 0 || v.length > MAX_PARTS) return undefined;
  const out: Part[] = [];
  for (const x of v) {
    if (!x || typeof x !== "object" || Array.isArray(x)) return undefined;
    const { key, params } = x as { key?: unknown; params?: unknown };
    if (typeof key !== "string" || key.length > 80 || !KEY_RE.test(key)) return undefined;
    const p: Record<string, ParamValue> = Object.create(null);
    if (params !== undefined) {
      if (!params || typeof params !== "object" || Array.isArray(params)) return undefined;
      const entries = Object.entries(params);
      if (entries.length > MAX_PARAMS) return undefined;
      for (const [name, value] of entries) {
        if (!NAME_RE.test(name)) return undefined;
        if (typeof value === "number") {
          if (!Number.isFinite(value) || Math.abs(value) > 1e12) return undefined;
          p[name] = value;
        } else if (typeof value === "string") {
          if (value.length > MAX_PARAM_LENGTH * 4) return undefined;
          // No control characters; one line; capped.
          const clean = value.replace(/[\u0000-\u001f\u007f]/g, " ");
          p[name] = clean.length > MAX_PARAM_LENGTH ? clean.slice(0, MAX_PARAM_LENGTH) + "…" : clean;
        } else {
          return undefined;
        }
      }
    }
    out.push({ key, params: { ...p } });
  }
  return out;
}

// ---- Templates ----

type ParamType = "" | "dur" | "ago" | "date";
const PH_RE = /\{(\w+)(?::(dur|ago|date))?\}/g;
const MARKUP: Record<string, string> = { "[b]": "<b>", "[/b]": "</b>", "[code]": "<code>", "[/code]": "</code>", "[kbd]": "<kbd>", "[/kbd]": "</kbd>" };
const MARKUP_RE = /\[\/?(?:b|code|kbd)\]/g;

const forms = (e: Entry): string[] => (typeof e === "string" ? [e] : [e.other, ...(e.one ? [e.one] : [])]);

// placeholders lists the parameters a template uses: name → type.
export function placeholders(e: Entry): Map<string, ParamType> {
  const m = new Map<string, ParamType>();
  for (const f of forms(e)) for (const x of f.matchAll(PH_RE)) m.set(x[1], (x[2] ?? "") as ParamType);
  return m;
}

const expectedCache = new Map<string, Map<string, ParamType>>();
function expected(key: CheckKey): Map<string, ParamType> {
  let m = expectedCache.get(key);
  if (!m) expectedCache.set(key, (m = placeholders(checksEn[key] as Entry)));
  return m;
}

const isCount = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= 1e9;

// valid: the key is known and the params are exactly the ones it takes.
export function validPart(p: Part): p is Part & { key: CheckKey } {
  if (!Object.hasOwn(checksEn, p.key)) return false;
  const want = expected(p.key as CheckKey);
  const names = Object.keys(p.params);
  if (names.length !== want.size) return false;
  for (const [name, type] of want) {
    if (!Object.hasOwn(p.params, name)) return false;
    const v = p.params[name];
    switch (type) {
      case "":
        if (name === "n" ? !isCount(v) : typeof v !== "string" && typeof v !== "number") return false;
        break;
      case "dur":
      case "ago":
        if (!isCount(v)) return false;
        break;
      case "date":
        if (typeof v !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(v) || Number.isNaN(Date.parse(v + "T00:00:00Z"))) return false;
        break;
    }
  }
  return true;
}

// ---- Values ----

const plurals = new Map<Lang, Intl.PluralRules>();
function plural(lang: Lang, n: number): "one" | "other" {
  let r = plurals.get(lang);
  if (!r) plurals.set(lang, (r = new Intl.PluralRules(lang === "zh" ? "zh-CN" : lang)));
  return r.select(n) === "one" ? "one" : "other";
}

// duration: seconds as the client's English says them ("45 seconds", "1 minute", "2.5 minutes").
export function duration(lang: Lang, secs: number): string {
  const fmt = (m: number) => (Number.isInteger(m) ? String(m) : m.toFixed(1));
  if (secs < 60) {
    if (lang === "vi") return `${secs} giây`;
    if (lang === "zh") return `${secs} 秒`;
    return secs === 1 ? "1 second" : `${secs} seconds`;
  }
  const m = secs / 60;
  if (lang === "vi") return `${fmt(m).replace(".", ",")} phút`;
  if (lang === "zh") return `${fmt(m)} 分钟`;
  return m === 1 ? "1 minute" : `${fmt(m)} minutes`;
}

// daysAgo: "today", "1 day ago", "3 days ago".
export function daysAgo(lang: Lang, days: number): string {
  if (lang === "vi") return days === 0 ? "hôm nay" : `${days} ngày trước`;
  if (lang === "zh") return days === 0 ? "今天" : `${days} 天前`;
  return days === 0 ? "today" : days === 1 ? "1 day ago" : `${days} days ago`;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function value(L: I18n, type: ParamType, v: ParamValue): string {
  switch (type) {
    case "dur":
      return duration(L.lang, v as number);
    case "ago":
      return daysAgo(L.lang, v as number);
    case "date": {
      const [y, m, d] = String(v).split("-").map(Number);
      return L.lang === "en" ? `${d} ${MONTHS[m - 1]} ${y}` : L.day(String(v));
    }
  }
  // Counts, ports and versions are shown as sent: no digit grouping.
  return String(v);
}

// ---- Rendering ----

function literal(s: string, fix: boolean): string {
  let out = "";
  let last = 0;
  for (const m of s.matchAll(MARKUP_RE)) {
    const text = s.slice(last, m.index);
    out += fix ? linkify(text).value : escape(text);
    out += MARKUP[m[0]];
    last = m.index + m[0].length;
  }
  const rest = s.slice(last);
  return out + (fix ? linkify(rest).value : escape(rest));
}

function renderPart(L: I18n, p: Part & { key: CheckKey }, fix: boolean): string {
  const entry: Entry = CATALOGS[L.lang][p.key] ?? (checksEn[p.key] as Entry);
  const tmpl = typeof entry === "string" ? entry : (entry[plural(L.lang, Number(p.params.n))] ?? entry.other);
  const types = expected(p.key);
  let out = "";
  let last = 0;
  for (const m of tmpl.matchAll(PH_RE)) {
    out += literal(tmpl.slice(last, m.index), fix);
    const name = m[1];
    const v = Object.hasOwn(p.params, name) ? value(L, types.get(name) ?? "", p.params[name]) : `{${name}}`;
    out += fix ? linkify(v).value : escape(v);
    last = m.index + m[0].length;
  }
  return out + literal(tmpl.slice(last), fix);
}

// renderParts is the parts in the reader's language, or null when any part
// cannot be rendered (unknown key, wrong parameters).
export function renderParts(L: I18n, parts: Part[] | undefined, fix = false): Html | null {
  if (!parts || parts.length === 0 || !parts.every(validPart)) return null;
  // A summary reads as one paragraph. A fix's parts are separate steps
  // (several problems, each with its own fix), so each gets its own line;
  // the .fix box keeps line breaks.
  const sep = fix ? "\n" : L.lang === "zh" ? "" : " ";
  return new Html(parts.map((p) => renderPart(L, p as Part & { key: CheckKey }, fix)).join(sep));
}

export interface HasText {
  summary: string;
  fix: string;
  summary_parts?: Part[];
  fix_parts?: Part[];
}

// summaryHtml: the result's summary in the reader's language, else the English the machine sent.
export function summaryHtml(L: I18n, r: HasText): Html {
  return renderParts(L, r.summary_parts) ?? new Html(escape(r.summary));
}

// fixHtml: the fix in the reader's language, else the English; trusted links clickable either way.
export function fixHtml(L: I18n, r: HasText): Html {
  return renderParts(L, r.fix_parts, true) ?? linkify(r.fix);
}
