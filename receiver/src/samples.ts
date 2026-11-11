// Likely sample keys: findings the client's secrets check set aside because a
// rule (checks.secrets.sample_rules) says they look like samples, not real
// keys. A result's likely_samples is always sent by clients that know it,
// also without evidence; older clients leave it out. Every field came from
// the report, so it is bounded here and escaped wherever it is shown.
import { html, type Html } from "./html";
import type { I18n, Key } from "./i18n";

export interface LikelySample {
  path: string;
  name: string;
  kind: string;
  rule: string; // git-tracked | sdk | sample-dir | anything newer
}

export const MAX_LIKELY_SAMPLES = 200;
export const SAMPLE_RULES = ["git-tracked", "sdk", "sample-dir"];

// Lists longer than this are folded on the machine page.
const SHOW_OPEN = 8;

// parseLikelySamples keeps well-formed entries (a path and a rule, every
// field a string if present), capped in number and length; anything else is
// dropped. undefined when the field is not a list.
export function parseLikelySamples(v: unknown): LikelySample[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: LikelySample[] = [];
  for (const x of v.slice(0, MAX_LIKELY_SAMPLES * 2)) {
    if (!x || typeof x !== "object" || Array.isArray(x)) continue;
    const o = x as Record<string, unknown>;
    const fields = ["path", "name", "kind", "rule"];
    if (fields.some((f) => o[f] !== undefined && typeof o[f] !== "string")) continue;
    const one = (f: string, max: number) => {
      const s = typeof o[f] === "string" ? (o[f] as string).replace(/[\u0000-\u001f\u007f]/g, " ").trim() : "";
      return s.length > max ? s.slice(0, max) + "…" : s;
    };
    const e = { path: one("path", 500), name: one("name", 128), kind: one("kind", 64), rule: one("rule", 32) };
    if (!e.path || !e.rule) continue;
    out.push(e);
    if (out.length >= MAX_LIKELY_SAMPLES) break;
  }
  return out;
}

const RULE_KEYS: Record<string, Key> = {
  "git-tracked": "machine.sampleRuleGit",
  sdk: "machine.sampleRuleSdk",
  "sample-dir": "machine.sampleRuleDir",
};

// ruleLabel names a rule in the reader's language; a rule this portal does
// not know is shown as sent (escaped by html).
function ruleLabel(L: I18n, rule: string): Html | string {
  const k = RULE_KEYS[rule];
  return k ? L.t(k) : rule;
}

// likelySamplesList is the machine page's section under the secrets check:
// path, name or kind, and the rule. Long lists are folded.
export function likelySamplesList(L: I18n, items: LikelySample[] | undefined): Html | string {
  if (!items?.length) return "";
  const li = (i: LikelySample) =>
    html`<li class="ev">${i.path}  ${i.kind}${i.name ? html` (${i.name})` : ""} <span class="muted">· ${ruleLabel(L, i.rule)}</span></li>`;
  const head = html`<p><b>${L.t("machine.likelySamples", { n: items.length })}</b> <span class="muted small">${L.t("machine.likelySamplesNote")}</span></p>`;
  if (items.length <= SHOW_OPEN) return html`<div class="ignored samples">${head}<ul class="evidence">${items.map(li)}</ul></div>`;
  return html`<div class="ignored samples">${head}<details><summary class="small">${L.t("machine.likelySamplesShow", { n: items.length })}</summary><ul class="evidence">${items.map(li)}</ul></details></div>`;
}

// countLikelySamples adds up the likely samples of some results.
export function countLikelySamples(results: { likely_samples?: LikelySample[] }[]): number {
  return results.reduce((n, r) => n + (r.likely_samples?.length ?? 0), 0);
}
