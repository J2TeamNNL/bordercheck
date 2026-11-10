// The receiver's side of keeping the check messages in sync: checks.en.json
// must be exactly the Go table in internal/msg/catalog.go (the Go side has
// the same test, TestCatalogJSON). Regenerate with: go generate ./internal/msg
import { describe, expect, it } from "vitest";
import catalogGo from "../../internal/msg/catalog.go?raw";
import checksEn from "../src/i18n/checks.en.json";

type Entry = string | { one?: string; other: string };

// parseGoCatalog reads the `"key": s("…" + "…")` and `"key": pl("…", "…")`
// entries of catalog.go: Go string literals, concatenated with +.
function parseGoCatalog(src: string): Record<string, Entry> {
  const out: Record<string, Entry> = {};
  const head = /"([A-Za-z0-9.]+)":\s*(s|pl)\(/g;
  for (let m = head.exec(src); m; m = head.exec(src)) {
    let i = head.lastIndex;
    const args: string[] = [];
    let cur = "";
    for (;;) {
      while (/\s/.test(src[i])) i++;
      if (src[i] === '"') {
        i++;
        while (src[i] !== '"') {
          if (src[i] === "\\") {
            const c = src[++i];
            cur += c === "n" ? "\n" : c === "t" ? "\t" : c;
          } else cur += src[i];
          i++;
        }
        i++;
      } else if (src[i] === "+") i++;
      else if (src[i] === ",") {
        args.push(cur);
        cur = "";
        i++;
      } else if (src[i] === ")") {
        if (cur !== "" || args.length === 0) args.push(cur);
        break;
      } else throw new Error(`unexpected ${JSON.stringify(src.slice(i, i + 20))} in ${m[1]}`);
    }
    out[m[1]] = m[2] === "s" ? args[0] : { one: args[0], other: args[1] };
  }
  return out;
}

describe("checks.en.json", () => {
  it("is the Go message table, key for key", () => {
    const go = parseGoCatalog(catalogGo);
    expect(Object.keys(go).length).toBeGreaterThan(100);
    expect(checksEn).toEqual(go);
  });
});
