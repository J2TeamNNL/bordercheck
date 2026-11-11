// Likely sample keys (checks.secrets.sample_rules): the result's
// likely_samples list, from parsing to every page.
import { describe, expect, it } from "vitest";
import { machineDetail } from "../src/fleet";
import { parseReport } from "../src/report";
import { validateRolePolicy } from "../src/roles";
import { MAX_LIKELY_SAMPLES } from "../src/samples";
import { ADMIN_TOKEN, adminGet, BASE, call, enrolled, env, post, report, result } from "./helpers";

const samples = [
  { path: "~/forks/app/config/default.pem", kind: "Private key", rule: "git-tracked" },
  { path: "~/demo-apps/web/.env", name: "SESSION_SECRET", kind: "Secret-looking variable", rule: "sample-dir" },
  { path: "~/tizen-studio/tools/certificate-generator/certificates/distributor/tizen-distributor-signer.p12", kind: "certificate bundle", rule: "sdk" },
];
const hostile = { path: "~/<script>alert(1)</script>/.env", name: "A&B", kind: "<b>kind</b>", rule: `"><img src=x onerror=alert(1)>` };

describe("likely_samples in a report", () => {
  it("is parsed, bounded and cleaned; anything malformed is dropped", () => {
    const r = parseReport(
      report({}, [
        result("secrets", "warn", {
          likely_samples: [
            ...samples,
            { path: "~/a\n.env", kind: "k", rule: "x".repeat(500), extra: { nested: true } },
            { path: "", rule: "sdk" },
            { path: "~/b", rule: "" },
            { path: 5, rule: "sdk" },
            { path: "~/c", rule: "sdk", name: ["x"] },
            "a string",
            null,
          ],
        }),
      ]),
    );
    const ls = r.results[0].likely_samples!;
    expect(ls).toHaveLength(4);
    expect(ls[0]).toEqual({ ...samples[0], name: "" });
    expect(ls[1]).toEqual(samples[1]);
    expect(ls[3].path).toBe("~/a .env");
    expect(ls[3].rule.length).toBeLessThanOrEqual(33);
    expect(ls[3]).not.toHaveProperty("extra");

    const many = Array.from({ length: 1000 }, (_, i) => ({ path: `~/demo${i}/.env`, kind: "k", rule: "sample-dir" }));
    expect(parseReport(report({}, [result("secrets", "pass", { likely_samples: many })])).results[0].likely_samples).toHaveLength(MAX_LIKELY_SAMPLES);
    expect(parseReport(report({}, [result("secrets", "pass", { likely_samples: { path: "~/x" } })])).results[0].likely_samples).toBeUndefined();
  });

  it("is absent from an older client's report, which parses as before", () => {
    expect(parseReport(report()).results.every((x) => x.likely_samples === undefined)).toBe(true);
  });
});

describe("pages and the API", () => {
  it("the machine page lists them under the secrets check, escaped, with the rule", async () => {
    const an = await enrolled("smp-an@acme.com");
    await post(report({}, [result("secrets", "pass", { likely_samples: [...samples, hostile] })]), { token: an.token });
    const body = await (await adminGet(`/admin/machine/${an.install_id}`)).text();
    expect(body).toContain("Look like sample keys (4)");
    expect(body).toContain("~/demo-apps/web/.env  Secret-looking variable (SESSION_SECRET)");
    expect(body).toContain("in a demo or example folder");
    expect(body).toContain("unchanged in git");
    expect(body).toContain("shipped with an SDK");
    expect(body).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(body).toContain("A&amp;B");
    expect(body).toContain("&lt;b&gt;kind&lt;/b&gt;");
    expect(body).not.toContain("<img src=x");
    expect(body).not.toContain("<b>kind</b>");
    expect(body).not.toContain("<details>"); // short: shown open

    // A long list is folded.
    const bo = await enrolled("smp-bo@acme.com");
    const many = Array.from({ length: 12 }, (_, i) => ({ path: `~/examples/${i}/.env`, kind: "Secret-looking variable", rule: "sample-dir" }));
    await post(report({}, [result("secrets", "warn", { severity: "medium", likely_samples: many })]), { token: bo.token });
    const long = await (await adminGet(`/admin/machine/${bo.install_id}`)).text();
    expect(long).toContain("Look like sample keys (12)");
    expect(long).toContain("<details>");
    expect(long).toContain("Show all 12");

    for (const [lang, want] of [["vi", "Có vẻ là khoá mẫu (4)"], ["zh", "看起来是示例密钥（4）"]]) {
      const res = await call(new Request(`${BASE}/admin/machine/${an.install_id}`, { headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "accept-language": lang } }));
      expect(await res.text()).toContain(want);
    }
  });

  it("the report page shows only the count", async () => {
    const m = await enrolled("smp-cy@acme.com");
    const res = await post(
      report({}, [result("firewall", "fail", { severity: "high" }), result("secrets", "warn", { severity: "medium", likely_samples: [samples[1], hostile] })]),
      { token: m.token },
    );
    const { report_url } = await res.json<{ report_url: string }>();
    const page = await (await call(new Request(report_url.replace("https://bordercheck.example.com", BASE)))).text();
    expect(page).toContain("<b>2</b> look like sample keys");
    expect(page).not.toContain("SESSION_SECRET");
    expect(page).not.toContain("demo-apps");
    expect(page).not.toContain("alert(1)");
    const old = await enrolled("smp-dee@acme.com");
    const r2 = await post(report(), { token: old.token });
    const p2 = await (await call(new Request((await r2.json<{ report_url: string }>()).report_url.replace("https://bordercheck.example.com", BASE)))).text();
    expect(p2).not.toContain("sample keys");
  });

  it("MCP/API machine detail: the count always, the items with evidence, under untrusted", async () => {
    const m = await enrolled("smp-ed@acme.com");
    await post(report({}, [result("secrets", "pass", { likely_samples: [samples[1], hostile] })]), { token: m.token });
    const plain = await machineDetail(env, m.install_id, {}, new Date());
    const d = plain.ok ? (plain.data as Record<string, unknown>) : {};
    expect(d.likely_samples_count).toBe(2);
    expect(d.likely_samples).toBeUndefined();
    expect(JSON.stringify(d)).not.toContain("SESSION_SECRET");

    const full = await machineDetail(env, m.install_id, { evidence: true }, new Date());
    const items = (full.ok ? (full.data as Record<string, unknown>) : {}).likely_samples as { check_id: string; rule: string; untrusted: Record<string, string> }[];
    expect(items).toHaveLength(2);
    expect(items[0]).toEqual({ check_id: "secrets", rule: "sample-dir", untrusted: { path: "~/demo-apps/web/.env", name: "SESSION_SECRET", kind: "Secret-looking variable" } });
    expect(items[1].rule).toBe("other");
    expect(items[1].untrusted.rule).toContain("img src");

    const old = await enrolled("smp-fay@acme.com");
    await post(report(), { token: old.token });
    const o = await machineDetail(env, old.install_id, { evidence: true }, new Date());
    expect((o.ok ? (o.data as Record<string, unknown>) : {}).likely_samples_count).toBe(0);
  });
});

describe("role policies", () => {
  it("accept sample_rules on secrets as a list of known rules", () => {
    const now = new Date();
    expect(validateRolePolicy({ checks: { secrets: { sample_rules: [] } } }, now)).toEqual([]);
    expect(validateRolePolicy({ checks: { secrets: { sample_rules: ["git-tracked", "sdk", "sample-dir"] } } }, now)).toEqual([]);
    expect(validateRolePolicy({ checks: { secrets: { sample_rules: ["tests"] } } }, now).map((m) => m.key)).toEqual(["v.notOneOf"]);
    expect(validateRolePolicy({ checks: { secrets: { sample_rules: "sdk" } } }, now).map((m) => m.key)).toEqual(["v.strList"]);
  });
});
