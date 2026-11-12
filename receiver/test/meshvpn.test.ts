// mesh-vpn took over the tailscale check: roles may set either key, and
// waivers may name either check.
import { describe, expect, it } from "vitest";
import { POLICY_CHECKS, validateRolePolicy } from "../src/roles";
import { en } from "../src/i18n/en";
import { vi } from "../src/i18n/vi";
import { zh } from "../src/i18n/zh";

describe("mesh-vpn", () => {
  const now = new Date("2026-11-10T12:00:00Z");
  it("accepts the old and the new key in a role", () => {
    expect(POLICY_CHECKS).toContain("tailscale");
    expect(POLICY_CHECKS).toContain("mesh-vpn");
    expect(validateRolePolicy({ checks: { tailscale: { enabled: false } } }, now)).toEqual([]);
    expect(validateRolePolicy({ checks: { "mesh-vpn": { allow: ["zerotier"], on_problem: "fail" }, tailscale: {} } }, now)).toEqual([]);
    expect(
      validateRolePolicy(
        { waivers: [{ check: "tailscale", email: "an@domain.com", until: "2026-12-01", reason: "lab" },
          { check: "mesh-vpn", email: "an@domain.com", until: "2026-12-01", reason: "lab" }] },
        now,
      ),
    ).toEqual([]);
  });
  it("keeps titles for old reports and has them for new ones", () => {
    for (const d of [en, vi, zh] as Record<string, unknown>[]) {
      expect(d["checkTitle.tailscale"]).toBeTruthy();
      expect(d["checkTitle.mesh-vpn"]).toBeTruthy();
    }
  });
});
