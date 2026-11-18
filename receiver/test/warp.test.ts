import { describe, expect, it } from "vitest";
import { atLeast, clientVersion, composePolicy, WARP_SINCE, validateRolePolicy } from "../src/roles";
import { BASE, call } from "./helpers";
import { enrolled, makeRole } from "./portal";

const WARP = { enabled: true, team: "senprints", posture_only: true };

describe("warp check", () => {
  it("reads the client's version from its User-Agent", () => {
    expect(clientVersion("bordercheck/v0.5.21")).toEqual([0, 5, 21]);
    expect(clientVersion("bordercheck/0.6.0")).toEqual([0, 6, 0]);
    expect(clientVersion("bordercheck/dev")).toBe("new");
    expect(clientVersion("Go-http-client/1.1")).toBeNull();
    expect(clientVersion(null)).toBeNull();
    expect(atLeast([0, 5, 21], WARP_SINCE)).toBe(true);
    expect(atLeast([0, 5, 20], WARP_SINCE)).toBe(false);
    expect(atLeast([0, 6, 0], WARP_SINCE)).toBe(true);
    expect(atLeast([1, 0, 0], WARP_SINCE)).toBe(true);
    expect(atLeast(null, WARP_SINCE)).toBe(false);
  });

  it("is left out, with its waivers, of the policy an older client gets", () => {
    const now = new Date("2026-11-18T12:00:00Z");
    const role = {
      checks: { warp: WARP, docker: { enabled: false } },
      waivers: [{ check: "warp", email: "an@domain.com", until: "2026-12-01", reason: "no client yet" }],
    };
    const m = { install_id: "abc", email: "an@domain.com" };
    const own = [{ check_id: "warp", until: "2026-12-01", reason: "trip" }];
    const old = composePolicy(role, "Dev", m, own, BASE, now, null);
    expect(old.checks).toEqual({ docker: { enabled: false } });
    expect(old.waivers).toEqual([]);
    const fresh = composePolicy(role, "Dev", m, own, BASE, now, [0, 5, 21]);
    expect((fresh.checks as Record<string, unknown>).warp).toEqual(WARP);
    expect((fresh.waivers as unknown[]).length).toBe(2);
    expect((role.checks as Record<string, unknown>).warp).toEqual(WARP); // the role itself is untouched
  });

  it("is served by version over /policy", async () => {
    await makeRole("Gated", { checks: { warp: WARP } });
    const { token } = await enrolled("warp@domain.com", "Gated");
    const get = (ua?: string) =>
      call(new Request(`${BASE}/policy`, { headers: { authorization: `Bearer ${token}`, ...(ua ? { "user-agent": ua } : {}) } }))
        .then((r) => r.json<{ checks?: Record<string, unknown> }>());
    expect((await get()).checks?.warp).toBeUndefined();
    expect((await get("bordercheck/v0.5.20")).checks?.warp).toBeUndefined();
    expect((await get("bordercheck/v0.5.21")).checks?.warp).toEqual(WARP);
  });

  it("needs a team name when it is on", () => {
    const at = new Date();
    const v = (warp: unknown) => validateRolePolicy({ checks: { warp } }, at).map((e) => e.key);
    expect(v(WARP)).toEqual([]);
    expect(v({ enabled: false, team: "", posture_only: false })).toEqual([]);
    expect(v({ enabled: true })).toEqual(["v.warpTeam"]);
    expect(v({ enabled: true, team: "senprints.cloudflareaccess.com" })).toEqual(["v.warpTeam"]);
    expect(v({ team: "-bad" })).toEqual(["v.warpTeam"]);
    expect(v({ enabled: true, team: "senprints", posture_only: "yes" })).toEqual(["v.mustBool"]);
  });
});
