import { describe, expect, it } from "vitest";
import { alertLine, prune } from "../src/alerts";
import type { Env } from "../src/env";
import { geoFromCf } from "../src/geo";
import { parseLocalIps, parseLocation, validIP } from "../src/report";
import { adminGet, BASE, call, env, REPORT_TOKEN, report } from "./helpers";
import { adminPost } from "./portal";

const ID = "4f1c0000aaaabbbbccccdddd";

const CF = {
  country: "GB",
  region: "England",
  city: "London",
  latitude: "51.50740",
  longitude: "-0.12780",
  timezone: "Europe/London",
  asn: 64500,
  asOrganization: "Example ISP",
};

function postFrom(body: unknown, opts: { ip?: string; cf?: Record<string, unknown>; e?: Partial<Env>; headers?: Record<string, string> } = {}) {
  const headers: Record<string, string> = { "content-type": "application/json", authorization: `Bearer ${REPORT_TOKEN}`, ...opts.headers };
  if (opts.ip) headers["cf-connecting-ip"] = opts.ip;
  const init = { method: "POST", headers, body: JSON.stringify(body), cf: opts.cf } as RequestInit;
  return call(new Request(`${BASE}/report`, init), opts.e);
}

const machine = () =>
  env.DB.prepare("SELECT public_ip, geo, local_ips, device_location, report FROM machines WHERE install_id = ?")
    .bind(ID)
    .first<{ public_ip: string; geo: string; local_ips: string; device_location: string; report: string }>();

const DEVICE = { lat: 51.5, lon: -0.12, accuracy_m: 35, source: "corelocation", time: "2026-11-10T09:00:00Z" };

describe("where reports come from", () => {
  it("records Cloudflare's IP and geolocation, and device-reported data, latest and in history", async () => {
    const res = await postFrom(report({ host: { os: "darwin", arch: "arm64", hostname: "an-mbp", ips: ["192.168.1.20", "fe80::1%en0", "not-an-ip", 7] }, location: DEVICE }), {
      ip: "198.51.100.23",
      cf: CF,
      headers: { "x-forwarded-for": "10.9.9.9", "x-real-ip": "10.8.8.8" },
    });
    expect(res.status).toBe(200);
    const m = (await machine())!;
    expect(m.public_ip).toBe("198.51.100.23");
    expect(JSON.parse(m.geo)).toEqual({
      country: "GB", region: "England", city: "London", lat: 51.5074, lon: -0.1278, timezone: "Europe/London", asn: 64500, as_org: "Example ISP",
    });
    expect(JSON.parse(m.local_ips)).toEqual(["192.168.1.20", "fe80::1%en0"]);
    expect(JSON.parse(m.device_location)).toEqual({ lat: 51.5, lon: -0.12, accuracy_m: 35, source: "corelocation", time: "2026-11-10T09:00:00Z" });
    expect(JSON.parse(m.report).host.ips).toEqual(["192.168.1.20", "fe80::1%en0"]);
    const all = JSON.stringify(m);
    expect(all).not.toContain("10.9.9.9");
    expect(all).not.toContain("10.8.8.8");

    await postFrom(report(), { ip: "203.0.113.5", cf: { ...CF, country: "FR", city: "Paris", region: "Ile-de-France" } });
    const hist = await env.DB.prepare("SELECT ip, geo FROM reports WHERE install_id = ? ORDER BY id").bind(ID).all<{ ip: string; geo: string }>();
    expect(hist.results.map((h) => [h.ip, JSON.parse(h.geo).city])).toEqual([
      ["198.51.100.23", "London"],
      ["203.0.113.5", "Paris"],
    ]);
    // The second report sent no device data, so the latest has none.
    expect((await machine())!.device_location).toBe("");

    const page = await (await adminGet(`/admin/machine/${ID}`)).text();
    expect(page).toContain("203.0.113.5");
    expect(page).toContain("Paris, Ile-de-France, FR");
    expect(page).toContain("https://www.openstreetmap.org/?mlat=51.50740&amp;mlon=-0.12780");
    expect(page).toContain('rel="noreferrer noopener"');
    expect(page).toContain("Device-reported location");
    expect(page).toContain("London, England, GB"); // in history
    const list = await (await adminGet("/admin")).text();
    expect(list).toContain("Paris, Ile-de-France, FR");
    expect(list).toContain("203.0.113.5");
  });

  it("works without Cloudflare (local dev): nothing recorded, report accepted", async () => {
    expect((await postFrom(report())).status).toBe(200);
    const m = (await machine())!;
    expect([m.public_ip, m.geo, m.local_ips, m.device_location]).toEqual(["", "", "", ""]);
    expect(await (await adminGet(`/admin/machine/${ID}`)).text()).toContain("Nothing recorded");
  });

  it("collection can be switched off", async () => {
    const body = report({ host: { os: "darwin", arch: "arm64", hostname: "h", ips: ["10.0.0.2"] }, location: DEVICE });
    await postFrom(body, { ip: "198.51.100.23", cf: CF, e: { STORE_PUBLIC_IP: "off" } });
    let m = (await machine())!;
    expect(m.public_ip).toBe("");
    expect(m.local_ips).toBe("");
    expect(m.report).not.toContain("10.0.0.2");
    expect(m.geo).toContain("London");
    await postFrom(body, { ip: "198.51.100.23", cf: CF, e: { STORE_GEO: "off" } });
    m = (await machine())!;
    expect(m.public_ip).toBe("198.51.100.23");
    expect(m.geo).toBe("");
    expect(m.device_location).toBe("");
    expect(m.report).not.toContain("corelocation");
    const hist = await env.DB.prepare("SELECT ip, geo, device_location FROM reports ORDER BY id").all<Record<string, string>>();
    expect(hist.results[0].ip).toBe("");
    expect(hist.results[1].geo).toBe("");
    expect(hist.results[1].device_location).toBe("");
  });

  it("forget deletes it; pruning clears it from machines silent beyond history", async () => {
    await postFrom(report({ location: DEVICE }), { ip: "198.51.100.23", cf: CF });
    await prune(env, new Date(Date.now() + 400 * 86400000));
    const m = (await machine())!;
    expect([m.public_ip, m.geo, m.device_location]).toEqual(["", "", ""]);
    expect(m.report).not.toContain("corelocation");
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM reports").first<number>("n")).toBe(0);

    await postFrom(report(), { ip: "198.51.100.23", cf: CF });
    await adminPost(`/admin/machine/${ID}/forget`);
    expect(await machine()).toBeNull();
    const left = await env.DB.prepare("SELECT COUNT(*) AS n FROM reports WHERE ip != ''").first<number>("n");
    expect(left).toBe(0);
  });

  it("validates device-reported fields", () => {
    expect(validIP("192.168.1.1")).toBe("192.168.1.1");
    expect(validIP("256.1.1.1")).toBe("");
    expect(validIP("2001:DB8::1")).toBe("2001:db8::1");
    expect(validIP("1::2::3")).toBe("");
    expect(validIP("<script>")).toBe("");
    expect(parseLocalIps(Array.from({ length: 100 }, (_, i) => `10.0.${i}.1`))).toHaveLength(32);
    expect(parseLocalIps("10.0.0.1")).toEqual([]);
    expect(parseLocation({ lat: 91, lon: 0 })).toBeNull();
    expect(parseLocation({ lat: "1", lon: 0 })).toBeNull();
    expect(parseLocation({ lat: 1, lon: 2, accuracy_m: -5, source: "x".repeat(100), time: "nope" })).toEqual({
      lat: 1, lon: 2, accuracy_m: null, source: "x".repeat(32) + "…", time: "",
    });
    expect(geoFromCf(undefined)).toBeNull();
    expect(geoFromCf({ latitude: "x", longitude: "1", country: "US" })).toEqual({ country: "US" });
  });

  it("escapes device-reported values", async () => {
    await postFrom(
      report({ location: { lat: 1, lon: 2, source: "<img src=x onerror=alert(1)>", time: "2026-11-10T09:00:00Z" } }),
      { cf: { city: "<script>alert(1)</script>", country: "<b>" } },
    );
    for (const path of [`/admin/machine/${ID}`, "/admin"]) {
      const body = await (await adminGet(path)).text();
      expect(body).not.toContain("<img");
      expect(body).not.toContain("<script>");
      expect(body).toContain("&lt;script&gt;");
      expect(body).not.toContain(", <b>");
      expect(body).toContain(", &lt;b&gt;");
    }
  });

  it("alerts on a new country only when switched on, without IP or coordinates", async () => {
    const on = { ALERT_NEW_COUNTRY: "on" };
    await postFrom(report(), { ip: "198.51.100.1", cf: CF, e: on });
    await postFrom(report(), { ip: "198.51.100.2", cf: CF, e: on });
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM alerts WHERE kind = 'new_country'").first<number>("n")).toBe(0);
    await postFrom(report(), { ip: "198.51.100.3", cf: { ...CF, country: "FR" } }); // off by default
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM alerts WHERE kind = 'new_country'").first<number>("n")).toBe(0);
    await postFrom(report(), { ip: "198.51.100.4", cf: { ...CF, country: "DE", city: "Berlin" }, e: on });
    const a = await env.DB.prepare("SELECT * FROM alerts WHERE kind = 'new_country'").all<any>();
    expect(a.results).toHaveLength(1);
    const line = alertLine(env, a.results[0]);
    expect(line).toContain("new country `DE`");
    expect(line).toContain("was `FR`");
    expect(a.results[0].detail).not.toContain("198.51.100");
    expect(a.results[0].detail).not.toContain("Berlin");
    // Seen before (in history): no alert.
    await postFrom(report(), { cf: CF, e: on });
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM alerts WHERE kind = 'new_country'").first<number>("n")).toBe(1);
  });

  it("never puts IPs or coordinates in other alerts", async () => {
    await postFrom(report(), { ip: "198.51.100.23", cf: CF });
    const rows = await env.DB.prepare("SELECT detail FROM alerts").all<{ detail: string }>();
    expect(rows.results.length).toBeGreaterThan(0);
    for (const r of rows.results) {
      expect(r.detail).not.toContain("198.51.100.23");
      expect(r.detail).not.toContain("51.5");
    }
  });
});
