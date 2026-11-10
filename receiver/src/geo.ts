// Where a report came from, as Cloudflare saw the connection: the public IP
// (CF-Connecting-IP, which Cloudflare sets and overwrites) and the IP-based
// geolocation in request.cf. Nothing else in the request is trusted for this;
// the report's own host.ips and location are kept separately and labelled as
// device-reported. Under local dev there is no request.cf and no
// CF-Connecting-IP, so everything here is optional.

import { str, validIP } from "./report";

export interface Geo {
  country?: string;
  region?: string;
  city?: string;
  lat?: number;
  lon?: number;
  timezone?: string;
  asn?: number;
  as_org?: string;
}

function coord(v: unknown, max: number): number | undefined {
  const n = typeof v === "number" ? v : typeof v === "string" && v.trim() !== "" ? Number(v) : NaN;
  return Number.isFinite(n) && Math.abs(n) <= max ? n : undefined;
}

export function geoFromCf(cf: unknown): Geo | null {
  if (!cf || typeof cf !== "object") return null;
  const c = cf as Record<string, unknown>;
  const g: Geo = {};
  const s = (k: string, max: number) => {
    const v = str(c[k], max).replace(/[\n\t]/g, " ").trim();
    return v || undefined;
  };
  g.country = s("country", 8);
  g.region = s("region", 100);
  g.city = s("city", 100);
  g.lat = coord(c.latitude, 90);
  g.lon = coord(c.longitude, 180);
  if (g.lat === undefined || g.lon === undefined) g.lat = g.lon = undefined;
  g.timezone = s("timezone", 64);
  g.asn = typeof c.asn === "number" && Number.isInteger(c.asn) && c.asn > 0 ? c.asn : undefined;
  g.as_org = s("asOrganization", 200);
  const clean = Object.fromEntries(Object.entries(g).filter(([, v]) => v !== undefined)) as Geo;
  return Object.keys(clean).length ? clean : null;
}

export function publicIP(req: Request): string {
  return validIP(req.headers.get("cf-connecting-ip") ?? "");
}

export function parseGeo(s: string | null | undefined): Geo | null {
  if (!s) return null;
  try {
    const v = JSON.parse(s);
    return v && typeof v === "object" ? (v as Geo) : null;
  } catch {
    return null;
  }
}

// place is a short "City, Region, CC" for tables.
export function place(g: Geo | null): string {
  if (!g) return "";
  return [g.city, g.region && g.region !== g.city ? g.region : undefined, g.country].filter(Boolean).join(", ");
}

// mapLink is an OpenStreetMap link carrying only the coordinates. It is a
// plain link the admin chooses to click; pages load nothing from it.
export function mapLink(lat: number, lon: number): string {
  const la = lat.toFixed(5);
  const lo = lon.toFixed(5);
  return `https://www.openstreetmap.org/?mlat=${la}&mlon=${lo}#map=12/${la}/${lo}`;
}
