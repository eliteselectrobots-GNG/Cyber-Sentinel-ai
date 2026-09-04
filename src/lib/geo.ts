/**
 * IP geolocation enrichment.
 *
 * Resolves IPv4 addresses to city-level location, ISP, and ASN via
 * ipwho.is (free, HTTPS, CORS-enabled, no API key). Results are cached
 * for the session. Lookups are best-effort: when the network is
 * unreachable or an address is reserved, the UI degrades honestly to
 * "location unavailable" — nothing is fabricated for real scans.
 *
 * Precision note: IP geolocation is city-level at best ("New Delhi,
 * Delhi, India"), never street-level.
 */

export type GeoInfo = {
  ip: string;
  country: string;
  countryCode: string;
  region: string;
  city: string;
  lat: number;
  lon: number;
  isp: string;
  org: string;
  asn: string;
  /** "live" = resolved from a real lookup; "demo" = part of the demo dataset. */
  source: "live" | "demo";
};

const cache = new Map<string, GeoInfo | null>();

/** Reserved / private / documentation ranges are never worth a lookup. */
export function isPublicIpv4(ip: string): boolean {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return false;
  const octets = ip.split(".").map(Number);
  if (octets.some((octet) => octet > 255)) return false;
  const a = octets[0] ?? 0;
  const b = octets[1] ?? 0;
  const c = octets[2] ?? 0;
  if (a === 0) return false; // "this network"
  if (a === 10) return false; // RFC1918
  if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
  if (a === 127) return false; // loopback
  if (a === 169 && b === 254) return false; // link-local
  if (a === 172 && b >= 16 && b <= 31) return false; // RFC1918
  if (a === 192 && b === 168) return false; // RFC1918
  if (a === 192 && b === 0 && c === 2) return false; // TEST-NET-1
  if (a === 198 && b === 51 && c === 100) return false; // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return false; // TEST-NET-3
  if (a === 198 && b === 18) return false; // benchmarking
  if (a >= 224) return false; // multicast / reserved
  return true;
}

export async function lookupGeo(ip: string): Promise<GeoInfo | null> {
  if (cache.has(ip)) return cache.get(ip) ?? null;
  if (!isPublicIpv4(ip)) {
    cache.set(ip, null);
    return null;
  }
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 6000);
    const response = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, { signal: controller.signal });
    clearTimeout(timer);
    if (!response.ok) throw new Error(`Geo lookup failed: ${response.status}`);
    const data = (await response.json()) as {
      success?: boolean;
      country?: string;
      country_code?: string;
      region?: string;
      city?: string;
      latitude?: number;
      longitude?: number;
      connection?: { asn?: number; org?: string; isp?: string };
    };
    if (!data || data.success === false) {
      cache.set(ip, null);
      return null;
    }
    const info: GeoInfo = {
      ip,
      country: data.country ?? "Unknown",
      countryCode: data.country_code ?? "",
      region: data.region ?? "",
      city: data.city ?? "",
      lat: typeof data.latitude === "number" ? data.latitude : 0,
      lon: typeof data.longitude === "number" ? data.longitude : 0,
      isp: data.connection?.isp ?? "",
      org: data.connection?.org ?? "",
      asn: data.connection?.asn ? `AS${data.connection.asn}` : "",
      source: "live",
    };
    cache.set(ip, info);
    return info;
  } catch {
    cache.set(ip, null);
    return null;
  }
}

/**
 * Looks up a list of IPs (deduped, public-only, capped) sequentially so
 * the free tier is treated politely. Returns only the successful hits.
 */
export async function enrichIps(ips: string[]): Promise<Record<string, GeoInfo>> {
  const unique = [...new Set(ips.map((ip) => ip.trim()).filter(Boolean))].filter(isPublicIpv4).slice(0, 10);
  const found: Record<string, GeoInfo> = {};
  for (const ip of unique) {
    const info = await lookupGeo(ip);
    if (info) found[info.ip] = info;
    await new Promise((resolve) => setTimeout(resolve, 120));
  }
  return found;
}

/** Country code → flag emoji, or a globe when the code is unknown. */
export function flagEmoji(countryCode: string): string {
  if (!countryCode || countryCode.length !== 2) return "🌐";
  const upper = countryCode.toUpperCase();
  if (!/[A-Z]{2}/.test(upper)) return "🌐";
  return String.fromCodePoint(...[...upper].map((char) => 127397 + char.charCodeAt(0)));
}

/** "New Delhi, Delhi, India" — deduped, city-level label. */
export function locationLabel(geo: GeoInfo): string {
  const parts = [geo.city, geo.region, geo.country].filter((part) => part && part !== "Unknown");
  const unique: string[] = [];
  for (const part of parts) if (!unique.includes(part)) unique.push(part);
  return unique.join(", ") || "Location unknown";
}

/** Great-circle distance between two coordinates in kilometers. */
export function distanceKm(a: { lat: number; lon: number }, b: { lat: number; lon: number }): number {
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const dLat = toRad(b.lat - a.lat);
  const dLon = toRad(b.lon - a.lon);
  const s =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(a.lat)) * Math.cos(toRad(b.lat)) * Math.sin(dLon / 2) ** 2;
  return Math.round(2 * 6371 * Math.asin(Math.min(1, Math.sqrt(s))));
}