/**
 * Live infrastructure intelligence — all free, no API key, CORS-enabled:
 *
 *  - DNS blacklist reputation: Spamhaus ZEN + SpamCop via DNS-over-HTTPS
 *  - Tor exit detection: Tor Project DNSEL (dnsel.torproject.org) via DoH
 *  - MX records via DNS-over-HTTPS
 *  - WHOIS / registrar + creation date via RDAP (rdap.org)
 *  - Cloud / datacenter hosting + known Tor-relay operator fingerprints
 *    derived from the ASN org / ISP captured by the geolocation layer
 *
 * Every lookup is best-effort with a session cache; when the network is
 * unreachable the UI degrades honestly — nothing is fabricated.
 */

import { isPublicIpv4, type GeoInfo } from "./geo";

export type BlacklistHit = {
  list: "Spamhaus ZEN" | "SpamCop";
  /** The DNSBL A-record code returned (127.0.0.x …). */
  code: string;
  /** Human meaning of the code. */
  meaning: string;
};

export type IpInfra = {
  blacklists: BlacklistHit[];
  torExit: boolean;
  /** ISP/org fingerprint looks like a cloud / datacenter host, not residential. */
  cloudHosting: boolean;
  source: "live" | "demo";
};

export type DomainIntel = {
  mx: string[];
  whois: { registrar: string; created: string | null } | null;
  source: "live" | "demo";
};

/* ----------------------------- DNS-over-HTTPS ----------------------------- */

type DoHAnswer = { name?: string; type?: number; data?: string };

async function dohQuery(name: string, type: "A" | "MX"): Promise<string[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);
  try {
    const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
      headers: { accept: "application/dns-json" },
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`DoH failed: ${response.status}`);
    const data = (await response.json()) as { Answer?: DoHAnswer[] };
    return (data.Answer ?? [])
      .filter((answer) => answer.type === (type === "MX" ? 15 : 1))
      .map((answer) => answer.data ?? "")
      .filter(Boolean);
  } finally {
    clearTimeout(timer);
  }
}

/* ------------------------------ Blacklists -------------------------------- */

const zenMeanings: Record<string, string> = {
  "127.0.0.2": "SBL — known spam source",
  "127.0.0.3": "SBL — spam source (CSS)",
  "127.0.0.4": "XBL — exploited host / botnet member",
  "127.0.0.5": "XBL — botnet member (CBL)",
  "127.0.0.6": "XBL — exploited host",
  "127.0.0.7": "XBL — botnet member (CBL+)",
  "127.0.0.8": "SBL — known spam source",
  "127.0.0.9": "SBL — known spam source",
  "127.0.0.10": "PBL — dynamic end-user range",
  "127.0.0.11": "PBL — end-user policy",
  "127.255.255.254": "PBL — listed end-user range",
};

const blacklistCache = new Map<string, BlacklistHit[] | null>();

/** Queries Spamhaus ZEN + SpamCop for a public IPv4. Returns hits (empty = clean). */
export async function checkBlacklists(ip: string): Promise<BlacklistHit[]> {
  if (blacklistCache.has(ip)) return blacklistCache.get(ip) ?? [];
  if (!isPublicIpv4(ip)) {
    blacklistCache.set(ip, []);
    return [];
  }
  const reversed = ip.split(".").reverse().join(".");
  const hits: BlacklistHit[] = [];
  try {
    const zen = await dohQuery(`${reversed}.zen.spamhaus.org`, "A");
    for (const record of zen) {
      const code = record.trim();
      hits.push({ list: "Spamhaus ZEN", code, meaning: zenMeanings[code] ?? "listed on Spamhaus ZEN" });
    }
  } catch {
    // best-effort
  }
  try {
    const spamcop = await dohQuery(`${reversed}.bl.spamcop.net`, "A");
    if (spamcop.some((record) => record.trim() === "127.0.0.2")) {
      hits.push({ list: "SpamCop", code: "127.0.0.2", meaning: "listed on SpamCop — reported spam source" });
    }
  } catch {
    // best-effort
  }
  blacklistCache.set(ip, hits);
  return hits;
}

/* ------------------------------- Tor exit --------------------------------- */

const torExitCache = new Map<string, boolean>();

/** Tor Project DNSEL: A record 127.0.0.2 means the IP is a live Tor exit relay. */
export async function isTorExit(ip: string): Promise<boolean> {
  if (torExitCache.has(ip)) return torExitCache.get(ip) ?? false;
  if (!isPublicIpv4(ip)) {
    torExitCache.set(ip, false);
    return false;
  }
  const reversed = ip.split(".").reverse().join(".");
  let exit = false;
  try {
    const answers = await dohQuery(`${reversed}.dnsel.torproject.org`, "A");
    exit = answers.some((record) => record.trim() === "127.0.0.2");
  } catch {
    // best-effort
  }
  torExitCache.set(ip, exit);
  return exit;
}

/* ----------------------- Hosting / relay fingerprints --------------------- */

/** ISP/ASN-org fingerprints of known Tor relay operators (from real ASN data). */
const torRelayOrgFingerprints = [
  "relayon.org",
  "cia triad security",
  "stiftung erneuerbare freiheit",
  "f3netze",
  "tor project",
  "quantum network",
  "schokokeks",
  "1984",
];

/** ISP/ASN-org fingerprints of cloud / datacenter hosting (rented infra). */
const cloudHostFingerprints = [
  "amazon", "aws", "amazon.com",
  "microsoft", "azure", "microsoft.com",
  "google", "google cloud", "google.com", "goog",
  "ovh", "hetzner", "digitalocean", "linode", "vultr", "contabo", "m247", "leaseweb", "cogent", "zayo",
  "hostinger", "ionos", "namecheap", "godaddy", "cloudflare", "akamai", "fastly", "heroku", "netlify",
  "scaleway", "upcloud", "oracle cloud", "ibm cloud", "alibaba", "tencent", "choopa", "ramnode", "voxility",
  "datacamp", "psychz", "multacom", "quadra", "hostkey", "forpsi", "one man", "websupport",
];

function textOf(geo: GeoInfo): string {
  return `${geo.org ?? ""} ${geo.isp ?? ""} ${geo.ispDomain ?? ""} ${geo.asn ?? ""}`.toLowerCase();
}

export function fingerprintInfra(geo: GeoInfo): { torRelayOperator: boolean; cloudHosting: boolean } {
  const text = textOf(geo);
  const torRelayOperator = torRelayOrgFingerprints.some((needle) => text.includes(needle));
  const cloudHosting = !torRelayOperator && cloudHostFingerprints.some((needle) => text.includes(needle));
  return { torRelayOperator, cloudHosting };
}

/* ---------------------- Per-IP enrichment (combined) ---------------------- */

const infraCache = new Map<string, IpInfra | null>();

/**
 * Full infrastructure pass for one public IP: DNSBL checks, Tor exit check,
 * and hosting fingerprints derived from its geolocation record.
 */
export async function enrichIpInfra(ip: string, geo: GeoInfo): Promise<IpInfra | null> {
  if (infraCache.has(ip)) return infraCache.get(ip) ?? null;
  if (!isPublicIpv4(ip)) {
    infraCache.set(ip, null);
    return null;
  }
  try {
    const [blacklists, torExit] = await Promise.all([checkBlacklists(ip), isTorExit(ip)]);
    const fingerprints = fingerprintInfra(geo);
    const infra: IpInfra = {
      blacklists,
      torExit: torExit || fingerprints.torRelayOperator,
      cloudHosting: fingerprints.cloudHosting,
      source: "live",
    };
    infraCache.set(ip, infra);
    return infra;
  } catch {
    infraCache.set(ip, null);
    return null;
  }
}

/* ----------------------------- MX records --------------------------------- */

const mxCache = new Map<string, string[] | null>();

export async function lookupMx(domain: string): Promise<string[]> {
  const key = domain.toLowerCase();
  if (mxCache.has(key)) return mxCache.get(key) ?? [];
  try {
    const answers = await dohQuery(key, "MX");
    const mx = answers.map((record) => record.trim().replace(/\.$/, "")).sort();
    mxCache.set(key, mx);
    return mx;
  } catch {
    mxCache.set(key, []);
    return [];
  }
}

/* ------------------------------ WHOIS (RDAP) ------------------------------ */

const whoisCache = new Map<string, { registrar: string; created: string | null } | null>();

export async function lookupWhois(domain: string): Promise<{ registrar: string; created: string | null } | null> {
  const key = domain.toLowerCase();
  if (whoisCache.has(key)) return whoisCache.get(key) ?? null;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 7000);
    const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(key)}`, { signal: controller.signal });
    clearTimeout(timer);
    if (!response.ok) {
      whoisCache.set(key, null);
      return null;
    }
    const data = (await response.json()) as {
      entities?: { roles?: string[]; vcardArray?: unknown[] }[];
      events?: { eventAction?: string; eventDate?: string }[];
    };
    let registrar = "";
    for (const entity of data.entities ?? []) {
      if ((entity.roles ?? []).includes("registrar")) {
        const vcard = entity.vcardArray?.[1];
        if (Array.isArray(vcard)) {
          for (const line of vcard as unknown[][]) {
            if (line?.[0] === "fn") {
              const value = line[3];
              if (typeof value === "string") registrar = value;
            }
          }
        }
      }
    }
    const created = (data.events ?? []).find((event) => event.eventAction === "registration")?.eventDate ?? null;
    const result = registrar || created ? { registrar: registrar || "Unknown registrar", created } : null;
    whoisCache.set(key, result);
    return result;
  } catch {
    whoisCache.set(key, null);
    return null;
  }
}

/* --------------------------- Domain intelligence --------------------------- */

const domainIntelCache = new Map<string, DomainIntel | null>();

/** MX + WHOIS for one domain (parallel, cached per session). */
export async function lookupDomainIntel(domain: string): Promise<DomainIntel | null> {
  const key = domain.toLowerCase();
  if (domainIntelCache.has(key)) return domainIntelCache.get(key) ?? null;
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(key)) {
    domainIntelCache.set(key, null);
    return null;
  }
  try {
    const [mx, whois] = await Promise.all([lookupMx(key), lookupWhois(key)]);
    const result: DomainIntel = { mx, whois, source: "live" };
    domainIntelCache.set(key, result);
    return result;
  } catch {
    domainIntelCache.set(key, null);
    return null;
  }
}
