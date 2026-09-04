import { scanEmail } from "./email-scanner";
import { toStoredScan, type StoredScan } from "./store";
import type { GeoInfo } from "./geo";
import type { DomainIntel, IpInfra } from "./infra";

/**
 * Demo dataset. Every entry is a realistic raw message that is pushed
 * through the REAL scan engine — nothing here bypasses analysis. Entries
 * are clearly marked as demo evidence in the UI.
 */

const demoMessages: { subject?: string; raw: string; minutesAgo: number }[] = [
  {
    // reply-to mismatch + urgency + payment language
    raw: `From: Finance Desk <finance@acme-corp.example>
To: accounts@northstar.example
Reply-To: payments-team@acme-corp-updates.example
Subject: URGENT: Updated bank details — action required
Date: Sun, 30 Aug 2026 09:41:12 +0530
Return-Path: <bounce@acme-corp.example>
Authentication-Results: northstar.example; spf=fail smtp.mailfrom=acme-corp.example; dkim=none
Received: from relay.acme-corp-updates.example (185.220.101.4) by mx2.example.net
Received: from unknown (203.0.113.44) by relay.acme-corp-updates.example

Please process the attached invoice immediately and confirm the new beneficiary account before 12:00. Reply to payments-team@acme-corp-updates.example.`,
    minutesAgo: 6,
  },
  {
    // mailbox quota / credential harvesting
    raw: `From: IT Service Desk <support@mail-northstar-secure.example>
To: r.kapoor@northstar.example
Subject: Your mailbox quota has been exceeded — verify now
Date: Sun, 30 Aug 2026 08:56:00 +0530
Return-Path: <bounce@mail-northstar-secure.example>
Received: from smtp-02.mail-northstar-secure.example (198.51.100.17) by mx1.example.net

Your mailbox has exceeded its storage quota. Sign in at the secure portal within 24 hours to keep your account active, otherwise messages will be suspended. Verify your identity with your corporate password.`,
    minutesAgo: 33,
  },
  {
    // lookalike-ish domain, softfail auth, urgency
    raw: `From: NorthStar Bank <alerts@northstarbank.example>
Reply-To: noreply@northstarbank.example
Subject: Final notice: unusual sign-in attempt on your account
Date: Sun, 30 Aug 2026 07:12:45 +0530
Return-Path: <bounce@northstarbank.example>
Authentication-Results: mx1.example.net; spf=softfail smtp.mailfrom=northstarbank.example
Received: from mailer.northstarbank-verify.example (203.0.113.88) by mx1.example.net

Dear customer, we detected an unusual sign-in from a new device. If this was not you, confirm your details immediately to prevent account suspension. Click here to review the activity: https://northstarbank-verify.example/secure/login`,
    minutesAgo: 61,
  },
  {
    // benign control sample
    raw: `From: R. Kapoor <r.kapoor@northstar.example>
To: procurement@northstar.example
Cc: finance@northstar.example
Subject: Re: acquisition materials — draft attached
Date: Sun, 30 Aug 2026 08:32:10 +0530
Return-Path: <r.kapoor@northstar.example>
Received: from smtp-01.northstar.example (192.0.2.25) by mx1.northstar.example

Hi team, attaching the draft deck from yesterday's review. Please share feedback by EOD so we can finalize before the vendor call on Wednesday. Thanks!`,
    minutesAgo: 72,
  },
];

/**
 * Demo geolocation. The demo messages use reserved documentation-range IPs
 * (which no lookup can resolve), so the dataset carries realistic city-level
 * coordinates tagged `demo` — consistent with the demo content itself.
 */
/**
 * Demo infrastructure intelligence — tagged `demo` like the geolocation it
 * accompanies, because the demo messages use reserved documentation-range
 * IPs and .example domains that real lookups cannot resolve.
 */
const demoInfra: Record<string, IpInfra> = {
  // Phishing origin (Old Delhi broadband): on Spamhaus ZEN
  "203.0.113.44": { blacklists: [{ list: "Spamhaus ZEN", code: "127.0.0.2", meaning: "SBL — known spam source" }], torExit: false, cloudHosting: false, source: "demo" },
  // Relay (Berlin): live Tor exit relay operator
  "185.220.101.4": { blacklists: [{ list: "Spamhaus ZEN", code: "127.255.255.254", meaning: "PBL — listed end-user range" }], torExit: true, cloudHosting: false, source: "demo" },
  // Quota phish (Mumbai data center)
  "198.51.100.17": { blacklists: [], torExit: false, cloudHosting: true, source: "demo" },
  // Bank phish (Bengaluru mobile line)
  "203.0.113.88": { blacklists: [], torExit: false, cloudHosting: false, source: "demo" },
  // Benign control (Gurugram corporate gateway)
  "192.0.2.25": { blacklists: [], torExit: false, cloudHosting: false, source: "demo" },
};

/** Demo MX / WHOIS records for the fictional domains used by the demo messages. */
const demoDomainIntel: Record<string, DomainIntel> = {
  "northstar.example": { mx: ["10 mx1.northstar.example", "20 mx2.northstar.example"], whois: { registrar: "Demo Registrar Ltd.", created: "2019-06-01T00:00:00Z" }, source: "demo" },
  "northstarbank.example": { mx: ["10 mx1.northstarbank.example"], whois: { registrar: "Demo Registrar Ltd.", created: "2024-02-14T00:00:00Z" }, source: "demo" },
};

const demoGeo: Record<string, GeoInfo> = {
  // Phishing origin: a consumer broadband line in Old Delhi
  "203.0.113.44": { ip: "203.0.113.44", country: "India", countryCode: "IN", region: "Delhi", city: "New Delhi", lat: 28.6139, lon: 77.209, isp: "Residential broadband", org: "Example ISP", asn: "AS132165", source: "demo" },
  // Relay: a Tor exit node in Berlin
  "185.220.101.4": { ip: "185.220.101.4", country: "Germany", countryCode: "DE", region: "Berlin", city: "Berlin", lat: 52.52, lon: 13.405, isp: "Tor exit relay", org: "Tor network", asn: "", source: "demo" },
  // Quota phish from a Mumbai data center
  "198.51.100.17": { ip: "198.51.100.17", country: "India", countryCode: "IN", region: "Maharashtra", city: "Mumbai", lat: 19.076, lon: 72.8777, isp: "Data-center hosting", org: "Example hosting", asn: "AS47583", source: "demo" },
  // Bank phish from a Bengaluru mobile line
  "203.0.113.88": { ip: "203.0.113.88", country: "India", countryCode: "IN", region: "Karnataka", city: "Bengaluru", lat: 12.9716, lon: 77.5946, isp: "Mobile broadband", org: "Example mobile operator", asn: "AS45609", source: "demo" },
  // Benign control: the company's own mail gateway
  "192.0.2.25": { ip: "192.0.2.25", country: "India", countryCode: "IN", region: "Haryana", city: "Gurugram", lat: 28.4595, lon: 77.0266, isp: "Corporate mail gateway", org: "NorthStar example", asn: "AS37963", source: "demo" },
};

export async function buildDemoDataset(): Promise<StoredScan[]> {
  const now = Date.now();
  const scans: StoredScan[] = [];
  for (const message of demoMessages) {
    const result = await scanEmail(message.raw);
    const geo: Record<string, GeoInfo> = {};
    for (const hop of result.hops) {
      const info = demoGeo[hop.ip];
      if (info) geo[hop.ip] = info;
    }
    const scan = toStoredScan(message.raw, result, now - message.minutesAgo * 60_000, true, undefined, geo);
    const infra: Record<string, IpInfra> = {};
    for (const hop of result.hops) {
      const info = demoInfra[hop.ip];
      if (info) infra[hop.ip] = info;
    }
    if (Object.keys(infra).length > 0) scan.infra = infra;
    const intel: Record<string, DomainIntel> = {};
    const senderDomain = result.senderAddress.split("@")[1]?.toLowerCase() ?? "";
    const replyDomain = result.replyTo.includes("@") ? result.replyTo.split("@")[1]?.toLowerCase() ?? "" : "";
    for (const domain of [senderDomain, replyDomain]) {
      const record = demoDomainIntel[domain];
      if (record) intel[domain] = record;
    }
    if (Object.keys(intel).length > 0) scan.domainIntel = intel;
    scans.push(scan);
  }
  return scans.sort((a, b) => b.scannedAt - a.scannedAt);
}
