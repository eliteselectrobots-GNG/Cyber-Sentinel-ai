import type { EmailScanResult } from "./email-scanner";
import type { StoredScan } from "./store";

export type IoC = {
  type: "IP" | "Domain" | "URL" | "Email";
  value: string;
  source: string;
};

const urlPattern = /\bhttps?:\/\/[^\s<>"']+/gi;
const domainPattern = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
const ipPattern = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const emailPattern = /\b[\w.!#$%&'*+/=?^`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b/gi;

/** Tokens that appear in SPF/DKIM/DMARC result grammar, not real domains. */
const pseudoDomainDenylist = new Set(["smtp.mailfrom", "smtp.helo", "mailfrom", "helo", "header.from", "envelope.from"]);

function normalizeUrl(raw: string): string {
  return raw.replace(/[),.;]+$/, "");
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return "";
  }
}

/**
 * Extract indicators of compromise straight from the evidence — body text,
 * routing headers, and the reconstructed hop list.
 */
export function extractIocs(raw: string, result: EmailScanResult): IoC[] {
  const iocs: IoC[] = [];
  const seen = new Set<string>();

  const push = (type: IoC["type"], value: string, source: string) => {
    const key = `${type}:${value.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    iocs.push({ type, value, source });
  };

  // URLs from the body (highest signal)
  for (const match of raw.match(urlPattern) ?? []) {
    const url = normalizeUrl(match);
    push("URL", url, "Message body");
    const host = hostOf(url);
    if (host) push("Domain", host, "Extracted URL");
  }

  // Emails visible in headers and body
  const emailCandidates = new Set<string>();
  if (result.senderAddress.includes("@")) emailCandidates.add(result.senderAddress.toLowerCase());
  for (const header of ["reply-to", "return-path"]) {
    const value = header === "reply-to" ? result.replyTo : result.returnPath;
    const match = value.match(emailPattern);
    if (match) emailCandidates.add(match[0].toLowerCase());
  }
  for (const match of raw.match(emailPattern) ?? []) {
    emailCandidates.add(match.toLowerCase());
  }
  for (const email of emailCandidates) push("Email", email, "Headers");

  // Domains from the message (deduped against extracted email domains)
  const emailDomains = new Set([...emailCandidates].map((email) => email.split("@")[1]));
  const hostCandidates = new Set<string>();
  for (const match of raw.match(domainPattern) ?? []) {
    const domain = match.toLowerCase();
    if (emailDomains.has(domain)) continue;
    hostCandidates.add(domain);
  }
  for (const domain of hostCandidates) {
    if (pseudoDomainDenylist.has(domain)) continue;
    push("Domain", domain, "Headers / body");
  }

  // IPs from Received hops
  for (const hop of result.hops) {
    if (hop.ip !== "Not disclosed") push("IP", hop.ip, "Received header");
  }

  return iocs;
}

export function iocTotals(iocs: IoC[]): Record<IoC["type"], number> {
  return {
    IP: iocs.filter((ioc) => ioc.type === "IP").length,
    Domain: iocs.filter((ioc) => ioc.type === "Domain").length,
    URL: iocs.filter((ioc) => ioc.type === "URL").length,
    Email: iocs.filter((ioc) => ioc.type === "Email").length,
  };
}

/** Cases sharing a sender domain, reply domain, or origin IP with the given case. */
export function relatedCases(scan: StoredScan, all: StoredScan[]): StoredScan[] {
  const senderDomain = scan.result.senderAddress.split("@")[1]?.toLowerCase();
  const replyDomain = scan.result.replyTo.includes("@") ? scan.result.replyTo.split("@")[1]?.toLowerCase() : null;
  const originIp = scan.result.hops.find((hop) => hop.status === "origin")?.ip;

  return all.filter((candidate) => {
    if (candidate.id === scan.id) return false;
    const candidateSender = candidate.result.senderAddress.split("@")[1]?.toLowerCase();
    const candidateReply = candidate.result.replyTo.includes("@") ? candidate.result.replyTo.split("@")[1]?.toLowerCase() : null;
    const candidateOrigin = candidate.result.hops.find((hop) => hop.status === "origin")?.ip;
    return (senderDomain && senderDomain === candidateSender) || (replyDomain && replyDomain === candidateReply) || (originIp && originIp === candidateOrigin);
  });
}
