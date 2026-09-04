import { z } from "zod";

const emailInputSchema = z
  .string()
  .trim()
  .min(1, "Add an email or raw headers to begin the scan.")
  .max(1_000_000, "The scan input must be smaller than 1 MB.");

export type ScanFinding = {
  label: string;
  detail: string;
  severity: "critical" | "high" | "medium" | "info";
};

export type ScanHop = {
  label: string;
  detail: string;
  ip: string;
  status: "origin" | "relay" | "destination";
};

export type EmailScanResult = {
  id: string;
  subject: string;
  sender: string;
  senderAddress: string;
  replyTo: string;
  returnPath: string;
  receivedAt: string;
  riskScore: number;
  riskLabel: "Critical" | "High" | "Medium" | "Low";
  findings: ScanFinding[];
  hops: ScanHop[];
  evidenceHash: string;
  headersFound: number;
  bodyPreview: string;
};

type HeaderMap = Record<string, string[]>;

const urgencyTerms = /urgent|immediately|asap|action required|within \d+ hours?|final notice|suspended/i;
const paymentTerms = /invoice|payment|bank details|wire transfer|beneficiary|account number|gift card/i;
const credentialTerms = /password|verify your account|sign in|login|mailbox quota|security alert|credential/i;
const ipPattern = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const addressPattern = /<([^>\s]+@[^>\s]+)>|\b([\w.!#$%&'*+/=?^`{|}~-]+@[\w-]+(?:\.[\w-]+)+)\b/i;

function parseHeaders(raw: string): { headers: HeaderMap; body: string } {
  const separator = raw.search(/\r?\n\r?\n/);
  const headerText = separator >= 0 ? raw.slice(0, separator) : raw;
  const body = separator >= 0 ? raw.slice(separator).replace(/^\r?\n\r?\n/, "") : "";
  const unfolded = headerText.replace(/\r?\n[ \t]+/g, " ");
  const headers: HeaderMap = {};

  for (const line of unfolded.split(/\r?\n/)) {
    const separatorIndex = line.indexOf(":");
    if (separatorIndex <= 0) continue;
    const name = line.slice(0, separatorIndex).trim().toLowerCase();
    const value = line.slice(separatorIndex + 1).trim();
    if (!value) continue;
    headers[name] = [...(headers[name] ?? []), value];
  }

  return { headers, body };
}

function firstAddress(value: string): string {
  const match = value.match(addressPattern);
  return match?.[1] ?? match?.[2] ?? value.trim();
}

function domainOf(value: string): string {
  return firstAddress(value).split("@")[1]?.toLowerCase() ?? "";
}

/** Accepts only canonical dotted-quads — real Received-header IPs never carry leading zeros. */
function canonicalIpv4(ip: string): string | null {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)) return null;
  for (const octet of ip.split(".")) {
    if (octet.length > 1 && octet.startsWith("0")) return null; // e.g. 08.23.06.20 is a parsing artifact, never a real address
    const num = Number(octet);
    if (!Number.isInteger(num) || num > 255 || String(num) !== octet) return null;
  }
  return ip;
}

function extractIps(value: string): string[] {
  const candidates = (value.match(ipPattern) ?? [])
    .map(canonicalIpv4)
    .filter((ip): ip is string => ip !== null);
  if (candidates.length === 0) return [];
  // Received headers carry the real hop IP inside parentheses or brackets;
  // prefer those so date/id fragments elsewhere in the line can't win.
  const bracketed = new Set(
    [...value.matchAll(/[\[(](\d{1,3}(?:\.\d{1,3}){3})[\])]/g)].map((match) => match[1])
  );
  const preferred = candidates.filter((ip) => bracketed.has(ip));
  return [...new Set(preferred.length > 0 ? preferred : candidates)];
}

async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function makeHops(received: string[]): ScanHop[] {
  const hops: ScanHop[] = received.map((header, index) => {
    const ips = extractIps(header);
    return {
      label: `Relay ${String(index + 1).padStart(2, "0")}`,
      detail: ips[0] ? `Header hop · ${header.split(";").at(-1)?.trim() ?? "Received"}` : "Header hop · IP not disclosed",
      ip: ips[0] ?? "Not disclosed",
      status: "relay",
    };
  });

  const unique = hops.filter((hop, index) => hops.findIndex((candidate) => candidate.ip === hop.ip) === index);
  const origin = unique.at(-1);
  if (origin) origin.status = "origin";
  return unique.length > 0 ? unique : [{ label: "Origin", detail: "No Received IP found", ip: "Not disclosed", status: "origin" }];
}

export async function scanEmail(rawInput: string): Promise<EmailScanResult> {
  const raw = emailInputSchema.parse(rawInput);
  const { headers, body } = parseHeaders(raw);
  const subject = headers["subject"]?.[0] ?? "Untitled message";
  const from = headers["from"]?.[0] ?? "Unknown sender";
  const senderAddress = firstAddress(from);
  const replyTo = headers["reply-to"]?.[0] ?? "Not present";
  const returnPath = headers["return-path"]?.[0] ?? "Not present";
  const searchableText = `${subject} ${from} ${replyTo} ${body}`;
  const findings: ScanFinding[] = [];
  let score = 8;

  if (urgencyTerms.test(searchableText)) {
    score += 18;
    findings.push({ label: "Urgency language", detail: "Pressure tactics detected in the subject or message body.", severity: "high" });
  }
  if (paymentTerms.test(searchableText)) {
    score += 24;
    findings.push({ label: "Payment diversion cues", detail: "Financial or bank-change language requires verification.", severity: "critical" });
  }
  if (credentialTerms.test(searchableText)) {
    score += 22;
    findings.push({ label: "Credential harvesting cues", detail: "Account access or mailbox verification language detected.", severity: "high" });
  }

  const fromDomain = domainOf(from);
  const replyDomain = domainOf(replyTo);
  if (replyDomain && fromDomain && replyDomain !== fromDomain) {
    score += 25;
    findings.push({ label: "Reply-to mismatch", detail: `${fromDomain} sends the message, but replies route to ${replyDomain}.`, severity: "critical" });
  }

  const authResults = [...(headers["authentication-results"] ?? []), ...(headers["received-spf"] ?? [])].join(" ").toLowerCase();
  if (/fail|softfail|temperror|none/.test(authResults)) {
    score += 18;
    findings.push({ label: "Authentication anomaly", detail: "SPF, DKIM, or DMARC-related failure language found in the headers.", severity: "high" });
  }
  if (headers["received"]?.length) {
    findings.push({ label: "Relay path reconstructed", detail: `${headers["received"].length} Received header${headers["received"].length === 1 ? "" : "s"} parsed for forensic tracing.`, severity: "info" });
  } else {
    score += 8;
    findings.push({ label: "Missing relay evidence", detail: "No Received headers were available to establish a reliable origin.", severity: "medium" });
  }
  if (headers["x-mailer"] || headers["user-agent"]) {
    findings.push({ label: "Client fingerprint", detail: `Message client: ${headers["x-mailer"]?.[0] ?? headers["user-agent"]?.[0]}.`, severity: "info" });
  }
  if (findings.length === 0) {
    findings.push({ label: "No high-confidence indicators", detail: "No configured threat signals matched this message.", severity: "info" });
  }

  score = Math.min(99, score);
  const riskLabel = score >= 75 ? "Critical" : score >= 55 ? "High" : score >= 30 ? "Medium" : "Low";
  const hash = await sha256(raw);
  const allHeaders = Object.values(headers).flat();

  return {
    id: `AT-${hash.slice(0, 4).toUpperCase()}`,
    subject,
    sender: from.replace(addressPattern, "").replace(/[<>]/g, "").trim() || senderAddress,
    senderAddress,
    replyTo,
    returnPath,
    receivedAt: headers["date"]?.[0] ?? "Date not present",
    riskScore: score,
    riskLabel,
    findings,
    hops: makeHops(headers["received"] ?? []),
    evidenceHash: hash,
    headersFound: allHeaders.length,
    bodyPreview: body.replace(/\s+/g, " ").trim().slice(0, 180) || "No message body detected.",
  };
}

export const sampleEmail = `From: Finance Desk <finance@acme-corp.example>\nTo: accounts@northstar.example\nReply-To: payments-team@acme-corp-support.example\nSubject: URGENT: Updated bank details — action required\nDate: Sun, 30 Aug 2026 09:41:12 +0530\nReturn-Path: <bounce@acme-corp.example>\nAuthentication-Results: northstar.example; spf=fail smtp.mailfrom=acme-corp.example; dkim=none\nReceived: from relay.acme-corp-support.example (185.220.101.4) by mx2.example.net\nReceived: from unknown (203.0.113.44) by relay.acme-corp-support.example\n\nPlease process the attached invoice immediately and confirm the new beneficiary account before 12:00. Reply to payments-team@acme-corp-support.example.\n`;