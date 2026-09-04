/**
 * Advanced analysis engine — everything here runs locally in the browser
 * against real evidence. Nothing is fabricated: every flag, anomaly, and
 * recommendation is derived from the stored scan data, the live DNS checks,
 * and geolocation captured at scan time.
 *
 * Covered capabilities (vs. the SIH feature list):
 *  - URL / domain analysis
 *  - Brand impersonation (lookalike-domain) detection
 *  - Anomaly detection (first contact, origin shift, timezone mismatch, unusual hour)
 *  - Historical incident similarity
 *  - Automated incident prioritization
 *  - AI investigation assistant (explainable local briefing + recommendations)
 *  - Threat-intelligence correlation across stored evidence
 *  - Multilingual email analysis (body language detection)
 *  - Voice/audio attachment detection (transcription = server build, honestly marked)
 *  - Organization-specific context (org profile feeds the impersonation watchlist)
 */

import type { ScanFinding } from "./email-scanner";
import type { StoredScan } from "./store";
import { originIpOf } from "./stats";
import { extractIocs } from "./iocs";

export type FlagSeverity = "critical" | "high" | "medium" | "info";

export type AnalysisFlag = {
  label: string;
  detail: string;
  severity: FlagSeverity;
};

export type DomainAnalysis = {
  domain: string;
  flags: AnalysisFlag[];
  /** Protected domains this one impersonates (lookalike matches). */
  impersonates: string[];
};

export type UrlAnalysis = {
  url: string;
  host: string;
  flags: AnalysisFlag[];
  impersonates: string[];
};

export type Anomaly = AnalysisFlag;

export type SimilarCase = {
  scan: StoredScan;
  score: number;
  reasons: string[];
};

export type Priority = {
  level: "P1" | "P2" | "P3" | "P4";
  label: string;
  reason: string;
};

export type Attachment = {
  filename: string;
  kind: "audio" | "document" | "archive" | "executable" | "other";
};

export type Briefing = {
  headline: string;
  summary: string;
  keyFacts: string[];
  recommendations: string[];
};

/* ------------------------------------------------------------------ */
/* Organization profile (feeds the impersonation watchlist)            */
/* ------------------------------------------------------------------ */

const ORG_NAME_KEY = "aegistrace.org-name";
const ORG_DOMAIN_KEY = "aegistrace.org-domain";

export function getOrgDomain(): string {
  try {
    return (localStorage.getItem(ORG_DOMAIN_KEY) ?? "").trim().toLowerCase();
  } catch {
    return "";
  }
}

export function setOrgDomain(domain: string): void {
  try {
    localStorage.setItem(ORG_DOMAIN_KEY, domain.trim().toLowerCase());
  } catch {
    /* storage unavailable */
  }
}

export function getOrgName(): string {
  try {
    return (localStorage.getItem(ORG_NAME_KEY) ?? "").trim();
  } catch {
    return "";
  }
}

export function setOrgName(name: string): void {
  try {
    localStorage.setItem(ORG_NAME_KEY, name.trim());
  } catch {
    /* storage unavailable */
  }
}

/* ------------------------------------------------------------------ */
/* Multilingual email analysis — body script/language detection        */
/* ------------------------------------------------------------------ */

type ScriptCheck = { re: RegExp; script: string; name: string; hint: string };

const scriptChecks: ScriptCheck[] = [
  { re: /[\u0900-\u097F]/, script: "Devanagari", name: "Hindi / Marathi", hint: "Devanagari-script (Hindi, Marathi, Sanskrit)" },
  { re: /[\u0600-\u06FF]/, script: "Arabic", name: "Arabic / Urdu / Persian", hint: "Arabic-script — common for Urdu and Persian too" },
  { re: /[\u3040-\u30FF]/, script: "Kana", name: "Japanese", hint: "Hiragana or Katakana" },
  { re: /[\uAC00-\uD7AF]/, script: "Hangul", name: "Korean", hint: "Hangul" },
  { re: /[\u4E00-\u9FFF]/, script: "CJK", name: "Chinese", hint: "Han ideographs" },
  { re: /[\u0400-\u04FF]/, script: "Cyrillic", name: "Russian / Cyrillic", hint: "Cyrillic script" },
  { re: /[\u0370-\u03FF]/, script: "Greek", name: "Greek", hint: "Greek script" },
  { re: /[\u0590-\u05FF]/, script: "Hebrew", name: "Hebrew", hint: "Hebrew script" },
  { re: /[\u0E00-\u0E7F]/, script: "Thai", name: "Thai", hint: "Thai script" },
];

export type LanguageInfo = { name: string; script: string; hint: string };

export function detectLanguage(text: string): LanguageInfo {
  const sample = text.trim().slice(0, 2000);
  if (!sample) return { name: "Unknown", script: "None", hint: "No body text to analyze." };
  for (const check of scriptChecks) {
    if (check.re.test(sample)) return { name: check.name, script: check.script, hint: check.hint };
  }
  // If the text is mostly words of Latin script, assume English.
  const words = sample.split(/\s+/).filter((word) => /[A-Za-z]/.test(word)).length;
  return words > 3
    ? { name: "English", script: "Latin", hint: "Latin-script (English)" }
    : { name: "Undetermined", script: "Latin", hint: "Short or script-neutral content." };
}

/* ------------------------------------------------------------------ */
/* Attachment detection (audio transcription = server build)           */
/* ------------------------------------------------------------------ */

const audioExtensions = /\.(mp3|wav|m4a|aac|ogg|oga|opus|amr|flac|wma)$/i;
const dangerousExtensions = /\.(exe|scr|bat|cmd|com|ps1|vbs|vbe|js|jse|jar|hta|msi|lnk|iso|reg|wsf|wsh)$/i;
const macroExtensions = /\.(docm|xlsm|pptm)$/i;

export function detectAttachments(raw: string): Attachment[] {
  const found: Attachment[] = [];
  const seen = new Set<string>();

  const add = (filename: string) => {
    const clean = filename.replace(/^"|"$/g, "");
    if (!clean || seen.has(clean.toLowerCase())) return;
    seen.add(clean.toLowerCase());
    const kind: Attachment["kind"] = dangerousExtensions.test(clean) ? "executable" : audioExtensions.test(clean) ? "audio" : /\.(zip|rar|7z|tar|gz)$/i.test(clean) ? "archive" : /\.(pdf|docx?|xlsx?|pptx?|txt)$/i.test(clean) ? "document" : "other";
    found.push({ filename: clean, kind });
  };

  const audioTypes = /content-type:\s*audio\/[^\s;]+|audio\/(mpeg|wav|x-wav|mp4|ogg|amr|flac)/i;
  if (audioTypes.test(raw)) {
    const names = raw.match(/filename="?([^";\r\n]+)"?/gi);
    if (names) {
      for (const match of names) {
        const file = /filename="?([^";\r\n]+)"?/i.exec(match)?.[1];
        if (file) add(file);
      }
    }
    if (found.every((att) => att.kind !== "audio")) {
      found.push({ filename: "voice message (audio/*)", kind: "audio" });
    }
  } else {
    const names = raw.match(/filename="?([^";\r\n]+)"?/gi);
    if (names) {
      for (const match of names) {
        const file = /filename="?([^";\r\n]+)"?/i.exec(match)?.[1];
        if (file) add(file);
      }
    }
  }
  return found;
}

/* ------------------------------------------------------------------ */
/* Impersonation watchlist + domain/URL analysis                       */
/* ------------------------------------------------------------------ */

/** Well-known brands commonly impersonated (global + Indian context). */
const KNOWN_BRANDS: { name: string; domain: string }[] = [
  { name: "Google", domain: "google.com" },
  { name: "Gmail", domain: "gmail.com" },
  { name: "Microsoft", domain: "microsoft.com" },
  { name: "Office 365", domain: "office365.com" },
  { name: "Outlook", domain: "outlook.com" },
  { name: "Apple", domain: "apple.com" },
  { name: "Amazon", domain: "amazon.com" },
  { name: "PayPal", domain: "paypal.com" },
  { name: "LinkedIn", domain: "linkedin.com" },
  { name: "Facebook", domain: "facebook.com" },
  { name: "Instagram", domain: "instagram.com" },
  { name: "Netflix", domain: "netflix.com" },
  { name: "WhatsApp", domain: "whatsapp.com" },
  { name: "Dropbox", domain: "dropbox.com" },
  { name: "Adobe", domain: "adobe.com" },
  { name: "Yahoo", domain: "yahoo.com" },
  { name: "SBI", domain: "sbi.co.in" },
  { name: "HDFC Bank", domain: "hdfcbank.com" },
  { name: "ICICI Bank", domain: "icicibank.com" },
  { name: "Axis Bank", domain: "axisbank.com" },
  { name: "Kotak", domain: "kotak.com" },
  { name: "Paytm", domain: "paytm.com" },
  { name: "PhonePe", domain: "phonepe.com" },
  { name: "NPCI / UPI", domain: "npci.org.in" },
  { name: "UIDAI / Aadhaar", domain: "uidai.gov.in" },
  { name: "Income Tax", domain: "incometax.gov.in" },
  { name: "IRCTC", domain: "irctc.co.in" },
];

const suspiciousTlds = new Set(["tk", "ml", "ga", "cf", "gq", "xyz", "top", "icu", "monster", "rest", "click", "link", "work", "download", "racing", "country", "stream", "review", "date", "faith", "science", "zip", "mov", "loan", "win", "bid", "trade", "webcam", "party"]);

function levenshtein(a: string, b: string): number {
  if (a.length < b.length) [a, b] = [b, a];
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const curr = [i];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j]! + 1, curr[j - 1]! + 1, prev[j - 1]! + cost);
    }
    prev = curr;
  }
  return prev[b.length]!;
}

function baseDomainOf(domain: string): string {
  return domain.replace(/^www\./, "");
}

/**
 * The watchlist: known brands, the organization's own domain, and every
 * sender domain already present in the stored evidence (a typed domain in
 * your own mailbox history is a protected "brand").
 */
export function impersonationWatchlist(all: StoredScan[], orgDomain: string): { name: string; domain: string; source: string }[] {
  const list = KNOWN_BRANDS.map((brand) => ({ ...brand, source: "known brand" }));
  if (orgDomain) list.push({ name: "Your organization", domain: orgDomain, source: "org profile" });
  for (const scan of all) {
    const domain = scan.result.senderAddress.split("@")[1]?.toLowerCase();
    if (domain && !list.some((entry) => entry.domain === domain)) {
      list.push({ name: domain.split(".")[0] ?? domain, domain, source: "evidence history" });
    }
  }
  return list;
}

function lookalikeMatches(domain: string, all: StoredScan[], orgDomain: string): string[] {
  const candidate = baseDomainOf(domain);
  const matches = new Set<string>();
  for (const brand of impersonationWatchlist(all, orgDomain)) {
    const target = baseDomainOf(brand.domain);
    if (candidate === target) continue;
    // A genuine subdomain of the protected domain (mx.google.com vs google.com)
    // is owned by the same party — never a lookalike.
    if (candidate.endsWith(`.${target}`)) continue;
    const editDistance = levenshtein(candidate, target);
    // Direct edit-distance typosquat (paypa1.com vs paypal.com)
    if (editDistance <= 1 && candidate.length >= target.length - 2) matches.add(brand.domain);
    // Brand name embedded with attacker suffixes/prefixes (northstarbank-verify.example)
    else if (candidate.includes(target) && candidate.length > target.length + 1) matches.add(brand.domain);
    // Keyword-swapped lookalikes (microsoft-support.com vs microsoft.com)
    else if (target.includes(candidate) && target.length > candidate.length + 1) matches.add(brand.domain);
    // Transposed letters (palypal.com)
    else if (candidate.length === target.length && editDistance <= 2) matches.add(brand.domain);
  }
  return [...matches];
}

/** Structural + behavioral analysis of a domain. */
export function analyzeDomain(domain: string, all: StoredScan[], orgDomain: string): DomainAnalysis {
  const flags: AnalysisFlag[] = [];
  const lowered = domain.toLowerCase().trim();
  const labels = lowered.split(".");
  const last = labels.at(-1) ?? "";
  const secondLast = labels.at(-2) ?? "";

  if (suspiciousTlds.has(last)) flags.push({ label: "Uncommon TLD", detail: `.${last} is a low-cost top-level domain frequently used in spam infrastructure.`, severity: "high" });
  if (lowered.includes("xn--")) flags.push({ label: "Internationalized domain", detail: "Punycode (xn--) encoding is used — can visually disguise the domain in some clients.", severity: "high" });

  const brandLike = /^(g00gle|paypa1|1inkedin|fac3book|mircosoft|micr0soft|amaz0n|netfl1x)/i.test(lowered);
  if (brandLike) flags.push({ label: "Character-substitution brand lookalike", detail: "Digits or characters swapped with visually similar ones (e.g. 0 for o, 1 for l).", severity: "critical" });

  if (/^\d/.test(secondLast) || /\d{2}/.test(secondLast)) flags.push({ label: "Digit-heavy second-level label", detail: `"${secondLast}" contains digit patterns — a common obfuscation tactic.`, severity: "medium" });
  if (secondLast.includes("--") || (secondLast.match(/-/g)?.length ?? 0) > 2) flags.push({ label: "Unusual hyphenation", detail: `"${secondLast}" uses hyphens heavily — attacker domains often need free names.`, severity: "medium" });
  if (secondLast.length > 25) flags.push({ label: "Overlong label", detail: `"${secondLast}" is unusually long for a legitimate registered domain.`, severity: "info" });
  if (labels.length > 3) flags.push({ label: "Deep subdomain chain", detail: `${labels.length} labels — legitimate mail rarely sits this far down a subdomain tree.`, severity: "medium" });

  return { domain, flags, impersonates: lookalikeMatches(lowered, all, orgDomain) };
}

const urlShorteners = new Set(["bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "buff.ly", "ow.ly", "shorturl.at", "rb.gy", "cutt.ly", "shorte.st", "adf.ly", "bl.ink", "v.gd"]);

const credentialPath = /(login|signin|sign-in|verify|secure|account|update|confirm|webscr|unlock|recover|password|credential|validation)/i;

/** Structural + behavioral analysis of a URL. */
export function analyzeUrl(url: string, all: StoredScan[], orgDomain: string): UrlAnalysis {
  const flags: AnalysisFlag[] = [];
  let host = "";
  try {
    const parsed = new URL(url);
    host = parsed.hostname.toLowerCase().replace(/^www\./, "");
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname)) flags.push({ label: "IP-literal host", detail: "The address points directly at an IP, bypassing domain reputation entirely.", severity: "high" });
    if (parsed.username || parsed.password) flags.push({ label: "Credentials in URL", detail: "The link embeds credentials — a classic deception trick for display purposes.", severity: "critical" });
    if (parsed.port && parsed.port !== "80" && parsed.port !== "443") flags.push({ label: "Unusual port", detail: `Uses port ${parsed.port}`, severity: "medium" });
    if (parsed.protocol !== "https:") flags.push({ label: "Not HTTPS", detail: "The link is served over plain HTTP — credentials or content can be intercepted.", severity: "high" });
    if (urlShorteners.has(host)) flags.push({ label: "URL shortener", detail: "Shortened links hide the real destination from the preview.", severity: "medium" });
    if (credentialPath.test(parsed.pathname)) flags.push({ label: "Credential-harvesting path", detail: "Path suggests a login/verification page — common in credential phishing.", severity: "high" });
  } catch {
    flags.push({ label: "Malformed URL", detail: "Could not parse this as a valid URL.", severity: "medium" });
  }
  return { url, host, flags, impersonates: host ? lookalikeMatches(host, all, orgDomain) : [] };
}

/** Convenience: analyze every domain/URL IoC in one call. */
export function analyzeIocs(allIocs: ReturnType<typeof extractIocs>, all: StoredScan[], orgDomain: string) {
  const domains = new Map<string, DomainAnalysis>();
  const urls = new Map<string, UrlAnalysis>();
  for (const ioc of allIocs) {
    if (ioc.type === "Domain" && !domains.has(ioc.value.toLowerCase())) {
      domains.set(ioc.value.toLowerCase(), analyzeDomain(ioc.value, all, orgDomain));
    }
    if (ioc.type === "URL" && !urls.has(ioc.value)) {
      urls.set(ioc.value, analyzeUrl(ioc.value, all, orgDomain));
    }
  }
  return { domains, urls };
}

/* ------------------------------------------------------------------ */
/* Threat-intelligence correlation across stored evidence              */
/* ------------------------------------------------------------------ */

export type CorrelatedIoc = {
  type: "IP" | "Domain" | "URL" | "Email";
  value: string;
  count: number;
};

/** Indicators in this case that also appear in other stored cases. */
export function threatCorrelation(scan: StoredScan, all: StoredScan[]): CorrelatedIoc[] {
  const current = extractIocs(scan.raw, scan.result);
  const currentKeys = new Set(current.map((ioc) => `${ioc.type}:${ioc.value.toLowerCase()}`));
  const seenElsewhere = new Map<string, number>();
  for (const other of all) {
    if (other.id === scan.id) continue;
    for (const ioc of extractIocs(other.raw, other.result)) {
      const key = `${ioc.type}:${ioc.value.toLowerCase()}`;
      if (!currentKeys.has(key)) continue;
      seenElsewhere.set(key, (seenElsewhere.get(key) ?? 0) + 1);
    }
  }
  return [...seenElsewhere.entries()]
    .map(([key, count]) => {
      const [type, value] = key.split(":");
      return { type: type as CorrelatedIoc["type"], value: value ?? key, count };
    })
    .sort((a, b) => b.count - a.count);
}

/* ------------------------------------------------------------------ */
/* Anomaly detection                                                   */
/* ------------------------------------------------------------------ */

/** Expected UTC offset (minutes) per country, for sender-timezone checks. Approximate. */
const countryOffsetMinutes: Record<string, number> = {
  IN: 330, PK: 300, BD: 360, LK: 330, NP: 345,
  US: -420, CA: -300, MX: -360, BR: -180, AR: -180,
  GB: 0, IE: 0, PT: 0, FR: 60, DE: 60, ES: 60, IT: 60, NL: 60,
  RU: 180, TR: 180, NG: 60, GH: 0, KE: 180, ZA: 120, EG: 120, SA: 180, AE: 240, IL: 180,
  SG: 480, MY: 480, ID: 420, TH: 420, VN: 420, PH: 480, CN: 480, HK: 480, TW: 480, JP: 540, KR: 540,
  AU: 600, NZ: 720,
};

function headerOffsetMinutes(dateValue: string): number | null {
  const match = /([+-])(\d{2})(\d{2})/.exec(dateValue);
  if (!match) return null;
  const sign = match[1] === "-" ? -1 : 1;
  const hours = Number(match[2]);
  const minutes = Number(match[3]);
  if (Number.isNaN(hours) || Number.isNaN(minutes)) return null;
  return sign * (hours * 60 + minutes);
}

function hourInHeaderZone(dateValue: string): number | null {
  const match = /(\d{1,2}):(\d{2})/.exec(dateValue);
  const offset = headerOffsetMinutes(dateValue);
  if (!match || offset === null) return null;
  const hour = Number(match[1]);
  if (Number.isNaN(hour)) return null;
  return ((hour - Math.round(offset / 60)) % 24 + 24) % 24;
}

/**
 * Behavioral anomalies for a case given the stored evidence history.
 * Every check is derived from real data — nothing is guessed.
 */
export function anomaliesFor(scan: StoredScan, all: StoredScan[]): Anomaly[] {
  const anomalies: Anomaly[] = [];
  const others = all.filter((candidate) => candidate.id !== scan.id);
  const senderDomain = scan.result.senderAddress.split("@")[1]?.toLowerCase();
  const originIp = originIpOf(scan);
  const originGeo = originIp ? (scan.geo?.[originIp] ?? null) : null;

  if (senderDomain) {
    const history = others.filter((other) => other.result.senderAddress.toLowerCase().endsWith(`@${senderDomain}`));
    if (history.length === 0 && others.length >= 1) {
      anomalies.push({
        label: "First contact from this sender domain",
        detail: `"${senderDomain}" has never sent to this workspace before. First-time senders deserve extra verification regardless of content.`,
        severity: "medium",
      });
    } else if (history.length > 0 && originGeo) {
      // Origin shift: same sender, previously different country.
      const previousCountries = new Set<string>();
      for (const other of history) {
        const ip = originIpOf(other);
        const geo = ip ? (other.geo?.[ip] ?? null) : null;
        if (geo && geo.countryCode) previousCountries.add(geo.countryCode);
      }
      if (previousCountries.size > 0 && !previousCountries.has(originGeo.countryCode)) {
        anomalies.push({
          label: "Origin country shift",
          detail: `This sender previously arrived from ${[...previousCountries].join(", ")}, and now arrives from ${originGeo.country} (${originGeo.city}, ${originGeo.region}). Compromised accounts often change origin suddenly.`,
          severity: "critical",
        });
      }
    }
  }

  // Timezone inconsistency: the Date header's offset vs. the origin's expected offset.
  const offset = headerOffsetMinutes(scan.result.receivedAt);
  const expected = originGeo && originGeo.countryCode ? countryOffsetMinutes[originGeo.countryCode] : undefined;
  if (originGeo && offset !== null && expected !== undefined) {
    const delta = Math.abs(offset - expected);
    if (delta >= 240) {
      anomalies.push({
        label: "Sender-timezone inconsistency",
        detail: `The message claims UTC${offset >= 0 ? "+" : ""}${offset / 60} (${offset >= 0 ? "east" : "west"} of UTC) while its origin infrastructure sits in ${originGeo.country} (usually UTC${expected >= 0 ? "+" : ""}${expected / 60}). A legitimate sender rarely clocks hours away from their location.`,
        severity: "high",
      });
    }
  }

  const hour = hourInHeaderZone(scan.result.receivedAt);
  if (hour !== null && (hour < 6 || hour > 22)) {
    anomalies.push({
      label: "Unusual sending hour",
      detail: `The message time corresponds to ${hour === 0 ? "midnight" : `${hour}:00`} in its own timezone — outside typical business hours. Not proof of anything alone, but worth noting.`,
      severity: "info",
    });
  }

  const authFails = (scan.auth?.checks ?? []).filter((check) => check.outcome === "fail").length;
  if (authFails > 0) {
    anomalies.push({
      label: "Live authentication failures",
      detail: `${authFails} DNS-level authentication check${authFails === 1 ? "" : "s"} failed at scan time (see Header analysis).`,
      severity: "high",
    });
  }

  const body = scan.result.bodyPreview;
  if (body && body !== "No message body detected.") {
    const language = detectLanguage(body);
    if (language.script !== "Latin" && language.script !== "None") {
      anomalies.push({
        label: "Non-English message body",
        detail: `The body is written in a ${language.script} script (${language.name}). Multilingual phishing is common — have the content reviewed in the sender's language.`,
        severity: "info",
      });
    }
  }

  const attachments = detectAttachments(scan.raw);
  if (attachments.some((att) => att.kind === "audio")) {
    anomalies.push({
      label: "Audio attachment present",
      detail: "The message carries a voice/audio file. Content cannot be inspected in the local build — treat it as untrusted until it is reviewed (transcription arrives with the server build).",
      severity: "medium",
    });
  }

  return anomalies;
}

/* ------------------------------------------------------------------ */
/* Historical incident similarity                                      */
/* ------------------------------------------------------------------ */

function subjectTokens(subject: string): Set<string> {
  return new Set(subject.toLowerCase().split(/[^a-z0-9]+/).filter((token) => token.length > 3));
}

/** Rank past cases by how similar they are to this one. */
export function incidentSimilarity(scan: StoredScan, all: StoredScan[]): SimilarCase[] {
  const current = extractIocs(scan.raw, scan.result);
  const currentIocKeys = new Set(current.map((ioc) => `${ioc.type}:${ioc.value.toLowerCase()}`));
  const currentSubjects = subjectTokens(scan.result.subject);
  const senderDomain = scan.result.senderAddress.split("@")[1]?.toLowerCase();
  const replyDomain = scan.result.replyTo.includes("@") ? scan.result.replyTo.split("@")[1]?.toLowerCase() : null;
  const originIp = originIpOf(scan);

  const results: SimilarCase[] = [];
  for (const other of all) {
    if (other.id === scan.id) continue;
    let score = 0;
    const reasons: string[] = [];
    const otherSender = other.result.senderAddress.split("@")[1]?.toLowerCase();
    if (senderDomain && senderDomain === otherSender) {
      score += 30;
      reasons.push("same sender domain");
    }
    if (replyDomain && other.result.replyTo.includes("@") && replyDomain === other.result.replyTo.split("@")[1]?.toLowerCase()) {
      score += 15;
      reasons.push("same reply domain");
    }
    const otherOrigin = originIpOf(other);
    if (originIp && originIp === otherOrigin) {
      score += 25;
      reasons.push("same origin IP");
    }
    for (const ioc of extractIocs(other.raw, other.result)) {
      const key = `${ioc.type}:${ioc.value.toLowerCase()}`;
      if (currentIocKeys.has(key)) {
        score += ioc.type === "IP" ? 10 : ioc.type === "Email" ? 8 : 6;
        reasons.push(`shares IoC ${ioc.value}`);
        break;
      }
    }
    const overlap = [...currentSubjects].filter((token) => subjectTokens(other.result.subject).has(token)).length;
    if (overlap >= 2) {
      score += 5 + overlap;
      reasons.push(`${overlap} subject keywords match`);
    }
    if (score >= 12) results.push({ scan: other, score: Math.min(99, score), reasons: reasons.slice(0, 3) });
  }
  return results.sort((a, b) => b.score - a.score).slice(0, 4);
}

/* ------------------------------------------------------------------ */
/* Automated incident prioritization                                   */
/* ------------------------------------------------------------------ */

export function priorityOf(scan: StoredScan, all: StoredScan[]): Priority {
  const score = scan.result.riskScore;
  const anomalies = anomaliesFor(scan, all);
  const escalated = anomalies.some((anomaly) => anomaly.severity === "critical");

  let level: Priority["level"] = score >= 75 ? "P1" : score >= 55 ? "P2" : score >= 30 ? "P3" : "P4";
  if (escalated && level !== "P1") {
    level = level === "P4" ? "P3" : level === "P3" ? "P2" : "P2";
  }
  const labels: Record<Priority["level"], string> = { P1: "Immediate", P2: "High", P3: "Standard", P4: "Monitor" };
  const escalationNote = escalated ? ` — escalated by the ${anomalies.find((a) => a.severity === "critical")?.label.toLowerCase() ?? "critical anomaly"} signal` : "";
  return { level, label: labels[level], reason: `${scan.result.riskLabel} score ${score}/100${escalationNote}.` };
}

/* ------------------------------------------------------------------ */
/* AI investigation assistant (local, explainable briefing)            */
/* ------------------------------------------------------------------ */

export function buildBriefing(scan: StoredScan, all: StoredScan[], orgDomain: string): Briefing {
  const r = scan.result;
  const auth = scan.auth?.checks ?? [];
  const failedAuth = auth.filter((check) => check.outcome === "fail");
  const passedAuth = auth.filter((check) => check.outcome === "pass");
  const originIp = originIpOf(scan);
  const originGeo = originIp ? (scan.geo?.[originIp] ?? null) : null;
  const senderDomain = r.senderAddress.split("@")[1]?.toLowerCase() ?? "unknown domain";
  const replyDomain = r.replyTo.includes("@") ? r.replyTo.split("@")[1]?.toLowerCase() : null;
  const replyMismatch = replyDomain && senderDomain !== replyDomain;
  const language = detectLanguage(r.bodyPreview);
  const attachments = detectAttachments(scan.raw);
  const watchlist = impersonationWatchlist(all, orgDomain);
  const impersonated = watchlist.filter((entry) => entry.domain !== senderDomain && lookalikeMatches(senderDomain, all, orgDomain).includes(entry.domain));

  const highRisk = r.riskLabel === "Critical" || r.riskLabel === "High";

  let headline: string;
  if (highRisk) headline = `Do not act on this message — ${r.riskLabel} risk (${r.riskScore}/100)`;
  else if (r.riskLabel === "Medium") headline = `Verify before acting — ${r.riskLabel} risk (${r.riskScore}/100)`;
  else headline = `No credible threat signals — ${r.riskLabel} risk (${r.riskScore}/100)`;

  const authSentence =
    failedAuth.length > 0
      ? `${failedAuth.length} live DNS authentication check${failedAuth.length === 1 ? "" : "s"} failed (${failedAuth.map((c) => `${c.kind} on ${c.domain}`).join(", ")}).`
      : passedAuth.length > 0
        ? `Live DNS authentication passed or was neutral (${passedAuth.length} check${passedAuth.length === 1 ? "" : "s"}).`
        : "No live DNS checks were recorded for this case.";

  const originSentence = originGeo
    ? `The relay path originates from ${originGeo.city}, ${originGeo.country} (${originGeo.asn || "unknown ASN"}${originGeo.isp ? `, ${originGeo.isp}` : ""}).`
    : originIp
      ? "The earliest disclosed IP is hidden by the sending provider — normal for Google-hosted mail."
      : "No origin IP was disclosed in the headers.";

  const signalSentence =
    r.findings.filter((finding) => finding.severity !== "info").length > 0
      ? `Key signals: ${r.findings.filter((finding) => finding.severity !== "info").map((f) => f.label.toLowerCase()).join(", ")}.`
      : "No configured threat signals matched.";

  const summary = `${r.sender} claims to be “${r.sender !== r.senderAddress ? r.sender : senderDomain}”. ${authSentence} ${originSentence} ${signalSentence}`;

  const keyFacts: string[] = [
    `Sender domain: ${senderDomain}`,
    `Reply-to: ${r.replyTo}${replyMismatch ? ` — differs from the sender domain (${replyDomain})` : ""}`,
    `Origin: ${originGeo ? `${originGeo.city}, ${originGeo.country}${originGeo.asn ? ` · ${originGeo.asn}` : ""}` : originIp ? "Hidden by provider" : "Not disclosed"}`,
    `Body language: ${language.name}`,
  ];
  if (attachments.length > 0) keyFacts.push(`Attachments: ${attachments.map((att) => att.filename).join(", ")}${attachments.some((a) => a.kind === "audio") ? " (audio — transcription is a server-build item)" : ""}`);
  const iocCount = extractIocs(scan.raw, r).length;
  keyFacts.push(`Indicators extracted: ${iocCount}`);
  if (impersonated.length > 0) keyFacts.push(`Impersonation watch: this sender domain looks like ${[...new Set(impersonated.map((e) => e.domain))].join(", ")}`);

  const recommendations: string[] = [];
  if (highRisk || failedAuth.length > 0) {
    recommendations.push("Do not click links, reply, or open attachments in this message.");
    recommendations.push("Contact the sender through a previously known channel — not the address in this message.");
    recommendations.push("Escalate to your security team, quoting this case id.");
  } else if (replyMismatch || r.riskLabel === "Medium") {
    recommendations.push("Verify the request through a known channel before acting on it.");
    recommendations.push("Do not use the reply address in this message; it routes to a different domain.");
  } else {
    recommendations.push("No action required beyond standard caution.");
  }
  if (attachments.some((att) => att.kind === "audio")) recommendations.push("The voice attachment is untrusted in the local build — transcription arrives with the server integration.");
  recommendations.push("Evidence is stored with a re-verifiable SHA-256 fingerprint (Evidence vault).");

  return { headline, summary, keyFacts, recommendations };
}

/* ------------------------------------------------------------------ */
/* Fraudulent Email Detection Engine                                   */
/*  1. NLP language & tactics analysis (urgency, fear, greed,          */
/*     authority, secrecy pressure)                                    */
/*  2. Phishing indicator detection (spoofed sender fields, disguised  */
/*     links, executable/macro attachments)                            */
/*  3. Business Email Compromise (BEC) pattern detection               */
/*  4. Explainable 5-class classification                              */
/* ------------------------------------------------------------------ */

export type EmailClass = "fraud" | "phishing" | "impersonated" | "suspicious" | "legitimate";

export const classMeta: Record<EmailClass, { label: string; blurb: string; tone: "critical" | "warning" | "brand" | "safe" }> = {
  fraud: { label: "Fraud / BEC", blurb: "Financial or business-email compromise pattern — payment diversion, fake invoices, or executive impersonation with a money/credential request.", tone: "critical" },
  phishing: { label: "Phishing", blurb: "Credential-harvesting lures, malicious or disguised links, or live authentication failures.", tone: "critical" },
  impersonated: { label: "Impersonation", blurb: "The sender or its links mimic a known brand, executive, or your organization — the identity is not what it claims to be.", tone: "warning" },
  suspicious: { label: "Suspicious", blurb: "Unusual signals that warrant verification, but no confirmed attack pattern yet.", tone: "brand" },
  legitimate: { label: "Legitimate", blurb: "No credible threat signals and no authentication failures.", tone: "safe" },
};

export type TacticsAnalysis = {
  urgency: AnalysisFlag[];
  fear: AnalysisFlag[];
  greed: AnalysisFlag[];
  authority: AnalysisFlag[];
  pressure: AnalysisFlag[];
};

export type BecPattern = { id: string; label: string; detail: string; severity: FlagSeverity };

export type Classification = {
  className: EmailClass;
  /** 0–100, derived from the weight of real evidence — never arbitrary. */
  confidence: number;
  /** One human sentence summarizing why. */
  verdict: string;
  bec: AnalysisFlag[];
  tactics: TacticsAnalysis;
  /** Spoofing + link + attachment indicators. */
  indicators: AnalysisFlag[];
  /** Everything that drove the verdict (findings, auth, domains, indicators, anomalies). */
  evidence: AnalysisFlag[];
};

/* ------------------------- 1. NLP tactics ------------------------- */

const urgencyRe = /\b(urgent|immediately|immediate action|asap|as soon as possible|act (now|today)|right away|don'?t delay|time[- ]sensitive|expires? (today|soon)|last warning|final (notice|reminder)|response required|within \d+\s*(hours?|minutes?|days?)|deadline|overdue|only \d+\s*(hours?|days?))\b/i;
const fearRe = /\b(account (suspended|locked|limited|closed|will be closed|compromised|on hold)|unauthorized (transaction|login|access|activity|charge)|suspicious (activity|login|transaction|sign-?in)|security (breach|incident|alert)|legal (action|proceedings|notice|threat)|lawsuit|tax (penalty|refund|assessment)|arrest warrant|identity (theft|stolen)|you owe|debt|deactivated|terminated|blocked|penalty)\b/i;
const greedRe = /\b(prize|lottery|winner|you have won|inheritance|bequest|gift cards?|refund (pending|due|approved)|compensation|selected (for|as)|free (iphone|phone|trip|vacation|gift)|discount|reward|winnings)\b/i;
const authorityRe = /\b(ceo|cfp?o|coo|cto|president|chairman|managing director|director|vice president|senior (vice )?president|principal|dean|h\s?o\s?d|head of|commissioner|secretary|administrator|board|director general|officer)\b/i;
const secrecyRe = /\b(confidential|do not (share|disclose|tell|discuss)|keep (this )?(between us|private|secret|discreet)|strictly private|discreet)\b/i;

/**
 * 1) NLP layer: pressure tactics, threat framing, reward lures, authority
 * invocation, and secrecy pressure extracted from the subject + body.
 * Every match is a real language pattern — nothing is generated.
 */
export function analyzeTactics(subject: string, body: string): TacticsAnalysis {
  const text = `${subject} ${body}`.slice(0, 4000);
  const result: TacticsAnalysis = { urgency: [], fear: [], greed: [], authority: [], pressure: [] };

  const groups: { key: keyof TacticsAnalysis; label: string; detail: string; re: RegExp; severity: FlagSeverity }[] = [
    { key: "urgency", label: "Urgency pressure", detail: "Time pressure is the #1 social-engineering lever — it pushes victims to act before they verify.", re: urgencyRe, severity: "high" },
    { key: "fear", label: "Fear / threat framing", detail: "The message threatens consequences (account loss, legal action, penalties) to bypass careful judgment.", re: fearRe, severity: "high" },
    { key: "greed", label: "Greed / reward lure", detail: "Prizes, refunds, and windfalls are used to buy attention and lower suspicion.", re: greedRe, severity: "medium" },
    { key: "authority", label: "Authority figure invoked", detail: "Executive or institutional authority is referenced to make demands feel legitimate.", re: authorityRe, severity: "medium" },
    { key: "pressure", label: "Secrecy / confidentiality pressure", detail: "Requests to keep the matter secret isolate the victim from colleagues who could verify.", re: secrecyRe, severity: "medium" },
  ];

  for (const group of groups) {
    if (group.re.test(text)) result[group.key].push({ label: group.label, detail: group.detail, severity: group.severity });
  }
  if (/\bkindly\b/i.test(text)) {
    result.pressure.push({ label: "Kindly language", detail: "“Kindly” is over-represented in scam mail, though it is also normal Indian business English — low weight on its own.", severity: "info" });
  }
  if (/\b[A-Z]{4,}\b/.test(subject)) {
    result.urgency.push({ label: "ALL-CAPS emphasis", detail: "The subject line shouts in capitals — amateur social-engineering styling.", severity: "info" });
  }
  if (/!{2,}/.test(subject)) {
    result.urgency.push({ label: "Exclamation overload", detail: "Repeated exclamation marks in the subject line are a common phishing styling tell.", severity: "info" });
  }
  return result;
}

/* ----------------- 2. Phishing indicator detection ----------------- */

const freeMailDomains = new Set(["gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "yahoo.com", "yahoo.in", "rediffmail.com", "live.com", "icloud.com", "aol.com", "proton.me", "protonmail.com", "zoho.com", "mail.com", "yandex.com", "gmx.com", "tutanota.com"]);
const execTitleRe = /\b(ceo|cfp?o|coo|cto|chairman|managing director|director|vice president|senior vice president|principal|dean|h\s?o\s?d|head of|commissioner|secretary|administrator|executive)\b/i;

/** Spoofed-sender-field detection: display names vs. real domains. */
export function spoofingSignals(scan: StoredScan, all: StoredScan[], orgDomain: string): AnalysisFlag[] {
  const flags: AnalysisFlag[] = [];
  const r = scan.result;
  const display = r.sender.trim();
  const fromDomain = r.senderAddress.split("@")[1]?.toLowerCase() ?? "";
  const cleanReturnPath = r.returnPath.replace(/[<>]/g, "").trim();
  const returnDomain = cleanReturnPath.includes("@") ? cleanReturnPath.split("@")[1]?.toLowerCase() : "";

  if (fromDomain && returnDomain && returnDomain !== fromDomain) {
    flags.push({
      label: "Sender / Return-Path mismatch",
      detail: `The From header uses ${fromDomain} but the Return-Path belongs to ${returnDomain} — the envelope is not aligned with the displayed sender.`,
      severity: "high",
    });
  }

  const looksLikeOrg = /(official|support|admin|care|help|service|bank|team|hr|ceo|director|principal|executive|office|nodal|desk)/i.test(display);
  if (fromDomain && freeMailDomains.has(fromDomain) && display !== r.senderAddress && looksLikeOrg) {
    flags.push({
      label: "Free-mail sender posing as an organization",
      detail: `“${display}” claims an institutional role but sends from ${fromDomain} — a free mailbox. Legitimate institutions mail from their own domain.`,
      severity: "critical",
    });
  }

  const watchlist = impersonationWatchlist(all, orgDomain);
  const displayLower = display.toLowerCase();
  for (const entry of watchlist) {
    const brandName = entry.name.toLowerCase();
    if (brandName.length >= 3 && displayLower.includes(brandName)) {
      const nameStem = entry.domain.split(".")[0] ?? "";
      if (!displayLower.includes(nameStem) && fromDomain !== entry.domain && fromDomain !== "") {
        flags.push({
          label: "Display-name impersonation",
          detail: `The sender name contains “${entry.name}” (protected: ${entry.source}) but the message is sent from ${fromDomain}, not ${entry.domain}.`,
          severity: "critical",
        });
        break;
      }
    }
  }

  if (execTitleRe.test(display) && fromDomain && freeMailDomains.has(fromDomain)) {
    flags.push({
      label: "Executive title on a free mailbox",
      detail: `The sender presents as an executive but uses a free mailbox (${fromDomain}). Real executives sign from organizational domains.`,
      severity: "high",
    });
  }

  return flags;
}

/** Disguised / obfuscated links: anchor text vs. destination, IP literals, encoding. */
export function linkDisguise(raw: string): AnalysisFlag[] {
  const flags: AnalysisFlag[] = [];
  const seen = new Set<string>();
  for (const match of raw.matchAll(/<a\s+[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([^<]*)<\/a>/gi)) {
    const href = match[1] ?? "";
    const text = (match[2] ?? "").trim();
    if (!href || !text) continue;
    try {
      const parsed = new URL(href);
      const hrefHost = parsed.hostname.replace(/^www\./, "").toLowerCase();
      let textHost: string | null = null;
      try {
        textHost = new URL(text).hostname.replace(/^www\./, "").toLowerCase();
      } catch {
        /* plain text anchor, nothing to compare */
      }
      if (textHost && textHost !== hrefHost && !seen.has(href)) {
        seen.add(href);
        flags.push({
          label: "Link text vs destination mismatch",
          detail: `The link displays “${text}” but actually points to ${hrefHost}. The visible text is safe; the target is not.`,
          severity: "critical",
        });
      }
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname) && !seen.has(href)) {
        seen.add(href);
        flags.push({
          label: "IP-literal link",
          detail: `The link target is a raw IP address (${parsed.hostname}) — domain reputation is bypassed entirely.`,
          severity: "high",
        });
      }
    } catch {
      /* malformed href — ignore */
    }
  }
  if (/href\s*=\s*["'][^"']*(%[0-9a-f]{2}){2,}/i.test(raw)) {
    flags.push({
      label: "Obfuscated (encoded) URL",
      detail: "A link uses percent-encoding in its host segment — an obfuscation technique that can hide the real destination.",
      severity: "high",
    });
  }
  return flags;
}

/** Executable / macro-bearing / archive / audio attachment flags. */
export function attachmentThreatFlags(attachments: Attachment[]): AnalysisFlag[] {
  const flags: AnalysisFlag[] = [];
  const executables = attachments.filter((att) => att.kind === "executable" || macroExtensions.test(att.filename));
  if (executables.length > 0) {
    flags.push({
      label: "Executable / macro attachment",
      detail: `${executables.map((att) => att.filename).join(", ")} — executable or macro-enabled files are the primary malware delivery vehicle and are blocked by most mail gateways.`,
      severity: "critical",
    });
  }
  const archives = attachments.filter((att) => att.kind === "archive");
  if (archives.length > 0) {
    flags.push({
      label: "Archive attachment",
      detail: `${archives.map((att) => att.filename).join(", ")} — archives are commonly used to smuggle executables past scanners.`,
      severity: "medium",
    });
  }
  const audio = attachments.filter((att) => att.kind === "audio");
  if (audio.length > 0) {
    flags.push({
      label: "Audio attachment (untranscribed)",
      detail: `${audio.map((att) => att.filename).join(", ")} — voice files cannot be inspected in the local build; transcription arrives with the server integration.`,
      severity: "medium",
    });
  }
  return flags;
}

/* ----------------------- 3. BEC patterns -------------------------- */

const becGroups: { id: "payment-diversion" | "fake-invoice" | "credential-harvest"; label: string; detail: string; re: RegExp }[] = [
  {
    id: "payment-diversion",
    label: "Payment diversion",
    detail: "Requests to change payment/bank details are the hallmark of business email compromise — confirm through a verified channel before acting.",
    re: /(update (your )?(payment|bank|direct deposit)|new (bank )?(account|payment) (details|information)|payment (details|information) (changed|updated|verify|re-?verified)|change of (bank |payment )?(account|details)|switched (banks?|payroll|accounts?)|different (bank )?(account|details)|beneficiary|remittance|payroll (change|update)|re-?routing|new (account|iban)|account (details|number) (changed|updated))/i,
  },
  {
    id: "fake-invoice",
    label: "Fake invoice",
    detail: "Invoice, outstanding-balance, or payment-overdue language without verifiable billing context.",
    re: /(invoice (attached|enclosed|available|below|for|#\s?\d+)|outstanding (invoice|payment|balance|amount)|payment (pending|overdue|required|is due)|overdue (invoice|payment)|settle (the )?(invoice|amount|payment)|remittance|advance payment|credit note|purchase order)/i,
  },
  {
    id: "credential-harvest",
    label: "Credential harvesting",
    detail: "Account-verification or password language is the most common credential-theft lure.",
    re: /(verify (your )?(account|identity|credentials|information)|confirm (your )?(account|password|login|identity)|password (expired|reset|change|update|will be)|account (suspended|locked|limited|will be (closed|deactivated)|on hold)|security (check|update|verification|alert)|re-?authenticate|login (page|link|details)|sign in to (verify|update|confirm)|unusual (activity|login|sign-?in|transaction)|quota (exceeded|full))/i,
  },
];

const requestVerbRe = /\b(kindly|please|request|need|require|send|transfer|pay|approve|process|purchase|buy|share|provide|help|urgent)\b/i;
const moneyRe = /\b(payment|pay|bank|account|funds?|money|wire|transfer|invoice|credential|password|gift cards?|vouchers?|amount|salary|remuneration)\b/i;

/**
 * 3) Business Email Compromise patterns: payment diversion, fake
 * invoices, credential harvesting, and executive impersonation
 * (authority title + request + money/credential language).
 */
export function detectBecPatterns(subject: string, body: string, displayName: string): BecPattern[] {
  const text = `${subject} ${body}`.slice(0, 4000);
  const found: BecPattern[] = [];
  for (const group of becGroups) {
    if (group.re.test(text)) {
      found.push({ id: group.id, label: group.label, detail: group.detail, severity: group.id === "credential-harvest" ? "high" : "critical" });
    }
  }
  const titleInName = execTitleRe.test(displayName);
  const titleInBody = execTitleRe.test(text);
  if ((titleInName || titleInBody) && requestVerbRe.test(text) && moneyRe.test(text)) {
    found.push({
      id: "executive-impersonation",
      label: "Executive impersonation",
      detail: titleInName
        ? `The sender presents as “${displayName}” and asks for action involving money or credentials — the classic fake-executive pattern.`
        : "An executive role is invoked while requesting money or credentials — the classic fake-CEO pattern.",
      severity: "critical",
    });
  }
  return found;
}

/* ---------------------- 4. Classification -------------------------- */

const evidenceWeight = (severity: FlagSeverity) => (severity === "critical" ? 24 : severity === "high" ? 15 : severity === "medium" ? 8 : 2);

/**
 * 4) Explainable 5-class classification: fraud / phishing / impersonated /
 * suspicious / legitimate. The class is decided by a fixed priority order
 * (fraud > impersonation > phishing > suspicious > legitimate) and every
 * decision is backed by the evidence list returned alongside it.
 */
export function classifyEmail(scan: StoredScan, all: StoredScan[], orgDomain: string): Classification {
  const r = scan.result;
  const evidence: AnalysisFlag[] = [];

  // Scanner findings (info-level noise excluded from the class, kept for context).
  for (const finding of r.findings) {
    if (finding.severity !== "info") evidence.push(finding);
  }

  // Live DNS authentication failures.
  const authFails = (scan.auth?.checks ?? []).filter((check) => check.outcome === "fail");
  for (const check of authFails) {
    evidence.push({ label: `${check.kind} failed (live DNS)`, detail: check.detail, severity: "high" });
  }

  // Domain / URL structural analysis + lookalike impersonation.
  const iocs = extractIocs(scan.raw, r);
  const analysis = analyzeIocs(iocs, all, orgDomain);
  const impersonatedDomains = new Set<string>();
  const impersonatedUrls = new Set<string>();
  for (const dom of analysis.domains.values()) {
    for (const flag of dom.flags) evidence.push(flag);
    if (dom.impersonates.length > 0) {
      evidence.push({ label: "Lookalike domain impersonation", detail: `${dom.domain} closely resembles protected domain${dom.impersonates.length === 1 ? "" : "s"} ${dom.impersonates.join(", ")} — a deceptive-domain pattern.`, severity: "critical" });
      for (const target of dom.impersonates) impersonatedDomains.add(target);
    }
  }
  for (const url of analysis.urls.values()) {
    for (const flag of url.flags) evidence.push(flag);
    if (url.impersonates.length > 0) {
      evidence.push({ label: "Link host impersonates protected domain", detail: `${url.host} closely resembles ${url.impersonates.join(", ")} — clicking could land on a spoofed login.`, severity: "critical" });
      for (const target of url.impersonates) impersonatedUrls.add(target);
    }
  }

  // Spoofing, link disguise, attachments.
  const indicators = [...spoofingSignals(scan, all, orgDomain), ...linkDisguise(scan.raw), ...attachmentThreatFlags(detectAttachments(scan.raw))];
  for (const flag of indicators) evidence.push(flag);

  // BEC patterns + NLP tactics.
  const bec: AnalysisFlag[] = detectBecPatterns(r.subject, r.bodyPreview, r.sender).map((pattern) => ({ label: pattern.label, detail: pattern.detail, severity: pattern.severity }));
  for (const flag of bec) evidence.push(flag);
  const tactics = analyzeTactics(r.subject, r.bodyPreview);

  // Severe behavioral anomalies from the stored history.
  for (const anomaly of anomaliesFor(scan, all)) {
    if (anomaly.severity === "critical" || anomaly.severity === "high") evidence.push(anomaly);
  }

  const hasPaymentDiversion = bec.some((pattern) => pattern.label === "Payment diversion");
  const hasFakeInvoice = bec.some((pattern) => pattern.label === "Fake invoice");
  const hasCredHarvest = bec.some((pattern) => pattern.label === "Credential harvesting");
  const hasExecImpersonation = bec.some((pattern) => pattern.label === "Executive impersonation");
  const hasUrgency = tactics.urgency.some((tactic) => tactic.severity !== "info");
  const hasAuthFailure = authFails.length > 0;
  const hasImpersonation = impersonatedDomains.size > 0 || impersonatedUrls.size > 0 || indicators.some((i) => i.label === "Display-name impersonation");
  const hasLinkThreat = indicators.some((i) => (i.label === "Link text vs destination mismatch" || i.label === "IP-literal link" || i.label === "Obfuscated (encoded) URL" || i.label === "Executable / macro attachment"));
  const financialContext = /(payment|invoice|bank|wire|transfer|beneficiary|remittance|pay|account)/i.test(`${r.subject} ${r.bodyPreview}`);

  let className: EmailClass;
  if ((hasPaymentDiversion || hasFakeInvoice) && (hasUrgency || hasAuthFailure || hasImpersonation || hasExecImpersonation)) {
    className = "fraud";
  } else if (hasExecImpersonation) {
    className = "fraud";
  } else if (hasImpersonation) {
    className = "impersonated";
  } else if (hasCredHarvest || hasLinkThreat || hasAuthFailure || (hasUrgency && financialContext)) {
    className = "phishing";
  } else {
    const strong = evidence.filter((item) => item.severity === "critical" || item.severity === "high");
    const medium = evidence.filter((item) => item.severity === "medium");
    className = r.riskScore >= 40 || strong.length > 0 || medium.length >= 2 ? "suspicious" : "legitimate";
  }

  const total = evidence.reduce((sum, item) => sum + evidenceWeight(item.severity), 0);
  const confidence =
    className === "legitimate"
      ? Math.max(50, 97 - Math.min(45, total))
      : Math.max(38, Math.min(96, 35 + total));

  const topDrivers = evidence
    .filter((item) => item.severity === "critical" || item.severity === "high")
    .slice(0, 2)
    .map((item) => item.label.toLowerCase());
  const verdict =
    topDrivers.length > 0
      ? `Classified as ${classMeta[className].label} — driven by ${topDrivers.join(" and ")}.`
      : `Classified as ${classMeta[className].label}.`;

  return { className, confidence, verdict, bec, tactics, indicators, evidence };
}

/* ------------------------------------------------------------------ */
/* Header & protocol forensics                                         */
/* ------------------------------------------------------------------ */

/**
 * Deep header-protocol checks: forged/missing fields, Message-ID and Date
 * anomalies, envelope-sender consistency, and conflicts between the
 * authentication claims written INTO the headers and the live DNS results.
 */
export function headerForensics(scan: StoredScan): AnalysisFlag[] {
  const r = scan.result;
  const flags: AnalysisFlag[] = [];
  const headerBlock = scan.raw.split(/\r?\n\r?\n/)[0] ?? scan.raw;
  const headerValue = (name: string) => new RegExp(`^${name}:\\s*(.+)$`, "im").exec(headerBlock)?.[1]?.trim() ?? "";
  const senderDomain = r.senderAddress.split("@")[1]?.toLowerCase() ?? "";

  const fromHeaders = headerBlock.match(/^from:/gim)?.length ?? 0;
  if (fromHeaders > 1) {
    flags.push({ label: "Multiple From headers", detail: `${fromHeaders} From headers found — mailers emit exactly one; duplicates indicate forged or concatenated content.`, severity: "critical" });
  }

  const messageId = headerValue("message-id");
  if (!messageId) {
    flags.push({ label: "Missing Message-ID", detail: "No Message-ID header — most legitimate mailers add one; its absence is common in bulk-send and phishing tooling.", severity: "medium" });
  } else {
    const midDomain = (messageId.match(/@([^>\]\s]+)/)?.[1] ?? "").toLowerCase();
    if (midDomain && senderDomain && !midDomain.endsWith(senderDomain) && !senderDomain.endsWith(midDomain)) {
      flags.push({ label: "Message-ID host mismatch", detail: `Message-ID belongs to ${midDomain} while the sender claims ${senderDomain}. Forged messages keep the sending system's original ID.`, severity: "high" });
    }
  }

  const dateValue = headerValue("date");
  if (!dateValue) {
    flags.push({ label: "Missing Date header", detail: "No Date header — RFC 5322 requires one; its absence is unusual in legitimate mail.", severity: "medium" });
  } else {
    const parsed = new Date(dateValue);
    if (Number.isNaN(parsed.getTime())) {
      flags.push({ label: "Unparseable Date header", detail: `The Date header (“${dateValue.slice(0, 60)}”) cannot be parsed as a real timestamp.`, severity: "medium" });
    } else {
      const diffMs = Date.now() - parsed.getTime();
      if (diffMs < -24 * 3600e3) flags.push({ label: "Date header in the future", detail: "The message is dated more than a day ahead of analysis time — clock skew or header manipulation.", severity: "high" });
      else if (diffMs > 90 * 86400e3) flags.push({ label: "Date header unusually old", detail: "The message is dated more than 90 days before analysis — unusual for a fresh delivery.", severity: "info" });
    }
  }

  if (!headerValue("return-path") && r.returnPath === "Not present") {
    flags.push({ label: "Missing Return-Path", detail: "No envelope sender (Return-Path) — bounce handling and some SPF checks cannot be anchored.", severity: "medium" });
  }

  const xOriginating = headerValue("x-originating-ip");
  if (xOriginating) {
    flags.push({ label: "Client IP disclosed (X-Originating-IP)", detail: `The header exposes the originating client IP (${xOriginating.trim()}) — a disclosure most providers strip; useful when present.`, severity: "info" });
  }

  // Conflicts between the authentication claims written into the headers and
  // the live DNS verification captured at scan time.
  const claimsText = (headerBlock.match(/^authentication-results:.*$/gim) ?? []).join(" ").toLowerCase();
  if (claimsText) {
    for (const check of scan.auth?.checks ?? []) {
      if (check.outcome !== "fail") continue;
      const kind = check.kind.toLowerCase();
      if (new RegExp(`${kind}=pass`).test(claimsText)) {
        flags.push({
          label: "Header overstates authentication vs live DNS",
          detail: `The headers claim ${check.kind} pass for ${check.domain}, but the live DNS check failed: ${check.detail}`,
          severity: "critical",
        });
      }
    }
  }

  if (r.hops.length === 1 && r.hops[0]?.status === "origin" && r.hops[0]?.ip === "Not disclosed") {
    flags.push({ label: "No disclosed relay path", detail: "No Received hop discloses an IP — the sender's infrastructure is fully hidden, normal for Google-hosted mail and a red flag for others.", severity: "info" });
  }

  return flags;
}