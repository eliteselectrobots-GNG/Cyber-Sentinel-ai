/**
 * Live mail authentication checks resolved through DNS-over-HTTPS
 * (Cloudflare's public endpoint, CORS-enabled). Each check reports an
 * outcome with the evidence it was based on, so the UI can show exactly
 * why a message failed authentication.
 */

export type AuthOutcome = "pass" | "fail" | "softfail" | "neutral" | "notfound" | "error";

export type AuthCheck = {
  kind: "SPF" | "DMARC" | "DKIM";
  domain: string;
  outcome: AuthOutcome;
  /** Human summary, e.g. "-all hard fail on acme-corp.example". */
  detail: string;
};

const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";
const TXT_TYPE = 16;

type DnsAnswer = { name: string; type: number; TTL: number; data: string };
type DnsResponse = { Status: number; Answer?: DnsAnswer[] };

async function queryDns(name: string, type: "TXT" | "MX"): Promise<DnsAnswer[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);
  try {
    const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(name)}&type=${type}`;
    const response = await fetch(url, {
      headers: { accept: "application/dns-json" },
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`DNS query failed: ${response.status}`);
    const payload = (await response.json()) as DnsResponse;
    return payload.Answer ?? [];
  } finally {
    clearTimeout(timer);
  }
}

function txtRecord(answer: DnsAnswer): string {
  return (answer.data ?? "").replace(/^"|"$/g, "").replace(/"\s*"/g, "");
}

function domainOfAddress(value: string): string | null {
  const at = value.lastIndexOf("@");
  if (at < 0) return null;
  return value.slice(at + 1).replace(/[>)]/g, "").toLowerCase() || null;
}

function splitQualifier(token: string): { qualifier: string; mech: string } {
  const q = token[0];
  if (q === "-" || q === "~" || q === "?" || q === "+") return { qualifier: q, mech: token.slice(1) };
  return { qualifier: "+", mech: token };
}

async function evaluateSpf(domain: string, ip: string): Promise<{ outcome: AuthOutcome; detail: string; mechanisms: string[] }> {
  const answers = await queryDns(domain, "TXT");
  const spfRecord = answers.map(txtRecord).find((txt) => txt.startsWith("v=spf1"));
  if (!spfRecord) {
    return { outcome: "notfound", detail: `No SPF record published for ${domain}.`, mechanisms: [] };
  }
  const tokens = spfRecord.split(/\s+/).slice(1);
  if (!ip) {
    return { outcome: "notfound", detail: `SPF record published for ${domain} (${tokens.length} mechanisms) — no connecting IP was disclosed to evaluate it against.`, mechanisms: tokens };
  }

  const checkMechanism = (token: string): boolean => {
    const { mech } = splitQualifier(token);
    if (mech === "ip4") return token === `ip4:${ip}`;
    if (mech === "ip6") return token === `ip6:${ip}`;
    return false;
  };

  const walk = async (mechs: string[], depth: number): Promise<{ matched: boolean; qualifier: string; hardAll: boolean; softAll: boolean }> => {
    let matched = false;
    let qualifier = "+";
    let hardAll = false;
    let softAll = false;
    for (const token of mechs) {
      const { qualifier: q, mech } = splitQualifier(token);
      if (mech === "all") {
        hardAll = q === "-";
        softAll = q === "~";
        continue;
      }
      if (mech === "ip4" || mech === "ip6") {
        if (checkMechanism(token)) {
          matched = true;
          qualifier = q;
          return { matched, qualifier, hardAll, softAll };
        }
        continue;
      }
      if (mech.startsWith("include:") && depth < 3) {
        const includedDomain = mech.slice("include:".length);
        try {
          const included = await evaluateSpf(includedDomain, ip);
          if (included.outcome === "pass") {
            matched = true;
            qualifier = q;
            return { matched, qualifier, hardAll, softAll };
          }
        } catch {
          // an unresolvable include is treated as a permerror by RFC 7208;
          // for our purposes, skip and keep evaluating local mechanisms.
        }
      }
    }
    return { matched, qualifier, hardAll, softAll };
  };

  const { matched, qualifier, hardAll, softAll } = await walk(tokens, 0);

  if (matched) {
    if (qualifier === "-") return { outcome: "fail", detail: `SPF hard fail: ${ip} matched a "-" mechanism on ${domain}.`, mechanisms: tokens };
    if (qualifier === "~") return { outcome: "softfail", detail: `SPF softfail: ${ip} matched a "~" mechanism on ${domain}.`, mechanisms: tokens };
    return { outcome: "pass", detail: `SPF pass: ${ip} is authorized to send for ${domain}.`, mechanisms: tokens };
  }
  if (hardAll) return { outcome: "fail", detail: `SPF hard fail (-all): ${ip} is not authorized to send for ${domain}.`, mechanisms: tokens };
  if (softAll) return { outcome: "softfail", detail: `SPF softfail (~all): ${ip} is not authorized to send for ${domain}.`, mechanisms: tokens };
  return { outcome: "neutral", detail: `SPF record for ${domain} returned no decisive result for ${ip}.`, mechanisms: tokens };
}

async function checkDmarc(domain: string): Promise<AuthCheck> {
  const answers = await queryDns(`_dmarc.${domain}`, "TXT");
  const record = answers.map(txtRecord).find((txt) => txt.toLowerCase().startsWith("v=dmarc1"));
  if (!record) {
    return { kind: "DMARC", domain, outcome: "notfound", detail: `No DMARC policy published for ${domain}.` };
  }
  const policy = /p=(\w+)/.exec(record)?.[1];
  if (policy === "reject") {
    return { kind: "DMARC", domain, outcome: "fail", detail: `DMARC p=reject: receiving servers should reject mail that fails authentication from ${domain}.` };
  }
  if (policy === "quarantine") {
    return { kind: "DMARC", domain, outcome: "softfail", detail: `DMARC p=quarantine: unauthenticated mail from ${domain} should be quarantined.` };
  }
  if (policy === "none") {
    return { kind: "DMARC", domain, outcome: "neutral", detail: `DMARC p=none for ${domain}: policy is published but not enforced.` };
  }
  return { kind: "DMARC", domain, outcome: "neutral", detail: `DMARC record found for ${domain}: ${record.slice(0, 160)}`.replace(/\s+/g, " ") };
}

const DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "s1", "s2", "k1", "k2", "mail", "2024", "2025"];

async function checkDkim(domain: string): Promise<AuthCheck> {
  // Probe all common selectors in parallel so a domain without DKIM keys
  // resolves in roughly one round-trip instead of one query per selector.
  const probed = await Promise.all(
    DKIM_SELECTORS.map(async (selector): Promise<{ selector: string; record: string } | null> => {
      try {
        const answers = await queryDns(`${selector}._domainkey.${domain}`, "TXT");
        const record = answers.map(txtRecord).find((txt) => txt.toLowerCase().includes("v=dkim1"));
        return record ? { selector, record } : null;
      } catch {
        return null;
      }
    })
  );
  const found = probed.find((entry): entry is { selector: string; record: string } => entry !== null);
  if (found) {
    const dTag = /(?:^|;)\s*d=([^\s;]+)/i.exec(found.record)?.[1];
    const aligned = !dTag || dTag.toLowerCase() === domain;
    return aligned
      ? { kind: "DKIM", domain, outcome: "pass", detail: `DKIM key published for selector "${found.selector}" on ${domain}.` }
      : { kind: "DKIM", domain, outcome: "softfail", detail: `DKIM key found under "${found.selector}" but d=${dTag} does not match ${domain}.` };
  }
  return { kind: "DKIM", domain, outcome: "notfound", detail: `No DKIM key found for common selectors on ${domain}.` };
}

export type DnsEnrichment = {
  checks: AuthCheck[];
  checkedAt: number;
  offline: boolean;
};

/**
 * Runs live authentication checks for a message using the sender domain,
 * the reply/return-path domains, and the connecting IP from the relay path.
 * When DNS is unreachable the result is marked offline instead of failing.
 */
export async function enrichWithDns(sender: string, replyTo: string, returnPath: string, originIp: string | null): Promise<DnsEnrichment> {
  const senderDomain = domainOfAddress(sender) ?? domainOfAddress(sender.split(">")[0] ?? "");
  const checkedAt = Date.now();

  const offline = await queryDns("example.com", "TXT")
    .then(() => false)
    .catch(() => true);

  if (!senderDomain) {
    return { checks: [], checkedAt, offline };
  }

  if (offline) {
    return {
      checks: [{ kind: "SPF", domain: senderDomain, outcome: "error", detail: "DNS unreachable — live authentication checks are unavailable in this offline session." }],
      checkedAt,
      offline: true,
    };
  }

  // SPF, DMARC, and DKIM are independent of each other — run them concurrently
  // so authentication resolves in roughly one network round-trip.
  const checks: AuthCheck[] = [];
  const [spf, dmarc, dkim] = await Promise.all([
    evaluateSpf(senderDomain, originIp ?? "")
      .then((spfResult) => ({ kind: "SPF", domain: senderDomain, outcome: spfResult.outcome, detail: spfResult.detail } as AuthCheck))
      .catch(() => ({ kind: "SPF", domain: senderDomain, outcome: "error", detail: `SPF lookup failed for ${senderDomain} (DNS error).` } as AuthCheck)),
    checkDmarc(senderDomain).catch(() => ({ kind: "DMARC", domain: senderDomain, outcome: "error", detail: `DMARC lookup failed for ${senderDomain} (DNS error).` } as AuthCheck)),
    checkDkim(senderDomain).catch(() => ({ kind: "DKIM", domain: senderDomain, outcome: "error", detail: `DKIM lookup failed for ${senderDomain} (DNS error).` } as AuthCheck)),
  ]);
  checks.push(spf, dmarc, dkim);

  const replyDomain = domainOfAddress(replyTo);
  if (replyDomain && replyDomain !== senderDomain) {
    checks.push({ kind: "DMARC", domain: replyDomain, outcome: "fail", detail: `Alignment: replies route to ${replyDomain}, which differs from the sender domain ${senderDomain}.` });
  }
  const returnPathDomain = domainOfAddress(returnPath);
  if (returnPathDomain && returnPathDomain !== senderDomain) {
    checks.push({ kind: "SPF", domain: returnPathDomain, outcome: "softfail", detail: `Return-path domain ${returnPathDomain} differs from the sender domain ${senderDomain} (envelope alignment).` });
  }

  return { checks, checkedAt, offline: false };
}
