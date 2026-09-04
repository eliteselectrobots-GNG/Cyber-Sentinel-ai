import type { StoredScan } from "./store";

export type SeverityKey = "Critical" | "High" | "Medium" | "Low";

export function severityDistribution(scans: StoredScan[]): Record<SeverityKey, number> {
  const counts: Record<SeverityKey, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const scan of scans) {
    const key = scan.result.riskLabel;
    if (key in counts) counts[key as SeverityKey] += 1;
    else counts.Low += 1;
  }
  return counts;
}

export function severityCount(scans: StoredScan[], severity: SeverityKey): number {
  return severityDistribution(scans)[severity];
}

/** Earliest reliable origin IP for a scan (from its reconstructed hops). */
export function originIpOf(scan: StoredScan): string | null {
  const origin = scan.result.hops.find((hop) => hop.status === "origin");
  const candidate = origin?.ip ?? scan.result.hops[0]?.ip;
  return candidate && candidate !== "Not disclosed" ? candidate : null;
}

export type CampaignCluster = {
  key: string;
  label: string;
  count: number;
  worstRisk: number;
  worstLabel: string;
  origins: string[];
  domains: string[];
};

/**
 * Real campaign correlation: cluster scans that share infrastructure —
 * the same origin IP, or the same sender/reply domain.
 */
export function campaignClusters(scans: StoredScan[]): CampaignCluster[] {
  const clusters = new Map<string, CampaignCluster>();

  const ensure = (key: string, label: string) => {
    let cluster = clusters.get(key);
    if (!cluster) {
      cluster = { key, label, count: 0, worstRisk: 0, worstLabel: "Low", origins: [], domains: [] };
      clusters.set(key, cluster);
    }
    return cluster;
  };

  for (const scan of scans) {
    const originIp = originIpOf(scan);
    const senderDomain = scan.result.senderAddress.split("@")[1]?.toLowerCase();
    const replyDomain = scan.result.replyTo.includes("@") ? scan.result.replyTo.split("@")[1]?.toLowerCase() : null;

    const keys = new Set<string>();
    if (originIp) keys.add(`ip:${originIp}`);
    if (senderDomain) keys.add(`domain:${senderDomain}`);
    if (replyDomain) keys.add(`reply:${replyDomain}`);
    if (keys.size === 0) continue;

    for (const key of keys) {
      const cluster = ensure(key, key.startsWith("ip:") ? `Origin ${key.slice(3)}` : key.startsWith("reply:") ? `Replies to ${key.slice(6)}` : `Senders from ${key.slice(7)}`);
      cluster.count += 1;
      if (scan.result.riskScore > cluster.worstRisk) {
        cluster.worstRisk = scan.result.riskScore;
        cluster.worstLabel = scan.result.riskLabel;
      }
      if (originIp && !cluster.origins.includes(originIp)) cluster.origins.push(originIp);
      const domain = senderDomain ?? replyDomain;
      if (domain && !cluster.domains.includes(domain)) cluster.domains.push(domain);
    }
  }

  return [...clusters.values()].sort((a, b) => b.count - a.count || b.worstRisk - a.worstRisk);
}
