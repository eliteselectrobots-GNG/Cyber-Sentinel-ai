import { AlertTriangle, BellRing, CheckCircle2, Database, FlaskConical, HardDrive, KeyRound, Network, Server, ShieldCheck, Trash2, XCircle } from "lucide-react";
import { useMemo } from "react";
import { Button } from "@/components/ui/button";
import { campaignClusters, originIpOf } from "@/lib/stats";
import { extractIocs } from "@/lib/iocs";
import type { StoredScan } from "@/lib/store";
import { Card, CardHeader, EmptyState, GeoLine, InfraChips, PageHeader, timeAgo, type PageKey } from "./ui";

export function RelayTracePage({ scans, navigate }: { scans: StoredScan[]; navigate: (page: PageKey) => void }) {
  const latest = scans[0];
  const hops = useMemo(() => {
    if (!latest) return [];
    const reversed = [...latest.result.hops];
    if (reversed[0]?.status === "relay" && reversed.at(-1)?.status === "origin") reversed.reverse();
    return reversed;
  }, [latest]);

  return (
    <>
      <PageHeader title="Relay trace reconstruction" description="The forwarding path of each message, rebuilt from its Received headers, with city-level geolocation and ASN attribution resolved live at scan time." actions={<Button variant="outline" onClick={() => navigate("overview")}><Network className="size-4" />Overview</Button>} />
      {scans.length === 0 ? (
        <div className="border border-border bg-surface"><EmptyState title="No traces yet" detail="Analyze an email that includes Received headers to reconstruct its path." /></div>
      ) : (
        <div className="grid gap-6 xl:grid-cols-[minmax(0,1.2fr)_minmax(320px,0.8fr)]">
          <Card>
            <CardHeader title={`Latest case path — ${latest?.caseId}`} subtitle={`${latest?.result.subject} · ${latest ? timeAgo(latest.scannedAt) : ""}`} />
            {hops.length === 0 ? (
              <EmptyState title="No Received headers" detail="This message did not carry Received headers, so no forwarding path could be reconstructed." />
            ) : (
              <div className="space-y-0 p-5">
                {hops.map((hop, index) => {
                  const isOrigin = index === 0;
                  const isLast = index === hops.length - 1;
                  const hopGeo = latest?.geo?.[hop.ip] ?? null;
                  return (
                    <div key={`${hop.ip}-${index}`} className="relative flex gap-4 pb-6 last:pb-0">
                      {!isLast && <span className="absolute left-[13px] top-7 h-full w-px bg-border" />}
                      <div className={`relative z-10 flex size-7 shrink-0 items-center justify-center border ${isOrigin ? "border-status-critical text-status-critical" : "border-brand text-brand"} bg-surface`}>
                        {isOrigin ? <AlertTriangle className="size-3.5" /> : isLast ? <Server className="size-3.5" /> : <Network className="size-3.5" />}
                      </div>
                      <div className="min-w-0 pt-0.5">
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="text-xs font-semibold text-foreground">{isOrigin ? "Earliest reliable origin" : isLast ? "Destination MX" : `Relay ${index}`}</p>
                          <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{hop.status}</span>
                        </div>
                        <p className={`mt-1 font-mono text-xs ${hop.ip === "Not disclosed" ? "text-muted-foreground" : "text-foreground"}`}>{hop.ip}</p>
                        {hopGeo ? <div className="mt-1"><GeoLine geo={hopGeo} /></div> : <p className="mt-0.5 text-[11px] leading-5 text-muted-foreground">{hop.detail}</p>}
                        {latest && <InfraChips scan={latest} ip={hop.ip} />}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </Card>
          <Card>
            <CardHeader title="Origins across all cases" subtitle="Earliest disclosed IP per stored message" />
            <div className="divide-y divide-border">
              {scans.map((scan) => {
                const originIp = originIpOf(scan);
                const originGeo = originIp ? (scan.geo?.[originIp] ?? null) : null;
                return (
                  <div key={scan.id} className="flex items-center gap-3 p-4">
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-xs font-medium text-foreground">{scan.result.subject}</p>
                      <p className="mt-1 font-mono text-[9px] text-muted-foreground">{scan.caseId} · {timeAgo(scan.scannedAt)}</p>
                      {originGeo && <p className="mt-1"><GeoLine geo={originGeo} compact /></p>}
                      {originIp && <InfraChips scan={scan} ip={originIp} />}
                    </div>
                    <p className={`max-w-40 truncate font-mono text-xs ${originIp ? "text-foreground" : "text-muted-foreground"}`}>{originIp ?? "Not disclosed"}</p>
                  </div>
                );
              })}
            </div>
          </Card>
        </div>
      )}
    </>
  );
}

type GraphNode = { id: string; kind: "case" | "domain" | "ip"; label: string; sub: string; scanId?: string; risk: number; demo: boolean; degree: number };
type GraphEdge = { from: string; to: string; risk: number };

const graphRiskColor = (risk: number) => (risk >= 75 ? "#e5484d" : risk >= 55 ? "#c9a227" : risk >= 30 ? "#7c69ef" : "#53d88a");

function buildGraph(scans: StoredScan[]): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const byId = new Map<string, GraphNode>();
  const addNode = (node: GraphNode) => {
    if (!byId.has(node.id)) {
      byId.set(node.id, node);
      nodes.push(node);
    }
    return byId.get(node.id)!;
  };

  const limited = scans.slice(0, 14);
  for (const scan of limited) {
    const r = scan.result;
    const senderDomain = r.senderAddress.split("@")[1]?.toLowerCase() ?? "";
    const replyDomain = r.replyTo.includes("@") ? r.replyTo.split("@")[1]?.toLowerCase() ?? "" : "";
    const originIp = originIpOf(scan);
    const caseNode = addNode({
      id: `case-${scan.id}`,
      kind: "case",
      label: scan.caseId,
      sub: r.subject.slice(0, 34),
      scanId: scan.id,
      risk: r.riskScore,
      demo: scan.demo === true,
      degree: 0,
    });
    const link = (target: { id: string } | undefined) => {
      if (target && target.id !== `case-${scan.id}`) edges.push({ from: caseNode.id, to: target.id, risk: r.riskScore });
    };
    if (senderDomain) {
      link(addNode({ id: `dom-${senderDomain}`, kind: "domain", label: senderDomain, sub: "sender domain", risk: r.riskScore, demo: scan.demo === true, degree: 0 }));
    }
    if (replyDomain && replyDomain !== senderDomain) {
      link(addNode({ id: `dom-${replyDomain}`, kind: "domain", label: replyDomain, sub: "reply-to domain", risk: r.riskScore, demo: scan.demo === true, degree: 0 }));
    }
    if (originIp && originIp !== "Not disclosed") {
      const geo = scan.geo?.[originIp];
      link(addNode({ id: `ip-${originIp}`, kind: "ip", label: originIp, sub: geo ? `${geo.city}, ${geo.country}` : "origin IP", risk: r.riskScore, demo: (geo?.source ?? scan.demo) === "demo" || scan.demo === true, degree: 0 }));
    }
    // A couple of extra domains from the extracted IoCs round out the picture.
    for (const ioc of extractIocs(scan.raw, r)) {
      if (nodes.length >= 40) break;
      if (ioc.type === "Domain" && ioc.value.toLowerCase() !== senderDomain && ioc.value.toLowerCase() !== replyDomain) {
        link(addNode({ id: `dom-${ioc.value.toLowerCase()}`, kind: "domain", label: ioc.value.toLowerCase(), sub: "indicator domain", risk: r.riskScore, demo: scan.demo === true, degree: 0 }));
      }
    }
  }

  // Degree = number of distinct cases attached to a node (shared-infrastructure strength).
  const caseLinks = new Map<string, Set<string>>();
  for (const edge of edges) {
    const caseId = edge.from.startsWith("case-") ? edge.from : edge.to;
    const other = edge.from.startsWith("case-") ? edge.to : edge.from;
    if (!caseLinks.has(other)) caseLinks.set(other, new Set());
    caseLinks.get(other)!.add(caseId);
  }
  for (const node of nodes) {
    node.degree = caseLinks.get(node.id)?.size ?? 0;
  }
  return { nodes, edges };
}

function ThreatGraphSvg({ graph, onOpenCase }: { graph: ReturnType<typeof buildGraph>; onOpenCase?: (id: string) => void }) {
  if (graph.nodes.length === 0) return null;
  const W = 1020;
  const columns: Record<GraphNode["kind"], { x: number; w: number }> = {
    case: { x: 40, w: 190 },
    domain: { x: 410, w: 190 },
    ip: { x: 790, w: 180 },
  };
  const rowIndex = new Map<string, number>();
  const colCounts: Record<GraphNode["kind"], number> = { case: 0, domain: 0, ip: 0 };
  const positions = new Map<string, { x: number; y: number; h: number; w: number }>();
  for (const node of graph.nodes) {
    const index = colCounts[node.kind];
    rowIndex.set(node.id, index);
    colCounts[node.kind] = index + 1;
  }
  const rowH = 46;
  const maxRows = Math.max(colCounts.case, colCounts.domain, colCounts.ip, 1);
  const H = maxRows * rowH + 90;
  for (const node of graph.nodes) {
    const col = columns[node.kind];
    const index = rowIndex.get(node.id) ?? 0;
    const h = node.kind === "case" ? 42 : 26;
    const w = col.w;
    const y = 60 + index * rowH + (node.kind === "case" ? 0 : 8);
    positions.set(node.id, { x: col.x, y, h, w });
  }
  const center = (id: string) => {
    const pos = positions.get(id);
    return pos ? { x: pos.x + pos.w / 2, y: pos.y + pos.h / 2 } : { x: 0, y: 0 };
  };
  const shared = graph.nodes.filter((node) => node.degree >= 2);

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="Threat relationship graph" style={{ minHeight: 300 }}>
      <defs>
        <pattern id="graph-grid" width="26" height="26" patternUnits="userSpaceOnUse">
          <circle cx="1.5" cy="1.5" r="1.1" fill="rgba(124,105,239,0.16)" />
        </pattern>
      </defs>
      <rect width={W} height={H} fill="#15152a" />
      <rect width={W} height={H} fill="url(#graph-grid)" />
      {graph.edges.map((edge, index) => {
        const a = center(edge.from);
        const b = center(edge.to);
        const bend = Math.max(24, (b.x - a.x) * 0.42);
        return (
          <path key={`${edge.from}-${edge.to}-${index}`} d={`M ${a.x} ${a.y} C ${a.x + bend} ${a.y}, ${b.x - bend} ${b.y}, ${b.x} ${b.y}`} fill="none" stroke={graphRiskColor(edge.risk)} strokeWidth="1.1" opacity="0.28" />
        );
      })}
      {graph.nodes.map((node) => {
        const pos = positions.get(node.id)!;
        const stroke = node.kind === "case" ? graphRiskColor(node.risk) : node.kind === "domain" ? "#7c69ef" : "#4f9cf7";
        const isShared = node.degree >= 2;
        return (
          <g key={node.id} className="cursor-pointer" onClick={node.kind === "case" && node.scanId && onOpenCase ? () => onOpenCase(node.scanId!) : undefined}>
            {isShared && <rect x={pos.x - 5} y={pos.y - 5} width={pos.w + 10} height={pos.h + 10} rx={9} fill="none" stroke="#c9a227" strokeWidth="1" strokeDasharray="4 3" opacity="0.9" />}
            <rect x={pos.x} y={pos.y} width={pos.w} height={pos.h} rx={node.kind === "case" ? 7 : 5} fill={node.kind === "case" ? "#1c1c3a" : "#181830"} stroke={stroke} strokeWidth={node.kind === "case" ? 1.4 : 1} />
            {node.kind === "case" ? (
              <>
                <text x={pos.x + 10} y={pos.y + 15} fontSize="10.5" fontFamily="IBM Plex Mono, monospace" fontWeight="600" fill="#eef0fa">{node.label}{node.demo ? " · demo" : ""}</text>
                <text x={pos.x + 10} y={pos.y + 28} fontSize="8" fontFamily="IBM Plex Mono, monospace" fill="#8b93a7">{node.sub.slice(0, 26)}</text>
                <text x={pos.x + pos.w - 10} y={pos.y + 15} fontSize="9" fontFamily="IBM Plex Mono, monospace" textAnchor="end" fill={graphRiskColor(node.risk)}>{node.risk}</text>
              </>
            ) : (
              <>
                <text x={pos.x + 8} y={pos.y + 16} fontSize="9.5" fontFamily="IBM Plex Mono, monospace" fill="#eef0fa">{node.label.slice(0, 26)}</text>
                <title>{`${node.label} — ${node.sub}${node.degree >= 2 ? ` · shared by ${node.degree} cases` : ""}`}</title>
              </>
            )}
            {node.kind === "case" && <title>{`${node.label} · ${node.sub} · risk ${node.risk}/100 — click to open`}</title>}
          </g>
        );
      })}
      <g fontSize="9" fontFamily="IBM Plex Mono, monospace">
        <text x={40} y={24} fill="#5b6478">CASES</text>
        <text x={410} y={24} fill="#5b6478">SENDER / REPLY / IOC DOMAINS</text>
        <text x={790} y={24} fill="#5b6478">ORIGIN IPS</text>
        <text x={W - 40} y={H - 14} textAnchor="end" fill="#5b6478">click a case to open it · dashed outline = infrastructure shared by 2+ cases</text>
      </g>
    </svg>
  );
}

export function CampaignPage({ scans, onOpenCase }: { scans: StoredScan[]; onOpenCase?: (id: string) => void }) {
  const graph = useMemo(() => buildGraph(scans), [scans]);
  const clusters = campaignClusters(scans).filter((c) => c.count >= 2);
  const sharedNodes = graph.nodes.filter((node) => node.degree >= 2).length;
  return (
    <>
      <PageHeader title="Threat relationship graph" description="How every stored case connects to its sender domains, reply domains, indicator domains, and origin IPs — shared infrastructure is highlighted and linked to each investigation." />
      <div className="mb-4 grid gap-px border border-border bg-border sm:grid-cols-3">
        <div className="bg-surface p-5"><p className="mb-4 text-xs font-medium text-muted-foreground">Cases mapped</p><p className="font-display text-3xl font-semibold">{graph.nodes.filter((node) => node.kind === "case").length}</p><p className="mt-3 font-mono text-[10px] text-muted-foreground">investigation nodes</p></div>
        <div className="bg-surface p-5"><p className="mb-4 text-xs font-medium text-muted-foreground">Infrastructure nodes</p><p className="font-display text-3xl font-semibold">{graph.nodes.filter((node) => node.kind !== "case").length}</p><p className="mt-3 font-mono text-[10px] text-muted-foreground">domains + origin IPs</p></div>
        <div className="bg-surface p-5"><p className="mb-4 text-xs font-medium text-muted-foreground">Shared infrastructure</p><p className="font-display text-3xl font-semibold">{sharedNodes}</p><p className="mt-3 font-mono text-[10px] text-brand">{clusters.length} campaign cluster{clusters.length === 1 ? "" : "s"} detected</p></div>
      </div>
      <div className="border border-border bg-surface">
        {graph.nodes.length === 0 ? (
          <EmptyState title="No relationships to map yet" detail="Scan at least one message with disclosed sender domains or origin IPs, and its place in the graph appears here." />
        ) : (
          <div className="overflow-x-auto">
            {onOpenCase ? <ThreatGraphSvg graph={graph} onOpenCase={onOpenCase} /> : <ThreatGraphSvg graph={graph} />}
          </div>
        )}
      </div>
      {clusters.length > 0 && (
        <div className="mt-6">
          <h2 className="mb-3 font-display text-base font-semibold">Correlated campaigns</h2>
          <div className="grid gap-4 lg:grid-cols-2">
            {clusters.map((cluster) => (
              <Card key={cluster.key}>
                <div className="flex items-start justify-between gap-3 border-b border-border p-5">
                  <div>
                    <div className="flex items-center gap-2"><Network className="size-4 text-brand" /><h3 className="font-display text-base font-semibold">{cluster.label}</h3></div>
                    <p className="mt-1 text-xs text-muted-foreground">{cluster.count} scan{cluster.count === 1 ? "" : "s"} correlated</p>
                  </div>
                  <div className="text-right">
                    <p className={`font-mono text-lg font-semibold ${cluster.worstRisk >= 75 ? "text-status-critical" : cluster.worstRisk >= 55 ? "text-status-warning" : "text-brand"}`}>{cluster.worstRisk}</p>
                    <p className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground">worst risk</p>
                  </div>
                </div>
                <div className="space-y-3 p-5">
                  <div>
                    <p className="mb-1 font-mono text-[9px] uppercase tracking-wider text-muted-foreground">Origins</p>
                    <p className="font-mono text-xs text-foreground">{cluster.origins.join(", ") || "—"}</p>
                  </div>
                  <div>
                    <p className="mb-1 font-mono text-[9px] uppercase tracking-wider text-muted-foreground">Sender / reply domains</p>
                    <p className="break-all font-mono text-xs text-foreground">{cluster.domains.join(", ") || "—"}</p>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        </div>
      )}
    </>
  );
}

const engineSignals = [
  { name: "NLP language & social-engineering tactics", status: true, note: "Urgency · fear · greed · authority · secrecy pressure" },
  { name: "BEC pattern detection", status: true, note: "Payment diversion · fake invoice · credential harvest · executive impersonation" },
  { name: "5-class classification verdict", status: true, note: "Legitimate / Suspicious / Impersonated / Phishing / Fraud" },
  { name: "Display-name & Return-Path spoofing", status: true, note: "Cross-field sender alignment" },
  { name: "Link-disguise & obfuscated URL detection", status: true, note: "Anchor text vs destination · IP literals · encoding" },
  { name: "Executable / macro attachment flags", status: true, note: "exe · scr · docm · xlsm · archives" },
  { name: "Lookalike-domain & brand impersonation", status: true, note: "Known brands + org profile + evidence history" },
  { name: "URL structural analysis", status: true, note: "Bad TLDs · punycode · credential paths · shorteners" },
  { name: "Threat scoring", status: true, note: "Explainable 0–100 with findings" },
  { name: "Reply-to domain mismatch", status: true, note: "Header cross-check" },
  { name: "SPF / DKIM / DMARC anomaly", status: true, note: "Header result parsing" },
  { name: "Relay path reconstruction", status: true, note: "Received header parsing" },
  { name: "Evidence fingerprinting", status: true, note: "SHA-256 via WebCrypto" },
  { name: ".eml intake (≤1 MB)", status: true, note: "Local file ingestion" },
  { name: "DNS-level SPF/DKIM/DMARC verification", status: true, note: "Live · DNS-over-HTTPS" },
  { name: "IP geolocation & ASN attribution", status: true, note: "Live · city-level, per hop" },
  { name: "Tor exit detection", status: true, note: "Live · Tor Project DNSEL + relay-operator fingerprints" },
  { name: "DNS blacklist reputation", status: true, note: "Live · Spamhaus ZEN + SpamCop via DoH" },
  { name: "Cloud / datacenter hosting flags", status: true, note: "ASN org / ISP fingerprints" },
  { name: "Header & protocol forensics", status: true, note: "Message-ID · Date · envelope · header-vs-live-DNS conflicts" },
  { name: "MX record verification", status: true, note: "Live · DNS-over-HTTPS" },
  { name: "WHOIS / registrar intelligence", status: true, note: "Live · RDAP (registration date, registrar)" },
  { name: "Commercial threat feeds", status: false, note: "Phase 2 · server (VirusTotal / AbuseIPDB need API keys)" },
  { name: "Audio transcription", status: false, note: "Phase 2 · server (needs AI API key)" },
  { name: "Organization-specific RAG", status: false, note: "Phase 2 · server (needs LLM API key)" },
];

export function HealthPage({ scans }: { scans: StoredScan[] }) {
  const approxKb = useMemo(() => {
    const bytes = scans.reduce((sum, scan) => sum + scan.raw.length + JSON.stringify(scan.result).length, 0);
    return Math.max(1, Math.round(bytes / 1024));
  }, [scans]);
  const hopCount = scans.reduce((sum, scan) => sum + scan.result.hops.length, 0);

  return (
    <>
      <PageHeader title="Detection health" description="The true status of this engine and its detection signals — nothing here is simulated." />
      <div className="mb-6 grid gap-px border border-border bg-border sm:grid-cols-3">
        <div className="bg-surface p-5"><p className="mb-6 text-xs font-medium text-muted-foreground">Evidence stored</p><p className="font-display text-3xl font-semibold">{scans.length}<span className="ml-2 font-mono text-xs text-muted-foreground">records</span></p><p className="mt-3 font-mono text-[10px] text-brand">≈ {approxKb} KB local</p></div>
        <div className="bg-surface p-5"><p className="mb-6 text-xs font-medium text-muted-foreground">Hops reconstructed</p><p className="font-display text-3xl font-semibold">{hopCount}</p><p className="mt-3 font-mono text-[10px] text-status-safe">from Received headers</p></div>
        <div className="bg-surface p-5"><p className="mb-6 text-xs font-medium text-muted-foreground">Engine mode</p><p className="font-display text-2xl font-semibold">Local</p><p className="mt-3 font-mono text-[10px] text-muted-foreground">in-browser · deterministic</p></div>
      </div>
      <Card>
        <CardHeader title="Detection signals" subtitle="Which signals are live today and which require the server build" />
        <div className="divide-y divide-border">
          {engineSignals.map((signal) => (
            <div key={signal.name} className="flex items-center gap-3 p-4">
              {signal.status ? <CheckCircle2 className="size-4 shrink-0 text-status-safe" /> : <XCircle className="size-4 shrink-0 text-muted-foreground/50" />}
              <div className="min-w-0 flex-1">
                <p className={`text-xs font-medium ${signal.status ? "text-foreground" : "text-muted-foreground"}`}>{signal.name}</p>
                <p className="mt-0.5 font-mono text-[9px] uppercase tracking-wider text-muted-foreground">{signal.note}</p>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </>
  );
}

export function SettingsPage({ scans, analyst, onAnalystChange, onLoadDemo, onClearAll, notify, onEnableAlerts, onSetRetention, retentionDays, onSetMasking, maskingEnabled }: { scans: StoredScan[]; analyst: string; onAnalystChange: (name: string) => void; onLoadDemo: () => Promise<void>; onClearAll: () => Promise<void>; notify: (msg: string) => void; onEnableAlerts: () => Promise<void>; onSetRetention: (days: number | null) => void; retentionDays: number | null; onSetMasking: (enabled: boolean) => void; maskingEnabled: boolean }) {
  return (
    <>
      <PageHeader title="Settings" description="Workspace identity and local evidence controls. All data lives in this browser only." />
      <div className="grid gap-6 xl:grid-cols-2">
        <Card>
          <CardHeader title="Analyst identity" subtitle="Shown in the workspace header" />
          <div className="flex items-center gap-3 p-5">
            <KeyRound className="size-4 shrink-0 text-brand" />
            <input
              aria-label="Analyst name"
              value={analyst}
              onChange={(event) => onAnalystChange(event.target.value)}
              placeholder="Enter your name (shown locally)"
              className="h-9 w-full border border-input bg-shell px-3 text-xs text-foreground outline-none placeholder:text-muted-foreground focus:border-brand"
            />
          </div>
        </Card>
        <Card>
          <CardHeader title="Evidence retention" subtitle="Auto-delete local evidence older than a configurable window" />
          <div className="p-5">
            <div className="flex flex-wrap gap-2">
              {[{ days: null, label: "Keep indefinitely" }, { days: 7, label: "7 days" }, { days: 30, label: "30 days" }, { days: 90, label: "90 days" }].map((option) => {
                const active = (option.days ?? null) === retentionDays;
                return (
                  <button key={option.label} onClick={() => onSetRetention(option.days)} className={`border px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider transition-colors ${active ? "border-brand bg-brand/15 text-brand" : "border-border text-muted-foreground hover:border-brand/40 hover:text-foreground"}`}>
                    {option.label}
                  </button>
                );
              })}
            </div>
            <p className="mt-3 text-[11px] leading-5 text-muted-foreground">{retentionDays === null ? "Retention off — records persist until removed manually." : `Scans older than ${retentionDays} days are removed automatically on the next load or setting change. Demo records are exempt, and every deletion is written to the chain-of-custody log.`}</p>
          </div>
        </Card>
        <Card>
          <CardHeader title="Data masking" subtitle="Control how personal data appears in exported reports" />
          <div className="p-5">
            <div className="flex items-center gap-2">
              <Button size="sm" variant={maskingEnabled ? "default" : "outline"} onClick={() => onSetMasking(!maskingEnabled)}>{maskingEnabled ? "Masking on" : "Masking off"}</Button>
              <span className="text-[11px] leading-5 text-muted-foreground">Email addresses in exported reports are masked (r***@bpitindia.com) while domains stay readable for analysis. Raw evidence and fingerprints are never altered.</span>
            </div>
          </div>
        </Card>
        <Card>
          <CardHeader title="Real-time alerts" subtitle="Desktop notifications when a scan returns Critical or High risk" />
          <div className="p-5">
            <div className="flex items-start gap-2 text-[11px] leading-5 text-muted-foreground"><BellRing className="mt-0.5 size-3.5 shrink-0 text-brand" /><span>With permission, a native desktop notification fires the moment a scan is classified Critical or High — so the analyst is alerted without keeping the tab focused.</span></div>
            <div className="mt-3 flex flex-wrap gap-2">
              <Button size="sm" onClick={() => void onEnableAlerts()}><BellRing className="size-3.5" />Enable desktop alerts</Button>
              <span className="self-center font-mono text-[9px] uppercase tracking-wider text-muted-foreground">in-app alerts always active</span>
            </div>
          </div>
        </Card>
        <Card>
          <CardHeader title="Local evidence" subtitle={`${scans.length} record${scans.length === 1 ? "" : "s"} stored`} />
          <div className="space-y-3 p-5">
            <div className="flex items-start gap-2 text-[11px] leading-5 text-muted-foreground"><HardDrive className="mt-0.5 size-3.5 shrink-0 text-status-safe" /><span>Records persist in this browser (IndexedDB) across reloads and are never uploaded anywhere.</span></div>
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" size="sm" onClick={() => void onLoadDemo()}><FlaskConical className="size-3.5" />Load demo dataset</Button>
              <Button variant="outline" size="sm" className="text-muted-foreground hover:text-status-critical" onClick={() => void onClearAll()}><Trash2 className="size-3.5" />Clear all evidence</Button>
            </div>
            <Button variant="ghost" size="sm" onClick={() => notify("Storage runs in this browser only — see Phase 2 for the shared server database.")}><Database className="size-3.5" />About storage</Button>
          </div>
        </Card>
      </div>
      <div className="mt-6 flex flex-col gap-3 py-6 text-[10px] text-muted-foreground sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2 font-mono uppercase tracking-wider"><ShieldCheck className="size-3 text-status-safe" />AegisTrace engine · local build</div>
        <div className="flex items-center gap-4 font-mono uppercase tracking-wider"><span>Phase 1 · client persistence</span><span className="hidden text-border sm:block">|</span><span>server integration planned</span></div>
      </div>
    </>
  );
}
