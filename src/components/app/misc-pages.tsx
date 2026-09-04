import { AlertTriangle, CheckCircle2, Database, FlaskConical, HardDrive, KeyRound, Network, Server, ShieldCheck, Trash2, XCircle } from "lucide-react";
import { useMemo } from "react";
import { Button } from "@/components/ui/button";
import { campaignClusters, originIpOf } from "@/lib/stats";
import type { StoredScan } from "@/lib/store";
import { Card, CardHeader, EmptyState, PageHeader, timeAgo, type PageKey } from "./ui";

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
      <PageHeader title="Relay trace reconstruction" description="The forwarding path of each message, rebuilt from its Received headers. Enrichment such as ASN, geolocation, and reputation lands with the server integration." actions={<Button variant="outline" onClick={() => navigate("overview")}><Network className="size-4" />Overview</Button>} />
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
                        <p className="mt-0.5 text-[11px] leading-5 text-muted-foreground">{hop.detail}</p>
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
                return (
                  <div key={scan.id} className="flex items-center gap-3 p-4">
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-xs font-medium text-foreground">{scan.result.subject}</p>
                      <p className="mt-1 font-mono text-[9px] text-muted-foreground">{scan.caseId} · {timeAgo(scan.scannedAt)}</p>
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

export function CampaignPage({ scans }: { scans: StoredScan[] }) {
  const clusters = campaignClusters(scans).filter((c) => c.count >= 2);
  return (
    <>
      <PageHeader title="Campaign graph" description="Messages sharing infrastructure — the same origin IP or sender domain — are correlated automatically. Graph visualization arrives with the server build." />
      {clusters.length === 0 ? (
        <div className="border border-border bg-surface">
          <EmptyState title="No campaign clusters yet" detail="Scan at least two messages that share an origin IP or sender domain, and the cluster will appear here." />
        </div>
      ) : (
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
      )}
    </>
  );
}

const engineSignals = [
  { name: "Urgency & pressure language", status: true, note: "Heuristic text analysis" },
  { name: "Payment-diversion language", status: true, note: "Invoice / bank change cues" },
  { name: "Credential-harvesting cues", status: true, note: "Login / quota / verification language" },
  { name: "Reply-to domain mismatch", status: true, note: "Header cross-check" },
  { name: "SPF / DKIM / DMARC anomaly", status: true, note: "Header result parsing" },
  { name: "Relay path reconstruction", status: true, note: "Received header parsing" },
  { name: "Evidence fingerprinting", status: true, note: "SHA-256 via WebCrypto" },
  { name: ".eml intake (≤1 MB)", status: true, note: "Local file ingestion" },
  { name: "DNS-level SPF/DKIM/DMARC verification", status: true, note: "Live · DNS-over-HTTPS" },
  { name: "IP reputation, ASN & geolocation", status: false, note: "Phase 2 · origin map" },
  { name: "Lookalike-domain detection", status: false, note: "Phase 2 · server" },
  { name: "URL extraction & reputation", status: false, note: "Phase 2 · server" },
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

export function SettingsPage({ scans, analyst, onAnalystChange, onLoadDemo, onClearAll, notify }: { scans: StoredScan[]; analyst: string; onAnalystChange: (name: string) => void; onLoadDemo: () => Promise<void>; onClearAll: () => Promise<void>; notify: (msg: string) => void }) {
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
