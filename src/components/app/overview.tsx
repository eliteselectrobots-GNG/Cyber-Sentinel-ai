import { AlertTriangle, ArrowUpRight, CheckCircle2, ChevronRight, Database, Fingerprint, FlaskConical, Globe2, MailWarning, Network, RefreshCw, Server, Zap } from "lucide-react";
import { useMemo, useState } from "react";
import { Cell, Pie, PieChart, ResponsiveContainer } from "recharts";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { timeAgo, Bar, Card, CardHeader, DemoTag, DotLegend, EmptyState, PageHeader, SeverityBadge, Stat, type PageKey } from "./ui";

const severityColors: Record<string, string> = { Critical: "#e5484d", High: "#e2c04c", Medium: "#35c7c0", Low: "#53d88a" };
const signalTone: Record<string, string> = { critical: "bg-status-critical", high: "bg-status-warning", medium: "bg-brand", info: "bg-brand" };

function TopSignals({ scans }: { scans: StoredScan[] }) {
  const frequency = useMemo(() => {
    const map = new Map<string, { count: number; severity: string }>();
    for (const scan of scans) {
      for (const finding of scan.result.findings) {
        if (finding.severity === "info") continue;
        const entry = map.get(finding.label) ?? { count: 0, severity: finding.severity };
        entry.count += 1;
        map.set(finding.label, entry);
      }
    }
    return [...map.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, 5);
  }, [scans]);
  const max = Math.max(1, ...frequency.map(([, entry]) => entry.count));
  if (frequency.length === 0) return null;
  return (
    <div className="space-y-3 border-t border-border pt-5">
      <p className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground">Top detected signals</p>
      {frequency.map(([label, entry]) => (
        <Bar key={label} label={label} value={String(entry.count)} pct={(entry.count / max) * 100} tone={signalTone[entry.severity] ?? "bg-brand"} />
      ))}
    </div>
  );
}
import { severityCount, severityDistribution, campaignClusters } from "@/lib/stats";
import { verifyEvidence, type StoredScan } from "@/lib/store";

export function OverviewPage({ scans, openScanner, openCase, navigate, notify, loadDemo }: { scans: StoredScan[]; openScanner: () => void; openCase: (id: string) => void; navigate: (page: PageKey) => void; notify: (msg: string) => void; loadDemo: () => void }) {
  const distribution = severityDistribution(scans);
  const latest = scans[0];
  const clusters = campaignClusters(scans).filter((c) => c.count >= 2);

  return (
    <>
      <PageHeader
        title="Threat operations overview"
        description="Live numbers computed from every evidence scan stored in this workspace. No sample data is shown unless you load it explicitly."
        actions={
          <>
            <Button variant="outline" onClick={() => navigate("evidence")}><Database className="size-4" />Evidence vault</Button>
            <Button onClick={openScanner}><Zap className="size-4" />Analyze email</Button>
          </>
        }
      />

      {scans.length === 0 && (
        <section className="mb-6 overflow-hidden border border-brand/30 bg-gradient-to-br from-brand/10 via-surface to-surface">
          <div className="flex flex-col gap-6 p-6 lg:flex-row lg:items-center lg:justify-between">
            <div className="max-w-xl">
              <p className="mb-2 font-mono text-[10px] font-semibold uppercase tracking-[0.2em] text-brand">Welcome to AegisTrace</p>
              <h2 className="font-display text-2xl font-semibold tracking-tight text-foreground">First scan takes under 30 seconds</h2>
              <p className="mt-2 text-sm leading-6 text-muted-foreground">Paste a suspicious email or upload a .eml file. You get an explainable verdict, the relay path, and a verifiable evidence fingerprint — all processed in your browser.</p>
              <ol className="mt-4 space-y-1.5 text-xs text-muted-foreground">
                <li className="flex items-center gap-2"><span className="flex size-4 items-center justify-center rounded-full bg-brand/15 font-mono text-[9px] font-semibold text-brand">1</span>Add the raw email or .eml evidence</li>
                <li className="flex items-center gap-2"><span className="flex size-4 items-center justify-center rounded-full bg-brand/15 font-mono text-[9px] font-semibold text-brand">2</span>Get an explainable risk verdict with findings</li>
                <li className="flex items-center gap-2"><span className="flex size-4 items-center justify-center rounded-full bg-brand/15 font-mono text-[9px] font-semibold text-brand">3</span>Evidence is stored with a re-verifiable SHA-256 fingerprint</li>
              </ol>
            </div>
            <div className="flex shrink-0 flex-col gap-2 sm:flex-row lg:flex-col">
              <Button onClick={openScanner}><Zap className="size-4" />Analyze an email</Button>
              <Button variant="outline" onClick={loadDemo}><FlaskConical className="size-4" />Or explore with demo data</Button>
            </div>
          </div>
        </section>
      )}

      <section className="mb-6 grid gap-px border border-border bg-border sm:grid-cols-2 xl:grid-cols-4" aria-label="Live summary">
        <Stat label="Emails analyzed" value={String(scans.length)} sub={`${scans.length === 1 ? "evidence record" : "evidence records"} stored locally`} icon={MailWarning} tone="brand" />
        <Stat label="Latest risk index" value={latest ? String(latest.result.riskScore) : "—"} suffix={latest ? "/100" : ""} sub={latest ? `${latest.result.riskLabel} · ${timeAgo(latest.scannedAt)}` : "No scans yet"} icon={Zap} tone={latest && latest.result.riskLabel === "Critical" ? "critical" : latest?.result.riskLabel === "High" ? "warning" : "brand"} />
        <Stat label="Critical alerts" value={String(severityCount(scans, "Critical"))} sub="need attention" icon={AlertTriangle} tone="critical" />
        <Stat label="Evidence fingerprints" value={String(scans.length)} sub="SHA-256 · stored locally" icon={Fingerprint} tone="safe" />
      </section>

      {latest && <LatestScanCard scan={latest} notify={notify} />}

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1.4fr)_minmax(340px,0.8fr)]">
        <Card labelledBy="queue-heading">
          <CardHeader id="queue-heading" title="Investigation queue" subtitle="Prioritized by explainable threat score — from real stored scans" right={<Button variant="ghost" size="sm" onClick={openScanner}>New scan <ArrowUpRight className="size-3.5" /></Button>} />
          {scans.length === 0 ? (
            <EmptyState title="No investigations yet" detail="Analyze an email to start your first investigation, or load the demo dataset to see the workflow." action={<Button size="sm" onClick={openScanner}>Analyze email</Button>} />
          ) : (
            <div className="divide-y divide-border">
              {scans.map((scan) => (
                <button key={scan.id} onClick={() => openCase(scan.id)} className="flex w-full items-center gap-3 p-4 text-left transition-colors hover:bg-surface-elevated sm:gap-4">
                  <div className={`flex size-9 shrink-0 items-center justify-center text-[11px] font-semibold ${scan.result.riskLabel === "Critical" ? "bg-status-critical/15 text-status-critical" : scan.result.riskLabel === "High" ? "bg-status-warning/15 text-status-warning" : scan.result.riskLabel === "Medium" ? "bg-brand/10 text-brand" : "bg-status-safe/10 text-status-safe"}`}>
                    {scan.result.sender.slice(0, 2).toUpperCase()}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                      <p className="text-xs font-semibold text-foreground">{scan.result.sender}</p>
                      <span className="text-[10px] text-muted-foreground">{timeAgo(scan.scannedAt)}</span>
                      {scan.demo && <DemoTag />}
                    </div>
                    <p className="mt-1 truncate text-sm text-muted-foreground">{scan.result.subject}</p>
                  </div>
                  <div className="flex shrink-0 flex-col items-end gap-1">
                    <span className={`font-mono text-sm font-semibold ${scan.result.riskLabel === "Critical" ? "text-status-critical" : scan.result.riskLabel === "High" ? "text-status-warning" : "text-brand"}`}>{scan.result.riskScore}</span>
                    <span className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground">risk</span>
                  </div>
                  <ChevronRight className="hidden size-4 text-muted-foreground sm:block" />
                </button>
              ))}
            </div>
          )}
        </Card>

        <Card labelledBy="posture-heading">
          <CardHeader id="posture-heading" title="Detection posture" subtitle="Distribution of real scan verdicts" right={<Button variant="ghost" size="icon" aria-label="View investigations" onClick={() => navigate("investigations")}><ArrowUpRight className="size-4" /></Button>} />
          {scans.length === 0 ? (
            <EmptyState title="Nothing to measure yet" detail="Run a few scans and the severity distribution will appear here." />
          ) : (
            <div className="space-y-5 p-5">
              <div className="flex items-center gap-6">
                <div className="relative size-36 shrink-0">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={[
                        { name: "Critical", value: distribution.Critical, fill: severityColors["Critical"] },
                        { name: "High", value: distribution.High, fill: severityColors["High"] },
                        { name: "Medium", value: distribution.Medium, fill: severityColors["Medium"] },
                        { name: "Low", value: distribution.Low, fill: severityColors["Low"] },
                      ]} dataKey="value" nameKey="name" innerRadius={46} outerRadius={64} paddingAngle={2} strokeWidth={0}>
                        {(["Critical", "High", "Medium", "Low"] as const).map((key) => <Cell key={key} fill={severityColors[key]} />)}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                    <p className="font-display text-xl font-semibold text-foreground">{scans.length}</p>
                    <p className="font-mono text-[8px] uppercase tracking-wider text-muted-foreground">scans</p>
                  </div>
                </div>
                <div className="min-w-0 flex-1 space-y-3">
                  <DotLegend color="bg-status-critical" label="Critical" value={String(distribution.Critical)} />
                  <DotLegend color="bg-status-warning" label="High" value={String(distribution.High)} />
                  <DotLegend color="bg-brand" label="Medium" value={String(distribution.Medium)} />
                  <DotLegend color="bg-muted-foreground/40" label="Low / clean" value={String(distribution.Low)} />
                </div>
              </div>
              <TopSignals scans={scans} />
            </div>
          )}
        </Card>
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-[minmax(0,1.5fr)_minmax(330px,0.7fr)]">
        <RelayTraceCard scans={scans} navigate={navigate} />
        <Card labelledBy="campaign-heading">
          <CardHeader id="campaign-heading" title="Campaign intelligence" subtitle="Correlated infrastructure from your scans" right={<Button variant="ghost" size="icon" aria-label="Open campaign graph" onClick={() => navigate("campaign")}><Network className="size-4" /></Button>} />
          {clusters.length === 0 ? (
            <EmptyState title="No shared infrastructure yet" detail="When two or more scans share an origin IP or sender domain, the correlation appears here automatically." />
          ) : (
            <div className="space-y-4 p-5">
              {clusters.map((cluster) => (
                <button key={cluster.key} onClick={() => navigate("campaign")} className="flex w-full items-center gap-3 border-b border-border pb-4 text-left last:border-0 last:pb-0">
                  <div className={`flex size-8 items-center justify-center ${cluster.worstRisk >= 75 ? "bg-status-critical/10 text-status-critical" : cluster.worstRisk >= 55 ? "bg-status-warning/10 text-status-warning" : "bg-brand/10 text-brand"}`}><Network className="size-4" /></div>
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-xs font-semibold text-foreground">{cluster.label}</p>
                    <p className="mt-1 font-mono text-[10px] text-muted-foreground">{cluster.count} scan{cluster.count === 1 ? "" : "s"} · {cluster.origins.length} origin{cluster.origins.length === 1 ? "" : "s"}</p>
                  </div>
                  <div className="text-right">
                    <p className={`font-mono text-sm font-semibold ${cluster.worstRisk >= 75 ? "text-status-critical" : cluster.worstRisk >= 55 ? "text-status-warning" : "text-brand"}`}>{cluster.worstRisk}</p>
                    <p className="font-mono text-[9px] uppercase text-muted-foreground">worst risk</p>
                  </div>
                </button>
              ))}
            </div>
          )}
        </Card>
      </div>

      <section className="mt-6 border border-border bg-surface" aria-labelledby="integrity-heading">
        <div className="grid sm:grid-cols-3">
          <div className="flex items-center gap-4 border-b border-border p-5 last:border-b-0 sm:border-b-0 sm:border-r sm:last:border-r-0">
            <div className="flex size-9 items-center justify-center bg-brand/10 text-brand"><Fingerprint className="size-4" /></div>
            <div><p className="text-xs text-muted-foreground">SHA-256 evidence records</p><div className="mt-1 flex items-baseline gap-2"><span className="font-display text-xl font-semibold">{scans.length}</span><span className="font-mono text-[9px] text-status-safe">stored locally</span></div></div>
          </div>
          <div className="flex items-center gap-4 border-b border-border p-5 last:border-b-0 sm:border-b-0 sm:border-r sm:last:border-r-0">
            <div className="flex size-9 items-center justify-center bg-brand/10 text-brand"><Server className="size-4" /></div>
            <div><p className="text-xs text-muted-foreground">Reconstructed relay hops</p><div className="mt-1 flex items-baseline gap-2"><span className="font-display text-xl font-semibold">{scans.reduce((sum, s) => sum + s.result.hops.length, 0)}</span><span className="font-mono text-[9px] text-muted-foreground">from Received headers</span></div></div>
          </div>
          <div className="flex items-center gap-4 border-b border-border p-5 last:border-b-0 sm:border-b-0">
            <div className="flex size-9 items-center justify-center bg-brand/10 text-brand"><CheckCircle2 className="size-4" /></div>
            <div><p className="text-xs text-muted-foreground">Evidence integrity</p><div className="mt-1 flex items-baseline gap-2"><span className="font-display text-xl font-semibold">Verifiable</span><span className="font-mono text-[9px] text-status-safe">re-hash any record</span></div></div>
          </div>
        </div>
      </section>
    </>
  );
}

function LatestScanCard({ scan, notify }: { scan: StoredScan; notify: (msg: string) => void }) {
  const [verifyState, setVerifyState] = useState<"idle" | "checking" | "ok" | "fail">("idle");

  const runVerify = async () => {
    setVerifyState("checking");
    const { matches } = await verifyEvidence(scan.raw, scan.result.evidenceHash);
    setVerifyState(matches ? "ok" : "fail");
    notify(matches ? `Integrity verified — fingerprint matches the stored evidence (${scan.caseId}).` : `Integrity check FAILED for ${scan.caseId}.`);
  };

  return (
    <section className="mb-6 border border-brand/30 bg-surface" aria-labelledby="latest-case-heading">
      <div className="flex flex-col gap-4 border-b border-border p-5 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <Badge variant="outline" className="border-brand/40 bg-brand/10 text-brand">Latest case</Badge>
            <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{scan.caseId} · {scan.result.headersFound} header values parsed · {timeAgo(scan.scannedAt)}</span>
            {scan.demo && <DemoTag />}
          </div>
          <h2 id="latest-case-heading" className="max-w-3xl truncate font-display text-lg font-semibold">{scan.result.subject}</h2>
          <p className="mt-1 text-xs text-muted-foreground">From {scan.result.senderAddress} · {scan.result.receivedAt}</p>
        </div>
        <div className="flex shrink-0 items-center gap-3">
          <div className={`flex items-center gap-3 border px-4 py-3 ${scan.result.riskLabel === "Critical" || scan.result.riskLabel === "High" ? "border-status-critical/30 bg-status-critical/10" : "border-status-safe/30 bg-status-safe/10"}`}>
            <div className="text-right">
              <p className={`font-mono text-[9px] uppercase tracking-wider ${scan.result.riskLabel === "Critical" || scan.result.riskLabel === "High" ? "text-status-critical" : "text-status-safe"}`}>Threat score</p>
              <p className={`font-display text-2xl font-semibold ${scan.result.riskLabel === "Critical" || scan.result.riskLabel === "High" ? "text-status-critical" : "text-status-safe"}`}>{scan.result.riskScore}<span className="font-mono text-xs">/100</span></p>
            </div>
            {scan.result.riskLabel === "Critical" || scan.result.riskLabel === "High" ? <AlertTriangle className="size-5 text-status-critical" /> : <CheckCircle2 className="size-5 text-status-safe" />}
          </div>
          <SeverityBadge risk={scan.result.riskLabel} />
        </div>
      </div>
      <div className="grid gap-5 p-5 xl:grid-cols-[1.4fr_0.8fr_0.8fr]">
        <div>
          <p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Explainable findings</p>
          <div className="space-y-2">
            {scan.result.findings.map((finding) => (
              <div key={finding.label} className="flex items-start gap-3 border-b border-border pb-2 last:border-0">
                <span className={`mt-1 size-1.5 shrink-0 rounded-full ${finding.severity === "critical" ? "bg-status-critical" : finding.severity === "high" ? "bg-status-warning" : finding.severity === "medium" ? "bg-brand" : "bg-status-safe"}`} />
                <div>
                  <p className="text-xs font-medium text-foreground">{finding.label}</p>
                  <p className="mt-0.5 text-[11px] leading-5 text-muted-foreground">{finding.detail}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="border-l border-border pl-5">
          <p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Message routing</p>
          <dl className="space-y-3 text-xs">
            <div><dt className="text-muted-foreground">Reply-to</dt><dd className="mt-1 break-all font-mono text-foreground">{scan.result.replyTo}</dd></div>
            <div><dt className="text-muted-foreground">Return-path</dt><dd className="mt-1 break-all font-mono text-foreground">{scan.result.returnPath}</dd></div>
            <div><dt className="text-muted-foreground">Relay hops</dt><dd className="mt-1 font-mono text-brand">{scan.result.hops.length} reconstructed</dd></div>
          </dl>
        </div>
        <div className="border-l border-border pl-5">
          <p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Evidence fingerprint</p>
          <div className="flex items-start gap-2"><Globe2 className="mt-0.5 size-4 shrink-0 text-brand" /><p className="break-all font-mono text-[10px] leading-5 text-foreground">{scan.result.evidenceHash}</p></div>
          <Button variant="outline" size="sm" className="mt-3" onClick={() => void runVerify()} disabled={verifyState === "checking"}>
            <RefreshCw className={`size-3.5 ${verifyState === "checking" ? "animate-spin" : ""}`} />
            {verifyState === "ok" ? "Verified ✓" : verifyState === "fail" ? "Mismatch — retry" : verifyState === "checking" ? "Verifying…" : "Re-verify hash"}
          </Button>
        </div>
      </div>
    </section>
  );
}

function RelayTraceCard({ scans, navigate }: { scans: StoredScan[]; navigate: (page: PageKey) => void }) {
  const latest = scans[0];
  const hops = useMemo(() => {
    if (!latest) return [];
    const reversed = [...latest.result.hops];
    if (reversed[0]?.status === "relay" && reversed.at(-1)?.status === "origin") reversed.reverse();
    return reversed;
  }, [latest]);

  return (
    <Card className="overflow-hidden" labelledBy="trace-heading">
      <CardHeader id="trace-heading" title="Relay trace reconstruction" subtitle={latest ? `Parsed from ${latest.result.hops.length} real Received header${latest.result.hops.length === 1 ? "" : "s"} — case ${latest.caseId}` : "Parsed from real Received headers"} right={<Button variant="outline" size="sm" onClick={() => navigate("relay")}><Network className="size-3.5" />Open trace</Button>} />
      {!latest || hops.length === 0 ? (
        <EmptyState title="No relay trace yet" detail="Analyze an email that includes Received headers to reconstruct its forwarding path." />
      ) : (
        <div className="space-y-0 p-5">
          {hops.map((hop, index) => {
            const isOrigin = index === 0;
            const isLast = index === hops.length - 1;
            const disclosed = hop.ip !== "Not disclosed";
            return (
              <div key={`${hop.ip}-${index}`} className="relative flex gap-4 pb-6 last:pb-0">
                {!isLast && <span className="absolute left-[13px] top-7 h-full w-px bg-border" />}
                <div className={`relative z-10 flex size-7 shrink-0 items-center justify-center border ${isOrigin ? "border-status-critical text-status-critical" : "border-brand text-brand"} bg-surface`}>
                  {isOrigin ? <AlertTriangle className="size-3.5" /> : isLast ? <Server className="size-3.5" /> : <Network className="size-3.5" />}
                </div>
                <div className="min-w-0 pt-0.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-xs font-semibold text-foreground">{isOrigin ? "Earliest origin" : isLast ? "Destination MX" : `Relay ${index}`}</p>
                    <span className="font-mono text-[10px] text-muted-foreground">{hop.detail}</span>
                  </div>
                  <p className={`mt-1 font-mono text-xs ${disclosed ? "text-foreground" : "text-muted-foreground"}`}>{hop.ip}</p>
                </div>
              </div>
            );
          })}
          <div className="mt-5 flex items-center gap-2 border border-status-warning/20 bg-status-warning/5 px-3 py-2 font-mono text-[10px] text-status-warning">
            <AlertTriangle className="size-3" />
            Confidence is header-based only — IP reputation and geolocation enrichment arrive with the server integration.
          </div>
        </div>
      )}
    </Card>
  );
}
