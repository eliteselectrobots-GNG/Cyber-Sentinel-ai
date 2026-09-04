import { AlertTriangle, CheckCircle2, ChevronRight, Download, Fingerprint, Globe2, Link2, Mail, Network, RefreshCw, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { verifyEvidence, type StoredScan } from "@/lib/store";
import { extractIocs, iocTotals, relatedCases, type IoC } from "@/lib/iocs";
import { DemoTag, EmptyState, IntegrityBadge, PageHeader, SeverityBadge, timeAgo, type PageKey } from "./ui";

function downloadReport(scan: StoredScan) {
  const iocs = extractIocs(scan.raw, scan.result);
  const lines = [
    `AEGISTRACE — FORENSIC CASE REPORT`,
    `=================================`,
    `Case id:      ${scan.caseId}`,
    `Scanned at:   ${new Date(scan.scannedAt).toISOString()}`,
    `Subject:      ${scan.result.subject}`,
    `From:         ${scan.result.sender} <${scan.result.senderAddress}>`,
    `Reply-To:     ${scan.result.replyTo}`,
    `Return-Path:  ${scan.result.returnPath}`,
    `Date:         ${scan.result.receivedAt}`,
    `Risk score:   ${scan.result.riskScore}/100 (${scan.result.riskLabel})`,
    ``,
    `FINDINGS`,
    `--------`,
    ...scan.result.findings.map((f) => `[${f.severity.toUpperCase()}] ${f.label} — ${f.detail}`),
    ``,
    `RELAY PATH`,
    `----------`,
    ...scan.result.hops.map((h, i) => `${i + 1}. ${h.label}: ${h.ip} (${h.status}) — ${h.detail}`),
    ``,
    `INDICATORS OF COMPROMISE`,
    `------------------------`,
    ...iocs.map((ioc) => `${ioc.type.toUpperCase()}\t${ioc.value}\t(${ioc.source})`),
    ``,
    `EVIDENCE`,
    `--------`,
    `SHA-256 fingerprint: ${scan.result.evidenceHash}`,
    `Headers parsed:      ${scan.result.headersFound}`,
    ``,
    `RAW EVIDENCE SUBMITTED`,
    `----------------------`,
    scan.raw,
  ];
  const blob = new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `${scan.caseId}-forensic-report.txt`;
  anchor.click();
  URL.revokeObjectURL(url);
}

type DetailTab = "Overview" | "Header analysis" | "IoCs" | "Timeline" | "Body";

const tabs: DetailTab[] = ["Overview", "Header analysis", "IoCs", "Timeline", "Body"];

export function InvestigationsPage({
  scans,
  selectedId,
  onSelect,
  onDelete,
  navigate,
  notify,
}: {
  scans: StoredScan[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onDelete: (id: string) => void;
  navigate: (page: PageKey) => void;
  notify: (msg: string) => void;
}) {
  const selected = scans.find((s) => s.id === selectedId) ?? scans[0] ?? null;

  return (
    <>
      <PageHeader title="Investigations" description="Every case stored in this workspace, opened from the raw evidence that produced it." />
      {scans.length === 0 ? (
        <div className="border border-border bg-surface">
          <EmptyState title="No investigations yet" detail="Analyze an email to create your first case. The raw content, verdict, and fingerprint are stored together." action={<Button onClick={() => navigate("overview")}>Go to Overview</Button>} />
        </div>
      ) : (
        <div className="grid gap-6 xl:grid-cols-[minmax(280px,0.55fr)_minmax(0,1.45fr)]">
          <div className="max-h-[75vh] divide-y divide-border overflow-y-auto border border-border bg-surface">
            {scans.map((scan) => (
              <button key={scan.id} onClick={() => onSelect(scan.id)} className={`flex w-full items-center gap-3 p-4 text-left transition-colors hover:bg-surface-elevated ${selected?.id === scan.id ? "bg-surface-elevated" : ""}`}>
                <div className={`flex size-9 shrink-0 items-center justify-center text-[11px] font-semibold ${scan.result.riskLabel === "Critical" ? "bg-status-critical/15 text-status-critical" : scan.result.riskLabel === "High" ? "bg-status-warning/15 text-status-warning" : scan.result.riskLabel === "Medium" ? "bg-brand/10 text-brand" : "bg-status-safe/10 text-status-safe"}`}>{scan.result.sender.slice(0, 2).toUpperCase()}</div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2"><p className="truncate text-xs font-semibold text-foreground">{scan.result.sender}</p><span className="shrink-0 font-mono text-[9px] text-muted-foreground">{scan.caseId}</span>{scan.demo && <DemoTag />}</div>
                  <p className="mt-1 truncate text-sm text-muted-foreground">{scan.result.subject}</p>
                  <p className="mt-1 font-mono text-[9px] uppercase tracking-wider text-muted-foreground">{timeAgo(scan.scannedAt)} · score {scan.result.riskScore}</p>
                </div>
              </button>
            ))}
          </div>

          {selected && <CaseDetail scan={selected} scans={scans} onSelect={onSelect} onDelete={onDelete} notify={notify} />}
        </div>
      )}
    </>
  );
}

function CaseDetail({ scan, scans, onSelect, onDelete, notify }: { scan: StoredScan; scans: StoredScan[]; onSelect: (id: string) => void; onDelete: (id: string) => void; notify: (msg: string) => void }) {
  const [tab, setTab] = useState<DetailTab>("Overview");
  const [verifyState, setVerifyState] = useState<"idle" | "checking" | "ok" | "fail">("idle");

  const iocs = useMemo(() => extractIocs(scan.raw, scan.result), [scan]);
  const totals = useMemo(() => iocTotals(iocs), [iocs]);
  const related = useMemo(() => relatedCases(scan, scans), [scan, scans]);

  const runVerify = async () => {
    setVerifyState("checking");
    const { matches } = await verifyEvidence(scan.raw, scan.result.evidenceHash);
    setVerifyState(matches ? "ok" : "fail");
    notify(matches ? `Integrity verified for ${scan.caseId}.` : `Integrity check FAILED for ${scan.caseId}.`);
  };

  const originHop = scan.result.hops.find((hop) => hop.status === "origin");
  const highRisk = scan.result.riskLabel === "Critical" || scan.result.riskLabel === "High";

  return (
    <div className="border border-border bg-surface">
      <div className="flex flex-col gap-4 border-b border-border p-5 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <SeverityBadge risk={scan.result.riskLabel} />
            <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{scan.caseId} · {scan.result.headersFound} header values parsed · {timeAgo(scan.scannedAt)}</span>
            {scan.demo && <DemoTag />}
          </div>
          <h2 className="font-display text-lg font-semibold leading-6">{scan.result.subject}</h2>
          <p className="mt-1 break-all text-xs text-muted-foreground">From {scan.result.senderAddress} · {scan.result.receivedAt}</p>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-2">
          <div className="flex items-center gap-3 border border-border px-4 py-3">
            <p className={`font-display text-2xl font-semibold ${highRisk ? "text-status-critical" : "text-status-safe"}`}>{scan.result.riskScore}<span className="font-mono text-xs">/100</span></p>
            {highRisk ? <AlertTriangle className="size-5 text-status-critical" /> : <CheckCircle2 className="size-5 text-status-safe" />}
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => downloadReport(scan)}><Download className="size-3.5" />Report</Button>
            <Button variant="outline" size="sm" onClick={() => void runVerify()} disabled={verifyState === "checking"}><RefreshCw className={`size-3.5 ${verifyState === "checking" ? "animate-spin" : ""}`} />Re-verify</Button>
            <Button variant="ghost" size="icon" aria-label="Delete case" className="text-muted-foreground hover:text-status-critical" onClick={() => onDelete(scan.id)}><Trash2 className="size-4" /></Button>
          </div>
        </div>
      </div>

      <div className="flex gap-1 overflow-x-auto border-b border-border px-5 pt-3">
        {tabs.map((name) => (
          <button key={name} onClick={() => setTab(name)} className={`whitespace-nowrap border-b-2 px-2 pb-3 text-xs font-medium transition-colors ${tab === name ? "border-brand text-brand" : "border-transparent text-muted-foreground hover:text-foreground"}`}>
            {name}
            {name === "IoCs" && <span className="ml-1.5 font-mono text-[9px] text-muted-foreground">{iocs.length}</span>}
            {name === "Header analysis" && <span className="ml-1.5 font-mono text-[9px] text-muted-foreground">{scan.result.headersFound}</span>}
          </button>
        ))}
      </div>

      <div className="p-5">
        {tab === "Overview" && (
          <div className="grid gap-6 lg:grid-cols-2">
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
            <div className="space-y-6">
              <div>
                <p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Routing & attribution</p>
                <dl className="space-y-3 text-xs">
                  <div className="flex justify-between gap-4"><dt className="text-muted-foreground">Reply-to</dt><dd className="break-all text-right font-mono text-foreground">{scan.result.replyTo}</dd></div>
                  <div className="flex justify-between gap-4"><dt className="text-muted-foreground">Return-path</dt><dd className="break-all text-right font-mono text-foreground">{scan.result.returnPath}</dd></div>
                  <div className="flex justify-between gap-4"><dt className="text-muted-foreground">Relay hops</dt><dd className="font-mono text-brand">{scan.result.hops.length} reconstructed</dd></div>
                  <div className="flex justify-between gap-4"><dt className="text-muted-foreground">Earliest origin</dt><dd className="break-all text-right font-mono text-foreground">{originHop?.ip ?? "Not disclosed"}</dd></div>
                  <div className="flex justify-between gap-4"><dt className="text-muted-foreground">IoCs found</dt><dd className="font-mono text-foreground">{iocs.length} ({totals.IP} IP · {totals.URL} URL)</dd></div>
                </dl>
              </div>
              <div>
                <p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Evidence fingerprint</p>
                <div className="flex items-start gap-2"><Fingerprint className="mt-0.5 size-4 shrink-0 text-brand" /><p className="break-all font-mono text-[10px] leading-5 text-foreground">{scan.result.evidenceHash}</p></div>
                <div className="mt-3 flex items-center gap-2">
                  {verifyState === "ok" && <IntegrityBadge verified />}
                  {verifyState === "fail" && <IntegrityBadge verified={false} />}
                  <span className="text-[11px] leading-5 text-muted-foreground">Re-running the exact submitted content through the engine proves chain of custody.</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {tab === "Header analysis" && <HeaderAnalysis scan={scan} />}
        {tab === "IoCs" && <IocTab iocs={iocs} />}
        {tab === "Timeline" && <TimelineTab scan={scan} />}
        {tab === "Body" && <BodyTab scan={scan} />}
      </div>

      {related.length > 0 && (
        <div className="border-t border-border p-5">
          <p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Related cases · shared sender domain or origin infrastructure</p>
          <div className="divide-y divide-border">
            {related.slice(0, 5).map((caseScan) => (
              <button key={caseScan.id} onClick={() => onSelect(caseScan.id)} className="flex w-full items-center gap-3 py-2.5 text-left transition-colors hover:bg-surface-elevated">
                <div className={`size-2 shrink-0 rounded-full ${caseScan.result.riskLabel === "Critical" ? "bg-status-critical" : caseScan.result.riskLabel === "High" ? "bg-status-warning" : "bg-brand"}`} />
                <div className="min-w-0 flex-1">
                  <p className="truncate text-xs font-medium text-foreground">{caseScan.result.subject}</p>
                  <p className="mt-0.5 font-mono text-[9px] text-muted-foreground">{caseScan.caseId} · {timeAgo(caseScan.scannedAt)}</p>
                </div>
                <span className={`font-mono text-xs ${caseScan.result.riskLabel === "Critical" || caseScan.result.riskLabel === "High" ? "text-status-critical" : "text-brand"}`}>{caseScan.result.riskScore}</span>
                <ChevronRight className="size-4 text-muted-foreground" />
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function HeaderAnalysis({ scan }: { scan: StoredScan }) {
  const rawHeaderBlock = scan.raw.split(/\r?\n\r?\n/)[0] ?? scan.raw;
  const rows: { label: string; value: string }[] = [
    { label: "From", value: `${scan.result.sender} <${scan.result.senderAddress}>` },
    { label: "Reply-To", value: scan.result.replyTo },
    { label: "Return-Path", value: scan.result.returnPath },
    { label: "Subject", value: scan.result.subject },
    { label: "Date", value: scan.result.receivedAt },
    { label: "Headers parsed", value: String(scan.result.headersFound) },
    { label: "Relay hops", value: `${scan.result.hops.length} (${scan.result.hops.map((hop) => hop.ip).join(" → ")})` },
  ];
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <div>
        <p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Key routing fields</p>
        <dl className="space-y-3 text-xs">
          {rows.map((row) => (
            <div key={row.label} className="flex justify-between gap-4 border-b border-border pb-2">
              <dt className="shrink-0 text-muted-foreground">{row.label}</dt>
              <dd className="break-all text-right font-mono text-foreground">{row.value}</dd>
            </div>
          ))}
        </dl>
      </div>
      <div>
        <p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Raw header block</p>
        <pre className="max-h-[420px] overflow-auto border border-border bg-shell p-3 font-mono text-[10px] leading-5 text-foreground">{rawHeaderBlock}</pre>
      </div>
    </div>
  );
}

const iocTypeMeta: Record<IoC["type"], { icon: typeof Globe2; color: string }> = {
  IP: { icon: Globe2, color: "bg-status-critical/10 text-status-critical border-status-critical/30" },
  Domain: { icon: Network, color: "bg-status-warning/10 text-status-warning border-status-warning/30" },
  URL: { icon: Link2, color: "bg-brand/10 text-brand border-brand/30" },
  Email: { icon: Mail, color: "bg-status-safe/10 text-status-safe border-status-safe/30" },
};

function IocTab({ iocs }: { iocs: IoC[] }) {
  if (iocs.length === 0) {
    return <EmptyState title="No indicators extracted" detail="No IPs, domains, URLs, or addresses could be extracted from this evidence." />;
  }
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap gap-4 text-xs">
        <span><b className="font-mono text-foreground">{iocs.filter((i) => i.type === "IP").length}</b> <span className="text-muted-foreground">IPs</span></span>
        <span><b className="font-mono text-foreground">{iocs.filter((i) => i.type === "Domain").length}</b> <span className="text-muted-foreground">domains</span></span>
        <span><b className="font-mono text-foreground">{iocs.filter((i) => i.type === "URL").length}</b> <span className="text-muted-foreground">URLs</span></span>
        <span><b className="font-mono text-foreground">{iocs.filter((i) => i.type === "Email").length}</b> <span className="text-muted-foreground">addresses</span></span>
      </div>
      <div className="grid gap-2 sm:grid-cols-2">
        {iocs.map((ioc) => {
          const meta = iocTypeMeta[ioc.type];
          const Icon = meta.icon;
          return (
            <div key={`${ioc.type}:${ioc.value}`} className={`flex items-start gap-3 border p-3 ${meta.color}`}>
              <Icon className="mt-0.5 size-4 shrink-0" />
              <div className="min-w-0">
                <p className="break-all font-mono text-xs text-foreground">{ioc.value}</p>
                <p className="mt-1 font-mono text-[9px] uppercase tracking-wider opacity-70">{ioc.type} · {ioc.source}</p>
              </div>
            </div>
          );
        })}
      </div>
      <p className="text-[11px] leading-5 text-muted-foreground">Reputation lookups for these indicators (threat feeds, URL scanners) arrive with the server integration.</p>
    </div>
  );
}

function TimelineTab({ scan }: { scan: StoredScan }) {
  const events = useMemo(() => {
    const items: { time: string; label: string; detail: string; kind: "safe" | "warn" | "critical" | "info" }[] = [
      { time: scan.result.receivedAt, label: "Message received / dated", detail: `Sender ${scan.result.senderAddress}`, kind: "info" },
    ];
    scan.result.hops.forEach((hop, index) => {
      const datePart = hop.detail.includes(";") ? hop.detail.split(";").at(-1)?.trim() : null;
      items.push({
        time: datePart ?? `Hop ${index + 1}`,
        label: hop.status === "origin" ? "Earliest origin identified" : `Relay hop ${index + 1}`,
        detail: `${hop.ip} — ${hop.detail}`,
        kind: hop.status === "origin" ? "critical" : "warn",
      });
    });
    scan.result.findings.forEach((finding) => {
      items.push({
        time: "During analysis",
        label: finding.label,
        detail: finding.detail,
        kind: finding.severity === "critical" ? "critical" : finding.severity === "high" ? "warn" : "info",
      });
    });
    items.push({
      time: new Date(scan.scannedAt).toLocaleTimeString(),
      label: "Analysis completed",
      detail: `Risk score ${scan.result.riskScore}/100 (${scan.result.riskLabel}) — evidence fingerprint ${scan.result.evidenceHash.slice(0, 12)}…`,
      kind: scan.result.riskLabel === "Critical" || scan.result.riskLabel === "High" ? "critical" : "safe",
    });
    return items;
  }, [scan]);

  return (
    <div className="space-y-0">
      {events.map((event, index) => {
        const color = event.kind === "critical" ? "border-status-critical bg-status-critical/15 text-status-critical" : event.kind === "warn" ? "border-status-warning bg-status-warning/15 text-status-warning" : event.kind === "safe" ? "border-status-safe bg-status-safe/15 text-status-safe" : "border-brand bg-brand/10 text-brand";
        const dot = event.kind === "critical" ? "bg-status-critical" : event.kind === "warn" ? "bg-status-warning" : event.kind === "safe" ? "bg-status-safe" : "bg-brand";
        return (
          <div key={`${event.label}-${index}`} className="relative flex gap-4 pb-6 last:pb-0">
            {index < events.length - 1 && <span className="absolute left-[5px] top-6 h-full w-px bg-border" />}
            <div className="relative z-10 flex flex-col items-center">
              <span className={`mt-1 size-2.5 rounded-full ${dot}`} />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <p className="text-xs font-semibold text-foreground">{event.label}</p>
                <span className={`border px-1.5 py-0.5 font-mono text-[9px] ${color}`}>{event.time}</span>
              </div>
              <p className="mt-1 break-all text-[11px] leading-5 text-muted-foreground">{event.detail}</p>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function BodyTab({ scan }: { scan: StoredScan }) {
  return (
    <div className="space-y-4">
      <p className="text-xs text-muted-foreground">Extracted message preview from the raw evidence body.</p>
      <div className="border border-border bg-shell p-4">
        <p className="whitespace-pre-wrap break-words font-mono text-xs leading-6 text-foreground">{scan.result.bodyPreview}</p>
      </div>
      <div className="flex items-center gap-2 border border-border bg-surface-elevated p-3 text-[11px] text-muted-foreground">
        <Badge variant="outline" className="border-brand/40 bg-brand/10 text-brand">Full text retained</Badge>
        <span>The complete raw message is preserved as evidence and can be re-verified at any time.</span>
      </div>
    </div>
  );
}
