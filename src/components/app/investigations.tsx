import { AlertTriangle, CheckCircle2, Download, RefreshCw, Trash2 } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { verifyEvidence, type StoredScan } from "@/lib/store";
import { DemoTag, EmptyState, IntegrityBadge, PageHeader, SeverityBadge, timeAgo, type PageKey } from "./ui";

function downloadReport(scan: StoredScan) {
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
        <div className="grid gap-6 xl:grid-cols-[minmax(280px,0.6fr)_minmax(0,1.4fr)]">
          <div className="max-h-[70vh] divide-y divide-border overflow-y-auto border border-border bg-surface">
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

          {selected && <CaseDetail scan={selected} onDelete={onDelete} notify={notify} />}
        </div>
      )}
    </>
  );
}

function CaseDetail({ scan, onDelete, notify }: { scan: StoredScan; onDelete: (id: string) => void; notify: (msg: string) => void }) {
  const [verifyState, setVerifyState] = useState<"idle" | "checking" | "ok" | "fail">("idle");

  const runVerify = async () => {
    setVerifyState("checking");
    const { matches } = await verifyEvidence(scan.raw, scan.result.evidenceHash);
    setVerifyState(matches ? "ok" : "fail");
    notify(matches ? `Integrity verified for ${scan.caseId}.` : `Integrity check FAILED for ${scan.caseId}.`);
  };

  const riskColor = scan.result.riskLabel === "Critical" || scan.result.riskLabel === "High" ? "text-status-critical" : "text-status-safe";

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
            <p className={`font-display text-2xl font-semibold ${riskColor}`}>{scan.result.riskScore}<span className="font-mono text-xs">/100</span></p>
            {scan.result.riskLabel === "Critical" || scan.result.riskLabel === "High" ? <AlertTriangle className="size-5 text-status-critical" /> : <CheckCircle2 className="size-5 text-status-safe" />}
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => downloadReport(scan)}><Download className="size-3.5" />Report</Button>
            <Button variant="outline" size="sm" onClick={() => void runVerify()} disabled={verifyState === "checking"}><RefreshCw className={`size-3.5 ${verifyState === "checking" ? "animate-spin" : ""}`} />Re-verify hash</Button>
            <Button variant="ghost" size="icon" aria-label="Delete case" className="text-muted-foreground hover:text-status-critical" onClick={() => onDelete(scan.id)}><Trash2 className="size-4" /></Button>
          </div>
        </div>
      </div>

      <div className="grid gap-6 p-5 lg:grid-cols-2">
        <section>
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
        </section>
        <section>
          <p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Reconstructed relay path</p>
          {scan.result.hops.length === 0 ? (
            <p className="text-xs text-muted-foreground">No Received headers were present in this evidence.</p>
          ) : (
            <div className="space-y-0">
              {scan.result.hops.map((hop, index) => (
                <div key={`${hop.ip}-${index}`} className="relative flex gap-4 pb-5 last:pb-0">
                  {index < scan.result.hops.length - 1 && <span className="absolute left-[9px] top-5 h-full w-px bg-border" />}
                  <span className={`relative z-10 mt-1 size-[9px] shrink-0 rounded-full ${hop.status === "origin" ? "bg-status-critical" : "bg-brand"}`} />
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2"><p className="text-xs font-semibold text-foreground">{hop.label}</p><span className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground">{hop.status}</span></div>
                    <p className="mt-0.5 break-all font-mono text-xs text-foreground">{hop.ip}</p>
                    <p className="mt-0.5 text-[11px] leading-5 text-muted-foreground">{hop.detail}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      <div className="border-t border-border p-5">
        <p className="mb-2 font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Evidence fingerprint</p>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <p className="break-all font-mono text-[10px] leading-5 text-foreground">{scan.result.evidenceHash}</p>
          {verifyState === "ok" && <IntegrityBadge verified />}
          {verifyState === "fail" && <IntegrityBadge verified={false} />}
        </div>
        <p className="mt-3 text-[11px] leading-5 text-muted-foreground">Re-verification re-runs the exact submitted content through the engine and compares the freshly computed fingerprint. This is your chain-of-custody proof during a demo.</p>
      </div>
    </div>
  );
}
