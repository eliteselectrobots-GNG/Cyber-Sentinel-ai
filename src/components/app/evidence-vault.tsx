import { Fingerprint, RefreshCw, Trash2 } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { verifyEvidence, type StoredScan } from "@/lib/store";
import { Card, DemoTag, EmptyState, IntegrityBadge, PageHeader, SeverityBadge, timeAgo, type PageKey } from "./ui";

export function EvidenceVaultPage({ scans, onDelete, navigate, notify }: { scans: StoredScan[]; onDelete: (id: string) => void; navigate: (page: PageKey) => void; notify: (msg: string) => void }) {
  return (
    <>
      <PageHeader
        title="Evidence vault"
        description="Every raw submission and its SHA-256 fingerprint. Verify any record by re-running the exact content through the engine."
        actions={<Button variant="outline" onClick={() => navigate("overview")}><Fingerprint className="size-4" />Back to overview</Button>}
      />
      {scans.length === 0 ? (
        <div className="border border-border bg-surface">
          <EmptyState title="Vault is empty" detail="Records appear here the moment you analyze an email. Raw content stays in this browser." action={<Button onClick={() => navigate("overview")}>Analyze an email</Button>} />
        </div>
      ) : (
        <div className="grid gap-4 xl:grid-cols-2">
          {scans.map((scan) => <VaultRow key={scan.id} scan={scan} onDelete={onDelete} notify={notify} />)}
        </div>
      )}
    </>
  );
}

function VaultRow({ scan, onDelete, notify }: { scan: StoredScan; onDelete: (id: string) => void; notify: (msg: string) => void }) {
  const [verifyState, setVerifyState] = useState<"idle" | "checking" | "ok" | "fail">("idle");

  const runVerify = async () => {
    setVerifyState("checking");
    const { matches } = await verifyEvidence(scan.raw, scan.result.evidenceHash);
    setVerifyState(matches ? "ok" : "fail");
    notify(matches ? `Integrity verified for ${scan.caseId}.` : `Integrity check FAILED for ${scan.caseId}.`);
  };

  return (
    <Card className="flex flex-col">
      <div className="flex flex-col gap-3 border-b border-border p-5 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <SeverityBadge risk={scan.result.riskLabel} />
            <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{scan.caseId}</span>
            {scan.demo && <DemoTag />}
          </div>
          <h3 className="truncate font-display text-base font-semibold">{scan.result.subject}</h3>
          <p className="mt-1 truncate text-xs text-muted-foreground">{scan.result.senderAddress} · {timeAgo(scan.scannedAt)}</p>
        </div>
        <div className="flex shrink-0 items-center gap-1">
          <Button variant="outline" size="icon" aria-label="Verify integrity" title="Re-verify SHA-256" onClick={() => void runVerify()} disabled={verifyState === "checking"}><RefreshCw className={`size-3.5 ${verifyState === "checking" ? "animate-spin" : ""}`} /></Button>
          <Button variant="outline" size="icon" aria-label="Delete record" title="Delete record" className="text-muted-foreground hover:text-status-critical" onClick={() => onDelete(scan.id)}><Trash2 className="size-3.5" /></Button>
        </div>
      </div>
      <div className="flex flex-1 flex-col justify-between gap-3 p-5">
        <div>
          <p className="mb-1 font-mono text-[9px] uppercase tracking-wider text-muted-foreground">SHA-256 fingerprint</p>
          <p className="break-all font-mono text-[10px] leading-5 text-foreground">{scan.result.evidenceHash}</p>
        </div>
        <div className="flex items-center justify-between">
          {verifyState === "idle" && <span className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground">Not yet re-verified this session</span>}
          {verifyState === "checking" && <span className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground">Re-running engine…</span>}
          {verifyState === "ok" && <IntegrityBadge verified />}
          {verifyState === "fail" && <IntegrityBadge verified={false} />}
        </div>
      </div>
    </Card>
  );
}
