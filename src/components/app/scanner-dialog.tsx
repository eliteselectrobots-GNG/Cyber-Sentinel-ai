import { Activity, LockKeyhole, MailWarning, Upload, X, Zap } from "lucide-react";
import { useRef, useState } from "react";
import { scanEmail, sampleEmail, type EmailScanResult } from "@/lib/email-scanner";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";

export function ScannerDialog({
  open,
  onOpenChange,
  onResult,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onResult: (raw: string, result: EmailScanResult) => void;
}) {
  const [scanInput, setScanInput] = useState("");
  const [scanFileName, setScanFileName] = useState("");
  const [scanError, setScanError] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFile = async (file: File | undefined) => {
    if (!file) return;
    if (file.size > 1_000_000) {
      setScanError("That file is larger than 1 MB. Choose a smaller .eml file.");
      return;
    }
    setScanFileName(file.name);
    setScanError("");
    setScanInput(await file.text());
  };

  const reset = () => {
    setScanInput("");
    setScanFileName("");
    setScanError("");
  };

  const runScan = async () => {
    setIsScanning(true);
    setScanError("");
    try {
      const result = await scanEmail(scanInput);
      onResult(scanInput, result);
      // Close on the next tick: the verdict now saves almost instantly, and
      // closing synchronously mid-click would let the mouse-up fall through
      // to the button beneath and immediately reopen the dialog.
      window.setTimeout(() => {
        onOpenChange(false);
        reset();
      }, 120);
    } catch (error) {
      setScanError(error instanceof Error ? error.message : "The email could not be scanned.");
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(next) => { onOpenChange(next); if (!next) reset(); }}>
      <DialogContent className="max-w-3xl border-border bg-surface p-0 text-foreground">
        <DialogHeader className="border-b border-border px-6 py-5 text-left">
          <div className="flex items-center gap-3">
            <div className="flex size-10 items-center justify-center border border-brand/30 bg-brand/10 text-brand"><MailWarning className="size-5" /></div>
            <div>
              <DialogTitle className="font-display text-lg">Analyze suspicious email</DialogTitle>
              <DialogDescription className="mt-1 text-xs text-muted-foreground">Paste the raw message or upload an .eml file for local forensic analysis.</DialogDescription>
            </div>
          </div>
        </DialogHeader>
        <div className="space-y-5 px-6 py-5">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-xs font-semibold text-foreground">Evidence intake</p>
              <p className="mt-1 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">Raw content stays in this browser</p>
            </div>
            <div className="flex items-center gap-2">
              <input ref={fileInputRef} type="file" accept=".eml,.txt,message/rfc822" className="hidden" onChange={(event) => void handleFile(event.target.files?.[0])} />
              <Button variant="outline" size="sm" onClick={() => fileInputRef.current?.click()}><Upload className="size-3.5" />Upload .eml</Button>
              {scanFileName && <span className="max-w-40 truncate font-mono text-[10px] text-brand" title={scanFileName}>{scanFileName}</span>}
            </div>
          </div>
          <Textarea
            aria-label="Raw email content"
            value={scanInput}
            onChange={(event) => setScanInput(event.target.value)}
            placeholder={"From: sender@example.com\nTo: analyst@your-org.com\nSubject: Suspicious message\nReceived: from ...\n\nPaste the full raw email here..."}
            className="min-h-[280px] resize-y border-input bg-shell font-mono text-xs leading-5"
            maxLength={1_000_000}
          />
          <div className="flex flex-col gap-3 border border-border bg-shell/60 p-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-start gap-2 text-[11px] leading-5 text-muted-foreground">
              <LockKeyhole className="mt-0.5 size-3.5 shrink-0 text-status-safe" />
              <span>The result is stored locally in this browser with a SHA-256 fingerprint of the exact content submitted.</span>
            </div>
            <Button variant="ghost" size="sm" onClick={() => setScanInput(sampleEmail)}>Load sample</Button>
          </div>
          {scanError && <p className="border border-status-critical/30 bg-status-critical/10 px-3 py-2 text-xs text-status-critical" role="alert">{scanError}</p>}
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button onClick={() => void runScan()} disabled={isScanning || !scanInput.trim()}>
              {isScanning ? <><Activity className="size-4 animate-pulse" />Scanning evidence…</> : <><Zap className="size-4" />Run threat scan</>}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
