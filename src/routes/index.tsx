import { createFileRoute } from "@tanstack/react-router";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Bell,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Clock3,
  Database,
  Download,
  FileCheck2,
  FileText,
  Fingerprint,
  Globe2,
  Hash,
  LayoutDashboard,
  LockKeyhole,
  MailWarning,
  MapPin,
  Menu,
  Network,
  PanelLeftClose,
  Search,
  Server,
  Settings2,
  ShieldCheck,
  SlidersHorizontal,
  Upload,
  UserRound,
  X,
  Zap,
  type LucideIcon,
} from "lucide-react";
import { useMemo, useRef, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { scanEmail, sampleEmail, type EmailScanResult } from "@/lib/email-scanner";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "AegisTrace — Email Threat Intelligence" },
      {
        name: "description",
        content: "AI-powered email threat detection, relay tracing, and forensic intelligence for security teams.",
      },
      { property: "og:title", content: "AegisTrace — Email Threat Intelligence" },
      {
        property: "og:description",
        content: "Investigate suspicious email with explainable risk scoring, relay reconstruction, and campaign intelligence.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: AegisTraceDashboard,
});

type NavItem = { label: string; icon: LucideIcon; count?: string };

const navItems: NavItem[] = [
  { label: "Overview", icon: LayoutDashboard },
  { label: "Investigations", icon: MailWarning, count: "12" },
  { label: "Relay traces", icon: Network },
  { label: "Campaign graph", icon: Network },
  { label: "Evidence vault", icon: Fingerprint },
];

const queueItems = [
  { initials: "AM", sender: "A. Mehta", subject: "Updated bank details — action required", meta: "09:41 · external", risk: "critical", score: "94" },
  { initials: "NP", sender: "N. Patel", subject: "Q4 invoice reconciliation", meta: "09:18 · reply-to mismatch", risk: "high", score: "82" },
  { initials: "IT", sender: "IT Support", subject: "Your mailbox quota has been exceeded", meta: "08:56 · lookalike domain", risk: "high", score: "78" },
  { initials: "RK", sender: "R. Kapoor", subject: "Re: acquisition materials", meta: "08:32 · SPF softfail", risk: "medium", score: "61" },
];

function AegisTraceDashboard() {
  const [activeNav, setActiveNav] = useState("Overview");
  const [queueFilter, setQueueFilter] = useState("All alerts");
  const [selectedQueueItem, setSelectedQueueItem] = useState(0);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [notice, setNotice] = useState("");
  const [scanOpen, setScanOpen] = useState(false);
  const [scanInput, setScanInput] = useState("");
  const [scanFileName, setScanFileName] = useState("");
  const [scanError, setScanError] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<EmailScanResult | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const displayQueue = useMemo(() => {
    if (!scanResult) return queueItems;
    return [
      {
        initials: scanResult.sender.slice(0, 2).toUpperCase(),
        sender: scanResult.sender,
        subject: scanResult.subject,
        meta: `${scanResult.riskLabel.toLowerCase()} risk · just now`,
        risk: scanResult.riskLabel === "Critical" ? "critical" : scanResult.riskLabel === "High" ? "high" : "medium",
        score: String(scanResult.riskScore),
      },
      ...queueItems,
    ];
  }, [scanResult]);

  const filteredQueue = displayQueue.filter((item) => {
    if (queueFilter === "Critical") return item.risk === "critical";
    if (queueFilter === "Needs review") return item.risk !== "critical";
    return true;
  });

  const showNotice = (message: string) => {
    setNotice(message);
    window.setTimeout(() => setNotice(""), 2800);
  };

  const openScanner = () => {
    setScanOpen(true);
    setScanError("");
  };

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

  const runScan = async () => {
    setIsScanning(true);
    setScanError("");
    try {
      const result = await scanEmail(scanInput);
      setScanResult(result);
      setSelectedQueueItem(0);
      setScanOpen(false);
      setActiveNav("Overview");
      showNotice(`${result.riskLabel} risk detected · evidence fingerprint created`);
    } catch (error) {
      setScanError(error instanceof Error ? error.message : "The email could not be scanned.");
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-shell text-foreground">
      {notice && (
        <div className="fixed right-5 top-5 z-50 flex items-center gap-3 border border-status-safe/30 bg-surface-elevated px-4 py-3 text-sm font-medium text-foreground shadow-command" role="status">
          <CheckCircle2 className="size-4 text-status-safe" />
          {notice}
          <button aria-label="Dismiss notification" className="text-muted-foreground hover:text-foreground" onClick={() => setNotice("")}><X className="size-4" /></button>
        </div>
      )}
      <Dialog open={scanOpen} onOpenChange={setScanOpen}>
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
            <Textarea aria-label="Raw email content" value={scanInput} onChange={(event) => setScanInput(event.target.value)} placeholder="From: sender@example.com\nTo: analyst@your-org.com\nSubject: Suspicious message\nReceived: from ...\n\nPaste the full raw email here..." className="min-h-[280px] resize-y border-input bg-shell font-mono text-xs leading-5" maxLength={1_000_000} />
            <div className="flex flex-col gap-3 border border-border bg-shell/60 p-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-start gap-2 text-[11px] leading-5 text-muted-foreground"><LockKeyhole className="mt-0.5 size-3.5 shrink-0 text-status-safe" /><span>PII masking stays enabled. A SHA-256 fingerprint is generated from the submitted evidence.</span></div>
              <Button variant="ghost" size="sm" onClick={() => setScanInput(sampleEmail)}>Load sample</Button>
            </div>
            {scanError && <p className="border border-status-critical/30 bg-status-critical/10 px-3 py-2 text-xs text-status-critical" role="alert">{scanError}</p>}
            <div className="flex justify-end gap-2">
              <Button variant="ghost" onClick={() => setScanOpen(false)}>Cancel</Button>
              <Button onClick={() => void runScan()} disabled={isScanning || !scanInput.trim()}>{isScanning ? <><Activity className="size-4 animate-pulse" />Scanning evidence…</> : <><Zap className="size-4" />Run threat scan</>}</Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
      <aside className={`fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-sidebar-border bg-sidebar transition-transform duration-200 lg:translate-x-0 ${mobileNavOpen ? "translate-x-0" : "-translate-x-full"}`}>
        <div className="flex h-20 items-center justify-between border-b border-sidebar-border px-6">
          <div className="flex items-center gap-3">
            <div className="flex size-9 items-center justify-center border border-brand/40 bg-brand/10 text-brand"><ShieldCheck className="size-5" /></div>
            <div>
              <p className="font-display text-[15px] font-semibold tracking-wide text-sidebar-foreground">AEGISTRACE</p>
              <p className="mt-0.5 font-mono text-[9px] uppercase tracking-[0.18em] text-muted-foreground">Forensic intelligence</p>
            </div>
          </div>
          <button className="text-muted-foreground hover:text-sidebar-foreground lg:hidden" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)}><X className="size-5" /></button>
        </div>

        <div className="flex-1 px-3 py-6">
          <p className="mb-3 px-3 font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Workspace</p>
          <nav className="space-y-1" aria-label="Primary navigation">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeNav === item.label;
              return (
                <button
                  key={item.label}
                  onClick={() => { setActiveNav(item.label); setMobileNavOpen(false); }}
                  className={`group flex w-full items-center justify-between border-l-2 px-3 py-2.5 text-left text-sm transition-colors ${isActive ? "border-brand bg-sidebar-accent text-sidebar-foreground" : "border-transparent text-muted-foreground hover:bg-sidebar-accent/60 hover:text-sidebar-foreground"}`}
                >
                  <span className="flex items-center gap-3"><Icon className={`size-4 ${isActive ? "text-brand" : "text-muted-foreground"}`} />{item.label}</span>
                  {item.count && <span className="font-mono text-[10px] text-status-critical">{item.count}</span>}
                </button>
              );
            })}
          </nav>

          <p className="mb-3 mt-9 px-3 font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">System</p>
          <nav className="space-y-1">
            <button onClick={() => showNotice("All systems operational")} className="flex w-full items-center gap-3 border-l-2 border-transparent px-3 py-2.5 text-left text-sm text-muted-foreground transition-colors hover:bg-sidebar-accent/60 hover:text-sidebar-foreground"><Activity className="size-4" />Detection health</button>
            <button onClick={() => showNotice("Settings are ready for review")} className="flex w-full items-center gap-3 border-l-2 border-transparent px-3 py-2.5 text-left text-sm text-muted-foreground transition-colors hover:bg-sidebar-accent/60 hover:text-sidebar-foreground"><Settings2 className="size-4" />Settings</button>
          </nav>
        </div>

        <div className="border-t border-sidebar-border p-4">
          <div className="mb-4 flex items-center gap-3 border border-sidebar-border bg-sidebar-accent/50 p-3">
            <div className="flex size-8 items-center justify-center bg-brand/15 text-brand"><UserRound className="size-4" /></div>
            <div className="min-w-0"><p className="truncate text-xs font-medium text-sidebar-foreground">Priya Nair</p><p className="truncate font-mono text-[10px] text-muted-foreground">SOC / Tier 2</p></div>
            <span className="ml-auto size-1.5 rounded-full bg-status-safe" />
          </div>
          <div className="flex items-center justify-between px-1 font-mono text-[9px] uppercase tracking-wider text-muted-foreground"><span>Node IN-DEL-04</span><span>v2.4.1</span></div>
        </div>
      </aside>

      <main className="min-h-screen lg:pl-64">
        <header className="sticky top-0 z-30 flex h-20 items-center justify-between border-b border-border bg-shell/95 px-5 backdrop-blur lg:px-8">
          <div className="flex items-center gap-4">
            <Button variant="ghost" size="icon" className="lg:hidden" onClick={() => setMobileNavOpen(true)} aria-label="Open navigation"><Menu className="size-5" /></Button>
            <div className="hidden items-center gap-2 text-xs text-muted-foreground sm:flex"><span>Workspace</span><ChevronRight className="size-3" /><span className="text-foreground">{activeNav}</span></div>
            <p className="font-display text-sm font-semibold sm:hidden">{activeNav}</p>
          </div>
          <div className="flex items-center gap-2 sm:gap-4">
            <div className="relative hidden md:block"><Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" /><input aria-label="Search investigations" placeholder="Search investigations" className="h-9 w-56 border border-input bg-surface px-3 pl-9 text-xs text-foreground outline-none placeholder:text-muted-foreground focus:border-brand focus:ring-1 focus:ring-brand/30" /></div>
            <Button variant="ghost" size="icon" className="relative" aria-label="Notifications" onClick={() => showNotice("3 new investigation signals")}><Bell className="size-4" /><span className="absolute right-1.5 top-1.5 size-1.5 rounded-full bg-status-critical" /></Button>
            <div className="hidden h-5 w-px bg-border sm:block" />
            <button className="flex items-center gap-2 text-left" onClick={() => showNotice("Analyst profile opened")}><div className="flex size-8 items-center justify-center bg-brand text-xs font-bold text-brand-foreground">PN</div><span className="hidden text-xs font-medium sm:block">P. Nair</span></button>
          </div>
        </header>

        <div className="mx-auto max-w-[1600px] px-5 py-7 lg:px-8 lg:py-9">
          <section className="mb-8 flex flex-col justify-between gap-5 sm:flex-row sm:items-end">
            <div><div className="mb-3 flex items-center gap-2"><span className="status-pulse size-2 rounded-full bg-status-safe" /><span className="font-mono text-[10px] font-semibold uppercase tracking-[0.2em] text-status-safe">Monitoring active</span></div><h1 className="font-display text-3xl font-semibold tracking-tight text-foreground lg:text-4xl">Threat operations overview</h1><p className="mt-2 max-w-xl text-sm leading-6 text-muted-foreground">A consolidated view of inbound risk, protocol anomalies, and active campaign infrastructure.</p></div>
            <div className="flex items-center gap-2"><Button variant="outline" onClick={() => showNotice(scanResult ? `Report ready for ${scanResult.id}` : "Run a scan before exporting a report")}><Download className="size-4" />Export report</Button><Button onClick={openScanner}><Upload className="size-4" />Analyze email</Button></div>
          </section>

          <section className="mb-6 grid gap-px border border-border bg-border sm:grid-cols-2 xl:grid-cols-4" aria-label="Threat summary">
            <Metric label="Risk index" value={scanResult ? String(scanResult.riskScore) : "72"} suffix="/100" trend={scanResult ? scanResult.riskLabel : "+8.4%"} trendLabel={scanResult ? "latest scan" : "vs. last 24h"} icon={Zap} tone={scanResult?.riskLabel === "Low" ? "safe" : "critical"} />
            <Metric label="Emails analyzed" value={scanResult ? "18,427" : "18,426"} trend={scanResult ? "+1 new" : "+12.8%"} trendLabel="vs. last 24h" icon={MailWarning} tone="brand" />
            <Metric label="Active investigations" value={scanResult ? "13" : "12"} trend={scanResult ? "1 new" : "4 urgent"} trendLabel="need attention" icon={AlertTriangle} tone="warning" />
            <Metric label="Evidence integrity" value="100" suffix="%" trend="SHA-256" trendLabel="verified" icon={LockKeyhole} tone="safe" />
          </section>

           {scanResult && (
             <section className="mb-6 border border-brand/30 bg-surface" aria-labelledby="latest-scan-heading">
               <div className="flex flex-col gap-4 border-b border-border p-5 sm:flex-row sm:items-start sm:justify-between">
                 <div>
                   <div className="mb-2 flex flex-wrap items-center gap-2"><Badge variant="outline" className="border-brand/40 bg-brand/10 text-brand">Latest scan</Badge><span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{scanResult.id} · {scanResult.headersFound} header values parsed</span></div>
                   <h2 id="latest-scan-heading" className="max-w-3xl truncate font-display text-lg font-semibold">{scanResult.subject}</h2>
                   <p className="mt-1 text-xs text-muted-foreground">From {scanResult.senderAddress} · {scanResult.receivedAt}</p>
                 </div>
                 <div className="flex shrink-0 items-center gap-3 border border-status-critical/30 bg-status-critical/10 px-4 py-3"><div className="text-right"><p className="font-mono text-[9px] uppercase tracking-wider text-status-critical">Threat score</p><p className="font-display text-2xl font-semibold text-status-critical">{scanResult.riskScore}<span className="font-mono text-xs">/100</span></p></div><AlertTriangle className="size-5 text-status-critical" /></div>
               </div>
               <div className="grid gap-5 p-5 xl:grid-cols-[1.4fr_0.8fr_0.8fr]">
                 <div><p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Explainable findings</p><div className="space-y-2">{scanResult.findings.map((finding) => <div key={finding.label} className="flex items-start gap-3 border-b border-border pb-2 last:border-0"><span className={`mt-1 size-1.5 shrink-0 rounded-full ${finding.severity === "critical" ? "bg-status-critical" : finding.severity === "high" ? "bg-status-warning" : finding.severity === "medium" ? "bg-brand" : "bg-status-safe"}`} /><div><p className="text-xs font-medium text-foreground">{finding.label}</p><p className="mt-0.5 text-[11px] leading-5 text-muted-foreground">{finding.detail}</p></div></div>)}</div></div>
                 <div className="border-l border-border pl-5"><p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Message routing</p><dl className="space-y-3 text-xs"><div><dt className="text-muted-foreground">Reply-to</dt><dd className="mt-1 break-all font-mono text-foreground">{scanResult.replyTo}</dd></div><div><dt className="text-muted-foreground">Return-path</dt><dd className="mt-1 break-all font-mono text-foreground">{scanResult.returnPath}</dd></div><div><dt className="text-muted-foreground">Relay hops</dt><dd className="mt-1 font-mono text-brand">{scanResult.hops.length} reconstructed</dd></div></dl></div>
                 <div className="border-l border-border pl-5"><p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Evidence fingerprint</p><div className="flex items-start gap-2"><Hash className="mt-0.5 size-4 shrink-0 text-brand" /><p className="break-all font-mono text-[10px] leading-5 text-foreground">{scanResult.evidenceHash}</p></div><p className="mt-3 text-[11px] leading-5 text-muted-foreground">Generated from the exact submitted content for chain-of-custody verification.</p></div>
               </div>
             </section>
           )}

          <div className="grid gap-6 xl:grid-cols-[minmax(0,1.4fr)_minmax(340px,0.8fr)]">
             <section className="border border-border bg-surface" aria-labelledby="queue-heading">
               <div className="flex flex-col gap-4 border-b border-border p-5 sm:flex-row sm:items-center sm:justify-between">
                 <div><div className="flex items-center gap-2"><h2 id="queue-heading" className="font-display text-base font-semibold">Investigation queue</h2><Badge variant="outline" className="border-status-critical/40 bg-status-critical/10 text-status-critical">{displayQueue.length + 8} open</Badge></div><p className="mt-1 text-xs text-muted-foreground">Prioritized by explainable threat score</p></div>
                 <div className="flex items-center gap-2"><Button variant="outline" size="sm" onClick={() => showNotice(`${queueFilter} filter applied`)}><SlidersHorizontal className="size-3.5" />Filter</Button><Button variant="ghost" size="icon" aria-label="More queue options"><PanelLeftClose className="size-4" /></Button></div>
               </div>
              <div className="flex gap-1 overflow-x-auto border-b border-border px-5 pt-3">{["All alerts", "Critical", "Needs review"].map((filter) => <button key={filter} onClick={() => setQueueFilter(filter)} className={`whitespace-nowrap border-b-2 px-2 pb-3 text-xs font-medium transition-colors ${queueFilter === filter ? "border-brand text-brand" : "border-transparent text-muted-foreground hover:text-foreground"}`}>{filter}</button>)}</div>
               <div className="divide-y divide-border">{filteredQueue.map((item, index) => <button key={`${item.subject}-${index}`} onClick={() => setSelectedQueueItem(index)} className={`flex w-full items-center gap-3 p-4 text-left transition-colors hover:bg-surface-elevated sm:gap-4 ${selectedQueueItem === index ? "bg-surface-elevated" : ""}`}><div className={`flex size-9 shrink-0 items-center justify-center text-[11px] font-semibold ${item.risk === "critical" ? "bg-status-critical/15 text-status-critical" : item.risk === "high" ? "bg-status-warning/15 text-status-warning" : "bg-brand/10 text-brand"}`}>{item.initials}</div><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-x-2 gap-y-1"><p className="text-xs font-semibold text-foreground">{item.sender}</p><span className="text-[10px] text-muted-foreground">{item.meta}</span></div><p className="mt-1 truncate text-sm text-muted-foreground">{item.subject}</p></div><div className="flex shrink-0 flex-col items-end gap-1"><span className={`font-mono text-sm font-semibold ${item.risk === "critical" ? "text-status-critical" : item.risk === "high" ? "text-status-warning" : "text-brand"}`}>{item.score}</span><span className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground">risk</span></div><ChevronRight className="hidden size-4 text-muted-foreground sm:block" /></button>)}</div>
               <div className="flex items-center justify-between border-t border-border px-5 py-3"><p className="font-mono text-[10px] text-muted-foreground">Showing {filteredQueue.length} of {displayQueue.length} investigations</p><Button variant="ghost" size="sm" onClick={openScanner}>New scan <ArrowUpRight className="size-3.5" /></Button></div>
            </section>

            <section className="border border-border bg-surface" aria-labelledby="posture-heading">
              <div className="flex items-start justify-between border-b border-border p-5"><div><h2 id="posture-heading" className="font-display text-base font-semibold">Detection posture</h2><p className="mt-1 text-xs text-muted-foreground">Signal distribution · last 24 hours</p></div><Button variant="ghost" size="icon" aria-label="View posture details"><ArrowUpRight className="size-4" /></Button></div>
              <div className="space-y-5 p-5"><div className="flex items-center gap-6"><div className="relative flex size-32 shrink-0 items-center justify-center rounded-full border-[10px] border-brand/20 border-t-brand border-r-brand"><div className="text-center"><p className="font-display text-2xl font-semibold">72</p><p className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground">risk index</p></div></div><div className="min-w-0 space-y-3"><Legend color="bg-status-critical" label="Critical" value="04" /><Legend color="bg-status-warning" label="Elevated" value="21" /><Legend color="bg-brand" label="Monitored" value="68" /><Legend color="bg-muted-foreground/40" label="Clear" value="907" /></div></div><div className="space-y-3 border-t border-border pt-5"><PostureBar label="BEC / payment diversion" value="34%" width="w-1/3" tone="bg-status-critical" /><PostureBar label="Credential harvesting" value="28%" width="w-1/4" tone="bg-status-warning" /><PostureBar label="Lookalike domains" value="22%" width="w-1/5" tone="bg-brand" /><PostureBar label="Malware / attachment" value="16%" width="w-1/6" tone="bg-status-safe" /></div></div>
            </section>
          </div>

          <div className="mt-6 grid gap-6 xl:grid-cols-[minmax(0,1.5fr)_minmax(330px,0.7fr)]">
            <section className="overflow-hidden border border-border bg-surface" aria-labelledby="trace-heading">
              <div className="flex flex-col gap-4 border-b border-border p-5 sm:flex-row sm:items-center sm:justify-between"><div><div className="flex items-center gap-2"><h2 id="trace-heading" className="font-display text-base font-semibold">Relay trace reconstruction</h2><Badge variant="outline" className="border-status-warning/40 bg-status-warning/10 text-status-warning">Case AT-2048</Badge></div><p className="mt-1 text-xs text-muted-foreground">Earliest reliable origin identified · 4 hops reconstructed</p></div><Button variant="outline" size="sm" onClick={() => showNotice("Trace detail opened")}><Globe2 className="size-3.5" />Open trace</Button></div>
              <div className="relative h-[300px] overflow-hidden bg-map p-5 sm:h-[330px]"><div className="absolute inset-0 opacity-50 [background-image:linear-gradient(var(--grid-line)_1px,transparent_1px),linear-gradient(90deg,var(--grid-line)_1px,transparent_1px)] [background-size:48px_48px]" /><div className="absolute left-[12%] top-[61%] size-28 rounded-full bg-brand/5 blur-2xl" /><div className="absolute right-[12%] top-[18%] size-36 rounded-full bg-status-warning/5 blur-3xl" />
                <div className="relay-line relay-line-one" /><div className="relay-line relay-line-two" /><div className="relay-line relay-line-three" />
                <RelayNode position="node-origin" icon={MapPin} label="Origin" detail="185.220.101.4" tone="critical" /><RelayNode position="node-hop-one" icon={Server} label="Relay 01" detail="Frankfurt, DE" tone="warning" /><RelayNode position="node-hop-two" icon={Server} label="Relay 02" detail="London, UK" tone="brand" /><RelayNode position="node-destination" icon={Database} label="Target MX" detail="Mumbai, IN" tone="safe" />
                <div className="absolute bottom-4 left-5 flex items-center gap-2 font-mono text-[9px] uppercase tracking-widest text-muted-foreground"><CircleDot className="size-3 text-status-safe" />Realtime protocol view</div><div className="absolute right-5 top-5 flex items-center gap-2 border border-status-warning/30 bg-surface/90 px-2.5 py-1.5 font-mono text-[9px] text-status-warning"><AlertTriangle className="size-3" />Forged hop detected</div>
              </div>
              <div className="grid border-t border-border sm:grid-cols-4">{[{ label: "Origin IP", value: "185.220.101.4", icon: Globe2 }, { label: "ASN", value: "AS9009 · M247", icon: Network }, { label: "Reputation", value: "Known TOR exit", icon: AlertTriangle }, { label: "Confidence", value: "96.2%", icon: CheckCircle2 }].map((data) => { const Icon = data.icon; return <div key={data.label} className="flex items-center gap-3 border-b border-border p-4 last:border-b-0 sm:border-b-0 sm:border-r sm:last:border-r-0"><Icon className={`size-4 shrink-0 ${data.label === "Reputation" ? "text-status-critical" : "text-muted-foreground"}`} /><div className="min-w-0"><p className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground">{data.label}</p><p className="mt-1 truncate text-xs font-medium text-foreground">{data.value}</p></div></div>; })}</div>
            </section>

            <section className="border border-border bg-surface" aria-labelledby="campaign-heading"><div className="flex items-start justify-between border-b border-border p-5"><div><h2 id="campaign-heading" className="font-display text-base font-semibold">Campaign intelligence</h2><p className="mt-1 text-xs text-muted-foreground">Correlated infrastructure clusters</p></div><Button variant="ghost" size="icon" aria-label="Open campaign graph" onClick={() => setActiveNav("Campaign graph")}><Network className="size-4" /></Button></div><div className="space-y-4 p-5"><CampaignRow name="Silver Kestrel" nodes="18 nodes · 6 domains" risk="critical" score="94" /><CampaignRow name="Invoice Ghost" nodes="11 nodes · 4 domains" risk="high" score="81" /><CampaignRow name="Quiet Harbor" nodes="07 nodes · 3 domains" risk="medium" score="63" /></div><div className="mx-5 mb-5 border border-brand/20 bg-brand/5 p-3"><div className="flex items-start gap-3"><Zap className="mt-0.5 size-4 shrink-0 text-brand" /><div><p className="text-xs font-semibold text-foreground">New correlation detected</p><p className="mt-1 text-[11px] leading-5 text-muted-foreground">2 sender domains share infrastructure with Silver Kestrel.</p></div></div></div></section>
          </div>

          <section className="mt-6 border border-border bg-surface" aria-labelledby="integrity-heading"><div className="flex flex-col gap-4 border-b border-border p-5 sm:flex-row sm:items-center sm:justify-between"><div><div className="flex items-center gap-2"><h2 id="integrity-heading" className="font-display text-base font-semibold">Evidence & integrity</h2><Badge variant="outline" className="border-status-safe/30 bg-status-safe/10 text-status-safe"><CheckCircle2 className="mr-1 size-3" />Chain of custody intact</Badge></div><p className="mt-1 text-xs text-muted-foreground">Protected artifacts from your active cases</p></div><Button variant="outline" size="sm" onClick={() => setActiveNav("Evidence vault")}><FileText className="size-3.5" />Evidence vault</Button></div><div className="grid sm:grid-cols-3"><EvidenceStat icon={Fingerprint} label="SHA-256 artifacts" value="248" detail="100% verified" /><EvidenceStat icon={FileCheck2} label="Forensic reports" value="36" detail="8 generated today" /><EvidenceStat icon={Clock3} label="Retention window" value="180d" detail="Policy compliant" /></div></section>

          <footer className="flex flex-col gap-3 py-6 text-[10px] text-muted-foreground sm:flex-row sm:items-center sm:justify-between"><div className="flex items-center gap-2 font-mono uppercase tracking-wider"><ShieldCheck className="size-3 text-status-safe" />Privacy controls active · PII masking enabled</div><div className="flex items-center gap-4 font-mono uppercase tracking-wider"><span>Last sync 09:42:18 IST</span><span className="hidden text-border sm:block">|</span><span>AICTE Cyber Security Cell</span></div></footer>
        </div>
      </main>
    </div>
  );
}

function Metric({ label, value, suffix, trend, trendLabel, icon: Icon, tone }: { label: string; value: string; suffix?: string; trend: string; trendLabel: string; icon: typeof Zap; tone: "critical" | "brand" | "warning" | "safe" }) {
  return <div className="bg-surface p-5"><div className="mb-6 flex items-center justify-between"><p className="text-xs font-medium text-muted-foreground">{label}</p><Icon className={`size-4 ${tone === "critical" ? "text-status-critical" : tone === "warning" ? "text-status-warning" : tone === "safe" ? "text-status-safe" : "text-brand"}`} /></div><div className="flex items-baseline gap-1"><span className="font-display text-3xl font-semibold tracking-tight">{value}</span>{suffix && <span className="font-mono text-xs text-muted-foreground">{suffix}</span>}</div><div className="mt-3 flex items-center gap-2"><span className={`font-mono text-[10px] ${tone === "critical" ? "text-status-critical" : tone === "warning" ? "text-status-warning" : "text-status-safe"}`}>{trend}</span><span className="text-[10px] text-muted-foreground">{trendLabel}</span></div></div>;
}

function Legend({ color, label, value }: { color: string; label: string; value: string }) { return <div className="flex items-center gap-2.5 text-xs"><span className={`size-2 rounded-full ${color}`} /><span className="flex-1 text-muted-foreground">{label}</span><span className="font-mono text-foreground">{value}</span></div>; }
function PostureBar({ label, value, width, tone }: { label: string; value: string; width: string; tone: string }) { return <div><div className="mb-1.5 flex justify-between text-[11px]"><span className="text-muted-foreground">{label}</span><span className="font-mono text-foreground">{value}</span></div><div className="h-1.5 bg-muted"><div className={`h-full ${width} ${tone}`} /></div></div>; }
function RelayNode({ position, icon: Icon, label, detail, tone }: { position: string; icon: typeof MapPin; label: string; detail: string; tone: "critical" | "warning" | "brand" | "safe" }) { return <div className={`absolute ${position} z-10 flex items-center gap-2`}><div className={`flex size-9 items-center justify-center border bg-surface shadow-command ${tone === "critical" ? "border-status-critical text-status-critical" : tone === "warning" ? "border-status-warning text-status-warning" : tone === "safe" ? "border-status-safe text-status-safe" : "border-brand text-brand"}`}><Icon className="size-4" /></div><div className="hidden border border-border bg-surface/95 px-2.5 py-1.5 shadow-command sm:block"><p className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground">{label}</p><p className="mt-0.5 whitespace-nowrap text-[10px] font-medium text-foreground">{detail}</p></div></div>; }
function CampaignRow({ name, nodes, risk, score }: { name: string; nodes: string; risk: string; score: string }) { return <button className="flex w-full items-center gap-3 border-b border-border pb-4 text-left last:border-0 last:pb-0" onClick={() => undefined}><div className={`flex size-8 items-center justify-center ${risk === "critical" ? "bg-status-critical/10 text-status-critical" : risk === "high" ? "bg-status-warning/10 text-status-warning" : "bg-brand/10 text-brand"}`}><Network className="size-4" /></div><div className="min-w-0 flex-1"><p className="text-xs font-semibold text-foreground">{name}</p><p className="mt-1 font-mono text-[10px] text-muted-foreground">{nodes}</p></div><div className="text-right"><p className={`font-mono text-sm font-semibold ${risk === "critical" ? "text-status-critical" : risk === "high" ? "text-status-warning" : "text-brand"}`}>{score}</p><p className="font-mono text-[9px] uppercase text-muted-foreground">risk</p></div><ChevronRight className="size-4 text-muted-foreground" /></button>; }
function EvidenceStat({ icon: Icon, label, value, detail }: { icon: typeof Fingerprint; label: string; value: string; detail: string }) { return <div className="flex items-center gap-4 border-b border-border p-5 last:border-b-0 sm:border-b-0 sm:border-r sm:last:border-r-0"><div className="flex size-9 items-center justify-center bg-brand/10 text-brand"><Icon className="size-4" /></div><div><p className="text-xs text-muted-foreground">{label}</p><div className="mt-1 flex items-baseline gap-2"><span className="font-display text-xl font-semibold">{value}</span><span className="font-mono text-[9px] text-status-safe">{detail}</span></div></div></div>; }