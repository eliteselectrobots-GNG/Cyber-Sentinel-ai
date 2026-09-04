import { createFileRoute } from "@tanstack/react-router";
import { Activity, CheckCircle2, Fingerprint, LayoutDashboard, MailWarning, Menu, Network, Settings2, ShieldCheck, UserRound, X, type LucideIcon } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { addScan, clearScans, deleteScan, listScans, toStoredScan, type StoredScan } from "@/lib/store";
import { buildDemoDataset } from "@/lib/demo-data";
import { enrichWithDns } from "@/lib/dns";
import { enrichIps, flagEmoji, locationLabel } from "@/lib/geo";
import type { EmailScanResult } from "@/lib/email-scanner";
import { ScannerDialog } from "@/components/app/scanner-dialog";
import { OverviewPage } from "@/components/app/overview";
import { InvestigationsPage } from "@/components/app/investigations";
import { EvidenceVaultPage } from "@/components/app/evidence-vault";
import { CampaignPage, HealthPage, RelayTracePage, SettingsPage } from "@/components/app/misc-pages";
import type { PageKey } from "@/components/app/ui";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "AegisTrace — Email Threat Intelligence" },
      {
        name: "description",
        content: "Explainable email threat detection, relay tracing, and evidence fingerprinting for security teams.",
      },
      { property: "og:title", content: "AegisTrace — Email Threat Intelligence" },
      {
        property: "og:description",
        content: "Analyze suspicious email with explainable risk scoring, relay reconstruction, and evidence integrity verification.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: AegisTraceShell,
});

const ANALYST_KEY = "aegistrace.analyst";

type NavItem = { page: PageKey; label: string; icon: LucideIcon; badge?: string };

const workspaceNav: NavItem[] = [
  { page: "overview", label: "Overview", icon: LayoutDashboard },
  { page: "investigations", label: "Investigations", icon: MailWarning },
  { page: "relay", label: "Relay traces", icon: Network },
  { page: "campaign", label: "Campaign graph", icon: Network },
  { page: "evidence", label: "Evidence vault", icon: Fingerprint },
];

const systemNav: NavItem[] = [
  { page: "health", label: "Detection health", icon: Activity },
  { page: "settings", label: "Settings", icon: Settings2 },
];

const pageTitles: Record<PageKey, string> = {
  overview: "Overview",
  investigations: "Investigations",
  relay: "Relay traces",
  campaign: "Campaign graph",
  evidence: "Evidence vault",
  health: "Detection health",
  settings: "Settings",
};

function AegisTraceShell() {
  const [scans, setScans] = useState<StoredScan[]>([]);
  const [page, setPage] = useState<PageKey>("overview");
  const [selectedCase, setSelectedCase] = useState<string | null>(null);
  const [scanOpen, setScanOpen] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [analyst, setAnalyst] = useState<string>(() => {
    try { return localStorage.getItem(ANALYST_KEY) ?? ""; } catch { return ""; }
  });
  const [notice, setNotice] = useState("");
  const noticeTimer = useRef<number | undefined>(undefined);
  const mounted = useRef(false);

  const reload = async () => {
    const stored = await listScans();
    setScans(stored);
  };

  useEffect(() => {
    if (mounted.current) return;
    mounted.current = true;
    void reload().catch(() => setNotice("Could not read the local evidence store."));
    return () => { if (noticeTimer.current) window.clearTimeout(noticeTimer.current); };
  }, []);

  const notify = (message: string) => {
    setNotice(message);
    if (noticeTimer.current) window.clearTimeout(noticeTimer.current);
    noticeTimer.current = window.setTimeout(() => setNotice(""), 3200);
  };

  const criticalCount = useMemo(() => scans.filter((scan) => scan.result.riskLabel === "Critical").length, [scans]);
  const navBadges = (item: NavItem): string | undefined => {
    if (item.page === "investigations") return scans.length > 0 ? String(scans.length) : undefined;
    if (item.page === "overview") return criticalCount > 0 ? String(criticalCount) : undefined;
    return item.badge;
  };

  const navigate = (next: PageKey) => {
    setPage(next);
    setMobileNavOpen(false);
  };

  const openCase = (id: string) => {
    setSelectedCase(id);
    setPage("investigations");
    setMobileNavOpen(false);
  };

  const handleScanResult = async (raw: string, result: EmailScanResult) => {
    const stored = toStoredScan(raw, result);
    const originHop = result.hops.find((hop) => hop.status === "origin") ?? result.hops[0];
    const originIp = originHop && originHop.ip !== "Not disclosed" ? originHop.ip : null;
    try {
      const auth = await enrichWithDns(result.senderAddress, result.replyTo, result.returnPath, originIp);
      if (auth.checks.length > 0) stored.auth = auth;
    } catch {
      // live DNS is best-effort; the scan itself always succeeds
    }
    try {
      const geo = await enrichIps(result.hops.map((hop) => hop.ip));
      if (Object.keys(geo).length > 0) stored.geo = geo;
    } catch {
      // geolocation is best-effort; the scan itself always succeeds
    }
    await addScan(stored);
    await reload();
    navigate("overview");
    const failures = (stored.auth?.checks ?? []).filter((check) => check.outcome === "fail").length;
    const originGeo = originIp ? stored.geo?.[originIp] : undefined;
    const originNote = originGeo ? ` Origin located: ${locationLabel(originGeo)} ${flagEmoji(originGeo.countryCode)}.` : "";
    notify(failures > 0 ? `${result.riskLabel} risk · ${stored.caseId} — ${failures} live DNS check${failures === 1 ? "" : "s"} failed.${originNote}` : `${result.riskLabel} risk · case ${stored.caseId} stored in the evidence vault.${originNote}`);
  };

  const handleDelete = async (id: string) => {
    await deleteScan(id);
    if (selectedCase === id) setSelectedCase(null);
    await reload();
    notify("Case removed from local evidence.");
  };

  const handleLoadDemo = async () => {
    if (scans.length > 0 && !window.confirm("Replace the current local evidence with the demo dataset?")) return;
    await clearScans();
    const dataset = await buildDemoDataset();
    for (const scan of dataset) await addScan(scan);
    await reload();
    notify(`Demo dataset loaded — ${dataset.length} records, each processed by the real engine.`);
  };

  const handleClearAll = async () => {
    if (scans.length === 0) return;
    if (!window.confirm("Delete ALL locally stored evidence? This cannot be undone.")) return;
    await clearScans();
    setSelectedCase(null);
    await reload();
    notify("All local evidence cleared.");
  };

  const handleAnalystChange = (name: string) => {
    setAnalyst(name);
    try { localStorage.setItem(ANALYST_KEY, name); } catch { /* storage unavailable */ }
  };

  const initials = useMemo(() => {
    const parts = analyst.trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) return "AN";
    return parts.map((part) => part[0]).slice(0, 2).join("").toUpperCase();
  }, [analyst]);

  const renderPage = () => {
    switch (page) {
      case "overview":
        return <OverviewPage scans={scans} openScanner={() => setScanOpen(true)} openCase={openCase} navigate={navigate} notify={notify} loadDemo={() => void handleLoadDemo()} />;
      case "investigations":
        return <InvestigationsPage scans={scans} selectedId={selectedCase} onSelect={setSelectedCase} onDelete={(id) => void handleDelete(id)} navigate={navigate} notify={notify} />;
      case "relay":
        return <RelayTracePage scans={scans} navigate={navigate} />;
      case "campaign":
        return <CampaignPage scans={scans} />;
      case "evidence":
        return <EvidenceVaultPage scans={scans} onDelete={(id) => void handleDelete(id)} navigate={navigate} notify={notify} />;
      case "health":
        return <HealthPage scans={scans} />;
      case "settings":
        return <SettingsPage scans={scans} analyst={analyst} onAnalystChange={handleAnalystChange} onLoadDemo={handleLoadDemo} onClearAll={handleClearAll} notify={notify} />;
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

      <ScannerDialog open={scanOpen} onOpenChange={setScanOpen} onResult={(raw, result) => void handleScanResult(raw, result)} />

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
            {workspaceNav.map((item) => {
              const Icon = item.icon;
              const isActive = page === item.page;
              const badge = navBadges(item);
              return (
                <button
                  key={item.page}
                  onClick={() => navigate(item.page)}
                  className={`group flex w-full items-center justify-between border-l-2 px-3 py-2.5 text-left text-sm transition-colors ${isActive ? "border-brand bg-sidebar-accent text-sidebar-foreground" : "border-transparent text-muted-foreground hover:bg-sidebar-accent/60 hover:text-sidebar-foreground"}`}
                >
                  <span className="flex items-center gap-3"><Icon className={`size-4 ${isActive ? "text-brand" : "text-muted-foreground"}`} />{item.label}</span>
                  {badge && <span className={`font-mono text-[10px] ${item.page === "overview" ? "text-status-critical" : "text-muted-foreground"}`}>{badge}</span>}
                </button>
              );
            })}
          </nav>

          <p className="mb-3 mt-9 px-3 font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">System</p>
          <nav className="space-y-1">
            {systemNav.map((item) => {
              const Icon = item.icon;
              const isActive = page === item.page;
              return (
                <button
                  key={item.page}
                  onClick={() => navigate(item.page)}
                  className={`flex w-full items-center gap-3 border-l-2 px-3 py-2.5 text-left text-sm transition-colors ${isActive ? "border-brand bg-sidebar-accent text-sidebar-foreground" : "border-transparent text-muted-foreground hover:bg-sidebar-accent/60 hover:text-sidebar-foreground"}`}
                >
                  <Icon className={`size-4 ${isActive ? "text-brand" : "text-muted-foreground"}`} />{item.label}
                </button>
              );
            })}
          </nav>
        </div>

        <div className="border-t border-sidebar-border p-4">
          <div className="mb-4 flex items-center gap-3 border border-sidebar-border bg-sidebar-accent/50 p-3">
            <div className="flex size-8 items-center justify-center bg-brand/15 text-brand"><UserRound className="size-4" /></div>
            <div className="min-w-0">
              <p className="truncate text-xs font-medium text-sidebar-foreground">{analyst.trim() || "Guest analyst"}</p>
              <p className="truncate font-mono text-[10px] text-muted-foreground">Local workspace · Phase 1</p>
            </div>
            <span className="ml-auto size-1.5 rounded-full bg-status-safe" />
          </div>
          <div className="flex items-center justify-between px-1 font-mono text-[9px] uppercase tracking-wider text-muted-foreground"><span>Evidence in-browser</span><span>{scans.length} case{scans.length === 1 ? "" : "s"}</span></div>
        </div>
      </aside>

      <main className="min-h-screen lg:pl-64">
        <header className="sticky top-0 z-30 flex h-20 items-center justify-between border-b border-border bg-shell/95 px-5 backdrop-blur lg:px-8">
          <div className="flex items-center gap-4">
            <Button variant="ghost" size="icon" className="lg:hidden" onClick={() => setMobileNavOpen(true)} aria-label="Open navigation"><Menu className="size-5" /></Button>
            <span className="size-1.5 rounded-full bg-brand" aria-hidden="true" />
            <p className="font-display text-sm font-semibold tracking-wide text-foreground">{pageTitles[page]}</p>
          </div>
          <div className="flex items-center gap-2 sm:gap-4">
            <Button size="sm" onClick={() => setScanOpen(true)}><ShieldCheck className="size-3.5" />Analyze email</Button>
            <div className="hidden h-5 w-px bg-border sm:block" />
            <button className="flex items-center gap-2 text-left" aria-label="Open settings" onClick={() => navigate("settings")}>
              <div className="flex size-8 items-center justify-center bg-brand text-xs font-bold text-brand-foreground">{initials}</div>
              <span className="hidden text-xs font-medium sm:block">{analyst.trim() || "Guest analyst"}</span>
            </button>
          </div>
        </header>

        <div className="mx-auto max-w-[1600px] px-5 py-7 lg:px-8 lg:py-9">{renderPage()}</div>
      </main>
    </div>
  );
}
