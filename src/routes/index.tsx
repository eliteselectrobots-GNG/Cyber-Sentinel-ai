import { createFileRoute } from "@tanstack/react-router";
import { Activity, CheckCircle2, Fingerprint, LayoutDashboard, MailWarning, Menu, Network, Settings2, ShieldCheck, UserRound, X, type LucideIcon } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { addScan, clearScans, deleteScan, findScan, listScans, toStoredScan, type StoredScan } from "@/lib/store";
import { buildDemoDataset } from "@/lib/demo-data";
import { enrichWithDns } from "@/lib/dns";
import { enrichIps, flagEmoji, locationLabel, type GeoInfo } from "@/lib/geo";
import { enrichIpInfra, lookupDomainIntel } from "@/lib/infra";
import { applyRetention, logAudit, setRetentionDays, setMaskingEnabled, getRetentionDays, getMaskingEnabled } from "@/lib/compliance";
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

/**
 * Bounds a best-effort enrichment stage so a stalled endpoint can never
 * block the analyst's flow. Resolves with the work's result, or null when
 * the stage errors out or exceeds its time budget.
 */
function withBudget<T>(work: () => Promise<T>, ms = 15000): Promise<T | null> {
  return Promise.race([work().catch(() => null), new Promise<null>((resolve) => setTimeout(() => resolve(null), ms))]);
}

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
    let stored = await listScans();
    // Configurable retention: silently sweep records older than the window.
    const removed = await applyRetention(stored, deleteScan);
    if (removed > 0) stored = await listScans();
    setScans(stored);
    return removed;
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
    const id = stored.id;
    const originHop = result.hops.find((hop) => hop.status === "origin") ?? result.hops[0];
    const originIp = originHop && originHop.ip !== "Not disclosed" ? originHop.ip : null;

    // Persist the verdict immediately — the case must never wait on network
    // enrichment, which is best-effort and continues in the background below.
    await addScan(stored);
    await logAudit("case.scanned", stored.caseId, `${result.riskLabel} risk ${result.riskScore}/100 · ${result.headersFound} headers parsed`);
    await reload();
    navigate("overview");
    notify(`${result.riskLabel} risk · case ${stored.caseId} stored — running live DNS, geolocation, and blacklist checks in the background…`);

    // Desktop alert for high-risk verdicts, if the user has enabled notifications.
    if ((result.riskLabel === "Critical" || result.riskLabel === "High") && typeof Notification !== "undefined" && Notification.permission === "granted") {
      try {
        new Notification(`AegisTrace — ${result.riskLabel} risk (${result.riskScore}/100)`, { body: `${result.subject} · case ${stored.caseId}`, tag: stored.caseId });
      } catch {
        // notifications are optional
      }
    }

    // Background enrichment. Every stage is independent, time-budgeted, and
    // fails gracefully; the stored case is updated once the data lands.
    const hopIps = result.hops.map((hop) => hop.ip).filter((ip) => ip !== "Not disclosed");
    const domains = [...new Set([result.senderAddress.split("@")[1]?.toLowerCase() ?? "", result.replyTo.includes("@") ? result.replyTo.split("@")[1]?.toLowerCase() ?? "" : ""].filter(Boolean))].slice(0, 3);

    const [auth, geo, intel] = await Promise.all([
      withBudget(() => enrichWithDns(result.senderAddress, result.replyTo, result.returnPath, originIp)),
      withBudget(() => enrichIps(hopIps)),
      withBudget(async () => {
        const map: NonNullable<StoredScan["domainIntel"]> = {};
        const lookups = await Promise.all(domains.map((domain) => lookupDomainIntel(domain)));
        lookups.forEach((lookup, index) => {
          const domain = domains[index];
          if (lookup && domain) map[domain] = lookup;
        });
        return Object.keys(map).length > 0 ? map : null;
      }),
    ]);

    let infra: NonNullable<StoredScan["infra"]> | null = null;
    const geoEntries = geo ? (Object.entries(geo as Record<string, GeoInfo>).slice(0, 5) as [string, GeoInfo][]) : [];
    if (geoEntries.length > 0) {
      infra = await withBudget(async () => {
        const map: NonNullable<StoredScan["infra"]> = {};
        const results = await Promise.all(geoEntries.map(([ip, info]) => enrichIpInfra(ip, info)));
        geoEntries.forEach(([ip], index) => {
          const entry = results[index];
          if (entry) map[ip] = entry;
        });
        return Object.keys(map).length > 0 ? map : null;
      });
    }

    if (auth && auth.checks.length > 0) stored.auth = auth;
    if (geo && Object.keys(geo).length > 0) stored.geo = geo;
    if (intel) stored.domainIntel = intel;
    if (infra) stored.infra = infra;

    const enriched = (auth && auth.checks.length > 0) || (geo && Object.keys(geo).length > 0) || Boolean(intel) || Boolean(infra);
    if (!enriched) return;
    // Guard: never resurrect a case the analyst deleted while enrichment ran.
    const stillThere = await findScan(id);
    if (!stillThere) return;
    await addScan(stored);
    await reload();
    const failures = (stored.auth?.checks ?? []).filter((check) => check.outcome === "fail").length;
    const originGeo = originIp ? stored.geo?.[originIp] : undefined;
    const originNote = originGeo ? ` Origin: ${locationLabel(originGeo)} ${flagEmoji(originGeo.countryCode)}.` : "";
    const blacklistHits = Object.values(stored.infra ?? {}).flatMap((entry) => entry.blacklists);
    const torHops = Object.values(stored.infra ?? {}).filter((entry) => entry.torExit).length;
    const infraNote =
      blacklistHits.length > 0
        ? ` ${blacklistHits.length} blacklist hit${blacklistHits.length === 1 ? "" : "s"}${torHops > 0 ? ", relay uses Tor" : ""}.`
        : torHops > 0
          ? ` Relay path traverses a Tor exit node.`
          : "";
    notify(failures > 0 ? `Enrichment complete · case ${stored.caseId} — ${failures} live DNS check${failures === 1 ? "" : "s"} failed.${originNote}${infraNote}` : `Enrichment complete · case ${stored.caseId} updated with live data.${originNote}${infraNote}`);
  };

  const handleEnableAlerts = async () => {
    if (typeof Notification === "undefined") {
      notify("Desktop notifications are not supported in this browser.");
      return;
    }
    if (Notification.permission === "granted") {
      notify("Desktop alerts are already enabled.");
      return;
    }
    const permission = await Notification.requestPermission();
    notify(permission === "granted" ? "Desktop alerts enabled — you will be notified on Critical/High scans." : "Permission denied — alerts stay in-app only.");
  };

  const handleDelete = async (id: string) => {
    await deleteScan(id);
    const caseId = scans.find((scan) => scan.id === id)?.caseId;
    await logAudit("case.deleted", caseId);
    if (selectedCase === id) setSelectedCase(null);
    await reload();
    notify("Case removed from local evidence.");
  };

  const handleLoadDemo = async () => {
    if (scans.length > 0 && !window.confirm("Replace the current local evidence with the demo dataset?")) return;
    await clearScans();
    const dataset = await buildDemoDataset();
    for (const scan of dataset) await addScan(scan);
    await logAudit("demo.loaded", undefined, `${dataset.length} records loaded`);
    await reload();
    notify(`Demo dataset loaded — ${dataset.length} records, each processed by the real engine.`);
  };

  const handleClearAll = async () => {
    if (scans.length === 0) return;
    if (!window.confirm("Delete ALL locally stored evidence? This cannot be undone.")) return;
    await logAudit("evidence.cleared", undefined, `${scans.length} record(s) cleared`);
    await clearScans();
    setSelectedCase(null);
    await reload();
    notify("All local evidence cleared.");
  };

  const handleSetRetention = async (days: number | null) => {
    setRetentionDays(days);
    const removed = await applyRetention(scans, deleteScan);
    if (removed > 0) await reload();
    notify(days === null ? "Retention off — evidence is kept indefinitely." : removed > 0 ? `${removed} expired record${removed === 1 ? "" : "s"} auto-deleted (older than ${days} days).` : `Retention set to ${days} day${days === 1 ? "" : "s"}.`);
  };

  const handleSetMasking = (enabled: boolean) => {
    setMaskingEnabled(enabled);
    notify(enabled ? "Masking enabled — exported reports mask email addresses." : "Masking disabled — reports show full addresses.");
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
        return <CampaignPage scans={scans} onOpenCase={openCase} />;
      case "evidence":
        return <EvidenceVaultPage scans={scans} onDelete={(id) => void handleDelete(id)} navigate={navigate} notify={notify} />;
      case "health":
        return <HealthPage scans={scans} />;
      case "settings":
        return <SettingsPage scans={scans} analyst={analyst} onAnalystChange={handleAnalystChange} onLoadDemo={handleLoadDemo} onClearAll={handleClearAll} notify={notify} onEnableAlerts={() => handleEnableAlerts()} onSetRetention={(days) => void handleSetRetention(days)} retentionDays={getRetentionDays()} onSetMasking={(enabled) => handleSetMasking(enabled)} maskingEnabled={getMaskingEnabled()} />;
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
