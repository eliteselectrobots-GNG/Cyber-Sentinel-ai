import { AlertTriangle, Ban, CheckCircle2, Inbox, Server, ShieldAlert, ShieldCheck, XCircle, type LucideIcon } from "lucide-react";
import { useMemo, type ReactNode } from "react";
import { flagEmoji, locationLabel, type GeoInfo } from "@/lib/geo";
import { classifyEmail, classMeta, getOrgDomain } from "@/lib/advanced";
import type { StoredScan } from "@/lib/store";

export type PageKey = "overview" | "investigations" | "relay" | "campaign" | "evidence" | "health" | "settings";

export function PageHeader({ title, description, actions }: { title: string; description: string; actions?: ReactNode }) {
  return (
    <section className="mb-8 flex flex-col justify-between gap-5 sm:flex-row sm:items-end">
      <div>
        <div className="mb-3 flex items-center gap-2">
          <span className="status-pulse size-2 rounded-full bg-status-safe" />
          <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.2em] text-status-safe">Monitoring active · local mode</span>
        </div>
        <h1 className="font-display text-3xl font-semibold tracking-tight text-foreground lg:text-4xl">{title}</h1>
        <p className="mt-2 max-w-xl text-sm leading-6 text-muted-foreground">{description}</p>
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </section>
  );
}

export function Card({ children, className = "", labelledBy }: { children: ReactNode; className?: string; labelledBy?: string }) {
  return (
    <section aria-labelledby={labelledBy} className={`border border-border bg-surface ${className}`}>
      {children}
    </section>
  );
}

export function CardHeader({ id, title, subtitle, right }: { id?: string; title: string; subtitle?: string; right?: ReactNode }) {
  return (
    <div className="flex flex-col gap-3 border-b border-border p-5 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <div className="flex items-center gap-2">
          <h2 id={id} className="font-display text-base font-semibold">{title}</h2>
        </div>
        {subtitle && <p className="mt-1 text-xs text-muted-foreground">{subtitle}</p>}
      </div>
      {right && <div className="flex shrink-0 items-center gap-2">{right}</div>}
    </div>
  );
}

export function EmptyState({ title, detail, action }: { title: string; detail: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      <Inbox className="size-8 text-muted-foreground/40" />
      <p className="text-sm font-medium text-foreground">{title}</p>
      <p className="max-w-sm text-xs leading-5 text-muted-foreground">{detail}</p>
      {action && <div className="mt-3">{action}</div>}
    </div>
  );
}

export function SeverityBadge({ risk }: { risk: string }) {
  const critical = risk === "Critical";
  const high = risk === "High";
  return (
    <span
      className={`inline-flex items-center gap-1 border px-2 py-0.5 font-mono text-[9px] uppercase tracking-wider ${
        critical
          ? "border-status-critical/40 bg-status-critical/10 text-status-critical"
          : high
            ? "border-status-warning/40 bg-status-warning/10 text-status-warning"
            : risk === "Medium"
              ? "border-brand/40 bg-brand/10 text-brand"
              : "border-status-safe/30 bg-status-safe/10 text-status-safe"
      }`}
    >
      {critical ? <AlertTriangle className="size-3" /> : high ? <AlertTriangle className="size-3" /> : risk === "Medium" ? null : <ShieldCheck className="size-3" />}
      {risk}
    </span>
  );
}

export function DemoTag() {
  return <span className="border border-brand/40 bg-brand/10 px-1.5 py-0.5 font-mono text-[8px] uppercase tracking-wider text-brand">Demo</span>;
}

export function IntegrityBadge({ verified }: { verified: boolean }) {
  return verified ? (
    <span className="inline-flex items-center gap-1 border border-status-safe/30 bg-status-safe/10 px-2 py-0.5 font-mono text-[9px] uppercase tracking-wider text-status-safe">
      <CheckCircle2 className="size-3" /> Integrity verified
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 border border-status-critical/40 bg-status-critical/10 px-2 py-0.5 font-mono text-[9px] uppercase tracking-wider text-status-critical">
      <XCircle className="size-3" /> Integrity mismatch
    </span>
  );
}

export function Stat({ label, value, suffix, sub, tone = "brand", icon: Icon }: { label: string; value: string; suffix?: string; sub?: string; tone?: "critical" | "brand" | "warning" | "safe"; icon: LucideIcon }) {
  const color = tone === "critical" ? "text-status-critical" : tone === "warning" ? "text-status-warning" : tone === "safe" ? "text-status-safe" : "text-brand";
  const subColor = tone === "critical" ? "text-status-critical" : tone === "warning" ? "text-status-warning" : tone === "safe" ? "text-status-safe" : "text-muted-foreground";
  return (
    <div className="bg-surface p-5">
      <div className="mb-6 flex items-center justify-between">
        <p className="text-xs font-medium text-muted-foreground">{label}</p>
        <Icon className={`size-4 ${color}`} />
      </div>
      <div className="flex items-baseline gap-1">
        <span className="font-display text-3xl font-semibold tracking-tight text-foreground">{value}</span>
        {suffix && <span className="font-mono text-xs text-muted-foreground">{suffix}</span>}
      </div>
      {sub && <p className={`mt-3 font-mono text-[10px] ${subColor}`}>{sub}</p>}
    </div>
  );
}

export function DotLegend({ color, label, value }: { color: string; label: string; value: string }) {
  return (
    <div className="flex items-center gap-2.5 text-xs">
      <span className={`size-2 rounded-full ${color}`} />
      <span className="flex-1 text-muted-foreground">{label}</span>
      <span className="font-mono text-foreground">{value}</span>
    </div>
  );
}

export function Bar({ label, value, pct, tone }: { label: string; value: string; pct: number; tone: string }) {
  return (
    <div>
      <div className="mb-1.5 flex justify-between text-[11px]">
        <span className="text-muted-foreground">{label}</span>
        <span className="font-mono text-foreground">{value}</span>
      </div>
      <div className="h-1.5 bg-muted">
        <div className={`h-full ${tone}`} style={{ width: `${Math.max(2, Math.min(100, pct))}%` }} />
      </div>
    </div>
  );
}

export function GeoLine({ geo, compact = false }: { geo: GeoInfo; compact?: boolean }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs">
      <span aria-hidden="true">{flagEmoji(geo.countryCode)}</span>
      <span className="font-medium text-foreground">{locationLabel(geo)}</span>
      {geo.source === "demo" && <span className="border border-brand/40 bg-brand/10 px-1 py-px font-mono text-[8px] uppercase tracking-wider text-brand">demo</span>}
      {geo.asn && <span className="font-mono text-[10px] text-muted-foreground">{geo.asn}</span>}
      {geo.isp && !compact && <span className="font-mono text-[10px] text-muted-foreground">{geo.isp}</span>}
    </span>
  );
}

const classTone: Record<"critical" | "warning" | "brand" | "safe", string> = {
  critical: "border-status-critical/40 bg-status-critical/10 text-status-critical",
  warning: "border-status-warning/40 bg-status-warning/10 text-status-warning",
  brand: "border-brand/40 bg-brand/10 text-brand",
  safe: "border-status-safe/30 bg-status-safe/10 text-status-safe",
};

/** Compact 5-class verdict chip (Fraud / Phishing / Impersonation / Suspicious / Legitimate). */
export function ClassTag({ scan, scans }: { scan: StoredScan; scans: StoredScan[] }) {
  const detection = useMemo(() => classifyEmail(scan, scans, getOrgDomain()), [scan, scans]);
  const meta = classMeta[detection.className];
  return <span className={`inline-flex items-center border px-1.5 py-0.5 font-mono text-[8px] uppercase tracking-wider ${classTone[meta.tone]}`}>{meta.label}</span>;
}

/** Live infrastructure chips for one hop IP: Tor exit, blacklist hits, cloud hosting. */
export function InfraChips({ scan, ip }: { scan: StoredScan; ip: string }) {
  const infra = scan.infra?.[ip];
  if (!infra || (!infra.torExit && !infra.cloudHosting && infra.blacklists.length === 0)) return null;
  return (
    <div className="mt-1.5 flex flex-wrap gap-1.5">
      {infra.torExit && (
        <span title="Listed as a live Tor exit relay by Tor Project DNSEL or relay-operator ASN fingerprint" className="inline-flex items-center gap-1 border border-status-warning/40 bg-status-warning/10 px-1.5 py-0.5 font-mono text-[8px] uppercase tracking-wider text-status-warning">
          <ShieldAlert className="size-2.5" />Tor exit relay
        </span>
      )}
      {infra.blacklists.map((hit) => (
        <span key={hit.list} title={`${hit.meaning} — resolved live from ${hit.list}`} className="inline-flex items-center gap-1 border border-status-critical/40 bg-status-critical/10 px-1.5 py-0.5 font-mono text-[8px] uppercase tracking-wider text-status-critical">
          <Ban className="size-2.5" />Blacklisted · {hit.list}
        </span>
      ))}
      {infra.cloudHosting && (
        <span title="ISP/ASN fingerprint matches a cloud or datacenter hosting provider — rented infrastructure, not residential broadband" className="inline-flex items-center gap-1 border border-brand/40 bg-brand/10 px-1.5 py-0.5 font-mono text-[8px] uppercase tracking-wider text-brand">
          <Server className="size-2.5" />Cloud / datacenter host
        </span>
      )}
      {infra.source === "demo" && (
        <span className="inline-flex items-center border border-border bg-shell px-1.5 py-0.5 font-mono text-[8px] uppercase tracking-wider text-muted-foreground">demo</span>
      )}
    </div>
  );
}

export function timeAgo(timestamp: number): string {
  const seconds = Math.max(1, Math.round((Date.now() - timestamp) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return new Date(timestamp).toLocaleString();
}
