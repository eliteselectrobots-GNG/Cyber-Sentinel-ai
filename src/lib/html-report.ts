/**
 * Printable HTML forensic report — a self-contained, styled dossier that
 * opens in a new tab and prints/saves to PDF (Ctrl+P). Light theme so it
 * renders correctly on paper and in PDF viewers.
 */

import type { StoredScan } from "./store";
import { extractIocs } from "./iocs";
import { flagEmoji, locationLabel } from "./geo";
import { classifyEmail, attributionOf, classMeta, getOrgDomain, headerForensics, type AnalysisFlag } from "./advanced";

const esc = (value: string) =>
  value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

function severityDot(severity: AnalysisFlag["severity"]): string {
  const color = severity === "critical" ? "#e5484d" : severity === "high" ? "#c9a227" : severity === "medium" ? "#7c69ef" : "#53d88a";
  return `<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:${color};margin-right:8px;vertical-align:middle;"></span>`;
}

function flagList(flags: AnalysisFlag[], empty: string): string {
  if (flags.length === 0) return `<p class="muted">${esc(empty)}</p>`;
  return flags
    .map((flag) => `<p style="margin:0 0 6px 0;">${severityDot(flag.severity)}<b>${esc(flag.label)}</b><br/><span class="muted" style="margin-left:15px;">${esc(flag.detail)}</span></p>`)
    .join("");
}

function section(title: string, body: string): string {
  return `<section style="margin:22px 0;"><h2 style="font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:#7c69ef;border-bottom:1px solid #e6e6ef;padding-bottom:6px;margin:0 0 12px 0;">${esc(title)}</h2>${body}</section>`;
}

function kv(label: string, value: string): string {
  return `<div style="display:flex;gap:16px;padding:5px 0;border-bottom:1px dotted #ececf4;"><span class="muted" style="width:150px;flex-shrink:0;font-size:11px;">${esc(label)}</span><span style="font-family:'Courier New',monospace;font-size:11px;word-break:break-all;">${esc(value)}</span></div>`;
}

export function buildHtmlReport(scan: StoredScan, scans: StoredScan[]): string {
  const r = scan.result;
  const orgDomain = getOrgDomain();
  const classification = classifyEmail(scan, scans, orgDomain);
  const attribution = attributionOf(scan, scans, orgDomain);
  const forensics = headerForensics(scan);
  const iocs = extractIocs(scan.raw, r);
  const intel = scan.domainIntel ?? {};
  const scanned = new Date(scan.scannedAt);

  const reversed = [...r.hops];
  if (reversed[0]?.status === "relay" && reversed.at(-1)?.status === "origin") reversed.reverse();
  const orderedHops = reversed;

  const hopRows = orderedHops
    .map((hop, index) => {
      const role = index === 0 ? "Origin" : index === orderedHops.length - 1 ? "Destination" : `Relay ${index}`;
      const geo = scan.geo?.[hop.ip];
      const infra = scan.infra?.[hop.ip];
      const chips = [
        infra?.torExit ? "TOR EXIT" : "",
        ...(infra?.blacklists ?? []).map((hit) => `BLACKLISTED (${hit.list})`),
        infra?.cloudHosting ? "CLOUD/DATACENTER" : "",
      ].filter(Boolean);
      const location = geo ? `${locationLabel(geo)} ${flagEmoji(geo.countryCode)}${geo.asn ? ` · ${geo.asn}` : ""}${geo.isp ? ` · ${geo.isp}` : ""}` : "Location unavailable";
      const chipHtml = chips.length ? `<br/><span class="chip">${chips.map((chip) => esc(chip)).join("</span> <span class=\"chip\">")}</span>` : "";
      return `<tr><td style="white-space:nowrap;">${esc(role)}</td><td style="white-space:nowrap;">${esc(hop.ip)}</td><td>${esc(location)}${chipHtml}</td><td class="muted">${esc(hop.detail)}</td></tr>`;
    })
    .join("");

  const intelRows = Object.entries(intel)
    .map(([domain, record]) => {
      const registrar = record.whois ? `${record.whois.registrar}${record.whois.created ? ` · registered ${new Date(record.whois.created).toLocaleDateString()}` : ""}` : "No public WHOIS record";
      const mx = record.mx.length ? record.mx.slice(0, 4).map((entry) => esc(entry)).join(", ") : "none";
      return `<div style="padding:8px 0;border-bottom:1px dotted #ececf4;"><b style="font-family:'Courier New',monospace;">${esc(domain)}</b><br/><span class="muted">Registrar: ${esc(registrar)}</span><br/><span class="muted">MX: ${mx}</span></div>`;
    })
    .join("");
  const intelNote = Object.keys(intel).length === 0 ? '<p class="muted">Domain intelligence is captured at scan time — re-run the scan while online.</p>' : intelRows;

  const authHtml = scan.auth?.checks.length
    ? scan.auth.checks
        .map(
          (check) =>
            `<p style="margin:0 0 6px 0;"><span class="mono" style="text-transform:uppercase;font-size:10px;color:#666b82;">${esc(check.kind)} · ${esc(check.domain)}</span> — <b>${esc(check.outcome)}</b><br/><span class="muted" style="margin-left:15px;">${esc(check.detail)}</span></p>`
        )
        .join("")
    : '<p class="muted">No live DNS checks were captured with this case.</p>';

  const relayHtml =
    `<table><thead><tr><th>Role</th><th>IP</th><th>Geolocation &amp; infrastructure</th><th>Header detail</th></tr></thead><tbody>${hopRows}</tbody></table>` +
    (scan.raw.includes("Received:") ? "" : '<p class="muted">No Received headers were present.</p>');

  const iocHtml = iocs.length
    ? `<table><thead><tr><th>Type</th><th>Value</th><th>Source</th></tr></thead><tbody>${iocs
        .map((ioc) => `<tr><td class="mono">${esc(ioc.type)}</td><td class="mono">${esc(ioc.value)}</td><td class="muted">${esc(ioc.source)}</td></tr>`)
        .join("")}</tbody></table>`
    : '<p class="muted">No indicators extracted.</p>';

  const summaryHtml =
    `<p style="font-size:13px;margin:0 0 10px 0;"><b>${esc(r.subject)}</b></p>` +
    kv("From", `${r.sender} <${r.senderAddress}>`) +
    kv("Reply-To", r.replyTo) +
    kv("Return-Path", r.returnPath) +
    kv("Date", r.receivedAt) +
    kv("Headers parsed", `${r.headersFound} values · ${r.hops.length} relay hop(s)`) +
    (iocs.length ? kv("Indicators", `${iocs.length} extracted (${iocs.filter((ioc) => ioc.type === "IP").length} IP · ${iocs.filter((ioc) => ioc.type === "URL").length} URL)`) : "");

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>AegisTrace — ${esc(scan.caseId)} Forensic Report</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: Georgia, 'Times New Roman', serif; color: #1a1a2e; background: #fff; margin: 40px auto; max-width: 860px; padding: 0 24px; }
  .muted { color: #666b82; font-size: 10px; }
  .chip { display:inline-block; font-family:'Courier New',monospace; font-size:9px; letter-spacing:0.06em; padding:2px 6px; margin-top:6px; border:1px solid #c8c8e0; color:#444; }
  .mono { font-family:'Courier New',monospace; }
  table { width: 100%; border-collapse: collapse; font-size: 11px; }
  th { text-align: left; font-size: 9px; text-transform: uppercase; letter-spacing: 0.08em; color: #666b82; border-bottom: 1px solid #d8d8ea; padding: 6px 8px; }
  td { padding: 8px; border-bottom: 1px solid #f0f0f7; vertical-align: top; }
  .verdict { border: 1px solid #7c69ef; background: #f7f6ff; padding: 16px 18px; margin: 18px 0; }
  h1 { font-size: 20px; margin: 0; }
  @media print { body { margin: 0; } .no-print { display: none; } }
</style></head>
<body>
  <div class="no-print" style="margin-bottom:18px;font-size:11px;"><button onclick="window.print()" style="padding:8px 14px;background:#7c69ef;color:#fff;border:0;border-radius:4px;cursor:pointer;">Print / Save as PDF</button> <span class="muted">Tip: choose “Save as PDF” as the destination.</span></div>
  <div style="display:flex;justify-content:space-between;align-items:flex-start;border-bottom:2px solid #1a1a2e;padding-bottom:12px;">
    <div><p class="mono" style="letter-spacing:0.2em;font-size:10px;color:#7c69ef;margin:0;">AEGISTRACE</p>
    <h1>Forensic Case Report</h1></div>
    <div style="text-align:right;" class="mono"><div style="font-size:13px;"><b>${esc(scan.caseId)}</b></div><div class="muted">${esc(scanned.toLocaleString())}</div></div>
  </div>

  <div class="verdict">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <div><p class="mono" style="letter-spacing:0.1em;font-size:9px;color:#666b82;margin:0 0 4px 0;">CLASSIFICATION</p>
      <p style="font-size:18px;margin:0;"><b>${esc(classMeta[classification.className].label)}</b> — confidence ${classification.confidence}%</p></div>
      <div style="text-align:right;"><p class="mono" style="margin:0;font-size:11px;color:#666b82;">THREAT SCORE</p><p style="font-size:22px;margin:0;">${r.riskScore}<span class="muted">/100</span></p></div>
    </div>
    <p class="muted" style="margin:10px 0 0 0;">${esc(classification.verdict)}</p>
    <p style="font-size:12px;margin:8px 0 0 0;">${esc(attribution.label)} <span class="muted">(confidence ${attribution.confidence}%) — </span>${esc(attribution.description)}</p>
  </div>

  ${section("Message summary", summaryHtml)}

  ${section("Detection findings", flagList(r.findings, "No configured threat signals matched."))}

  ${section("Header & protocol forensics", flagList(forensics, "No protocol anomalies detected."))}

  ${section("Live authentication · DNS-over-HTTPS", authHtml)}

  ${section("Relay path reconstruction", relayHtml)}

  ${section("Domain intelligence", intelNote)}

  ${section("Indicators of compromise", iocHtml)}

  <section style="margin:22px 0;">
    <h2 style="font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:#7c69ef;border-bottom:1px solid #e6e6ef;padding-bottom:6px;margin:0 0 12px 0;">Evidence integrity</h2>
    <p class="mono" style="font-size:10px;word-break:break-all;">SHA-256: ${esc(r.evidenceHash)}</p>
    <p class="muted">Re-running the exact submitted content through the engine reproduces this fingerprint (chain of custody). Report generated ${esc(new Date().toLocaleString())}. All analysis ran locally in the browser; no message content left the device.</p>
  </section>
</body></html>`;
}

/** Opens the report in a new tab; falls back to downloading the .html file. */
export function openHtmlReport(scan: StoredScan, scans: StoredScan[]): void {
  const html = buildHtmlReport(scan, scans);
  const blob = new Blob([html], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const opened = window.open(url, "_blank");
  if (!opened) {
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${scan.caseId}-forensic-report.html`;
    anchor.click();
  }
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
}
