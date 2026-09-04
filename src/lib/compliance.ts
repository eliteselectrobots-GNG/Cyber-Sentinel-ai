/**
 * Privacy / legal / compliance controls:
 *
 *  - Chain-of-custody audit log (who did what, when, to which case). Events
 *    are append-only in IndexedDB and survive record deletion by design.
 *  - Configurable retention: auto-delete evidence older than N days.
 *  - Configurable masking of email addresses in exported reports.
 *
 * All three are client-side preferences and stay in this browser.
 */

import { addAuditEvent, type AuditEvent, type StoredScan } from "./store";

const ANALYST_STORAGE_KEY = "aegistrace.analyst";
const RETENTION_KEY = "aegistrace.retention-days";
const MASK_KEY = "aegistrace.mask-emails";

/* ------------------------------- Audit log ------------------------------- */

export const auditActionLabels: Record<string, string> = {
  "case.scanned": "Evidence analyzed",
  "case.deleted": "Case deleted",
  "integrity.verified": "Integrity verified",
  "integrity.failed": "Integrity MISMATCH",
  "report.exported": "Report exported",
  "evidence.cleared": "Evidence store cleared",
  "demo.loaded": "Demo dataset loaded",
  "retention.applied": "Retention applied",
};

function currentActor(): string {
  try {
    return (localStorage.getItem(ANALYST_STORAGE_KEY) ?? "").trim() || "Anonymous";
  } catch {
    return "Anonymous";
  }
}

/** Append one immutable chain-of-custody event (best-effort, never throws). */
export async function logAudit(action: keyof typeof auditActionLabels | string, caseId?: string, detail?: string): Promise<void> {
  const event: AuditEvent = { id: crypto.randomUUID(), at: Date.now(), actor: currentActor(), action };
  if (caseId) event.caseId = caseId;
  if (detail) event.detail = detail;
  await addAuditEvent(event);
}

/* ------------------------------- Retention ------------------------------- */

/** Days of retention, or null when retention is off. */
export function getRetentionDays(): number | null {
  try {
    const raw = Number(localStorage.getItem(RETENTION_KEY) ?? "0");
    return Number.isInteger(raw) && raw > 0 ? raw : null;
  } catch {
    return null;
  }
}

export function setRetentionDays(days: number | null): void {
  try {
    localStorage.setItem(RETENTION_KEY, String(days ?? 0));
  } catch {
    /* storage unavailable */
  }
}

/**
 * Deletes stored scans older than the configured retention window.
 * Demo records are exempt so the onboarding sample survives; audit events
 * are kept — deleting evidence is itself part of the chain of custody.
 * Returns the number of records removed.
 */
export async function applyRetention(scans: StoredScan[], deleteScan: (id: string) => Promise<void>): Promise<number> {
  const days = getRetentionDays();
  if (!days) return 0;
  const cutoff = Date.now() - days * 86400_000;
  const expired = scans.filter((scan) => !scan.demo && scan.scannedAt < cutoff);
  for (const scan of expired) {
    try {
      await deleteScan(scan.id);
    } catch {
      // best-effort per record
    }
  }
  if (expired.length > 0) {
    await logAudit("retention.applied", undefined, `${expired.length} record(s) older than ${days} day${days === 1 ? "" : "s"} auto-deleted.`);
  }
  return expired.length;
}

/* -------------------------------- Masking -------------------------------- */

export function getMaskingEnabled(): boolean {
  try {
    return localStorage.getItem(MASK_KEY) === "1";
  } catch {
    return false;
  }
}

export function setMaskingEnabled(enabled: boolean): void {
  try {
    localStorage.setItem(MASK_KEY, enabled ? "1" : "0");
  } catch {
    /* storage unavailable */
  }
}

/**
 * Masks the local part of one address ("r.kapoor@x.example" → "r***@x.example")
 * while keeping the domain readable for investigation. Unchanged when masking
 * is disabled or the address is not mailable-looking.
 */
export function maskAddress(email: string): string {
  if (!getMaskingEnabled()) return email;
  const match = /^([^@\s]+)@([^@\s]+)$/.exec(email.trim());
  if (!match) return email;
  const local = match[1] ?? "";
  const domain = match[2] ?? "";
  if (!domain.includes(".")) return email;
  const head = local.slice(0, Math.min(2, local.length));
  const stars = "*".repeat(Math.max(2, Math.min(6, local.length)));
  return `${head}${stars}@${domain}`;
}

/** Masks every email address found in a text block (report bodies etc.). */
export function maskAllEmails(text: string): string {
  if (!getMaskingEnabled()) return text;
  return text.replace(/\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b/g, (address) => {
    const masked = maskAddress(address);
    return masked.length < address.length ? masked : address;
  });
}
