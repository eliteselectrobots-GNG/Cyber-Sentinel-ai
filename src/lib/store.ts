import { scanEmail, type EmailScanResult } from "./email-scanner";
import type { DnsEnrichment } from "./dns";

export type StoredScan = {
  /** Stable unique id (uuid). */
  id: string;
  /** Display case id, e.g. AT-1F2A. */
  caseId: string;
  /** The exact raw content submitted. */
  raw: string;
  result: EmailScanResult;
  scannedAt: number;
  /** Set when the record came from the demo dataset, so UI can label it. */
  demo?: boolean;
  /** Live DNS authentication results captured at scan time (if reachable). */
  auth?: DnsEnrichment;
};

const DB_NAME = "aegistrace-db";
const DB_VERSION = 1;
const SCAN_STORE = "scans";

let dbPromise: Promise<IDBDatabase> | undefined;

function openDb(): Promise<IDBDatabase> {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(SCAN_STORE)) {
        const store = db.createObjectStore(SCAN_STORE, { keyPath: "id" });
        store.createIndex("scannedAt", "scannedAt");
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Could not open local evidence store"));
  });
  return dbPromise;
}

function requestToPromise<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Local store operation failed"));
  });
}

function transactionDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("Local store transaction failed"));
    tx.onabort = () => reject(tx.error ?? new Error("Local store transaction aborted"));
  });
}

export async function addScan(scan: StoredScan): Promise<void> {
  const db = await openDb();
  const tx = db.transaction(SCAN_STORE, "readwrite");
  tx.objectStore(SCAN_STORE).put(scan);
  await transactionDone(tx);
}

export async function listScans(): Promise<StoredScan[]> {
  const db = await openDb();
  const tx = db.transaction(SCAN_STORE, "readonly");
  const store = tx.objectStore(SCAN_STORE);
  const index = store.index("scannedAt");
  const all = await requestToPromise(index.getAll() as IDBRequest<StoredScan[]>);
  await transactionDone(tx);
  return all.sort((a, b) => b.scannedAt - a.scannedAt);
}

export async function deleteScan(id: string): Promise<void> {
  const db = await openDb();
  const tx = db.transaction(SCAN_STORE, "readwrite");
  tx.objectStore(SCAN_STORE).delete(id);
  await transactionDone(tx);
}

export async function clearScans(): Promise<void> {
  const db = await openDb();
  const tx = db.transaction(SCAN_STORE, "readwrite");
  tx.objectStore(SCAN_STORE).clear();
  await transactionDone(tx);
}

export async function countScans(): Promise<number> {
  const db = await openDb();
  const tx = db.transaction(SCAN_STORE, "readonly");
  const count = await requestToPromise(tx.objectStore(SCAN_STORE).count());
  await transactionDone(tx);
  return count;
}

/**
 * Chain-of-custody check: re-runs the exact raw content through the engine
 * and compares the freshly computed fingerprint with the stored one.
 */
export async function verifyEvidence(raw: string, expectedHash: string): Promise<{ matches: boolean; result: EmailScanResult }> {
  const result = await scanEmail(raw);
  return { matches: result.evidenceHash === expectedHash, result };
}

export function toStoredScan(raw: string, result: EmailScanResult, scannedAt = Date.now(), demo = false, auth?: DnsEnrichment): StoredScan {
  const scan: StoredScan = {
    id: crypto.randomUUID(),
    caseId: result.id,
    raw,
    result,
    scannedAt,
  };
  if (demo) scan.demo = true;
  if (auth && auth.checks.length > 0) scan.auth = auth;
  return scan;
}

export function riskTone(risk: string): "critical" | "high" | "medium" {
  if (risk === "Critical") return "critical";
  if (risk === "High") return "high";
  return "medium";
}
