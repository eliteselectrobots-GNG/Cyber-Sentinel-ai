import { scanEmail } from "./email-scanner";
import { toStoredScan, type StoredScan } from "./store";

/**
 * Demo dataset. Every entry is a realistic raw message that is pushed
 * through the REAL scan engine — nothing here bypasses analysis. Entries
 * are clearly marked as demo evidence in the UI.
 */

const demoMessages: { subject?: string; raw: string; minutesAgo: number }[] = [
  {
    // reply-to mismatch + urgency + payment language
    raw: `From: Finance Desk <finance@acme-corp.example>
To: accounts@northstar.example
Reply-To: payments-team@acme-corp-updates.example
Subject: URGENT: Updated bank details — action required
Date: Sun, 30 Aug 2026 09:41:12 +0530
Return-Path: <bounce@acme-corp.example>
Authentication-Results: northstar.example; spf=fail smtp.mailfrom=acme-corp.example; dkim=none
Received: from relay.acme-corp-updates.example (185.220.101.4) by mx2.example.net
Received: from unknown (203.0.113.44) by relay.acme-corp-updates.example

Please process the attached invoice immediately and confirm the new beneficiary account before 12:00. Reply to payments-team@acme-corp-updates.example.`,
    minutesAgo: 6,
  },
  {
    // mailbox quota / credential harvesting
    raw: `From: IT Service Desk <support@mail-northstar-secure.example>
To: r.kapoor@northstar.example
Subject: Your mailbox quota has been exceeded — verify now
Date: Sun, 30 Aug 2026 08:56:00 +0530
Return-Path: <bounce@mail-northstar-secure.example>
Received: from smtp-02.mail-northstar-secure.example (198.51.100.17) by mx1.example.net

Your mailbox has exceeded its storage quota. Sign in at the secure portal within 24 hours to keep your account active, otherwise messages will be suspended. Verify your identity with your corporate password.`,
    minutesAgo: 33,
  },
  {
    // lookalike-ish domain, softfail auth, urgency
    raw: `From: NorthStar Bank <alerts@northstarbank.example>
Reply-To: noreply@northstarbank.example
Subject: Final notice: unusual sign-in attempt on your account
Date: Sun, 30 Aug 2026 07:12:45 +0530
Return-Path: <bounce@northstarbank.example>
Authentication-Results: mx1.example.net; spf=softfail smtp.mailfrom=northstarbank.example
Received: from mailer.northstarbank-verify.example (203.0.113.88) by mx1.example.net

Dear customer, we detected an unusual sign-in from a new device. If this was not you, confirm your details immediately to prevent account suspension. Click here to review the activity: https://northstarbank-verify.example/secure/login`,
    minutesAgo: 61,
  },
  {
    // benign control sample
    raw: `From: R. Kapoor <r.kapoor@northstar.example>
To: procurement@northstar.example
Cc: finance@northstar.example
Subject: Re: acquisition materials — draft attached
Date: Sun, 30 Aug 2026 08:32:10 +0530
Return-Path: <r.kapoor@northstar.example>
Received: from smtp-01.northstar.example (192.0.2.25) by mx1.northstar.example

Hi team, attaching the draft deck from yesterday's review. Please share feedback by EOD so we can finalize before the vendor call on Wednesday. Thanks!`,
    minutesAgo: 72,
  },
];

export async function buildDemoDataset(): Promise<StoredScan[]> {
  const now = Date.now();
  const scans: StoredScan[] = [];
  for (const message of demoMessages) {
    const result = await scanEmail(message.raw);
    scans.push(toStoredScan(message.raw, result, now - message.minutesAgo * 60_000, true));
  }
  return scans.sort((a, b) => b.scannedAt - a.scannedAt);
}
