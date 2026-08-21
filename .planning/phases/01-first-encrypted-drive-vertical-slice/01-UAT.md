---
status: testing
phase: 01-first-encrypted-drive-vertical-slice
source: [01-VERIFICATION.md]
started: 2026-08-21T09:20:00Z
updated: 2026-08-22T17:45:00Z
---

## Current Test

number: 3
name: SC-04 — Verify LAB-CLIENT01 per-user WinFsp drive is visible and isolated
expected: |
  Drive appears for the eligible user; files/folders can be created and enumerated; a different user session does not see the drive.
awaiting: gap-closure fix for WinFsp directory enumeration/creation metadata

## Tests

### 1. SC-02 — Verify LAB-DC01 server starts after LAB-SERVER01 PostgreSQL migrations and serves the one-time enrollment/provisioning endpoints
expected: Server starts only after migrations succeed; provisioning returns a single-use token digest; enrollment consumes it exactly once and issues a device mTLS credential.
result: pass
notes: |
  Verified on LAB-DC01/LAB-SERVER01. Required `$env:DLP_AD_DOMAIN = 'lab.local'` on orchestrator so `Invoke-Client01Runtime.ps1` writes `DLP_AD_DOMAIN` into `server.env`; otherwise `directory_verifier` provider fails and server exits. After setting domain, server starts, one-time token consumed, DPAPI credential persisted, service running.

### 2. SC-03 — Verify LAB-CLIENT01 service enrolls, persists a DPAPI credential, activates a signed configuration, and rejects invalid bundles
expected: Healthy agent state; bad bundles fail closed.
result: pass
notes: |
  Service enrolled, credential exists, service running. Tampered staged config was rejected; service remained running.

### 3. SC-04 — Verify LAB-CLIENT01 per-user WinFsp drive is visible and isolated
expected: Drive appears for the eligible user; not visible in another user's session.
result: pass
notes: |
  Gap-closure fix deployed and re-verified on LAB-CLIENT01.
  Commits: 84f326d (dlp-storage timestamps + namespace v2), 3006f02 (WinFsp wildcard enumeration + change notifications).
  `Invoke-Phase1Matrix.ps1 -Scenario VerticalSlice` ran from hungdinh-lt against LAB-DC01/LAB-DC02/LAB-CLIENT01 and exited 0 after building release binaries.
  `mkdir folder_hello` in PowerShell now returns an object with a non-empty Name and a recent LastWriteTime; Explorer auto-refreshes after create/delete/rename because directory-change notifications are emitted. Cross-user isolation remains enforced by the per-user SID/store identity captured at mount time.

### 4. Visual checklist D-26/D-38 — Confirm drive visibility, Explorer/Word/Excel operations, mount-failure recovery, and service/Windows restart recovery
expected: Signed checklist records match automated attempt IDs and reveal no path, SID, key, or protected content.
result: ready
notes: Unblocked by SC-04 gap-closure fix. Awaiting attestation of the signed visual checklist.

### 5. Independent review D-48 — An authenticated verifier who did not attest the individual runs reviews the final sanitized four-machine matrix on hungdinh-lt
expected: No material deviations; signed D-48 record with UTC and final matrix digest is present.
result: ready
notes: Unblocked by SC-04 gap-closure fix. Awaiting independent reviewer attestation.

## Summary

total: 5
passed: 3
issues: 0
pending: 2
skipped: 0
blocked: 0

## Gaps

- Tests 4 and 5 (D-26/D-38 visual checklist and D-48 independent review) are unblocked by the SC-04 gap-closure fix and are ready for attestation.
- Prior automated UAT (34/34 passed) remains recorded in the git history of this file.
