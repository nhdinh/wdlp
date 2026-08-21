---
status: testing
phase: 01-first-encrypted-drive-vertical-slice
source: [01-VERIFICATION.md]
started: 2026-08-21T09:20:00Z
updated: 2026-08-21T17:45:00Z
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
result: issue-major
notes: |
  Drive letter P: is visible, but creating a folder from PowerShell (`mkdir folder_hello`) returns an object with an empty `Name` and a `LastWriteTime` of `1600-12-31` (FILETIME 0). Explorer shows the drive as empty. Backing store confirms the entry was persisted (`namespace.rec`, `.directory-flush`, and a new `files/file-...` directory), so the create reached the encrypted store but directory enumeration/file metadata is broken at the WinFsp layer.

  Suspected root causes in `crates/dlp-windows-drive/src/filesystem.rs`:
  - `read_directory` rejects any query pattern other than `"*"` with `STATUS_NOT_SUPPORTED`; Windows/Explorer/PowerShell often query directories with specific wildcard patterns, causing enumeration to fail or return incomplete metadata.
  - `file_info_for`, `create`, and `open` do not set `creation_time`/`last_access_time`/`last_write_time`/`change_time`, so every returned `FileInfo` has zero timestamps (shown as 1600 dates).
  - No directory-change notifications are sent after create/delete/write, so Explorer does not auto-refresh.

### 4. Visual checklist D-26/D-38 — Confirm drive visibility, Explorer/Word/Excel operations, mount-failure recovery, and service/Windows restart recovery
expected: Signed checklist records match automated attempt IDs and reveal no path, SID, key, or protected content.
result: pending
notes: Blocked until SC-04 directory bug is fixed.

### 5. Independent review D-48 — An authenticated verifier who did not attest the individual runs reviews the final sanitized four-machine matrix on hungdinh-lt
expected: No material deviations; signed D-48 record with UTC and final matrix digest is present.
result: pending
notes: Blocked until SC-04 directory bug is fixed.

## Summary

total: 5
passed: 2
issues: 1
pending: 2
skipped: 0
blocked: 0

## Gaps

- **SC-04 major issue**: WinFsp drive mounts but directory enumeration/creation metadata is broken in `crates/dlp-windows-drive/src/filesystem.rs`. Needs a gap-closure plan to fix `read_directory` pattern support, populate `FileInfo` timestamps, and emit directory-change notifications.
- Tests 4 and 5 (D-26/D-38 visual checklist and D-48 independent review) are pending until SC-04 is resolved and re-verified.
- Prior automated UAT (34/34 passed) remains recorded in the git history of this file.
