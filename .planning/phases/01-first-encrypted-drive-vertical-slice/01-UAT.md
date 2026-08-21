---
status: testing
phase: 01-first-encrypted-drive-vertical-slice
source: [01-VERIFICATION.md]
started: 2026-08-21T09:20:00Z
updated: 2026-08-21T09:20:00Z
---

## Current Test

number: 1
name: SC-02 — Verify LAB-DC01 server starts after LAB-SERVER01 PostgreSQL migrations and serves the one-time enrollment/provisioning endpoints
expected: |
  Server starts only after migrations succeed; provisioning returns a single-use token digest; enrollment consumes it exactly once and issues a device mTLS credential.
awaiting: user response

## Tests

### 1. SC-02 — Verify LAB-DC01 server starts after LAB-SERVER01 PostgreSQL migrations and serves the one-time enrollment/provisioning endpoints
expected: Server starts only after migrations succeed; provisioning returns a single-use token digest; enrollment consumes it exactly once and issues a device mTLS credential.
result: [pending]

### 2. SC-03 — Verify LAB-CLIENT01 service enrolls, persists a DPAPI credential, activates a signed configuration, and rejects invalid bundles
expected: Healthy agent state; bad bundles fail closed.
result: [pending]

### 3. SC-04 — Verify LAB-CLIENT01 per-user WinFsp drive is visible and isolated
expected: Drive appears for the eligible user; not visible in another user's session.
result: [pending]

### 4. Visual checklist D-26/D-38 — Confirm drive visibility, Explorer/Word/Excel operations, mount-failure recovery, and service/Windows restart recovery
expected: Signed checklist records match automated attempt IDs and reveal no path, SID, key, or protected content.
result: [pending]

### 5. Independent review D-48 — An authenticated verifier who did not attest the individual runs reviews the final sanitized four-machine matrix on hungdinh-lt
expected: No material deviations; signed D-48 record with UTC and final matrix digest is present.
result: [pending]

## Summary

total: 5
passed: 0
issues: 0
pending: 5
skipped: 0
blocked: 0

## Gaps

None — awaiting human verification results. Prior automated UAT (34/34 passed) is recorded in the git history of this file.
