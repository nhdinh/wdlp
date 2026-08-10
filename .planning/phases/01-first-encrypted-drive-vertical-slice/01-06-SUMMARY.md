---
phase: 01-first-encrypted-drive-vertical-slice
plan: "06"
subsystem: enrollment-authority
tags: [enrollment, ldaps, winrm, pki, provisioning]
requires: [01-05]
provides: ["Digest-only enrollment authority", "trusted-station collector", "administrator provisioning API contract"]
key-decisions:
  - "Administrator provisioning uses a bearer-authenticated server boundary; dlpctl has no database credentials."
  - "Hyper-V MSFT_Disk.UniqueId is explicit lab-only evidence; production requires a physical disk serial."
actuals:
  tokens: 0
  tasks: 2
  commits: 8
status: complete
---

# Phase 01 Plan 06: Enrollment Authority Summary

Trusted-station fingerprint collection, digest-only authority handling, constrained CA seams, and administrator provisioning boundaries are in place.

## Verification

- `cargo fmt --check`, server/CLI tests, and strict Clippy passed.
- User-authorized SQLite evidence ran at ignored `target/01-06-authority.sqlite` via `phase1-smoke`.
- Sanitized live collector evidence succeeded through PowerShell Direct to DC01 and Kerberos WinRM-over-HTTPS to `LAB-CLIENT01.lab.local`.
- PostgreSQL production migration/integration evidence remains open.

## Decisions Made

- dlpctl never receives database credentials; server owns one-time token generation and stores only its SHA-256 digest.
- Raw hardware values, credentials, CA keys, and plaintext tokens are not logged or committed.
- `DLP_LAB_ALLOW_VIRTUAL_DISK_UNIQUE_ID=true` permits a boot/system Hyper-V virtual disk UniqueId only for development evidence. Default production mode fails closed without `Win32_DiskDrive.SerialNumber`; this is not hardware attestation.

## Deviations from Plan

### Auto-fixed Issues

- [Rule 1 - Bug] Replaced ambiguous nested PowerShell `$args` forwarding with named child-process environment variables (`7448ffa`).
- [Rule 4 - Approved] Added the narrow authenticated administrator provisioning API boundary after explicit user approval (`80808c7`, `bf36a4c`).

## Known Limitations

- PostgreSQL migration/application evidence is unrun; SQLite under `target/` is the user-authorized development substitute only.

## Self-Check: PASSED

- Task commits exist and all modified production files compile and pass the recorded checks.
