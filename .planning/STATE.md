---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
status: unknown
stopped_at: Completed 01-04-PLAN.md
last_updated: "2026-08-08T13:30:35.803Z"
progress:
  total_phases: 1
  completed_phases: 0
  total_plans: 12
  completed_plans: 4
---

# Project State: Windows Data Leakage Prevention (DLP) Solution

## Project Reference

- **Core value**: An authorized Windows user can mount a private protected drive, store files in it, and read them back through the drive, while the backing store does not contain directly readable plaintext.
- **MVP boundary**: Enroll → signed config → mount → copy → encrypted store → read back → survive restart; policy blocking and toast follow.
- **Constraints**: Rust for endpoint agent and core domain; PostgreSQL server persistence; Docker Compose server deployment; WinFsp user-mode virtual drive; no kernel-mode filtering or signed driver; safe Rust in portable domain crates.

## Current Position

- **Phase**: 1 - First Encrypted-Drive Vertical Slice
- **Plan**: 5 of 12
- **Status**: Ready to execute
- **Progress**: 33%
- **Next plan**: 01-05 (Wave 4)

## Performance Metrics

- Target scale: 1,000 enrolled endpoints, 500 concurrently online, up to 5 administrators or auditors, one organization per server.
- No runtime metrics yet; baseline after Phase 1 implementation and initial tests.

**Per-Plan Metrics:**

| Plan | Duration | Tasks | Files |
|------|----------|-------|-------|
| Phase 01-first-encrypted-drive-vertical-slice P03 | 5m | 2 tasks | 1 files |
| Phase 01-first-encrypted-drive-vertical-slice P01 | 31m | 3 tasks | 13 files |
| Phase 01-first-encrypted-drive-vertical-slice P02 | 121m | 3 tasks | 15 files |
| Phase 01-first-encrypted-drive-vertical-slice P04 | 64m | 2 tasks | 12 files |

## Accumulated Context

- **Decisions**:
  - WinFsp is the primary virtual-drive framework; Dokany is the fallback.
  - Enforcement stays user-space only; no kernel-mode filtering or signed driver.
  - Server deploys via Docker Compose on a single Linux host per organization.
  - Offline allowance is seven days, with a warning around day five and drive lock after seven days.
  - A small per-user companion process shows toast notifications; no tray UI for MVP.
  - `require_justification` is rejected until the post-MVP workflow is implemented.
  - Ed25519 is the policy-bundle signing algorithm (see ADR-005).
- **Open questions**:
  - Exact WinFsp NTFS conformance and Office/Explorer validation scenarios.
  - DPAPI vs TPM key-wrapping decision for per-user store keys.
  - mTLS certificate issuance, renewal, and revocation lifecycle.
- **Blockers**: None

## Session Continuity

**Resume file:** None

**Last session:** 2026-08-08T13:30:35.784Z
**Stopped at:** Completed 01-04-PLAN.md

- Last action: Completed 01-04 encrypted storage format, durable generation, and SID-safe operation model; PostgreSQL verification limitation remains tracked in WINDOWS.md.

## Decisions

- [Phase 01]: Approved the exact Phase 1 dependency allowlist at the blocking human checkpoint.
- [Phase 01]: Approved dlp-store/aes256gcm-4m/v1 with AES-256-GCM, 4 MiB chunks, persisted random 96-bit nonces, identity-bound AAD, staged generations, encrypted manifests, authenticated commit/pointer publication, and explicit migrations for incompatible changes.
- [Phase 01]: Use fixed-field canonical bytes and strict Ed25519 verification before configuration activation.
- [Phase 01]: Amended Phase 1 approval allowlist with ed25519-dalek@3.0.0 and aes-gcm@0.11.0 for the approved crypto contracts.
- [Phase 01]: Server production composition rejects incomplete provider sets before database connection or listener binding.
- [Phase 01]: SQLite was used only as a user-authorized local migration verification substitute; PostgreSQL remains the production database and is unverified.
- [Phase 01]: Retain EncryptedStore as the stable portability trait and expose LocalEncryptedStore as the portable concrete encrypted-store implementation.
- [Phase 01]: Persisted v1 records use AES-256-GCM generated 96-bit nonces and fixed identity AAD across chunks, manifests, and commits.
