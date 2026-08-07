---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
status: unknown
stopped_at: Phase 1 context gathered
last_updated: "2026-08-07T11:00:41.687Z"
progress:
  total_phases: 1
  completed_phases: 0
  total_plans: 12
  completed_plans: 0
---

# Project State: Windows Data Leakage Prevention (DLP) Solution

## Project Reference

- **Core value**: An authorized Windows user can mount a private protected drive, store files in it, and read them back through the drive, while the backing store does not contain directly readable plaintext.
- **MVP boundary**: Enroll → signed config → mount → copy → encrypted store → read back → survive restart; policy blocking and toast follow.
- **Constraints**: Rust for endpoint agent and core domain; PostgreSQL server persistence; Docker Compose server deployment; WinFsp user-mode virtual drive; no kernel-mode filtering or signed driver; safe Rust in portable domain crates.

## Current Position

- **Phase**: 1 - First Encrypted-Drive Vertical Slice
- **Plan**: TBD
- **Status**: Not started
- **Progress**: 0%

## Performance Metrics

- Target scale: 1,000 enrolled endpoints, 500 concurrently online, up to 5 administrators or auditors, one organization per server.
- No runtime metrics yet; baseline after Phase 1 implementation and initial tests.

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

**Resume file:** .planning/phases/01-first-encrypted-drive-vertical-slice/01-CONTEXT.md

**Last session:** 2026-08-07T08:51:53.418Z
**Stopped at:** Phase 1 context gathered

- Last action: Restructured ROADMAP.md around the first encrypted-drive vertical slice; awaiting approval to begin Phase 1 planning.
