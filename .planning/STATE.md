---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
status: in_progress
stopped_at: "Paused 01-13-PLAN.md at Task 1 precondition: runtime secret provider unavailable"
last_updated: "2026-08-11T07:29:17.898Z"
progress:
  total_phases: 1
  completed_phases: 0
  total_plans: 11
  completed_plans: 3
---

# Project State: Windows Data Leakage Prevention (DLP) Solution

## Project Reference

- **Core value**: An authorized Windows user can mount a private protected drive, store files in it, and read them back through the drive, while the backing store does not contain directly readable plaintext.
- **MVP boundary**: Enroll → signed config → mount → copy → encrypted store → read back → survive restart; policy blocking and toast follow.
- **Constraints**: Rust for endpoint agent and core domain; PostgreSQL server persistence; Docker Compose server deployment; WinFsp user-mode virtual drive; no kernel-mode filtering or signed driver; safe Rust in portable domain crates.

## Current Position

- **Phase**: 1 - First Encrypted-Drive Vertical Slice
- **Plan**: 3 of 11
- **Status**: In progress
- **Progress**: 27%
- **Next plan**: 01-13 (Wave 4)
- **Topology update**: PostgreSQL database moved from LAB-DC01 to LAB-SERVER01 (192.168.50.12); LAB-DC01 retains management server and trusted provisioning.

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
| Phase 01-first-encrypted-drive-vertical-slice P05 | 10m | 2 tasks | 8 files |
| Phase 01-first-encrypted-drive-vertical-slice P09 | 39m | 2 tasks | 8 files |
| Phase 01-first-encrypted-drive-vertical-slice P07 | 3h 20m | 2 tasks | 13 files |
| Phase 01-first-encrypted-drive-vertical-slice P10 | 48min | 2 tasks | 14 files |
| Phase 01-first-encrypted-drive-vertical-slice P17 | 20m | 3 tasks | 9 files |
| Phase 01-first-encrypted-drive-vertical-slice P22 | 40m | 2 tasks | 9 files |
| Phase 01-first-encrypted-drive-vertical-slice P23 | 55m | 3 tasks | 12 files |

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

**Resume file:** 01-13-PLAN.md

**Last session:** 2026-08-11T07:29:16.544Z
**Stopped at:** Paused 01-13-PLAN.md at Task 1 precondition: runtime secret provider unavailable

- Last action: Split previously implicit server authority and trusted provisioning into source-complete Plans 01-22/01-23, made 01-13 execute dual-DC plus Kerberos WinRM-over-HTTPS provisioning before 01-14 enrollment, narrowed 01-14 to client-owned files, and made every automated verification fail closed. Eleven replacement plans now form eleven acyclic waves while all D-01 through D-50, 30 Phase 1 requirements, privilege/evidence controls, and nine historical summaries remain preserved.

## Decisions

- [Phase 01]: Approved the exact Phase 1 dependency allowlist at the blocking human checkpoint.
- [Phase 01]: Approved dlp-store/aes256gcm-4m/v1 with AES-256-GCM, 4 MiB chunks, persisted random 96-bit nonces, identity-bound AAD, staged generations, encrypted manifests, authenticated commit/pointer publication, and explicit migrations for incompatible changes.
- [Phase 01]: Use fixed-field canonical bytes and strict Ed25519 verification before configuration activation.
- [Phase 01]: Amended Phase 1 approval allowlist with ed25519-dalek@3.0.0 and aes-gcm@0.11.0 for the approved crypto contracts.
- [Phase 01]: Server production composition rejects incomplete provider sets before database connection or listener binding.
- [Phase 01]: SQLite was used only as a user-authorized local migration verification substitute; PostgreSQL remains the production database and is unverified.
- [Phase 01]: Retain EncryptedStore as the stable portability trait and expose LocalEncryptedStore as the portable concrete encrypted-store implementation.
- [Phase 01]: Persisted v1 records use AES-256-GCM generated 96-bit nonces and fixed identity AAD across chunks, manifests, and commits.
- [Phase 01]: Use the user-authorized ignored SQLite database only for 01-05 tracer evidence; PostgreSQL evidence remains open.
- [Phase 01]: Reject non-numeric, replayed, or lower signed-bundle versions before changing current/LKG.
- [Phase 01]: Missing selected pointers may recover only through a separately authenticated prior pointer; corrupt descendants are IntegrityFailure.
- [Phase 01]: Encrypted recovery evidence uses opaque names with SHA-256 digests recorded before preservation.
- [Phase 01]: Administrator and device peer roles remain bound to distinct configured issuer roots after rustls verification.
- [Phase 01]: Configuration selection is immutable and monotonic: equal/lower versions are rejected before the selected bundle changes.
- [Phase 01]: Persist namespace metadata as a versioned AEAD-protected Manifest record bound to format, store, and generation identity.
- [Phase 01]: Use documented WinFsp safe APIs and delay-load linkage only; publish write/truncate/overwrite before callback success.
- [Phase 01]: Phase 1 evidence is fail-closed: stale, deviated, wrong-machine, secret-bearing, inaccessible, and hash-mismatched evidence cannot pass.
- [Phase 01]: Approved exactly the eight digest-bound privilege manifests for plans 01-13, 01-14, 01-18, 01-19, 01-15, 01-20, 01-16, and 01-21.
- [Phase 01]: PostgreSQL source authority uses row locks and one transaction for token consumption, predecessor revocation, and new-serial activation.
- [Phase 01]: Plan 01-22 source tests do not substitute for LAB-DC01 PostgreSQL transaction evidence required by Plan 01-13.
- [Phase 01]: Bootstrap peer identity may be absent only at the TLS boundary; administrator and device route middleware require verified certificate roles.
- [Phase 01]: Trusted provisioning uses the approved reqwest@0.13.4 boundary and hands tokens only to a runtime secret provider.

### Blockers

- Plan 01-13 Task 1 precondition unmet: no runtime-only secret provider is configured to supply server/DB/PKI material to LAB-DC01 and LAB-SERVER01 without command-line disclosure. Hyper-V VMs LAB-DC01, LAB-DC02, LAB-CLIENT01, and the newly designated LAB-SERVER01 are required; required `DLP_*` environment variables or an equivalent runtime secret provider are absent.
- Plan 01-13 Task 1 precondition unmet: no runtime-only secret provider is configured to supply server/DB/PKI material to LAB-DC01 and LAB-SERVER01 without command-line disclosure. Required DLP_* environment variables or equivalent runtime secret provider are absent.
