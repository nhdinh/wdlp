---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
current_phase: 01-first-encrypted-drive-vertical-slice
status: in_progress
stopped_at: Completed 01.1-01-PLAN.md
last_updated: "2026-08-13T13:05:00Z"
progress:
  total_phases: 2
  completed_phases: 1
  total_plans: 12
  completed_plans: 8
---

# Project State: Windows Data Leakage Prevention (DLP) Solution

## Project Reference

- **Core value**: An authorized Windows user can mount a private protected drive, store files in it, and read them back through the drive, while the backing store does not contain directly readable plaintext.
- **MVP boundary**: Enroll → signed config → mount → copy → encrypted store → read back → survive restart; policy blocking and toast follow.
- **Constraints**: Rust for endpoint agent and core domain; PostgreSQL server persistence; Docker Compose server deployment; WinFsp user-mode virtual drive; no kernel-mode filtering or signed driver; safe Rust in portable domain crates.

## Quick Tasks Completed

| Date | Slug | Summary | Artifacts |
|------|------|---------|-----------|
| 2026-08-13 | hyperv-vm-start-guide | PowerShell walkthrough for starting and cold-starting Hyper-V VMs | `.planning/docs/HYPERV-VM-START-GUIDE.md` |
| 2026-08-13 | hyperv-dlp-start-guide | PowerShell walkthrough for starting/cold-starting DLP server/services/endpoint apps on Hyper-V VMs | `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md` |
| 2026-08-13 | deploy-client01-runtime | PowerShell orchestrator to build and deploy dlp-windows-service runtime to LAB-CLIENT01 | `.planning/quick/20260813-deploy-client01-runtime/`, `scripts/lab/Invoke-Client01Runtime.ps1` |
| 2026-08-13 | document-agent-env-vars | Document every DLP Windows agent runtime env var and cross-reference from the lab startup guide | `.planning/docs/ENV-VARS.md`, `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md`, `.planning/ROADMAP.md` |
| 2026-08-13 | update-startup-guide | Update HYPERV-DLP-STARTUP-GUIDE.md to deploy endpoint service via Invoke-Client01Runtime.ps1 | `.planning/quick/20260813-update-startup-guide/`, `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md` |
| 2026-08-13 | provisioning-token-capture | Configure Invoke-TrustedProvisioning.ps1 to capture and return dlpctl enrollment token | `.planning/quick/20260813-provisioning-token-capture/`, `scripts/lab/Invoke-TrustedProvisioning.ps1`, `scripts/lab/Invoke-Dc01Server.ps1` |

## Current Position

- **Phase:** 01 - First Encrypted-Drive Vertical Slice
- **Plan:** 7/11 complete; next: 01-15-PLAN.md (Wave 8)
- **Task:** 1 of 1
- **Status:** In progress
- **Progress:** [████████░░] 64%
- **Next plan:** 01-15-PLAN.md — Wire the per-session host, authenticated storage IPC, deterministic drive lifecycle, isolation, sign-out drain, and service-restart behavior
- **Topology update:** PostgreSQL database runs natively on LAB-SERVER01 (192.168.50.12); LAB-DC01 hosts the management server and trusted provisioning. LAB-CLIENT01 runtime verification remains blocked by token/VM reachability.

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
| Phase 01-first-encrypted-drive-vertical-slice P13 | 4h | 3 tasks | 14 files |
| Phase 01-first-encrypted-drive-vertical-slice P14 | 2h | 2 tasks | 9 files |
| Phase 01-first-encrypted-drive-vertical-slice P18 | 65min | 1 tasks | 6 files |
| Phase 01-first-encrypted-drive-vertical-slice P19 | 45m | 1 tasks | 10 files |
| Phase 01-first-encrypted-drive-vertical-slice P23 | 45m | 3 tasks | 13 files |
| Phase 01.1-add-docs-for-those-env-var-dlp-device-id-dlp-server-url-dlp P01 | 12m | 3 tasks | 3 files |

## Accumulated Context

- **Decisions**:
  - WinFsp is the primary virtual-drive framework; Dokany is the fallback.
  - Enforcement stays user-space only; no kernel-mode filtering or signed driver.
  - Server deploys via Docker Compose on a single Linux host per organization.
  - Offline allowance is seven days, with a warning around day five and drive lock after seven days.
  - A small per-user companion process shows toast notifications; no tray UI for MVP.
  - `require_justification` is rejected until the post-MVP workflow is implemented.
  - Ed25519 is the policy-bundle signing algorithm (see ADR-005).
  - Device-mTLS client uses pinned public root, ordinary hostname validation, and no bearer fallback.
  - Machine-DPAPI credential blob is UI-forbidden, owner/DACL restricted, and atomically written.
  - Signed-configuration cache uses content-addressed staging, atomic pointer swap, and monotonic version checks.
- **Open questions**:
  - Exact WinFsp NTFS conformance and Office/Explorer validation scenarios.
  - DPAPI vs TPM key-wrapping decision for per-user store keys.
  - mTLS certificate issuance, renewal, and revocation lifecycle.
- **Blockers**: None

### Roadmap Evolution

- Phase 01.1 inserted after Phase 01: Add docs for those env var DLP_DEVICE_ID, DLP_SERVER_URL, DLP_ROOT_CA_PEM, DLP_CONFIGURATION_PUBLIC_KEY_HEX. Add docs to guide how to collect/create all env vars for setting up (URGENT)

## Session Continuity

**Resume file:** None

**Last session:** 2026-08-13T12:55:44.975Z
**Stopped at:** Completed 01.1-01-PLAN.md

**Current session:** 2026-08-12
**Resumed at:** /gsd-execute-phase 1 — continuing Phase 1 Wave execution.

- Last action: Completed Plan 01-19 (SCM service lifecycle, native fingerprint, secret-free config, and LAB-CLIENT01 smoke artifacts). Source checks pass; LAB-CLIENT01 runtime blocked by token/VM reachability. Plan 01-18 source-level blocker resolved.

### Completed Plan 01-23 Evidence

- `cargo test --locked -p dlp-server --test server_enrollment` (20 passed).
- `cargo clippy --locked -p dlp-server --all-targets -- -D warnings`.
- `cargo test --locked -p dlpctl provisioning_` (6 passed).
- `cargo tree --locked -p dlpctl -i reqwest@0.13.4`.
- `ServerRouteSource`, `TrustedProvisioningClientSource`, and `TrustedProvisioningSource` evidence checks passed.

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
- [Phase 01]: 01-18: Use explicit binary wire format for cached bundles to avoid adding new dependencies and preserve the approved Cargo.lock.
- [Phase 01]: 01-18: Perform schema-version rejection during wire deserialization before signature verification.
- [Phase 01]: 01-18: Keep directory sync best-effort in portable dlp-agent-core; Windows-specific directory flush injected by service crate.
- [Phase 01]: 01-23: Return a versioned JSON provisioning response from the administrator route so the client validates device identity before token handoff.
- [Phase 01]: 01-23: Remove the obsolete bearer-style `DLP_ADMIN_PROVISIONING_KEY` and document mTLS provisioning runtime-provider paths.
- [Phase 01]: 01-19: Load cache pointers during service startup so restart recovery is validated before mTLS polling.
- [Phase 01]: 01-19: Keep diagnostic helpers redacted by calling hidden binary verbs that emit stable codes only.
- [Phase 01]: 01-19: Accept LAB-CLIENT01 runtime verification as blocked when the runtime token and VM reachability are unavailable; source artifacts must remain fail-closed.
- [Phase ?]: [Phase 01.1]: Kept example env-var lines in HYPERV-DLP-STARTUP-GUIDE.md as a quick reminder but added a comment and link deferring to ENV-VARS.md for collection/creation instructions.
- [Phase ?]: [Phase 01.1]: Documented DLP_ROOT_CA_PEM as accepting either PEM content or a filesystem path, matching the service loader and Invoke-Client01Runtime.ps1 behavior.

### Blockers

- 01-14 LAB-CLIENT01 runtime scenarios blocked: runtime token missing and LAB-CLIENT01 unreachable from hungdinh-lt; server /api/v1/enrollment route source contract is now wired by Plan 01-23 but PostgreSQL transaction evidence remains for Plan 01-13.
- 01-19 LAB-CLIENT01 runtime scenarios blocked: runtime token missing and LAB-CLIENT01/LAB-DC01 unreachable from hungdinh-lt; source artifacts and source checks are complete.
