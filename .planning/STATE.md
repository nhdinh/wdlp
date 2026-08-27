---
gsd_state_version: 1.0
milestone: v1.0
current_phase: 01
current_phase_name: first-encrypted-drive-vertical-slice
current_plan: 40 of 21
status: verifying
stopped_at: Completed 01-42-PLAN.md
last_updated: "2026-08-27T09:27:21.688Z"
last_activity: 2026-08-27
state_head: f5cc729b0f4058ad0a4e9bd765c212cbff7dbef8
progress:
  total_phases: 7
  completed_phases: 0
  total_plans: 35
  completed_plans: 35
milestone_name: milestone
last_activity_desc: Completed Plan 01-21 Task 2; FinalGate verifier passes (30/30 requirements, 7/7 success criteria, 50/50 decisions, 9/9 privilege manifests, valid independent review by lab/administrator, matrix digest 5ab3ae9d9baab7412fe951b1490ea2df36bd76dd90eebfe890f09064ec50b414).
---

# Project State: Windows Data Leakage Prevention (DLP) Solution

## Project Reference

- **Core value**: An authorized Windows user can mount a private protected drive, store files in it, and read them back through the drive, while the backing store does not contain directly readable plaintext.
- **MVP boundary**: Enroll → signed config → mount → copy → encrypted store → read back → survive restart; policy blocking and toast follow.
- **Constraints**: Rust for endpoint agent and core domain; PostgreSQL server persistence; Docker Compose server deployment; WinFsp user-mode virtual drive; no kernel-mode filtering or signed driver; safe Rust in portable domain crates.

Last activity: 2026-08-27

## Quick Tasks Completed

| Date | Slug | Summary | Artifacts |
|------|------|---------|-----------|
| 2026-08-13 | hyperv-vm-start-guide | PowerShell walkthrough for starting and cold-starting Hyper-V VMs | `.planning/docs/HYPERV-VM-START-GUIDE.md` |
| 2026-08-13 | hyperv-dlp-start-guide | PowerShell walkthrough for starting/cold-starting DLP server/services/endpoint apps on Hyper-V VMs | `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md` |
| 2026-08-13 | deploy-client01-runtime | PowerShell orchestrator to build and deploy dlp-windows-service runtime to LAB-CLIENT01 | `.planning/quick/20260813-deploy-client01-runtime/`, `scripts/lab/Invoke-Client01Runtime.ps1` |
| 2026-08-13 | document-agent-env-vars | Document every DLP Windows agent runtime env var and cross-reference from the lab startup guide | `.planning/docs/ENV-VARS.md`, `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md`, `.planning/ROADMAP.md` |
| 2026-08-13 | update-startup-guide | Update HYPERV-DLP-STARTUP-GUIDE.md to deploy endpoint service via Invoke-Client01Runtime.ps1 | `.planning/quick/20260813-update-startup-guide/`, `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md` |
| 2026-08-13 | provisioning-token-capture | Configure Invoke-TrustedProvisioning.ps1 to capture and return dlpctl enrollment token | `.planning/quick/20260813-provisioning-token-capture/`, `scripts/lab/Invoke-TrustedProvisioning.ps1`, `scripts/lab/Invoke-Dc01Server.ps1` |
| 2026-08-13 | pem-key-collection-guide | Guide for obtaining or generating the PEM/KEY files used by Phase 1 lab env vars | `.planning/docs/PEM-KEY-GUIDE.md`, `.planning/docs/ENV-VARS.md`, `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md` |
| 2026-08-13 | automatic-enrollment-token-acquisition | Orchestrator-chained automatic DLP_AGENT_ENROLLMENT_TOKEN acquisition, validation, cleanup, and doc update | `.planning/phases/01.2-dlp-agent-enrollment-token-should-be-obtained-automatically/01.2-01-SUMMARY.md`, `scripts/lab/Invoke-Client01Runtime.ps1`, `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md`, `.planning/docs/ENV-VARS.md` |
| 2026-08-14 | reorder-enrollment-section | Move Enrollment Flow section to precede endpoint deployment and renumber following sections | `.planning/quick/20260814-reorder-enrollment-section/`, `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md` |
| 2026-08-14 | append-enrollment-flow | Append dedicated enrollment-flow section to Hyper-V DLP startup guide | `.planning/quick/20260814-append-enrollment-flow/`, `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md` |
| 2026-08-14 | unify-certificate-names | Adopt single kebab-case PEM filename convention across fixtures, code, scripts, config, and docs | `tests/e2e/server_enrollment.rs`, `scripts/lab/*.ps1`, `config/*.example`, `deploy/compose.yaml`, `crates/dlpctl/src/{lib,main}.rs`, `crates/dlp-windows-service/src/service.rs`, `.planning/docs/PEM-KEY-GUIDE.md`, `.planning/docs/ENV-VARS.md` |
| 2026-08-14 | env-setup-instructions | Enhance Initialize-DlpEnvironment.ps1 to show step-by-step instructions for obtaining or generating each value at every prompt | `.planning/quick/20260814-env-setup-instructions/`, `scripts/lab/Initialize-DlpEnvironment.ps1` |
| 2026-08-14 | lab-setup-guide | Comprehensive DLP lab setup guide and scripts inventory | `.planning/docs/LAB-SETUP-GUIDE.md`, `scripts/lab/README.md`, `.planning/quick/20260814-lab-setup-guide/` |
| 2026-08-15 | consolidate-docs-in-planning-docs-and-sc | Consolidate docs in `.planning/docs` and scripts in `scripts` | `.planning/quick/260815-dti-consolidate-docs-in-planning-docs-and-sc/`, `.planning/docs/README.md`, `scripts/README.md` |
| 2026-08-15 | review-all-below-docs-and-make-sure-all- | Review and correct Phase 1 lab setup, PKI, environment, and initializer guidance | `.planning/quick/260815-gi1-review-all-below-docs-and-make-sure-all-/`, `.planning/docs/LAB-SETUP-GUIDE.md`, `.planning/docs/PEM-KEY-GUIDE.md`, `.planning/docs/ENV-VARS.md` |

## Current Position

- **Phase:** 01 (first-encrypted-drive-vertical-slice) — READY TO EXECUTE
- **Plan:** 40 of 21
- **Task:** 2 of 2
- **Status:** Phase complete — ready for verification
- **Progress:** [██████████] 100% of Phase 01
- **Current plan:** 40 of 21
- **Topology update:** PostgreSQL database runs natively on LAB-SERVER01 (192.168.50.12); LAB-DC01 hosts the management server and trusted provisioning. LAB-CLIENT01 secure session-host lifecycle, application/operation/size matrix, and D-19 failure/recovery matrix verified. Security closure manifest signed off with 19/19 blocking threats closed.

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
| Phase 01.3 P01 | 67m | 2 tasks | 8 files |
| Phase 01.3 P02 | 8m | 2 tasks | 6 files |
| Phase 01.1-add-docs-for-those-env-var-dlp-device-id-dlp-server-url-dlp P01 | 18min | 3 tasks | 3 files |
| Phase 01-first-encrypted-drive-vertical-slice P17 | 20m | 3 tasks | 7 files |
| Phase 01.2-dlp-agent-enrollment-token-should-be-obtained-automatically P01 | 90m | 3 tasks | 3 files |
| Phase 01-first-encrypted-drive-vertical-slice P17 | 15min | 3 tasks | 2 files |
| Phase 01-first-encrypted-drive-vertical-slice P22 | 25m | 2 tasks | 7 files |
| Phase 01-first-encrypted-drive-vertical-slice P23 | 45m | 3 tasks | 14 files |
| Phase 01-first-encrypted-drive-vertical-slice P13 | 75min | 3 tasks | 4 files |
| Phase 01 P21 | 210 | 1 tasks | 7 files |
| Phase 01 P01-25 | 29 | 3 tasks | 4 files |
| Phase 01.3 P03 | 12h | 2 tasks | 5 files |
| Phase 01-first-encrypted-drive-vertical-slice P30 | 16min | 2 tasks | 3 files |
| Phase 01 P31 | 35m | 3 tasks | 4 files |
| Phase 01 P32 | 1d | 1 tasks | 1 files |
| Phase 01 P33 | 25m | 2 tasks | 6 files |
| Phase 01 P34 | 5h28m | 3 tasks | 7 files |
| Phase 01 P35 | 50m | 3 tasks | 3 files |
| Phase 01 P39 | 30m | 2 tasks | 1 files |
| Phase 01 P40 | 15m | 2 tasks | 2 files |
| Phase 01 P41 | 25m | 3 tasks | 2 files |
| Phase 01 P42 | 1d | 4 tasks | 8 files |

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
- Phase 01.2 inserted after Phase 1: DLP_AGENT_ENROLLMENT_TOKEN should be obtained automatically when DlpWindowsService installed (URGENT)
- Phase 01.2 plan created: 01.2-01-PLAN.md — Orchestrator-chained automatic enrollment token acquisition, validation, cleanup, and doc update.
- Phase 01.3 inserted after Phase 1: Make a background app that run in devices to collect log and provide the result through a HTTP port for easier debugging (URGENT)

## Session Continuity

**Resume file:** None

**Last session:** 2026-08-27T09:27:21.633Z
**Stopped at:** Completed 01-42-PLAN.md

**Current session:** 2026-08-26T05:00:00.000Z
**Resumed at:** /gsd-resume-work — restored the 01-37 implementation and closed its missing summary.

- Last action: Backfilled remaining matrix rows, recorded independent verifier attestation by `lab/administrator`, and re-ran `scripts/verify-phase1.ps1` to a passing FinalGate.
- Next action: Execute Plan 01-38 to complete the separate D-48 reviewer setup and authenticated signing ceremony.

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
- [Phase 01.2]: Retained Manual as the default EnrollmentTokenProvider so existing operator workflows continue unchanged.
- [Phase 01.2]: Made token cleanup the default after successful enrollment; only retain with -RetainEnrollmentToken for explicit troubleshooting.
- [Phase 01.2]: Validated enrollment token length (<=512) and charset ([A-Za-z0-9_.~/-]) before any persistence to LAB-CLIENT01.
- [Phase ?]: 01.3-01: Omitted tail uses configured max_tail_lines; explicit values above it return invalid_tail.
- [Phase ?]: 01.3-01: Invalid config atomically selects localhost-only mode without authorized folders.
- [Phase ?]: 01.3-02: Authorize only accepted TCP peers via Axum ConnectInfo; forwarding and certificate-style headers are ignored.
- [Phase ?]: 01.3-02: Preserve Plan 01 tail semantics: omitted tail uses the configured maximum and over-limit input is invalid_tail.
- [Phase ?]: 01.3-02: SCM pre-binds 0.0.0.0 before Running and maps lifecycle failures to stable nonzero exits.
- [Phase ?]: Kept example env-var lines in HYPERV-DLP-STARTUP-GUIDE.md as quick reminder while deferring collection instructions to ENV-VARS.md
- [Phase ?]: Documented DLP_ROOT_CA_PEM as accepting inline PEM content or a filesystem path
- [Phase ?]: Added session-config variables to ENV-VARS.md to satisfy must-have that every consumed service variable is documented
- [Phase ?]: [Phase 01.2]: Retained Manual as the default EnrollmentTokenProvider so existing operator workflows continue unchanged.
- [Phase ?]: [Phase 01.2]: Made token cleanup the default after successful enrollment; only retain with -RetainEnrollmentToken for explicit troubleshooting.
- [Phase ?]: [Phase 01.2]: Validated enrollment token length (<=512) and charset ([A-Za-z0-9_.~/-]) before any persistence to LAB-CLIENT01.
- [Phase ?]: [Phase 01.2]: Replaced Get-FileHash with direct [System.Security.Cryptography.SHA256] calls because the Git-Bash-launched Windows PowerShell session could not auto-import Microsoft.PowerShell.Utility.
- [Phase ?]: Synthetic or stale evidence IDs in the requirement matrix must be cleared to unverified rather than left as passing placeholders. — The fail-closed contract requires every passing matrix row to point to accessible, hash-verified raw artifacts.
- [Phase ?]: Evidence schema enums and PowerShell verifier enums must remain synchronized. — A schema that accepts values the verifier rejects allows publication of evidence that cannot be validated, breaking the contract.
- [Phase ?]: The operator approved the existing eight digest-bound privilege manifests for Plans 01-13, 01-14, 01-18, 01-19, 01-15, 01-20, 01-16, and 01-21. — All manifests passed automated role, digest, and approval-identity validation; the human checkpoint confirmed the risk acceptance.
- [Phase ?]: Plan 01-22 source-only evidence published on hungdinh-lt for WRK-03, SRV-03, SRV-11, CRY-04, TST-05; LAB-DC01/LAB-SERVER01 acceptance evidence remains the responsibility of Plan 01-13.
- [Phase ?]: Production startup must construct and validate every provider (directory, PostgreSQL pool, certificate issuer, signer, repository, services, TLS paths) before running migrations or binding the listener.
- [Phase ?]: Bootstrap peer identity may be absent only at the TLS boundary; administrator and device route middleware require verified certificate roles.
- [Phase ?]: Trusted provisioning hands the one-time token only to a runtime secret provider; it is never written to stdout, argv, environment files, logs, Debug output, or evidence.
- [Phase ?]: Validated the approved 01-13 privilege-manifest digest before every mutating scenario.
- [Phase ?]: Resolved provisioning PEM file paths to inline content on the orchestrator host before passing them into LAB-DC01.
- [Phase ?]: Copied dlpctl.exe to LAB-DC01 and set DLP_PROVISIONING_DLPCTL_PATH instead of relying on VM PATH.
- [Phase 01]: Phase 01.3 uses credentialed lab.local WinRM with memory-only credentials for deterministic lab preflight.
- [Phase 01]: The debugger strict config requires max_tail_lines; omission intentionally selects localhost-only fallback.
- [Phase 01]: Signed-off security review trusts only mandatory external roots and reviewer policy.
- [Phase 01]: Security review publication uses detached CMS signatures and a durable mutex-protected atomic append.
- [Phase 01]: Independent approval provenance is accepted only from the authenticated LAB reviewer ceremony and externally rooted signed-off verification.
- [Phase 01]: Windows PowerShell security scripts explicitly load System.Security and distinguish unavailable PKCS runtime from invalid signatures.
- [Phase 01]: Preserve Windows PowerShell canonical CMS bytes and isolate CustomRootTrust chain construction in a short-lived pwsh process.
- [Phase 01]: LAB-DC02 is the D-22 trusted reviewer signing station; LAB-DC01 retains management, CA, and FinalGate roles.
- [Phase 01]: Plan 01-35 authorizes publication only from captured WindowsIdentity and COMPUTERNAME before preview or mutation.
- [Phase 01]: Plan 01-35 keeps the signed archival envelope additive and requires Plan 01-36 to publish the canonical generation.
- [Phase 01]: Retain observed Windows identity and COMPUTERNAME binding; mismatches fail before consent and mutation.
- [Phase 01]: Signed-off verification cryptographically checks every non-legacy historical CMS while preserving authenticated envelope compatibility for the legacy first entry.
- [Phase 01]: D-48 T-01-21-04 digest mismatch remains an explicit fail-closed diagnostic.
- [Phase 01]: Legacy archival null-subject compatibility remains versioned and authenticated by identity and thumbprint.
- [Phase 01]: Every historical and envelope CMS signer uses the complete external trust contract.

### Blockers

- Plan 01-38 is pending the explicit D-48 reviewer public policy/root and interactive signing ceremony; FinalGate remains fail-closed until that external setup is complete.
