---
phase: 01-first-encrypted-drive-vertical-slice
plan: "13"
subsystem: lab-orchestration
tags: [hyperv, postgresql, migrations, trusted-provisioning, powershell, phase1]
requires:
  - phase: 01-17
    provides: Evidence and privilege-control contract
  - phase: 01-22
    provides: PostgreSQL enrollment authority source contract
  - phase: 01-23
    provides: Trusted provisioning preflight source contract
provides:
  - Five-machine role manifest and role-guard automation
  - Developer-host cleanup and baseline audit
  - LAB-SERVER01 native PostgreSQL migration scenario orchestration
  - LAB-DC01 server/provisioning scenario orchestration
  - Source checks for native-PostgreSQL deployment and secret avoidance
key-files:
  created:
    - config/lab.roles.example.json
    - scripts/lab/Invoke-Phase1EnvironmentReconcile.ps1
    - scripts/lab/Invoke-Dc01Server.ps1
    - tests/e2e/compose.rs
    - .planning/docs/LAB-SERVER01-SETUP.md
  modified:
    - config/server.env.example
    - config/lab.phase1.example.yaml
    - deploy/compose.yaml
    - crates/dlp-server/Cargo.toml
key-decisions:
  - PostgreSQL runs natively on LAB-SERVER01 (Ubuntu, 192.168.50.12); Docker Compose is no longer used in the Phase 1 lab.
  - The 01-13 privilege manifest was updated to reference LAB-SERVER01 native PostgreSQL, producing a new digest that requires re-approval.
  - VM admin credentials for PowerShell Direct must be guest-OS administrators on LAB-DC01/LAB-CLIENT01, supplied via -Credential or DLP_VM_ADMIN_USER/PASSWORD.
  - Keep Invoke-TrustedProvisioning.ps1 from Plan 01-23 unchanged and override the approved digest inside the LAB-DC01 remote session.
metrics:
  duration: 110m
  completed: 2026-08-11
status: blocked
actuals:
  tokens: 32000
  tasks: 1
  commits: 4
---

# Phase 01 Plan 13: Lab Orchestration and PostgreSQL Evidence Summary

**Guarded five-machine role contracts, developer-host cleanup, native-PostgreSQL-on-LAB-SERVER01 scenario orchestration, and source checks are implemented; focused Hyper-V execution is blocked by missing guest-OS VM admin credentials.**

## Tasks Completed

1. **Task 1 (tracer): Reconcile machine roles and serve one LAB-DC01 readiness path**
   - Created `.planning/docs/LAB-SERVER01-SETUP.md` documenting native PostgreSQL on Ubuntu at 192.168.50.12.
   - Updated `config/lab.roles.example.json` to the five-machine contract (hungdinh-lt, LAB-SERVER01, LAB-DC01, LAB-DC02, LAB-CLIENT01).
   - Updated `config/lab.phase1.example.yaml` machine roles and the 01-13 privilege manifest to reference LAB-SERVER01 native PostgreSQL; computed new manifest digest.
   - Created `scripts/lab/Invoke-Phase1EnvironmentReconcile.ps1` for hungdinh-lt baseline audit and idempotent cleanup.
   - Created `scripts/lab/Invoke-Dc01Server.ps1` for native PostgreSQL migration proofs (via sqlx-cli from hungdinh-lt) and LAB-DC01/LAB-CLIENT01 Hyper-V orchestration.
   - Updated `deploy/compose.yaml` to a reference-only file documenting that the lab uses native PostgreSQL.
   - Updated `config/server.env.example` with runtime-provider contract notes.
   - Added `tests/e2e/compose.rs` source checks and registered it in `crates/dlp-server/Cargo.toml`.
   - Commits: `a3d5ceb` (initial implementation), `42e9765` (reconcile fixes), plus the LAB-SERVER01 updates in this continuation.

## Verification

- `cargo test --locked -p dlp-server --test compose` passes on hungdinh-lt.
- `scripts/lab/Invoke-Phase1EnvironmentReconcile.ps1 -Apply` passes on hungdinh-lt and publishes Phase 1 evidence.
- `scripts/lab/Invoke-Dc01Server.ps1 -Scenario Tracer` remains blocked: `vm_credentials_required` because the runtime provider does not contain `DLP_VM_ADMIN_USER`/`DLP_VM_ADMIN_PASSWORD` and the current session is not elevated for implicit PowerShell Direct.
- The native PostgreSQL migration path cannot be exercised until VM admin credentials are supplied, because the script needs PowerShell Direct to LAB-DC01 for server-readiness verification and to LAB-CLIENT01 for the TLS probe.

## Decisions Made

- PostgreSQL is native on LAB-SERVER01 (192.168.50.12); Docker Compose is reference-only for this lab.
- The approved 01-13 manifest digest changed from `ef32e822125bc4e3ead88153f5ae619f63f8ad7aebda71206aa1401b9e9fca4e` to `c5b6820546e0cc31eb37c075acf67cdd58e9a257f5779cf19488feb4db7807ba` because the manifest now describes native PostgreSQL on LAB-SERVER01. Re-approval is required before the new digest can satisfy the Plan 01-17 privilege verifier.
- VM admin credentials for PowerShell Direct are guest-OS administrators on the target VM (e.g., `LAB/Administrator` on LAB-DC01), not the hungdinh-lt host administrator.

## Deviations from Plan

### Architectural Adjustment (user-directed)

**1. Replaced Docker Compose PostgreSQL with native PostgreSQL on LAB-SERVER01.**
- **Reason:** User confirmed the lab no longer uses Docker; PostgreSQL now runs natively on LAB-SERVER01 (Ubuntu, 192.168.50.12).
- **Files modified:** `.planning/docs/LAB-SERVER01-SETUP.md` (new), `config/lab.phase1.example.yaml`, `config/lab.roles.example.json`, `deploy/compose.yaml`, `scripts/lab/Invoke-Dc01Server.ps1`, `tests/e2e/compose.rs`.
- **Impact:** The 01-13 privilege manifest digest changed and requires re-approval. The `deploy/compose.yaml` file is now reference-only.

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed reconcile script strict-mode failures.**
- **Found during:** Task 1 dry-run/apply verification.
- **Issue:** Pipeline outputs that resolve to `$null` became single-element arrays under `@(...)`, causing inflated counts and `Count` property failures in strict mode; `-and` was parsed as a cmdlet switch when unparenthesized.
- **Fix:** Wrapped final pipeline results with `| Where-Object { $_ -ne $null }`, parenthesized compound conditions, and switched hungdinh-lt host evidence to `portable_automation` tier.
- **Files modified:** `scripts/lab/Invoke-Phase1EnvironmentReconcile.ps1`
- **Commit:** `42e9765`

### Blockers

**1. Missing VM admin credentials for PowerShell Direct**
- **Found during:** Task 1 tracer verification (`Invoke-Dc01Server.ps1 -Scenario Tracer`).
- **Issue:** Hyper-V PowerShell Direct into LAB-DC01/LAB-CLIENT01 requires a guest-OS administrator credential. The runtime provider supplies server/DB/PKI material (`DLP_*` env vars) but no `DLP_VM_ADMIN_USER`/`DLP_VM_ADMIN_PASSWORD`. The current session is also not elevated, so implicit credentials are rejected.
- **Impact:** Cannot execute LAB-DC01 server-readiness or LAB-CLIENT01 TLS-probe scenarios, even though the native PostgreSQL orchestration path is ready.
- **Next step:** Provide guest-OS VM admin credentials via `DLP_VM_ADMIN_USER` and `DLP_VM_ADMIN_PASSWORD` in the runtime secret provider, or rerun the verification commands in an elevated PowerShell session with explicit `-Credential`.

**2. 01-13 privilege manifest requires re-approval**
- **Reason:** The manifest was updated to describe native PostgreSQL on LAB-SERVER01, changing its digest.
- **Next step:** Re-run the Plan 01-17 privilege approval step for plan 01-13 with the new digest `c5b6820546e0cc31eb37c075acf67cdd58e9a257f5779cf19488feb4db7807ba`.

## Known Stubs

| File | Line | Reason |
|------|------|--------|
| `scripts/lab/Invoke-Dc01Server.ps1` | `MigrationFailure` scenario | Checksum-drift injection is not implemented in source mode; it currently throws `checksum_drift_not_injected_in_source_mode`. |

## Self-Check: PASSED

- Created files exist: `config/lab.roles.example.json`, `scripts/lab/Invoke-Phase1EnvironmentReconcile.ps1`, `scripts/lab/Invoke-Dc01Server.ps1`, `tests/e2e/compose.rs`, `.planning/docs/LAB-SERVER01-SETUP.md`.
- Modified files updated: `config/server.env.example`, `config/lab.phase1.example.yaml`, `config/lab.roles.example.json`, `deploy/compose.yaml`, `crates/dlp-server/Cargo.toml`.
- Task commits `a3d5ceb` and `42e9765` exist in git history.
- `cargo test --locked -p dlp-server --test compose` passes.
- `Invoke-Phase1EnvironmentReconcile.ps1 -Apply` passes and publishes evidence.
