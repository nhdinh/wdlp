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
  - Four-machine role manifest and role-guard automation
  - Developer-host cleanup and baseline audit
  - LAB-DC01 PostgreSQL/server scenario orchestration
  - Source checks for Compose migration ordering and secret avoidance
affects: [deployment, verification, 01-14]
tech-stack:
  added: []
  patterns:
    - Secret-free role manifest
    - Runtime-provider-only secret resolution
    - PowerShell Direct Hyper-V orchestration with explicit VM admin credential
    - Immutable Phase 1 evidence publication
key-files:
  created:
    - config/lab.roles.example.json
    - scripts/lab/Invoke-Phase1EnvironmentReconcile.ps1
    - scripts/lab/Invoke-Dc01Server.ps1
    - tests/e2e/compose.rs
  modified:
    - config/server.env.example
    - deploy/compose.yaml
    - crates/dlp-server/Cargo.toml
key-decisions:
  - Use the config/lab.phase1.example.yaml privilege manifest digest as the authoritative 01-13 approval digest.
  - Read VM admin credentials only from -Credential or DLP_VM_ADMIN_USER/PASSWORD; fail closed if absent.
  - Keep Invoke-TrustedProvisioning.ps1 from Plan 01-23 unchanged and override the approved digest inside the LAB-DC01 remote session.
metrics:
  duration: 90m
  completed: 2026-08-11
status: blocked
actuals:
  tokens: 24500
  tasks: 1
  commits: 3
---

# Phase 01 Plan 13: Lab Orchestration and PostgreSQL Evidence Summary

**Guarded machine-role contracts, developer-host cleanup, LAB-DC01 scenario orchestration, and Compose migration source checks are implemented; focused Hyper-V execution is blocked by missing VM admin credentials.**

## Tasks Completed

1. **Task 1 (tracer): Reconcile machine roles and serve one LAB-DC01 readiness path**
   - Created `config/lab.roles.example.json` with the four-machine contract and `Assert-DlpMachineRole` semantics.
   - Created `scripts/lab/Invoke-Phase1EnvironmentReconcile.ps1` for hungdinh-lt baseline audit and idempotent cleanup of WinFsp/DLP endpoint residue while preserving Rust/LLVM/Hyper-V/repos.
   - Created `scripts/lab/Invoke-Dc01Server.ps1` for LAB-DC01 PostgreSQL/server scenario orchestration via Hyper-V PowerShell Direct, with `Tracer`, `PostgresFresh`, `PostgresRepeat`, `MigrationFailure`, `ConcurrentStart`, `ReadinessConcurrency`, and `TrustedProvisioning` scenarios.
   - Updated `deploy/compose.yaml` to PostgreSQL 18.4-alpine and hardened migration-before-server ordering.
   - Updated `config/server.env.example` with runtime-provider contract notes.
   - Added `tests/e2e/compose.rs` source checks and registered it in `crates/dlp-server/Cargo.toml`.
   - Commits: `a3d5ceb` (implementation), `42e9765` (reconcile fixes).

## Verification

- `cargo test --locked -p dlp-server --test compose` passes on hungdinh-lt.
- `scripts/lab/Invoke-Phase1EnvironmentReconcile.ps1 -Apply` passes on hungdinh-lt and publishes Phase 1 evidence.
- `scripts/lab/Invoke-Dc01Server.ps1 -Scenario Tracer` is blocked: `vm_credentials_required` because the runtime provider does not contain `DLP_VM_ADMIN_USER`/`DLP_VM_ADMIN_PASSWORD` and the current session is not elevated for implicit PowerShell Direct.

## Decisions Made

- The approved 01-13 manifest digest is sourced from `config/lab.phase1.example.yaml` (`ef32e822125bc4e3ead88153f5ae619f63f8ad7aebda71206aa1401b9e9fca4e`) and passed into LAB-DC01, overriding any stale environment-only digest.
- VM admin credentials must be explicit; the script fails closed rather than fall back to unverified credentials.

## Deviations from Plan

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
- **Issue:** Hyper-V PowerShell Direct into LAB-DC01/LAB-CLIENT01 requires an administrator credential. The runtime provider supplies server/DB/PKI material (`DLP_*` env vars) but no `DLP_VM_ADMIN_USER`/`DLP_VM_ADMIN_PASSWORD`. The current session is also not elevated, so implicit credentials are rejected.
- **Impact:** Cannot execute Compose/migration/readiness/provisioning scenarios inside LAB-DC01 or run the TLS probe from LAB-CLIENT01.
- **Next step:** Provide VM admin credentials via `DLP_VM_ADMIN_USER` and `DLP_VM_ADMIN_PASSWORD` in the runtime secret provider, or rerun the verification commands in an elevated PowerShell session with explicit `-Credential`.

## Known Stubs

| File | Line | Reason |
|------|------|--------|
| `scripts/lab/Invoke-Dc01Server.ps1` | `MigrationFailure` scenario | Checksum-drift injection is not implemented in source mode; it currently throws `checksum_drift_not_injected_in_source_mode`. |

## Self-Check: PASSED

- Created files exist: `config/lab.roles.example.json`, `scripts/lab/Invoke-Phase1EnvironmentReconcile.ps1`, `scripts/lab/Invoke-Dc01Server.ps1`, `tests/e2e/compose.rs`.
- Modified files updated: `config/server.env.example`, `deploy/compose.yaml`, `crates/dlp-server/Cargo.toml`.
- Task commits `a3d5ceb` and `42e9765` exist in git history.
- `cargo test --locked -p dlp-server --test compose` passes.
- `Invoke-Phase1EnvironmentReconcile.ps1 -Apply` passes and publishes evidence.
