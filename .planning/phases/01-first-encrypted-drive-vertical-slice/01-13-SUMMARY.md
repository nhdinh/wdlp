---
phase: 01-first-encrypted-drive-vertical-slice
plan: 13
subsystem: lab-orchestration
tags: [hyperv, postgresql, ldaps, kerberos, winrm, provisioning, evidence]
requires:
  - phase: 01-22
    provides: PostgreSQL enrollment authority and transactional credential activation
  - phase: 01-23
    provides: Production route partitioning, typed trusted-provisioning client, and dual-DC Kerberos preflight
provides:
  - Secret-free four-machine role contract and role guards
  - Developer-host cleanup that preserves Rust/LLVM/Hyper-V/source trees
  - LAB-SERVER01 native PostgreSQL migration/listener/readiness evidence through LAB-DC01
  - LAB-DC01 trusted provisioning with dual-DC corroboration and Kerberos WinRM-over-HTTPS fingerprint collection
affects: [01-14, 01-18, 01-19, 01-15, 01-20, 01-16, 01-21, deployment, enrollment]
actuals:
  tokens: 45000
  tasks: 3
  commits: 28
  files: 12
tech-stack:
  added: []
  patterns: [machine-role assertion before mutation, runtime-only secret provider, digest-bound privilege manifest, immutable focused-Hyper-V evidence, virtual-disk identifier substitute]
key-files:
  created: [config/lab.roles.example.json, scripts/lab/Invoke-Phase1EnvironmentReconcile.ps1, scripts/lab/Invoke-Dc01Server.ps1, scripts/lab/Invoke-TrustedProvisioning.ps1, scripts/lab/Reset-DlpPostgres.py, tests/e2e/compose.rs]
  modified: [config/server.env.example, deploy/compose.yaml, scripts/verify-phase1-evidence.ps1, evidence/phase1/requirement-matrix.yaml]
key-decisions:
  - "Management server runs on LAB-DC01; PostgreSQL remains native on LAB-SERVER01."
  - "DLP_LISTEN_ADDRESS configures bind address; default localhost, lab override 0.0.0.0:8443."
  - "Hyper-V virtual disk null SerialNumber falls back to Win32_DiskDrive.PNPDeviceID under the approved substitute clause."
  - "Worktree remains unmerged until all three Tasks pass verification."
patterns-established:
  - "Assert-DlpMachineRole aborts before mutation when actual computer name and expected role differ."
  - "Runtime secrets travel only through PowerShell Direct sessions, never repository files or command lines."
  - "Every scenario publishes an immutable focused-Hyper-V evidence attempt and updates only the correct matrix tier."
requirements-completed: [WRK-01, WRK-02, WRK-03, WRK-04, SRV-01, SRV-03, SRV-11, SRV-12, TST-05]
coverage:
  - id: T1
    description: Machine roles, developer-host cleanup, and LAB-DC01 tracer
    requirement: WRK-01/02/03/04, SRV-12
    verification:
      - kind: focused_hyperv
        ref: scripts/lab/Invoke-Dc01Server.ps1 -Scenario Tracer
        status: pass
      - kind: focused_hyperv
        ref: scripts/verify-phase1-evidence.ps1 -Scenario Dc01Tracer
        status: pass
    human_judgment: true
    rationale: Requires Hyper-V PowerShell Direct and the four named lab VMs.
  - id: T2
    description: LAB-SERVER01 PostgreSQL migration idempotency/concurrency/readiness
    requirement: SRV-11, SRV-12
    verification:
      - kind: focused_hyperv
        ref: scripts/lab/Invoke-Dc01Server.ps1 -Scenario All
        status: pass
      - kind: focused_hyperv
        ref: scripts/verify-phase1-evidence.ps1 -Scenario Dc01Postgres
        status: pass
    human_judgment: true
    rationale: Requires native PostgreSQL on LAB-SERVER01 and LAB-DC01 server listener.
  - id: T3
    description: Trusted LAB-CLIENT01 provisioning on LAB-DC01 before enrollment
    requirement: TST-05
    verification:
      - kind: focused_hyperv
        ref: scripts/lab/Invoke-Dc01Server.ps1 -Scenario TrustedProvisioning
        status: pass
      - kind: focused_hyperv
        ref: scripts/verify-phase1-evidence.ps1 -Scenario TrustedProvisioningApproved
        status: pass
    human_judgment: true
    rationale: Requires AD/LDAPS runtime secrets, domain-joined LAB-CLIENT01, and Kerberos WinRM-over-HTTPS.
duration: 4h 30m
completed: 2026-08-12
status: complete
---

# Phase 01 Plan 13: First Encrypted-Drive Vertical Slice — Lab Orchestration Summary

**The binding lab topology is established, developer-host residue is removed, real PostgreSQL migration/readiness evidence is collected, and trusted LAB-CLIENT01 provisioning is complete before enrollment.**

## Performance

- **Duration:** ~4h 30m across three sessions
- **Tasks:** 3/3
- **Files modified:** 12

## Accomplishments

- Created a secret-free `config/lab.roles.example.json` contract naming hungdinh-lt, LAB-DC01, LAB-SERVER01, LAB-DC02, and LAB-CLIENT01 roles.
- Implemented `Invoke-Phase1EnvironmentReconcile.ps1` with role assertion, dry-run inventory, and guarded cleanup of WinFsp/DLP endpoint residue while preserving Rust/LLVM/Hyper-V/source trees.
- Implemented `Invoke-Dc01Server.ps1` to orchestrate LAB-DC01 management-server startup against native PostgreSQL on LAB-SERVER01, with scenarios for tracer, migration idempotency/concurrency, and trusted provisioning.
- Proved SRV-11 and SRV-12 with `PostgresFresh`, `PostgresRepeat`, `MigrationFailure`, `ConcurrentStart`, and `ReadinessConcurrency` scenarios.
- Completed trusted provisioning: dual-DC AD corroboration, Kerberos WinRM-over-HTTPS fingerprint collection, stable virtual-disk identifier fallback, and TST-05 evidence publication.

## Task Commits

- **Task 1** — `a3d5ceb`, `42e9765`, `df329d3`, `784dff8`, `b5f08c9`, `2435b27`, `277c415`, `7744eae`, `c54f66f`, `135e1a0`, `48500f0`, `5296e1c`, `2abe8bf`, `62d7797`
- **Task 2** — `bf3c941`, `92974eb`, `46cad90`
- **Task 3** — `98cf2b6`, `d38e2a8`, `9be952d`, `98c8f99`, `17bde69`, `e2deb6f`

## Verification

- Passed: `cargo test --locked -p dlp-server -p dlpctl`
- Passed: `Invoke-Phase1EnvironmentReconcile.ps1 -Apply`
- Passed: `Invoke-Dc01Server.ps1 -Scenario Tracer`
- Passed: `Invoke-Dc01Server.ps1 -Scenario All`
- Passed: `Invoke-Dc01Server.ps1 -Scenario TrustedProvisioning`
- Passed: `verify-phase1-evidence.ps1 -Scenario Dc01Tracer`
- Passed: `verify-phase1-evidence.ps1 -Scenario Dc01Postgres`
- Passed: `verify-phase1-evidence.ps1 -Scenario TrustedProvisioningApproved`

## Known Substitutes

| Substitute | Scope | Rationale |
|---|---|---|
| `Win32_DiskDrive.PNPDeviceID` | Virtual disk identity for fingerprint workflow | Hyper-V virtual disk exposes null `SerialNumber`; approved Phase 1 substitute allows virtual disk identifier fixtures. |

## Deviations from Plan

- Management-server binding moved from default localhost to `0.0.0.0:8443` via `DLP_LISTEN_ADDRESS` so LAB-CLIENT01 can reach readiness endpoints.
- Native PostgreSQL on LAB-SERVER01 is reached via `Reset-DlpPostgres.py` over SSH/sudo instead of Docker Compose.

## Next Phase Readiness

- Plan 01-14 can proceed with LAB-CLIENT01 enrollment using the published fingerprint digest and runtime-secure token handoff.

## Self-Check: PASSED

- All three Tasks verified.
- TST-05 matrix row is `pass`.
- Worktree is ready for merge to master.
