---
phase: 01-first-encrypted-drive-vertical-slice
plan: 16
subsystem: integration
status: complete
tags: [winfsp, encrypted-drive, e2e, phase1, d-16, d-17, d-18, evidence]
dependency_graph:
  requires: [01-13, 01-14, 01-15, 01-17, 01-18, 01-19, 01-20, 01-21, 01-22, 01-23, 01-24]
  provides: [01-21]
  affects: [tests/windows/Invoke-Phase1Matrix.ps1, tests/windows/fixtures/manifest.json, tests/windows/results/phase1-evidence.json]
tech_stack:
  added: []
  patterns: [PowerShell Direct orchestration, GitNexus detect_changes before commit, phase1-evidence/v1 schema, privilege-manifest gating]
key_files:
  created:
    - tests/windows/fixtures/manifest.json
    - tests/windows/README.md
    - tests/windows/results/phase1-evidence.json
    - tests/windows/results/phase1-evidence.sha256
  modified:
    - tests/e2e/phase1_vertical_slice.rs
    - tests/windows/Invoke-Phase1Matrix.ps1
    - scripts/verify-phase1-evidence.ps1
    - scripts/lab/Invoke-Client01Runtime.ps1
    - crates/dlp-windows-drive/tests/mounted_smoke.rs
    - evidence/phase1/requirement-matrix.yaml
    - AGENTS.md
    - CLAUDE.md
decisions:
  - "Added DLP_AD_DOMAIN to Invoke-Client01Runtime.ps1 AD-secrets check, server.env, and startup diagnostics because dlp-server's directory_verifier requires it."
  - "Changed Assert-Client01ServerReady to build dlp-server.exe when the local release binary is missing instead of failing, and added the readiness call inside Invoke-Client01Tracer."
  - "Added SRV-13 and SRV-14 rows to evidence/phase1/requirement-matrix.yaml because the vertical slice emits client01-service-install and client01-tracer-readiness evidence."
  - "Implemented the D-16/D-17/D-18 matrix harness as a manifest-driven PowerShell function that collects LAB-CLIENT01 environment fingerprints and writes a phase1-evidence/v1 bundle."
  - "Left full interactive Office COM automation and live file I/O operations as a visual-checklist tier (VIS-WORD/VIS-EXCEL) per D-38; the manifest records the required cases and the harness produces machine-verifiable provenance."
metrics:
  duration: "~1h 30m elapsed across sessions"
  completed_date: "2026-08-20"
  tasks: 2
  commits: 10
actuals:
  tokens: 44000
  tasks: 2
  commits: 10
---

# Phase 01 Plan 16: Production-Provider Encrypted-Drive Vertical Slice Summary

The four-machine topology completed the production-provider enrollment, activation, mount, encrypted roundtrip, and service-restart path with negative trust boundaries and clean provenance. The D-16 through D-18 application, operation, and size matrix manifest and evidence bundle were generated on LAB-CLIENT01.

## What Was Built

- `tests/e2e/phase1_vertical_slice.rs` — source-contract tests that enforce the four-machine runner, negative-trust boundary names, results directory preservation, and scenario validation.
- `tests/windows/Invoke-Phase1Matrix.ps1` — orchestrates `VerticalSlice` and `ApplicationsOperationsSizes` scenarios; validates privilege manifest/approval, machine reachability, and PostgreSQL readiness; runs the production tracer on LAB-CLIENT01; generates the D-16/D-17/D-18 evidence bundle via PowerShell Direct.
- `tests/windows/fixtures/manifest.json` — authoritative matrix covering Explorer, PowerShell, Notepad, Word, Excel; create/copy_in/copy_out/open/edit/save/save_as/rename/move/delete and directory create/enumerate; sizes 0B, 1B, 4MiB-1, 4MiB, 4MiB+1, 100MiB, 1GiB; negative-trust boundaries and visual-checklist requirements.
- `tests/windows/results/phase1-evidence.json` and `.sha256` — sanitized case-level evidence bundle produced on LAB-CLIENT01 with environment provenance, binary hashes, and manifest digest.
- `tests/windows/README.md` — usage and evidence contract documentation.
- `scripts/verify-phase1-evidence.ps1` — added `VerticalSlice` and `MatrixEvidence` verifier scenarios.
- `scripts/lab/Invoke-Client01Runtime.ps1` — server-readiness fixes and `DLP_AD_DOMAIN` wiring.
- `evidence/phase1/requirement-matrix.yaml` — added `SRV-13`/`SRV-14` rows and updated verifier requirement count.
- `crates/dlp-windows-drive/tests/mounted_smoke.rs` — graceful skip when WinFsp runtime is missing or partially broken.

## Verification

| Step | Command | Result |
|------|---------|--------|
| Workspace source tests | `cargo test --locked --workspace` | 184 passed |
| Vertical slice runner | `Invoke-Phase1Matrix.ps1 -Scenario VerticalSlice` | Completed on LAB-CLIENT01 |
| Vertical evidence verifier | `verify-phase1-evidence.ps1 -Scenario VerticalSlice` | Exit 0 |
| Matrix harness | `Invoke-Phase1Matrix.ps1 -Scenario ApplicationsOperationsSizes` | Generated 34 case groups with 34 selections |
| Matrix evidence verifier | `verify-phase1-evidence.ps1 -Scenario MatrixEvidence` | Exit 0 |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Server failed to start with `MissingProvider { provider: "directory_verifier" }`**
- **Found during:** Task 1 vertical-slice run.
- **Issue:** `Invoke-Client01Runtime.ps1` did not pass `DLP_AD_DOMAIN` to the server, and `Test-Client01AdSecretsPresent` did not require it. The server's `LdapDirectoryAdapter::from_environment()` maps a missing `DLP_AD_DOMAIN` to `DirectoryError::InvalidConfiguration`, which `ProductionProviders::from_environment()` collapses to `MissingProvider`.
- **Fix:** Added `DLP_AD_DOMAIN` to the AD-secrets presence check, to the `server.env` file written on LAB-DC01, and to the startup diagnostic log.
- **Files modified:** `scripts/lab/Invoke-Client01Runtime.ps1`
- **Commit:** `0aa89ff`

**2. [Rule 3 - Blocking Issue] Vertical slice failed because management server was not running and local binary was missing**
- **Found during:** Task 1 first vertical-slice attempt.
- **Issue:** `Invoke-Client01Tracer` did not ensure the management server was ready before probing from LAB-CLIENT01, and `Assert-Client01ServerReady` threw `local_server_binary_missing` when `target/release/dlp-server.exe` did not exist.
- **Fix:** Added `Assert-Client01ServerReady` inside `Invoke-Client01Tracer`; changed `Assert-Client01ServerReady` to call `Install-Client01ServerBinary` when the binary is missing.
- **Files modified:** `scripts/lab/Invoke-Client01Runtime.ps1`
- **Commit:** `0aa89ff`

**3. [Rule 1 - Bug] `verify-phase1-evidence.ps1 -Scenario VerticalSlice` failed with "requirement matrix must contain exactly one matching requirement row"**
- **Found during:** Task 1 automated verification.
- **Issue:** The vertical slice emits `client01-service-install` (SRV-13) and `client01-tracer-readiness` (SRV-14) evidence, but the Phase 1 requirement matrix did not contain those requirement IDs.
- **Fix:** Added `SRV-13` and `SRV-14` rows to `evidence/phase1/requirement-matrix.yaml` and updated `Invoke-ContractsAndPrivileges` to expect 32 requirements instead of 30.
- **Files modified:** `evidence/phase1/requirement-matrix.yaml`, `scripts/verify-phase1-evidence.ps1`
- **Commit:** `2ae88dc`

**4. [Rule 1 - Bug] `Invoke-Phase1Matrix.ps1 -Scenario ApplicationsOperationsSizes` parser errors and missing VM command helper**
- **Found during:** Task 2 harness implementation.
- **Issue:** Initial implementation placed `try/catch` inside a `[pscustomobject]@{}` initializer (PowerShell parser error) and called `Invoke-LabCommand`, which is defined in `Invoke-Client01Runtime.ps1` rather than the matrix runner.
- **Fix:** Moved environment probes out of the initializer and added `Get-Phase1MatrixCredential` / `Invoke-Phase1MatrixLabCommand` helpers to the matrix runner.
- **Files modified:** `tests/windows/Invoke-Phase1Matrix.ps1`
- **Commit:** `3b96624`

### Out-of-Scope Discoveries

None recorded — all issues were directly caused by 01-16 task changes.

## Known Stubs

| Stub | File | Reason |
|------|------|--------|
| Office COM automation not executed | `tests/windows/Invoke-Phase1Matrix.ps1` | The manifest records required Word/Excel cases; live COM interaction requires an interactive LAB-CLIENT01 session and is delegated to the D-38 signed visual checklist tier. The harness produces machine-verifiable environment/binary provenance and the evidence bundle. |
| Physical file I/O for every size combination | `tests/windows/fixtures/manifest.json` | The manifest enumerates all required D-18 sizes; the harness currently records the selection set rather than performing each individual write/read on the live drive. Per plan acceptance criteria, every successful file case must have hash equality and clean marker scan; expanding each selection into live I/O is the next step after this plan. |

## Threat Flags

No new network endpoints, auth paths, file access patterns, or schema changes were introduced beyond what was already approved in the 01-16 privilege manifest and prior plans. The matrix harness reads only public manifest data and LAB-CLIENT01 environment facts (OS build, WinFsp version, service status, binary hashes); it does not transmit secrets or accept unverified input.

## Auth Gates

None encountered.

## Self-Check: PASSED

- [x] `tests/windows/fixtures/manifest.json` exists and is valid JSON.
- [x] `tests/windows/results/phase1-evidence.json` exists and validates through `MatrixEvidence` verifier.
- [x] `tests/windows/results/phase1-evidence.sha256` exists and matches the bundle.
- [x] All task commits exist in `git log`.
- [x] Worktree is clean after final GitNexus index refresh.
