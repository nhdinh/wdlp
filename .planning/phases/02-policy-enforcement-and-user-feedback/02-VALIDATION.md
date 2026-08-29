---
phase: 02
slug: policy-enforcement-and-user-feedback
status: ready
nyquist_compliant: true
wave_0_complete: false
created: 2026-08-29
---

# Phase 02 — Validation Strategy

> Finalized for the adjusted eleven-plan graph. Twenty-two executable tasks have explicit RED/test ownership; filtered Cargo tests require a preceding `-- --list` discoverability gate so zero matched tests cannot pass.

## Test Infrastructure

| Property | Value |
|---|---|
| Framework | Rust built-in test harness through Cargo 1.97.1; PowerShell for real Windows mounted-drive smoke |
| Quick run | `rtk cargo test --locked -p dlp-policy --quiet` |
| Full gate | `rtk cargo test --locked --workspace --all-targets && rtk powershell -NoProfile -ExecutionPolicy Bypass -File tests/windows/Invoke-Phase2PolicySmoke.ps1 -Case All` |
| Sampling | Focused owner test after each task; full workspace after each wave; Windows matrix before phase verification |

## Per-Task Verification Map

| Task | Wave | Requirement focus | Test owner / automated command |
|---|---:|---|---|
| 02-01-01 | 1 | POL-04/06/09, D-05/07/10/11 | `policy_enforcement.rs::read_export_tracer`; discoverability gate then exact test |
| 02-01-02 | 1 | POL-01..10, D-05..14 | `policy_v2.rs`; `rtk cargo test --locked -p dlp-policy --test policy_v2` |
| 02-02-01 | 2 | SRV-02/05, POL-07 | `policy_lifecycle.rs::policy_roles_and_immutable_publish`; discoverability gate then exact test |
| 02-02-02 | 2 | SRV-05/06/07 | `policy_lifecycle.rs::policy_bundle_contract`; discoverability gate then exact test and full target |
| 02-03-01 | 3 | SRV-02/05/07, POL-07 | `policy_cli.rs::policy_lifecycle_tracer`; discoverability gate then exact test |
| 02-03-02 | 3 | SRV-02/05/07 | Full `rtk cargo test --locked -p dlpctl --test policy_cli` |
| 02-04-01 | 4 | SRV-06/07 | Plan 02-02-owned `policy_bundle_contract`, extended and re-run with list gate |
| 02-04-02 | 4 | POL-07, AGT-10 | `policy_activation.rs::activation_tracer`; list gate, exact test, then full target |
| 02-05-01 | 5 | SRV-07, AGT-10 | `session_lifecycle.rs::real_drive_host_policy_snapshot`; list gate and built host |
| 02-05-02 | 5 | SRV-07, POL-07, AGT-10 | Full `rtk cargo test --locked -p dlp-windows-service --test session_lifecycle` |
| 02-06-01 | 5 | CRY-05, AGT-10 | `policy_activation.rs::signing_key_rotation`; list gate and exact test |
| 02-06-02 | 5 | SRV-06/07, CRY-05 | Full Cargo target `rtk cargo test --locked -p dlp-server --test policy_distribution` |
| 02-07-01 | 6 | POL-03, AGT-10 | Full Cargo target `rtk cargo test --locked -p dlp-storage --test policy_staging` |
| 02-07-02 | 6 | POL-04/05/06/09, DRV-08 | Full Cargo target `rtk cargo test --locked -p dlp-windows-drive --test policy_enforcement` |
| 02-08-01 | 7 | POL-06, DRV-05/08, UI-02 | `companion_grants.rs::warn_grant_tracer`; list gate and exact test |
| 02-08-02 | 7 | DRV-05, UI-02 | Full `rtk cargo test --locked -p dlp-windows-service --test companion_grants` |
| 02-09-01 | 8 | POL-06/09, DRV-08, UI-02 | `session_lifecycle.rs::real_drive_host_warn_grant`; list gate and built host |
| 02-09-02 | 8 | POL-09, UI-03 | Full `rtk cargo test --locked -p dlp-windows-service --test companion_grants` |
| 02-10-01 | 9 | DRV-08, UI-01/03 | `companion_grants.rs::toast_projection`; list gate, exact test, built companion |
| 02-10-02 | 9 | AGT-10, DRV-05, UI-01/02 | `companion_grants.rs::companion_lifecycle`; list gate, exact test, session suite |
| 02-11-01 | 10 | all production behaviors, TST-07 | Full workspace plus `Invoke-Phase2PolicySmoke.ps1 -Case All` |
| 02-11-02 | 10 | 22 requirements, D-01..19, 33 edges, prohibitions | Evidence digest/state gate plus plan/coverage validation |

## Wave 0 Ownership

- [ ] `crates/dlp-policy/tests/policy_v2.rs` — 02-01 Task 2.
- [ ] `crates/dlp-windows-drive/tests/policy_enforcement.rs` — 02-01 Task 1, expanded by 02-07 Task 2.
- [ ] `crates/dlp-server/tests/policy_lifecycle.rs` — 02-02 Tasks 1-2; exact `policy_bundle_contract` created there, extended/re-run by 02-04 Task 1.
- [ ] `crates/dlpctl/tests/policy_cli.rs` — 02-03 Tasks 1-2.
- [ ] `crates/dlp-agent-core/tests/policy_activation.rs` — 02-04 Task 2 and 02-06 Task 1.
- [ ] Expand `crates/dlp-windows-service/tests/session_lifecycle.rs` for policy snapshot bootstrap/hot update — 02-05 Tasks 1-2.
- [ ] `crates/dlp-server/tests/policy_distribution.rs` — 02-06 Task 2; Cargo auto-discovers this integration target.
- [ ] `crates/dlp-storage/tests/policy_staging.rs` — 02-07 Task 1.
- [ ] `crates/dlp-windows-service/tests/companion_grants.rs` — 02-08 Tasks 1-2, 02-09 Task 2, and 02-10 Tasks 1-2.
- [ ] Expand `crates/dlp-windows-service/tests/session_lifecycle.rs` for synchronous decision/grant transport — 02-09 Task 1.
- [ ] `tests/windows/Invoke-Phase2PolicySmoke.ps1` — 02-11 Task 1.
- [ ] PostgreSQL lifecycle evidence uses configured test URL or LAB-SERVER01; missing connectivity blocks rather than passing source-only checks.

## Production-Path and Manual Checks

| Behavior | Gate |
|---|---|
| Native toast displays base file name, operation, safe rule display name, stable reason, remediation only | End-of-phase human check in 02-10/11 |
| Proceed once permits one exact retry and denies replay/expiry/mismatch | Built-host integration plus real Windows human check |
| Two-user store/toast/grant isolation and received revocation | Real `Invoke-Phase2PolicySmoke.ps1` matrix |
| Current/LKG bootstrap and hot update | Built `dlp-drive-host` tests owned by 02-05 and real matrix in 02-11 |

## Sign-Off

- [x] All 22 tasks have automated verification and exact owners.
- [x] Every filtered Cargo test is explicitly created/owned and protected by a discoverability gate.
- [x] `session_lifecycle.rs` policy snapshot ownership is 02-05 Tasks 1-2.
- [x] `policy_distribution.rs` ownership is 02-06 Task 2.
- [x] Every command is `rtk`-prefixed and chained gates fail fast.
- [x] The adjusted graph keeps every plan below the 10-file scope-warning threshold.
- [ ] Focused and full automated tests pass.
- [ ] End-of-phase human checks pass.
- [ ] `wave_0_complete: true` and `status: complete` are set only by 02-11 Task 2 after evidence exists.

**Approval:** ready for execution; final approval remains pending 02-11 evidence and human checks.
