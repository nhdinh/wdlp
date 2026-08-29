---
phase: 02
slug: policy-enforcement-and-user-feedback
status: ready
nyquist_compliant: true
wave_0_complete: false
created: 2026-08-29
---

# Phase 02 — Validation Strategy

> Finalized per-phase validation contract for feedback sampling during execution. The six-plan graph contains fourteen executable tasks; every task is mapped below, including its TDD/Wave 0 owner.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in test harness through Cargo 1.97.1; PowerShell for Windows mounted-drive smoke |
| **Config file** | Workspace `Cargo.toml`; no separate Rust test-runner configuration |
| **Quick run command** | `rtk cargo test --locked -p dlp-policy --quiet` |
| **Full suite command** | `rtk cargo test --locked --workspace --all-targets && rtk powershell -NoProfile -ExecutionPolicy Bypass -File tests/windows/Invoke-Phase2PolicySmoke.ps1 -Case All` |
| **Estimated runtime** | Focused crate tests under 30 seconds where feasible; full Windows lab runtime measured during execution |

---

## Sampling Rate

- **After every task commit:** Run the changed crate's focused mapped test target.
- **After every plan wave:** Run `rtk cargo test --locked --workspace --all-targets`.
- **Before `$gsd-verify-work`:** The workspace suite and Windows Phase 2 smoke matrix must be green.
- **Max feedback latency:** 30 seconds for focused checks where feasible; longer Windows checks run at wave boundaries.

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | Wave 0 Owner | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|--------------|--------|
| 02-01-01 | 02-01 | 1 | POL-04,06,09 | T-02-01-03 | Read/export denial precedes plaintext copy and emits one redacted event | integration tracer | `rtk cargo test --locked -p dlp-windows-drive --test policy_enforcement read_export_tracer --quiet` | task RED | pending |
| 02-01-02 | 02-01 | 1 | POL-01..10 | T-02-01-01/02/04 | Deterministic bounded compilation/evaluation and fail-closed inspection | unit/property | `rtk cargo test --locked -p dlp-policy --test policy_v2 --quiet && rtk cargo test --locked -p dlp-policy --quiet && rtk cargo clippy --locked -p dlp-policy --all-targets -- -D warnings` | task RED | pending |
| 02-02-01 | 02-02 | 2 | SRV-02,05,06,07 | T-02-02-01/02/03 | Role-safe immutable lifecycle and transactional assignment | PostgreSQL integration | `rtk cargo test --locked -p dlp-server --test policy_lifecycle --quiet && rtk cargo test --locked -p dlp-server --test policy_lifecycle migration_ --quiet` | task RED | pending |
| 02-02-02 | 02-02 | 2 | SRV-02,05,07 | T-02-02-04/05 | Exact CLI grammar, deployment separation, monotonic redacted status | integration | `rtk cargo test --locked -p dlpctl --test policy_cli --quiet && rtk cargo test --locked -p dlp-server --test policy_lifecycle --quiet && rtk cargo clippy --locked -p dlpctl -p dlp-server --all-targets -- -D warnings` | task RED | pending |
| 02-03-01 | 02-03 | 3 | SRV-06,07, POL-07, AGT-10 | T-02-03-01/03/04 | Signed assigned bundle materializes atomically and preserves current/LKG on failure | integration tracer | `rtk cargo test --locked -p dlp-agent-core --test policy_activation activation_tracer --quiet && rtk cargo test --locked -p dlp-server --test policy_lifecycle policy_bundle_contract --quiet` | task RED | pending |
| 02-03-02 | 02-03 | 3 | SRV-07, POL-07, AGT-10 | T-02-03-01/03/04/05 | Verified current/LKG reaches the built dlp-drive-host through acknowledged service bootstrap/update and preserves its prior evaluator on failure | Windows process integration | `rtk cargo build --locked -p dlp-windows-drive --bin dlp-drive-host && rtk cargo test --locked -p dlp-windows-service --test session_lifecycle real_drive_host_policy_snapshot --quiet` | task RED | pending |
| 02-03-03 | 02-03 | 3 | CRY-05, SRV-06,07 | T-02-03-02/03 | Old-key-authorized rotation and the discovered distribution target remain replay-safe | integration/E2E | `rtk cargo test --locked -p dlp-agent-core --test policy_activation --quiet && rtk cargo test --locked -p dlp-server --test policy_distribution --quiet && rtk cargo clippy --locked -p dlp-protocol -p dlp-crypto -p dlp-agent-core --all-targets -- -D warnings` | task RED | pending |
| 02-04-01 | 02-04 | 4 | AGT-10, POL-03 | T-02-04-02/04/05 | Staged inspect/commit/abort and authenticated digest migration preserve prior generations | storage integration | `rtk cargo test --locked -p dlp-storage --test policy_staging --quiet && rtk cargo test --locked -p dlp-storage --quiet` | task RED | pending |
| 02-04-02 | 02-04 | 4 | POL-04,05,06,09, DRV-08 | T-02-04-01/03 | Every callback decides before effect and denial maps to `0xC0000022` | drive integration | `rtk cargo test --locked -p dlp-windows-drive --test policy_enforcement --quiet && rtk cargo clippy --locked -p dlp-storage -p dlp-windows-drive --all-targets -- -D warnings` | task RED | pending |
| 02-05-01 | 02-05 | 5 | DRV-05,08, UI-02 | T-02-05-01/02/05/06 | Built dlp-drive-host synchronously records the decision and receives one authenticated exact grant-consumption response; replay/timeout/frame failures deny | integration tracer + Windows process | `rtk cargo test --locked -p dlp-windows-service --test companion_grants warn_grant_tracer --quiet && rtk cargo test --locked -p dlp-windows-drive --test policy_enforcement warn --quiet && rtk cargo build --locked -p dlp-windows-drive --bin dlp-drive-host && rtk cargo test --locked -p dlp-windows-service --test session_lifecycle real_drive_host_warn_grant --quiet` | task RED | pending |
| 02-05-02 | 02-05 | 5 | POL-09, UI-02 | T-02-05-03/04 | Event creation precedes privacy-safe notification grouping without cross-user loss | unit/integration | `rtk cargo test --locked -p dlp-windows-service --test companion_grants --quiet && rtk cargo clippy --locked -p dlp-windows-service -p dlp-windows-drive --all-targets -- -D warnings` | task RED | pending |
| 02-06-01 | 02-06 | 6 | DRV-08, UI-01,03 | T-02-06-01/02/04 | Built companion renders one authenticated privacy-safe native toast | Windows adapter tracer | `rtk cargo test --locked -p dlp-windows-service --test companion_grants toast_projection --quiet && rtk cargo build --locked -p dlp-windows-service --bin dlp-companion` | task RED | pending |
| 02-06-02 | 02-06 | 6 | AGT-10, DRV-05, UI-01,02 | T-02-06-01/03 | Per-session launch, isolation, fail-closed restart, and grant invalidation | integration | `rtk cargo test --locked -p dlp-windows-service --test companion_grants companion_lifecycle --quiet && rtk cargo test --locked -p dlp-windows-service --test session_lifecycle --quiet && rtk cargo clippy --locked -p dlp-windows-service --all-targets -- -D warnings` | task RED | pending |
| 02-06-03 | 02-06 | 6 | AGT-10, DRV-05,08, UI-01..03, TST-07 | T-02-06-02/03/05 | Real service -> dlp-drive-host -> WinFsp snapshot/update, synchronous event/grant, toast, restart, isolation, and received-revocation evidence passes | Windows E2E | `rtk cargo test --locked --workspace --all-targets && rtk powershell -NoProfile -ExecutionPolicy Bypass -File tests/windows/Invoke-Phase2PolicySmoke.ps1 -Case All` | task implementation; owns final sign-off | pending |

*Status: pending · green · red · flaky*

---

## Wave 0 Ownership

Wave 0 is embedded as the RED step of each TDD task rather than emitted as a separate execution plan. `wave_0_complete` remains false until the files below have been created and their mapped commands pass. Plan 02-06 Task 3 owns the final status/sign-off update after the complete automated and human evidence gates.

- [ ] `crates/dlp-policy/tests/policy_v2.rs` — Plan 02-01 Task 2; POL-01 through POL-10 table/property coverage.
- [ ] `crates/dlp-server/tests/policy_lifecycle.rs` — Plan 02-02 Tasks 1-2; SRV-02/05/06/07 repository, API, concurrency, and role coverage.
- [ ] `crates/dlpctl/tests/policy_cli.rs` — Plan 02-02 Task 2; exact D-01 grammar, shared-compiler validation, publish/deploy separation, output versioning, and redaction coverage.
- [ ] `crates/dlp-agent-core/tests/policy_activation.rs` — Plan 02-03 Tasks 1 and 3; signed activation, key rotation, restart, and LKG failure coverage.
- [ ] `crates/dlp-storage/tests/policy_staging.rs` — Plan 02-04 Task 1; candidate inspect/commit/abort and digest migration coverage.
- [ ] `crates/dlp-windows-drive/tests/policy_enforcement.rs` — Plan 02-01 Task 1 then Plan 02-04 Task 2; callback timing, operation mapping, and access-denied contracts.
- [ ] `crates/dlp-windows-service/tests/companion_grants.rs` — Plan 02-05 Tasks 1-2 then Plan 02-06 Tasks 1-2; authenticated routing, grant expiry/replay/restart, toast projection, and lifecycle.
- [ ] Expand existing `crates/dlp-windows-service/tests/session_lifecycle.rs` — Plan 02-03 Task 1 then Plan 02-05 Task 1; built dlp-drive-host snapshot bootstrap/hot-update acknowledgement and synchronous event/grant response coverage.
- [ ] `crates/dlp-server/tests/policy_distribution.rs` — Plan 02-03 Task 2; Cargo auto-discovers the `policy_distribution` integration target.
- [ ] `tests/windows/Invoke-Phase2PolicySmoke.ps1` — Plan 02-06 Task 3; real toast activation, mounted-drive behavior, two-user isolation, restart, warn grant, LKG, and revocation matrix.
- [ ] Satisfy the Plan 02-02 Task 1 PostgreSQL precondition through the configured test URL or LAB-SERVER01; missing connectivity is a blocking test dependency, never a passing source-only substitute.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Native Windows toast activation and safe visible fields | UI-01, UI-03 | Requires an interactive Windows user session and shell notification infrastructure | Trigger a blocked and warned mounted-drive operation; verify one deduplicated toast shows only base file name, operation, safe rule display name, stable reason, and remediation. |
| Two-user mounted-drive isolation and revoked device | DRV-05, TST-07 | Requires separate Windows user sessions and a real WinFsp mount | Run the Phase 2 smoke cases as two users; confirm cross-user access and revoked-device operations return access denied and create the expected audit event. |
| Warn proceed-once interaction | UI-02, DRV-08 | Requires toast activation callback plus a real retry through the mounted drive | Select Proceed once, retry the exact operation, verify one success, then verify replay, expiry, changed path, changed operation, changed user, and changed policy version are denied. |

---

## Validation Sign-Off

- [x] All fourteen finalized tasks have an automated verification command and named Wave 0 owner.
- [x] Sampling continuity: every task has automated verification; no gap exists.
- [x] Wave 0 ownership covers every missing test reference above.
- [x] No watch-mode flags are used, all shell commands are `rtk`-prefixed, and chained checks fail fast.
- [ ] Focused-test feedback latency is under 30 seconds where feasible.
- [ ] Full workspace suite and Windows Phase 2 smoke matrix pass.
- [x] `nyquist_compliant: true` records that the finalized plan graph has complete automated coverage; it does not claim test execution.
- [ ] Plan 02-06 Task 3 sets `wave_0_complete: true`, `status: complete`, and records evidence only after all mapped tests and human checks pass.

**Approval:** ready for execution; final approval is owned by Plan 02-06 Task 3 and remains pending evidence.
