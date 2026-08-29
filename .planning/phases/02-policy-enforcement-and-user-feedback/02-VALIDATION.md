---
phase: 02
slug: policy-enforcement-and-user-feedback
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-08-29
---

# Phase 02 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution. Plan/task IDs are assigned when Phase 2 plans are finalized.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in test harness through Cargo 1.97.1; PowerShell for Windows mounted-drive smoke |
| **Config file** | Workspace `Cargo.toml`; no separate Rust test-runner configuration |
| **Quick run command** | `cargo test -p dlp-policy --quiet` |
| **Full suite command** | `cargo test --workspace --all-targets` plus `powershell -File tests/windows/Invoke-Phase2PolicySmoke.ps1` |
| **Estimated runtime** | Focused crate tests under 30 seconds where feasible; full Windows lab runtime measured during Wave 0 |

---

## Sampling Rate

- **After every task commit:** Run the changed crate's focused test target.
- **After every plan wave:** Run `cargo test --workspace --all-targets`.
- **Before `$gsd-verify-work`:** The workspace suite and Windows Phase 2 smoke matrix must be green.
- **Max feedback latency:** 30 seconds for focused checks where feasible; longer Windows checks run at wave boundaries.

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| TBD-policy-core | TBD | TBD | POL-01..10 | policy exhaustion / inspection bypass | Deterministic evaluation, bounded detectors, fail-closed inspection, stable reasons | unit/property | `cargo test -p dlp-policy --quiet` | ❌ W0 expansion | ⬜ pending |
| TBD-server | TBD | TBD | SRV-02,05,06,07 | unauthorized mutation / replay | Role-safe lifecycle, immutable signed bundles, assignment and deployment status | integration | `cargo test -p dlp-server --quiet` | ❌ W0 | ⬜ pending |
| TBD-agent | TBD | TBD | CRY-05, AGT-10 | key substitution / stale activation | Trusted rotation, atomic activation, restart-safe current/LKG | integration | `cargo test -p dlp-agent-core --quiet` | ❌ W0 expansion | ⬜ pending |
| TBD-drive | TBD | TBD | DRV-05, DRV-08, POL-04,06 | cross-user access / post-effect denial | Enforcement occurs before protected effects and denials map to `0xC0000022` | integration | `cargo test -p dlp-windows-drive --quiet` | ❌ W0 | ⬜ pending |
| TBD-feedback | TBD | TBD | UI-01,02,03 | spoofing / disclosure / grant replay | Authenticated per-user feedback, safe toast projection, exact single-use grants | unit/integration | `cargo test -p dlp-windows-service --quiet` | ❌ W0 | ⬜ pending |
| TBD-e2e | TBD | TBD | TST-07 | isolation / revoked credential reuse | Two-user isolation and revoked-device rejection hold on a mounted drive | Windows E2E | `powershell -File tests/windows/Invoke-Phase2PolicySmoke.ps1 -Case IsolationAndRevocation` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `crates/dlp-policy/tests/policy_v2.rs` — POL-01 through POL-10 table/property coverage.
- [ ] `crates/dlp-server/tests/policy_lifecycle.rs` — SRV-02/05/06/07 repository, API, concurrency, and role coverage.
- [ ] `crates/dlp-agent-core/tests/policy_activation.rs` — signed activation, key rotation, restart, and LKG failure coverage.
- [ ] `crates/dlp-storage/tests/policy_staging.rs` — candidate inspect/commit/abort and digest migration coverage.
- [ ] `crates/dlp-windows-drive/tests/policy_enforcement.rs` — callback timing, operation mapping, and access-denied contracts.
- [ ] `crates/dlp-windows-service/tests/companion_grants.rs` — authenticated routing, grant expiry/replay/restart, and toast projection.
- [ ] `tests/e2e/policy_distribution.rs` — publish/assign/poll/activate end-to-end coverage.
- [ ] `tests/windows/Invoke-Phase2PolicySmoke.ps1` — real toast activation, mounted-drive behavior, two-user isolation, restart, warn grant, LKG, and revocation matrix.
- [ ] Provide a PostgreSQL fixture for SQLx integration tests; Docker is not currently available locally.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Native Windows toast activation and safe visible fields | UI-01, UI-03 | Requires an interactive Windows user session and shell notification infrastructure | Trigger a blocked and warned mounted-drive operation; verify one deduplicated toast shows only base file name, operation, safe rule display name, stable reason, and remediation. |
| Two-user mounted-drive isolation and revoked device | DRV-05, TST-07 | Requires separate Windows user sessions and a real WinFsp mount | Run the Phase 2 smoke cases as two users; confirm cross-user access and revoked-device operations return access denied and create the expected audit event. |
| Warn proceed-once interaction | UI-02, DRV-08 | Requires toast activation callback plus a real retry through the mounted drive | Select Proceed once, retry the exact operation, verify one success, then verify replay, expiry, changed path, changed operation, changed user, and changed policy version are denied. |

---

## Validation Sign-Off

- [ ] All finalized tasks have an automated verification command or explicit Wave 0 dependency.
- [ ] Sampling continuity: no three consecutive tasks without automated verification.
- [ ] Wave 0 covers every missing test reference above.
- [ ] No watch-mode flags are used.
- [ ] Focused-test feedback latency is under 30 seconds where feasible.
- [ ] Full workspace suite and Windows Phase 2 smoke matrix pass.
- [ ] `nyquist_compliant: true` is set in frontmatter after validation.

**Approval:** pending
