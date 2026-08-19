---
phase: 01-first-encrypted-drive-vertical-slice
plan: 24
subsystem: windows-service

tags: [winfsp, windows-service, named-pipe, dpapi, session-host, wts, createprocessasuserw]

requires:
  - phase: 01-20
    provides: WinFsp integrity, service-restart, and Windows-reboot recovery contracts

provides:
  - Authenticated per-session host launch via WTS primary token and CreateProcessAsUserW
  - Service-owned named-pipe bootstrap with kernel-backed PID/SID/session authentication
  - DPAPI-unwrapped store-key handoff without secret-bearing argv/env
  - Safe user-session drive-letter selection using std::path::Path::try_exists
  - Reject-new-open drain with 30-second grace and active-handle accounting
  - Orphan-free cleanup, bounded retry, and one-host restart convergence
  - Deterministic source tests for launch, pipe authentication, and lifecycle

affects:
  - 01-16
  - 01-21

actuals:
  tokens: 34000
  tasks: 2
  commits: 5

tech-stack:
  added: []
  patterns:
    - "Per-actor unpredictable named pipe with restrictive DACL and kernel-backed client identity"
    - "Service-derived store identity/root/key bootstrap; host never selects identity or store"
    - "Safe std::path::Path::try_exists drive-letter probe instead of unsafe GetLogicalDrives"
    - "Shared admission gate for reject-new-open drain with exact active-handle counting"
    - "Injectable PipeFactory/PipeBootstrap seams for deterministic unit tests"

key-files:
  created: []
  modified:
    - crates/dlp-windows-service/src/session.rs
    - crates/dlp-windows-service/src/pipe.rs
    - crates/dlp-windows-drive/src/bin/dlp-drive-host.rs
    - crates/dlp-windows-drive/src/filesystem.rs
    - crates/dlp-windows-drive/Cargo.toml
    - crates/dlp-windows-service/Cargo.toml
    - crates/dlp-windows-service/tests/session_lifecycle.rs
    - Cargo.lock

key-decisions:
  - "Retained WTSQueryUserToken as the sole production identity source for the user-session host."
  - "Implemented safe drive-letter occupancy probe via std::path::Path::try_exists because windows 0.62.2 exposes GetLogicalDrives as unsafe and the workspace forbids unsafe code."
  - "Authenticated the pipe client by comparing GetNamedPipeClientProcessId to the retained child PID, then impersonating and checking TokenUser/TokenSessionId against the captured actor."
  - "Added PipeFactory/PipeBootstrap traits so SessionMonitor remains unit-testable without real WTS sessions or named pipes."

patterns-established:
  - "SessionHostLauncher seam: injectable Windows launcher for deterministic source tests on hungdinh-lt."
  - "PipeFactory/PipeBootstrap seam: replaceable named-pipe creation and authentication for test isolation."
  - "Actor pipe: one first-instance per actor, bounded framed messages, single accepted bootstrap, fail-closed on every identity mismatch."
  - "Admission control: Arc-backed handle counter shared between filesystem context and control loop for exact drain semantics."

requirements-completed:
  - WRK-04
  - CRY-01
  - CRY-04
  - AGT-01
  - AGT-07
  - DRV-01
  - DRV-02
  - DRV-03
  - DRV-04
  - DRV-09
  - TST-03
  - TST-08

coverage:
  - id: D1
    description: "WTS primary token launches exactly one dlp-drive-host.exe per eligible session with no secret-bearing argv/env"
    requirement: DRV-01
    verification:
      - kind: unit
        ref: "crates/dlp-windows-service/tests/session_lifecycle.rs#session_host_command_line_contains_no_secrets"
        status: pass
      - kind: unit
        ref: "crates/dlp-windows-service/tests/session_lifecycle.rs#session_host_launch_is_invoked_once_per_new_actor"
        status: pass
    human_judgment: false
  - id: D2
    description: "Named-pipe bootstrap authenticates client PID, SID, session, and generation before sending store identity/root/key"
    requirement: CRY-01
    verification:
      - kind: unit
        ref: "crates/dlp-windows-service/src/pipe.rs::tests"
        status: pass
      - kind: unit
        ref: "crates/dlp-windows-service/tests/session_lifecycle.rs#session_host_zero_store_key_is_rejected"
        status: pass
    human_judgment: false
  - id: D3
    description: "Drive-letter selection uses the user-session namespace and preserves occupied mappings"
    requirement: DRV-02
    verification:
      - kind: unit
        ref: "crates/dlp-windows-service/tests/session_lifecycle.rs drive letter selection contracts"
        status: pass
      - kind: unit
        ref: "crates/dlp-windows-drive/src/bin/dlp-drive-host.rs drive_letter_selection tests"
        status: pass
    human_judgment: false
  - id: D4
    description: "Sign-out drain rejects new opens, waits for active handles up to 30 seconds, and unmounts exactly once"
    requirement: DRV-09
    verification:
      - kind: unit
        ref: "crates/dlp-windows-service/tests/session_lifecycle.rs drain and restart tests"
        status: pass
    human_judgment: false
  - id: D5
    description: "Real LAB-CLIENT01 secure session-host lifecycle with privileged manifest approval"
    requirement: AGT-07
    verification: []
    human_judgment: true
    rationale: "Requires authenticated domain-operator approval of the 01-24 privilege manifest digest and physical LAB-CLIENT01 runtime with WinFsp/service/interactive session."

duration: "partial (Task 3 pending)"
completed: 2026-08-19
status: halted
---

# Phase 01: Plan 24 — Secure Session Host Lifecycle Summary

**Implemented the production Windows session-host launch, authenticated pipe bootstrap, real-key store open, safe drive-letter selection, and drain/cleanup/restart convergence in source; halted at the Task 3 privilege-manifest checkpoint before any LAB-CLIENT01 mutation.**

## Performance

- **Duration:** partial (Task 3 pending)
- **Started:** 2026-08-18T04:11:54Z
- **Tasks:** 2 of 3 completed
- **Files modified:** 9

## Accomplishments

- Implemented `SessionHostLauncher` using `WTSQueryUserToken`, `CreateEnvironmentBlock`, and `CreateProcessAsUserW` with the approved host binary, target-user environment, and non-secret actor rendezvous arguments.
- Replaced the directory-only `StoragePipeServer` seam with a real per-actor Windows named pipe: unpredictable endpoint, first-instance flag, restrictive DACL, bounded framed messages, and kernel-backed client PID/SID/session authentication before any store bootstrap bytes are sent.
- Wired the pipe into `SessionMonitor::session_logon`: create pipe before launch, spawn a dedicated authentication thread, wait up to 30 seconds, store the authenticated runtime on success, and terminate the child on failure.
- Added `PipeFactory` and `PipeBootstrap` traits plus a `WindowsPipeFactory` production implementation and `FakePipeFactory`/`FakePipeBootstrap` test doubles so `SessionMonitor` remains unit-testable without real WTS sessions.
- Updated `dlp-drive-host.rs` to connect with identification/impersonation SQOS using synchronous pipe I/O, validate the bounded bootstrap, open `LocalEncryptedStore` with the service-derived identity and real nonzero key, start WinFsp, send the selected drive letter back to the service, and retain the mounted volume in a control loop.
- Implemented safe drive-letter occupancy probing via `std::path::Path::try_exists` (workspace forbids unsafe `GetLogicalDrives`), preserving occupied mappings and falling back to the next free candidate.
- Added shared admission/handle accounting to `DlpFileSystemContext` for reject-new-open drain, 30-second grace, and exactly-once unmount on pipe EOF, service stop, host failure, or logoff.
- Added deterministic source tests covering launch idempotency, secret-free command line, zero-key rejection, pipe authentication, replay/stale-generation rejection, drive-letter selection, drain, and restart convergence.

## Task Commits

1. **Task 1 (RED):** `227a692` — `test(01-24): add session host launch contract tests`
2. **Task 1 (GREEN):** `686729b` — `feat(01-24): implement authenticated session host bootstrap and launch`
3. **Task 2 cleanup:** `ad6b586` — `fix(01-24): resolve clippy warnings in session host implementation`
4. **Pipe integration:** `6438506` — `feat(01-24): wire authenticated ActorPipe into SessionMonitor::session_logon`
5. **Host sync + drive selection:** `b02d8ac` — `feat(01-24): synchronous pipe I/O and safe drive-letter selection in drive host`

## Files Created/Modified

- `crates/dlp-windows-service/src/session.rs` — WTS-token launcher, per-session child ownership, authenticated pipe runtime storage, retry, drain, and restart convergence.
- `crates/dlp-windows-service/src/pipe.rs` — Bounded per-actor named-pipe transport with `PipeFactory`/`PipeBootstrap` seams, kernel-backed caller authentication, and versioned bootstrap.
- `crates/dlp-windows-drive/src/bin/dlp-drive-host.rs` — Synchronous authenticated bootstrap client, real-key encrypted-store open, safe drive selection, drive-letter ack, and control loop.
- `crates/dlp-windows-drive/src/filesystem.rs` — Drain admission gate and active-handle accounting.
- `crates/dlp-windows-drive/Cargo.toml` — Exact `winfsp = "=0.13.0"` pins for the safe mount API.
- `crates/dlp-windows-service/Cargo.toml` — Feature addition for `Win32_System_Environment`.
- `crates/dlp-windows-service/tests/session_lifecycle.rs` — Launch, pipe, drain, retry, and restart source contracts.
- `crates/dlp-storage/src/lib.rs` — Minor compatibility adjustment.
- `Cargo.lock` — Dependency pins.

## Decisions Made

- Kept `WTSQueryUserToken` as the sole production identity source and derived SID/session from the token, never from caller-supplied fields.
- Used `std::path::Path::try_exists` for drive-letter probing because the pinned `windows = 0.62.2` binding exposes `GetLogicalDrives` as unsafe and the workspace lint forbids unsafe code.
- Sent the service-derived store identity/root and DPAPI-unwrapped key only after pipe client PID, SID, session, and generation all match.
- Introduced `PipeFactory`/`PipeBootstrap` seams so `SessionMonitor` can be tested with a fake pipe without requiring real Windows sessions or named pipes.

## Deviations from Plan

None in this session. All changes align with the plan; no new auto-fixes or scope creep.

## Issues Encountered

- A previous executor run left a stranded worktree (`worktree-agent-a498a08541e4e74e6`) with Tasks 1–2 implementation but no SUMMARY.md. Recovered by inspecting, fixing clippy issues, and merging into `master`.
- The original `StoragePipeServer::bind` created no actual named pipe, which would have caused `dlp-drive-host.exe` to exit immediately. This was resolved by implementing `ActorPipe` with real `CreateNamedPipeW` semantics and wiring it into `SessionMonitor::session_logon`.
- Real WinFsp mount tests (`dlp-windows-drive/tests/mounted_smoke.rs`) fail on `hungdinh-lt` because the WinFsp runtime is not installed locally; these are not part of the source-only verification required by Tasks 1–2 and will run on LAB-CLIENT01 during Task 3.

## User Setup Required

**Task 3 requires a blocking human checkpoint before any LAB-CLIENT01 mutation:**

1. Review and approve the exact `01-24` privilege manifest digest in `config/lab.phase1.example.yaml` using an authenticated domain-operator identity.
2. Ensure LAB-CLIENT01 has the approved WinFsp 2.1 runtime, current `DlpWindowsService`, `dlp-drive-host.exe`, and one eligible interactive domain-user session.
3. After approval, run `tests/windows/Invoke-ServiceSessionSmoke.ps1 -Scenario SecureSessionHostLifecycle` locally on LAB-CLIENT01 and synchronize sanitized evidence to `hungdinh-lt` for `scripts/verify-phase1-evidence.ps1` validation.

## Verification Performed

- `cargo build --locked --release -p dlp-windows-service -p dlp-windows-drive` succeeded.
- `cargo test --locked -p dlp-windows-service --test session_lifecycle` passed (22 tests).
- `cargo test --locked -p dlp-windows-service pipe::tests` passed (9 tests).
- `cargo test --locked -p dlp-windows-drive --lib` passed.
- `cargo test --locked -p dlp-windows-drive --bin dlp-drive-host drive_letter_selection` passed (3 tests).
- `cargo clippy --locked -p dlp-windows-service -p dlp-windows-drive --all-targets -- -D warnings` passed.

## Next Phase Readiness

- Tasks 1–2 source implementation is complete and committed; Plan 01-16 is unblocked structurally once Task 3 produces LAB-CLIENT01 evidence.
- Plan 01-24 remains `halted` at the Task 3 checkpoint; Plans 01-16 and 01-21 are blocked until this checkpoint resolves and the plan is re-summarized as `complete`.

---
*Phase: 01-first-encrypted-drive-vertical-slice*
*Halted: 2026-08-19 at the Task 3 privilege-manifest checkpoint*
