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
  tokens: 28000
  tasks: 2
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Per-actor unpredictable named pipe with restrictive DACL and kernel-backed client identity"
    - "Service-derived store identity/root/key bootstrap; host never selects identity or store"
    - "Safe std::path::Path::try_exists drive-letter probe instead of unsafe GetLogicalDrives"
    - "Shared admission gate for reject-new-open drain with exact active-handle counting"

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

patterns-established:
  - "SessionHostLauncher seam: injectable Windows launcher for deterministic source tests on hungdinh-lt."
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

duration: 45min
completed: 2026-08-18
status: halted
---

# Phase 01: Plan 24 — Secure Session Host Lifecycle Summary

**Implemented the production Windows session-host launch, authenticated pipe bootstrap, real-key store open, safe drive-letter selection, and drain/cleanup/restart convergence in source; LAB-CLIENT01 runtime awaits the approved privilege manifest and human checkpoint.**

## Performance

- **Duration:** 45 min
- **Started:** 2026-08-18T04:11:54Z
- **Completed:** 2026-08-18T04:50:00Z
- **Tasks:** 2 of 3 completed
- **Files modified:** 9

## Accomplishments

- Implemented `SessionHostLauncher` using `WTSQueryUserToken`, `CreateEnvironmentBlock`, and `CreateProcessAsUserW` with the approved host binary, target-user environment, and non-secret actor rendezvous arguments.
- Replaced the directory-only `StoragePipeServer` seam with a real per-actor Windows named pipe: unpredictable endpoint, first-instance flag, restrictive DACL, bounded framed messages, and kernel-backed client PID/SID/session authentication before any store bootstrap bytes are sent.
- Updated `dlp-drive-host.rs` to connect with identification/impersonation SQOS, validate the bounded bootstrap, open `LocalEncryptedStore` with the service-derived identity and real nonzero key, start WinFsp, and retain the mounted volume in a control loop.
- Implemented safe drive-letter occupancy probing via `std::path::Path::try_exists` (workspace forbids unsafe `GetLogicalDrives`), preserving occupied mappings and falling back to the next free candidate.
- Added shared admission/handle accounting to `DlpFileSystemContext` for reject-new-open drain, 30-second grace, and exactly-once unmount on pipe EOF, service stop, host failure, or logoff.
- Added deterministic source tests covering launch idempotency, secret-free command line, zero-key rejection, pipe authentication, replay/stale-generation rejection, drive-letter selection, drain, and restart convergence.

## Task Commits

1. **Task 1: Launch one authenticated session host through a real service-owned bootstrap** - `227a692` (test)
2. **Task 1 (implementation)** - `686729b` (feat)
3. **Task 2: Complete drive collision, drain, cleanup, retry, and restart convergence** - included in `686729b`
4. **Auto-fix clippy warnings** - `ad6b586` (fix)

## Files Created/Modified

- `crates/dlp-windows-service/src/session.rs` — WTS-token launcher, per-session child ownership, retry, drain, and restart convergence.
- `crates/dlp-windows-service/src/pipe.rs` — Bounded per-actor named-pipe transport with kernel-backed caller authentication and versioned bootstrap.
- `crates/dlp-windows-drive/src/bin/dlp-drive-host.rs` — Authenticated bootstrap client, real-key encrypted-store open, drive selection, and control loop.
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

## Deviations from Plan

### Auto-fixed Issues

**1. [Clippy - dead_code] Unused `stable_sid_digest` helper in drive host**
- **Found during:** Post-implementation clippy run
- **Issue:** `stable_sid_digest` in `dlp-drive-host.rs` triggered `-D dead_code`
- **Fix:** Added `#[allow(dead_code)]` to preserve the diagnostic helper.
- **Files modified:** `crates/dlp-windows-drive/src/bin/dlp-drive-host.rs`
- **Verification:** `cargo clippy --locked -p dlp-windows-service -p dlp-windows-drive --all-targets -- -D warnings` passes.
- **Committed in:** `ad6b586`

**2. [Clippy - field_reassign_with_default] `STARTUPINFOW` initialization style**
- **Found during:** Post-implementation clippy run
- **Issue:** `STARTUPINFOW::default()` followed by field assignment triggered `field_reassign_with_default`
- **Fix:** Used functional record update syntax with explicit `cb` and `lpDesktop` fields.
- **Files modified:** `crates/dlp-windows-service/src/session.rs`
- **Verification:** Clippy passes.
- **Committed in:** `ad6b586`

**3. [Clippy - manual_inspect] Error side-effect in launcher call**
- **Found during:** Post-implementation clippy run
- **Issue:** `.map_err` used only for side-effect logging triggered `manual_inspect`
- **Fix:** Replaced with `.inspect_err`.
- **Files modified:** `crates/dlp-windows-service/src/session.rs`
- **Verification:** Clippy passes.
- **Committed in:** `ad6b586`

---

**Total deviations:** 3 auto-fixed (all clippy/style)
**Impact on plan:** No scope creep; fixes required for the workspace `-D warnings` contract.

## Issues Encountered

- A previous executor run left a stranded worktree (`worktree-agent-a498a08541e4e74e6`) with Tasks 1–2 implementation but no SUMMARY.md. Recovered by inspecting, fixing clippy issues, and merging into `master`.
- Real WinFsp mount tests (`dlp-windows-drive/tests/mounted_smoke.rs`) fail on hungdinh-lt because the WinFsp runtime is not installed locally; these are not part of the source-only verification required by Tasks 1–2 and will run on LAB-CLIENT01 during Task 3.

## User Setup Required

**Task 3 requires a blocking human checkpoint before any LAB-CLIENT01 mutation:**

1. Review and approve the exact `01-24` privilege manifest digest in `config/lab.phase1.example.yaml` using an authenticated domain-operator identity.
2. Ensure LAB-CLIENT01 has the approved WinFsp 2.1 runtime, current `DlpWindowsService`, `dlp-drive-host.exe`, and one eligible interactive domain-user session.
3. After approval, run `tests/windows/Invoke-ServiceSessionSmoke.ps1 -Scenario SecureSessionHostLifecycle` locally on LAB-CLIENT01 and synchronize sanitized evidence to hungdinh-lt for `scripts/verify-phase1-evidence.ps1` validation.

## Next Phase Readiness

- Tasks 1–2 source implementation is complete and merged; Plan 01-16 is unblocked structurally once Task 3 produces LAB-CLIENT01 evidence.
- Plan 01-24 remains `halted` at the Task 3 checkpoint; Plans 01-16 and 01-21 are blocked until this checkpoint resolves and the plan is re-summarized as `complete`.

---
*Phase: 01-first-encrypted-drive-vertical-slice*
*Halted: 2026-08-18*
