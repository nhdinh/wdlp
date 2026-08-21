---
phase: 01-first-encrypted-drive-vertical-slice
plan: 26
subsystem: storage

tags:
  - rust
  - winfsp
  - encrypted-storage
  - filetime
  - wildcard
  - change-notifications

requires:
  - phase: 01-first-encrypted-drive-vertical-slice
    provides: WinFsp per-user drive mount, encrypted store, SC-04 gap identified

provides:
  - EntryMetadata FILETIME timestamps persisted in encrypted namespace v2
  - Backward-compatible dlp-namespace/v1 loader with current-time fallback
  - WinFsp FileInfo timestamp population for files and directories
  - Case-insensitive Windows wildcard matching for directory enumeration
  - WinFsp directory-change notifications on create/delete/write/rename
  - SC-04 re-verification pass on LAB-CLIENT01

affects:
  - 01-first-encrypted-drive-vertical-slice
  - dlp-storage
  - dlp-windows-drive

actuals:
  tokens: 32852
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Versioned encrypted namespace format (v2) with v1 fallback loader"
    - "Portable EntryMetadata API consumed by platform-specific WinFsp adapter"
    - "Mutex-backed pending notification queue for NotifyingFileSystemContext"

key-files:
  created:
    - crates/dlp-windows-drive/src/wildmatch.rs
  modified:
    - crates/dlp-storage/src/store.rs
    - crates/dlp-storage/src/lib.rs
    - crates/dlp-storage/src/path.rs
    - crates/dlp-storage/tests/operations.rs
    - crates/dlp-windows-drive/src/filesystem.rs
    - crates/dlp-windows-drive/src/status.rs
    - crates/dlp-windows-drive/src/host.rs
    - crates/dlp-windows-drive/src/lib.rs
    - crates/dlp-windows-drive/src/bin/dlp-drive-host.rs
    - crates/dlp-windows-drive/tests/callback_contract.rs
    - .planning/phases/01-first-encrypted-drive-vertical-slice/01-UAT.md

key-decisions:
  - "Kept namespace v1 records loadable by converting missing timestamps to current FILETIME, preserving existing lab/test stores."
  - "Implemented wildcard matcher locally instead of adding a new Cargo dependency, matching Windows FindFirstFile semantics with * and ?."
  - "Used winfsp's default feature set which already includes notify; no Cargo.toml change was required."
  - "Queued notifications in a Mutex<Vec<NotifyInfo<255>>> because FileSystemContext callbacks use shared &self."

patterns-established:
  - "FileInfo timestamps are always sourced from EntryMetadata rather than left zero."
  - "Directory enumeration filters against the caller-supplied pattern using a bounded, non-recursive matcher."
  - "Mutating WinFsp callbacks emit a notification after the storage operation succeeds."

requirements-completed:
  - DRV-02
  - DRV-03
  - DRV-06
  - DRV-09
  - TST-08

coverage:
  - id: D1
    description: "Encrypted store exposes EntryMetadata FILETIME timestamps and persists them in namespace v2"
    requirement: DRV-02
    verification:
      - kind: unit
        ref: "cargo test --locked -p dlp-storage (store::timestamp_tests)"
        status: pass
      - kind: unit
        ref: "cargo clippy --locked -p dlp-storage --all-targets -- -D warnings"
        status: pass
    human_judgment: false

  - id: D2
    description: "WinFsp adapter populates FileInfo creation/access/write/change timestamps for files and directories"
    requirement: DRV-03
    verification:
      - kind: unit
        ref: "cargo test --locked -p dlp-windows-drive"
        status: pass
      - kind: unit
        ref: "crates/dlp-windows-drive/tests/callback_contract.rs#callback_adapter_declares_every_phase_one_operation_or_explicit_opt_out"
        status: pass
    human_judgment: false

  - id: D3
    description: "Directory enumeration accepts and filters Windows wildcard patterns instead of rejecting non-* queries"
    requirement: DRV-06
    verification:
      - kind: unit
        ref: "crates/dlp-windows-drive/src/wildmatch.rs#wildmatch tests"
        status: pass
      - kind: unit
        ref: "crates/dlp-windows-drive/tests/callback_contract.rs#callback_adapter_declares_every_phase_one_operation_or_explicit_opt_out"
        status: pass
    human_judgment: false

  - id: D4
    description: "WinFsp change notifications are emitted after create/delete/write/rename so Explorer auto-refreshes"
    requirement: DRV-09
    verification:
      - kind: unit
        ref: "crates/dlp-windows-drive/tests/callback_contract.rs#callback_adapter_declares_every_phase_one_operation_or_explicit_opt_out"
        status: pass
      - kind: e2e
        ref: "tests/windows/Invoke-Phase1Matrix.ps1 -Scenario VerticalSlice (exit 0)"
        status: pass
    human_judgment: false

  - id: D5
    description: "SC-04 UAT passes on LAB-CLIENT01 after gap-closure deployment"
    requirement: TST-08
    verification:
      - kind: e2e
        ref: "tests/windows/Invoke-Phase1Matrix.ps1 -Scenario VerticalSlice (exit 0)"
        status: pass
    human_judgment: false

duration: 35min
completed: 2026-08-21
status: complete
---

# Phase 01 Plan 26: SC-04 WinFsp Directory Metadata Gap-Closure Summary

**Closed the SC-04 WinFsp metadata gap by adding persisted FILETIME timestamps, Windows wildcard directory enumeration, and change notifications, then re-verified the fix on LAB-CLIENT01.**

## Performance

- **Duration:** 35 min
- **Started:** 2026-08-21T21:05:00Z
- **Completed:** 2026-08-21T21:40:58Z
- **Tasks:** 3
- **Files modified:** 12

## Accomplishments
- Added `EntryMetadata` to `dlp-storage` with FILETIME creation/access/write/change times and bumped the encrypted namespace to `dlp-namespace/v2` while keeping a `v1` fallback loader.
- Populated `FileInfo` timestamps in `DlpFileSystemContext::file_info_for` and `file_info_for_handle` so Explorer/PowerShell no longer show 1600 dates.
- Implemented a private `wildmatch` module with case-insensitive `*`/`?` matching and integrated it into `read_directory`, removing the early `STATUS_NOT_SUPPORTED` rejection for non-`*` patterns.
- Implemented `NotifyingFileSystemContext` for `DlpFileSystemContext` with a `Mutex<Vec<NotifyInfo<255>>>` queue and emitted notifications from create, cleanup-delete, write, flush, overwrite, set_file_size, and rename callbacks.
- Re-ran `tests/windows/Invoke-Phase1Matrix.ps1 -Scenario VerticalSlice` from `hungdinh-lt` against LAB-DC01/LAB-DC02/LAB-CLIENT01; it exited 0 and updated `01-UAT.md` to mark SC-04 as pass and unblock D-26/D-38 and D-48.

## Task Commits

Each task was committed atomically:

1. **Task 1: Tracer — expose entry timestamps and populate WinFsp FileInfo** - `84f326d` (feat)
2. **Task 2: Implement wildcard pattern matching and WinFsp change notifications** - `3006f02` (feat)
3. **Task 3: Re-verify SC-04 on LAB-CLIENT01 and unblock visual checklist** - `42719d7` (docs)

## Files Created/Modified
- `crates/dlp-storage/src/store.rs` - `EntryMetadata`, namespace v2 persistence, v1 fallback, timestamp updates on create/read/write/rename/delete.
- `crates/dlp-storage/src/lib.rs` - Re-export `EntryMetadata`.
- `crates/dlp-storage/src/path.rs` - Added `display_path()` helper for original-cased relative paths.
- `crates/dlp-storage/tests/operations.rs` - Mutable binding for `restarted` store.
- `crates/dlp-windows-drive/src/filesystem.rs` - Timestamp population, wildcard filtering, notification queue and helper, `NotifyingFileSystemContext` impl.
- `crates/dlp-windows-drive/src/status.rs` - `FILE_NOTIFY_*` and `FILE_ACTION_*` constants.
- `crates/dlp-windows-drive/src/host.rs` - Switched to `FileSystemHost::new_with_timer`.
- `crates/dlp-windows-drive/src/lib.rs` - Declared `wildmatch` module.
- `crates/dlp-windows-drive/src/wildmatch.rs` - New private wildcard matcher with unit tests.
- `crates/dlp-windows-drive/src/bin/dlp-drive-host.rs` - Fixed pre-existing redundant-pattern-matching clippy lint.
- `crates/dlp-windows-drive/tests/callback_contract.rs` - Added source assertions for notifications, wildcard matching, and timestamp population.
- `.planning/phases/01-first-encrypted-drive-vertical-slice/01-UAT.md` - SC-04 pass, phase-exit gates unblocked.

## Decisions Made
- Followed the plan's FILETIME computation exactly (`11644473600_u64 * 10000000` offset from Unix epoch in 100-ns units).
- Kept namespace v1 loadable by converting missing timestamps to current FILETIME, avoiding data loss for existing lab/test stores.
- Implemented the wildcard matcher inside the crate rather than adding a dependency, satisfying the "no new top-level Cargo dependency" constraint.
- Did not modify `crates/dlp-windows-drive/Cargo.toml` because the `winfsp` default feature set already includes the `notify` feature.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Added `VirtualPath::display_path()` helper for volume-relative notification names and child-path construction**
- **Found during:** Task 2 (WinFsp wildcard and notification implementation)
- **Issue:** `NotifyingFileSystemContext` needs the original-cased, backslash-separated relative path for `NotifyInfo` names, and `read_directory` child construction needed display-cased components rather than lowercase lookup keys. The plan did not list this helper.
- **Fix:** Added `pub fn display_path(&self) -> String` to `dlp-storage/src/path.rs` and used it in `notify_path` and `read_directory`.
- **Files modified:** `crates/dlp-storage/src/path.rs`, `crates/dlp-windows-drive/src/filesystem.rs`
- **Verification:** `cargo test --locked -p dlp-windows-drive` passes; `cargo clippy` clean.
- **Committed in:** `3006f02` (Task 2 commit)

**2. [Rule 2 - Missing Critical] Added extra storage timestamp tests beyond the plan's minimum**
- **Found during:** Task 1 (timestamp API)
- **Issue:** The plan required only tests for non-zero timestamps after create and survival after reopen. To satisfy correctness and the namespace v1 truth, additional tests were needed for directories, write-time updates, and v1 fallback.
- **Fix:** Added `entry_metadata_returns_nonzero_timestamps_after_create_directory`, `write_updates_last_write_and_change_time`, and `v1_namespace_loads_with_current_filetime_fallback`.
- **Files modified:** `crates/dlp-storage/src/store.rs`
- **Verification:** `cargo test --locked -p dlp-storage` passes.
- **Committed in:** `84f326d` (Task 1 commit)

**3. [Rule 3 - Blocking] Fixed pre-existing clippy lint in `dlp-drive-host.rs`**
- **Found during:** Task 2 verification (`cargo clippy --locked -p dlp-windows-drive --all-targets -- -D warnings`)
- **Issue:** `crates/dlp-windows-drive/src/bin/dlp-drive-host.rs:341` failed `clippy::redundant_pattern_matching`, blocking crate-wide clippy with `-D warnings`.
- **Fix:** Replaced `if let Err(_) = pipe_file.read_exact(...)` with `if pipe_file.read_exact(...).is_err()`.
- **Files modified:** `crates/dlp-windows-drive/src/bin/dlp-drive-host.rs`
- **Verification:** `cargo clippy --locked -p dlp-windows-drive --all-targets -- -D warnings` passes.
- **Committed in:** `3006f02` (Task 2 commit)

---

**Total deviations:** 3 auto-fixed (2 missing critical, 1 blocking)
**Impact on plan:** All auto-fixes were necessary for correctness, testability, or verification. No scope creep.

## Issues Encountered
- Initial lab harness run failed with `Error: MissingProvider { provider: "directory_verifier" }` because `DLP_AD_DOMAIN` was not set in the orchestrator environment. Re-running with `DLP_AD_DOMAIN=lab.local` allowed the server to start and the harness completed with exit code 0. This matches the observation already recorded in `01-UAT.md` for SC-02.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- SC-04 is now passing; D-26/D-38 visual checklist and D-48 independent review are unblocked and ready for attestation.
- No code blockers remain for Phase 1 exit.

## Self-Check: PASSED
- `01-26-SUMMARY.md` exists at `.planning/phases/01-first-encrypted-drive-vertical-slice/01-26-SUMMARY.md`.
- Task commits verified in git log: `84f326d`, `3006f02`, `42719d7`.

---
*Phase: 01-first-encrypted-drive-vertical-slice*
*Completed: 2026-08-21*
