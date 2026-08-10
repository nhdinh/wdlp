---
phase: 01-first-encrypted-drive-vertical-slice
plan: 10
subsystem: windows-drive
tags: [rust, winfsp, encrypted-storage, ntstatus, windows]
requires:
  - phase: 01-04
    provides: authenticated durable encrypted store and bounded VirtualPath
  - phase: 01-09
    provides: recovery and encrypted evidence behavior
provides:
  - Real delay-loaded WinFsp drive mounted over a captured SID/store identity
  - Versioned authenticated encrypted namespace index that survives restart
  - Windows callback handling for files, directories, lifecycle, rename, delete, and stable errors
affects: [01-11, 01-12, windows-service, drive-validation]
actuals:
  tokens: 41529
  tasks: 2
  commits: 8
tech-stack:
  added: [winfsp 0.13.0+winfsp-2.1]
  patterns: [captured-store callback context, authenticated namespace record, explicit NTSTATUS opt-outs]
key-files:
  created: [crates/dlp-windows-drive/src/filesystem.rs, crates/dlp-windows-drive/src/host.rs]
  modified: [crates/dlp-storage/src/store.rs, crates/dlp-windows-drive/tests/mounted_smoke.rs]
key-decisions:
  - "Persist virtual namespace state as a versioned AEAD-protected Manifest record bound to format, store, and generation identity."
  - "Use documented WinFsp safe Rust APIs and delay-load linkage only; keep raw winfsp-sys out of the project."
  - "Publish writes before callback success because the binding close callback cannot return a failure status."
patterns-established:
  - "Filesystem callbacks receive only parsed virtual paths and use the mount-captured identity/store."
  - "Unsupported Windows features return STATUS_NOT_SUPPORTED rather than partially succeeding."
requirements-completed: [WRK-04, DRV-02, DRV-03, DRV-04, DRV-06, DRV-07, TST-08]
coverage:
  - id: D1
    description: "Real SID-bound encrypted WinFsp drive mount, durable roundtrip, corruption denial, and clean unmount."
    requirement: DRV-02
    verification:
      - kind: integration
        ref: "tests/windows/Invoke-WinFspSmoke.ps1 -Extended"
        status: pass
    human_judgment: false
  - id: D2
    description: "Restart-visible encrypted namespace with directory, rename, delete, and callback status contracts."
    requirement: DRV-04
    verification:
      - kind: integration
        ref: "crates/dlp-windows-drive/tests/mounted_smoke.rs#sid_bound_context_mounts_roundtrips_denies_corruption_and_unmounts"
        status: pass
      - kind: unit
        ref: "crates/dlp-windows-drive/tests/callback_contract.rs"
        status: pass
    human_judgment: false
duration: 48min
completed: 2026-08-10
status: complete
---

# Phase 01 Plan 10: WinFsp Callback Adapter Summary

**A real WinFsp DLPDrive now maps captured SID-bound encrypted storage into Windows file, directory, restart, integrity, and lifecycle semantics.**

## Performance

- **Duration:** 48 min
- **Started:** 2026-08-10T06:53:56Z
- **Completed:** 2026-08-10T07:41:42Z
- **Tasks:** 2/2
- **Files modified:** 14

## Accomplishments

- Mounted an actual delay-loaded WinFsp volume and confirmed it appears and disappears in the interactive Windows session.
- Added an authenticated encrypted namespace record with generation/store/format AAD binding; directories, display names, rename, and restart recovery remain off the plaintext backing store.
- Implemented directory enumeration, create/open, overwrite/truncate, rename/replace, cleanup/delete-pending, bounded I/O, explicit flush, and stable NTSTATUS error handling.
- Extended the real smoke through concurrent handles, directory enumeration, rename-and-append, deletion, remount/restart visibility, plaintext scan, and corruption denial.

## Task Commits

1. **Task 1: Real WinFsp host mounts one SID-bound encrypted file path** - `d1cd0d0`, `97d3d3d`, `3ab530e`, `0c10df6` (test/feat/fix)
2. **Task 2: Complete Windows callback semantics and status mapping** - `89d3aae`, `0907af7`, `9af5123`, `dc5db3e` (test/feat)

## Files Created/Modified

- `crates/dlp-storage/src/path.rs` - internal root path representation without accepting empty caller paths.
- `crates/dlp-storage/src/store.rs` - encrypted namespace persistence, directory mutation, restart handle semantics, and rollback-safe index publication.
- `crates/dlp-windows-drive/src/filesystem.rs` - complete safe WinFsp callback adapter over the captured encrypted store.
- `crates/dlp-windows-drive/src/status.rs` - deterministic unsupported-feature status.
- `crates/dlp-windows-drive/tests/{callback_contract,mounted_smoke}.rs` - callback and real-mount coverage.
- `tests/windows/Invoke-WinFspSmoke.ps1` - extended runtime smoke entrypoint.

## Decisions Made

- Stored namespace metadata only inside the v1 AEAD envelope using the existing Manifest record kind and the reserved opaque `namespace-index` file identity, preserving compatibility with the existing encrypted record parser.
- Kept close error-free at the WinFsp binding boundary by publishing each successful write/truncate/overwrite before return and making a later flush idempotent.
- Used direct bounded `DirInfo` output instead of keeping a WinFsp directory buffer across host shutdown; this avoids a shutdown hang while retaining deterministic enumeration.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Corrected append-at-EOF and idempotent flush behavior**
- **Found during:** Task 2
- **Issue:** Windows append supplies a write-to-EOF request and a second flush can occur after durable publication.
- **Fix:** Resolve the append offset from the authenticated handle data and treat an already-flushed handle as a successful flush.
- **Files modified:** `crates/dlp-windows-drive/src/filesystem.rs`, `crates/dlp-storage/src/store.rs`
- **Verification:** Extended real mount smoke passes.
- **Committed in:** `dc5db3e`

**2. [Rule 1 - Bug] Replaced retained directory buffer enumeration with bounded direct entries**
- **Found during:** Task 2
- **Issue:** retaining the WinFsp directory buffer across teardown caused the smoke process to hang during host shutdown.
- **Fix:** Serialize bounded `DirInfo` entries directly into the callback buffer and honor the enumeration marker.
- **Files modified:** `crates/dlp-windows-drive/src/filesystem.rs`
- **Verification:** repeated real mount/unmount smoke passes cleanly.
- **Committed in:** `dc5db3e`

### Approved Architectural Deviation

- The user approved `approve-storage-index`: a narrow v1 encrypted namespace/index persistence seam was added because restart-visible directories, rename, delete-pending, and enumeration cannot be truthfully supplied by an in-memory namespace. The index is authenticated, versioned, rollback-safe in memory on publication failure, and stores no plaintext virtual metadata on disk.

**Total deviations:** 2 auto-fixed bugs and 1 approved storage-contract extension.

## Issues Encountered

- The callback-only contract test emits the linker’s harmless delay-load warning because it does not instantiate a WinFsp host; the real mounted smoke links and passes against the installed runtime.
- Official LLVM was required for the binding’s build-time bindgen support and was installed by the user with a process-scoped `LIBCLANG_PATH`; no global environment setting was changed.

## Known Stubs

None.

## Next Phase Readiness

- The service/session lifecycle work can now own a real, restart-visible encrypted drive.
- Phase 01-12 can use the extended smoke as the base for the exhaustive application, fault, and size matrix.

## Self-Check: PASSED

- Verified the Task 1 and Task 2 commits exist and the real extended mount smoke completed after the final Task 2 commit.
- Verified every committed adapter and storage file listed above exists.

---
*Phase: 01-first-encrypted-drive-vertical-slice*
*Completed: 2026-08-10*
