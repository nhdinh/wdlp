# Plan 01-24 Summary: Secure Session-Host Lifecycle

## Goal

Prove that `DlpWindowsService` (running as `LocalSystem`) can securely launch `dlp-drive-host.exe` in the user's interactive Windows session via `CreateProcessAsUserW`, authenticate the host through a service-owned named pipe, mount a real encrypted WinFsp drive, and recover cleanly from service restart and host termination without leaking plaintext or leaving orphaned drives.

## What Changed

| File | Change |
|------|--------|
| `crates/dlp-windows-service/src/session.rs` | Added host STDERR/STDOUT redirection, `HostProcessHandle::wait_for_exit`, and `SessionMonitor::stop_all` drain logic that closes pipes and waits up to 10s for host exit. |
| `crates/dlp-windows-service/src/pipe.rs` | Production named-pipe implementation with user-only DACL, kernel PID check, impersonation/SID/session verification, handle transfer to `AuthenticatedPipe`, and empty-`user_sid` allowance. Debug instrumentation removed. |
| `crates/dlp-windows-drive/src/bin/dlp-drive-host.rs` | Clean rewrite: parses service-supplied args, authenticates over pipe, decodes JSON acceptance response, sets `SetDllDirectoryW` for WinFsp DLL discovery, selects a free drive letter, mounts, reports letter, and runs a pipe-reading control loop that exits on EOF (clean unmount). |
| `crates/dlp-windows-drive/src/host.rs` | Removed temporary `host_debug` logging; kept safe WinFsp mount lifecycle. |
| `crates/dlp-windows-drive/Cargo.toml` | Added `Win32_System_LibraryLoader` feature for `SetDllDirectoryW`. |
| `tests/windows/Invoke-ServiceSessionSmoke.ps1` | Added `SecureSessionHostLifecycle` scenario with `Baseline`, `RecoveryControl`, and `RecoveryVerify` phases; asserts exactly one preferred drive after recovery. |

## Root Causes Fixed

1. **Host silent exit after auth request**: host expected bare `bool`; service sends `{"accepted":true,"code":"ok"}` → fixed JSON decode.
2. **Host died at `winfsp_init`**: `winfsp-x64.dll` not on PATH → fixed with `SetDllDirectoryW`.
3. **Orphan drives after recovery**: control loop did not read pipe; force-killed host could not unmount → fixed pipe-reading loop and RecoveryControl sequencing.
4. **Double drives P:/Q:**: stale drive letter not reclaimed after host kill → `fsptool-x64.exe unmount` added to RecoveryControl.

## Verification

- `cargo test -p dlp-windows-drive -p dlp-windows-service --lib` — 26 passed.
- Interactive smoke-test phases executed on `LAB-CLIENT01`:
  - **Baseline** (non-elevated): service running, host in interactive session, `P:` visible, encrypted roundtrip.
  - **RecoveryControl** (elevated): graceful service stop/start, force-kill host, `fsptool` reclaim, service restart, `P:` returns.
  - **RecoveryVerify** (non-elevated): roundtrip after recovery, baseline hash preserved, exactly one `P:` drive.
- Requirement `AGT-07` (restart-runtime) marked `pass` in `evidence/phase1/requirement-matrix.yaml`.

## Evidence

- Evidence artifact: `evidence/phase1/attempts/secure-session-host-lifecycle-c618578c-da4c-43c6-9049-46aeffab165b.json`
- Binary hashes at verification time:
  - `dlp-windows-service.exe`: `6bc95f77e07ceba8259091ddc9d55bbf8361e5aa5ace85df3bd06559ae3da3b5`
  - `dlp-drive-host.exe`: `1788607a1525ddd65da40f83e747b43e3881ba5e9c855beba56f27be3f0365dd`

## Constraints Preserved

- Normal/domain users cannot start/stop `DlpWindowsService`; only elevated administrators can.
- No secrets appear on the `dlp-drive-host.exe` command line.
- Backing store and diagnostic logs contain no plaintext marker.

## Next

Phase 01 is now complete for the secure session-host lifecycle. Continue with Plan 01-16 production-provider encrypted-drive vertical slice pending operator go-ahead.
