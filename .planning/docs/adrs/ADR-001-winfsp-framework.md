# ADR-001: User-space Windows file-system framework selection

## Status

Proposed

## Context

The MVP requires a per-user protected drive on Windows. The product cannot rely on a custom kernel driver because a code-signing certificate for kernel-mode drivers is not affordable for this project. The drive must:
- Mount as a normal Windows drive or mount point.
- Support common Windows applications (Office, Explorer, file dialogs).
- Run inside a Windows service with minimal user interaction.
- Be replaceable behind a Rust abstraction so the storage and policy layers remain portable.

Candidates considered:
- **WinFsp** — open-source Windows user-mode file system; NTFS-like semantics; Rust bindings (`winfsp-rs`); actively maintained.
- **Dokany** — open-source FUSE-like wrapper; has Rust bindings; less NTFS-native behavior.
- **Microsoft Projected File System (ProjFS)** — built into Windows 10+; no extra install; optimized for projection/materialization, not general read/write file systems.

## Decision

Use **WinFsp** with safe `winfsp`/`winfsp-rs` bindings.

Dokany remains an explicit fallback if the WinFsp prototype exposes compatibility problems with target applications.

## Consequences

- **Positive:** Mature, NTFS-like semantics, good Explorer integration, Windows service hosting supported, safe Rust bindings available, active maintenance.
- **Positive:** Filesystem callbacks can be isolated behind a Rust trait/abstraction, keeping `dlp-windows-drive` replaceable.
- **Negative:** Requires WinFsp runtime installation on endpoints; adds a deployment dependency.
- **Risk:** Compatibility with every target application must be validated by an early spike before building the storage layer around it.

## Validation

Run an early spike covering:
- Office files (Word, Excel) open/save.
- Concurrent access from multiple applications.
- Rename and delete operations.
- Large files (> 100 MB).
- Explorer shell integration.
- Crash recovery during writes.

## References

- WinFsp documentation: https://winfsp.dev/doc/
- Rust bindings: https://docs.rs/winfsp
- Microsoft ProjFS overview: https://learn.microsoft.com/en-us/windows/win32/projfs/provider-overview
