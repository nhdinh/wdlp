# ADR-010: Supported Windows versions and file-system semantics

## Status

Proposed

## Context

The MVP must target realistic Windows versions and support common file-system operations so that standard applications can use the protected drive.

## Decision

Support **Windows 10 version 1809 and later**, and **Windows 11**, 64-bit only.

The WinFsp drive must implement the file-system semantics expected by common Windows applications:
- File creation, opening, reading, writing, truncation, renaming, deletion.
- Directory enumeration and creation.
- File metadata (timestamps, attributes, streams where needed).
- Opportunistic locks and caching behavior sufficient for Office applications.
- Case-preserving but case-insensitive names (NTFS-like).

## Consequences

- **Positive:** Covers the vast majority of enterprise endpoints.
- **Positive:** WinFsp provides most required semantics through its host interface.
- **Negative:** Windows 7/8 and 32-bit systems are excluded.
- **Risk:** Some applications may rely on specific NTFS behaviors not perfectly emulated by WinFsp; the early spike must validate them.

## References

- PROJECT.md non-goals (no non-Windows support)
- ADR-001: User-space Windows file-system framework selection
