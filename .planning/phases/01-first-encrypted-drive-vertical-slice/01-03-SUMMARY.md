---
phase: 01-first-encrypted-drive-vertical-slice
plan: "03"
subsystem: security-governance
tags: [supply-chain, cryptography, encrypted-store, approval-gate]
requires: []
provides:
  - "Exact human-approved Cargo dependency allowlist for downstream manifests and lockfiles"
  - "Approved dlp-store/aes256gcm-4m/v1 persisted encrypted-store contract for downstream readers and writers"
affects: [01-01, 01-02, 01-04, 01-05, 01-06, 01-07, 01-08, 01-09, 01-10, 01-11, 01-12]
tech-stack:
  added: []
  patterns:
    - "Blocking human provenance approval before a gated Cargo dependency is installed"
    - "Versioned persisted-format approval before an encrypted store writes bytes"
key-files:
  created:
    - .planning/phases/01-first-encrypted-drive-vertical-slice/01-03-SUMMARY.md
  modified: []
key-decisions:
  - "Approved the exact Phase 1 dependency allowlist at the blocking human checkpoint."
  - "Approved dlp-store/aes256gcm-4m/v1: AES-256-GCM records with 4 MiB chunks and versioned migration boundaries."
patterns-established:
  - "Downstream manifests and lockfiles may use only the exact approved package/version pairs recorded below."
requirements-completed: [WRK-04, CRY-01, TST-03, TST-08]
coverage: []
duration: in-progress
completed: null
status: in_progress
---

# Phase 01 Plan 03: Approval Gates Summary

**Exact package provenance approval now gates every downstream Cargo install and lockfile change.**

## Task 1: Approved Package Allowlist

**Decision:** approved. The human completed the blocking `approved:` checkpoint with the exact versions below. No alternative package, version, Cargo manifest, lockfile, source file, or install state was selected or changed.

All rows retain the evidence reviewed at the checkpoint: the official registry record and linked repository, publisher continuity, license, release/yank status, dependency graph, build script, and native payload. `winfsp` additionally retained its required crate, source repository, docs.rs ownership/source, and `0.13.0+winfsp-2.1` runtime-relationship review.

| Package | Approved version | Registry | Repository | Reviewer-provided evidence | Approved at |
| --- | --- | --- | --- | --- | --- |
| winfsp | 0.13.0+winfsp-2.1 | https://crates.io/crates/winfsp/0.13.0+winfsp-2.1 | https://github.com/SnowflakePowered/winfsp-rs | Human `approved:` signal after the required provenance and WinFsp runtime review. | 2026-08-08T08:38:19Z |
| ldap3 | 0.11.5 | https://crates.io/crates/ldap3/0.11.5 | https://github.com/ildoc/ldap3 | Human `approved:` signal after the required provenance review. | 2026-08-08T08:38:19Z |
| rcgen | 0.14.8 | https://crates.io/crates/rcgen/0.14.8 | https://github.com/rustls/rcgen | Human `approved:` signal after the required provenance review. | 2026-08-08T08:38:19Z |
| windows | 0.62.2 | https://crates.io/crates/windows/0.62.2 | https://github.com/microsoft/windows-rs | Human `approved:` signal after the required provenance review. | 2026-08-08T08:38:19Z |
| sha2 | 0.11.0 | https://crates.io/crates/sha2/0.11.0 | https://github.com/RustCrypto/hashes | Human `approved:` signal after the required provenance review. | 2026-08-08T08:38:19Z |
| secrecy | 0.10.3 | https://crates.io/crates/secrecy/0.10.3 | https://github.com/iqlusioninc/crates | Human `approved:` signal after the required provenance review. | 2026-08-08T08:38:19Z |
| zeroize | 1.9.0 | https://crates.io/crates/zeroize/1.9.0 | https://github.com/iqlusioninc/crates | Human `approved:` signal after the required provenance review. | 2026-08-08T08:38:19Z |
| reqwest | 0.13.4 | https://crates.io/crates/reqwest/0.13.4 | https://github.com/seanmonstar/reqwest | Human `approved:` signal after the required provenance review. | 2026-08-08T08:38:19Z |
| uuid | 1.24.0 | https://crates.io/crates/uuid/1.24.0 | https://github.com/uuid-rs/uuid | Human `approved:` signal after the required provenance review. | 2026-08-08T08:38:19Z |
| thiserror | 2.0.19 | https://crates.io/crates/thiserror/2.0.19 | https://github.com/dtolnay/thiserror | Human `approved:` signal after the required provenance review. | 2026-08-08T08:38:19Z |
| tracing | 0.1.44 | https://crates.io/crates/tracing/0.1.44 | https://github.com/tokio-rs/tracing | Human `approved:` signal after the required provenance review. | 2026-08-08T08:38:19Z |
| tracing-subscriber | 0.3.23 | https://crates.io/crates/tracing-subscriber/0.3.23 | https://github.com/tokio-rs/tracing | Human `approved:` signal after the required provenance review. | 2026-08-08T08:38:19Z |
| tempfile | 3.27.0 | https://crates.io/crates/tempfile/3.27.0 | https://github.com/Stebalien/tempfile | Human `approved:` signal after the required provenance review. | 2026-08-08T08:38:19Z |
| wiremock | 0.6.5 | https://crates.io/crates/wiremock/0.6.5 | https://github.com/LukeMathWalker/wiremock-rs | Human `approved:` signal after the required provenance review. | 2026-08-08T08:38:19Z |

## Task 2: Approved Persisted Encrypted-Store Format

**Decision signal:** `approve-aes-4m`  
**Approved format ID:** `dlp-store/aes256gcm-4m/v1`

The human selected the recommended Phase 1 on-disk contract before any writer or test fixture produces persisted encrypted user data. It satisfies the selected durability and integrity decisions: successful flush/close follows a durable encrypted commit; interruption preserves the last committed generation; authentication failures return no plaintext; and a failed write leaves the prior committed version intact.

| Contract area | Approved v1 requirement |
| --- | --- |
| Cipher | AES-256-GCM for file contents and sensitive metadata. |
| Logical chunking | 4 MiB logical chunks; the boundary corpus includes 4 MiB - 1, 4 MiB, and 4 MiB + 1, plus the broader D-18 size range. |
| Nonces | Generate a random 96-bit nonce from the OS CSPRNG for every encrypted record, persist it with that record, and fail staging on a duplicate nonce in a generation. |
| AAD | Bind immutable identity fields before decryption: format ID/version, store ID, file ID, generation, record kind, chunk index, and plaintext length. |
| Write layout | Stage each replacement in a new unreferenced generation; write and flush encrypted chunk records and an encrypted manifest before publication. |
| Commit | Write and flush an authenticated commit record, atomically replace the selected-commit pointer, and flush the parent directory before reporting success. |
| Recovery | Trust only the last valid authenticated commit/pointer and discard unreferenced incomplete staging later; never expose a mixed or unauthenticated version. |
| Migration consequence | Any cipher, chunk size, record/AAD identity, manifest, commit, pointer, or layout change after v1 stores exist requires an explicit, tested versioned migration. A new writer/reader must not reinterpret existing v1 bytes in place. |

**Authorized downstream use:** 01-04 may implement this exact versioned writer/reader contract. Every later store producer or consumer must retain the format ID and migration boundary; no format variation is authorized by this approval.

## Verification Evidence

- Task 1 allowlist verification passed: all fourteen named package records and official crates.io URLs are present.
- Task 2 decision verification is ready to pass when the approved-format record contains `dlp-store/aes256gcm-4m/v1`, `96-bit`, `4 MiB`, and `migration`, while omitting an alternate decision signal.
- Repository check before the approvals found no `Cargo.toml`, `Cargo.lock`, encrypted-store data, production files, or test store bytes. The plan changed only this approval record.
