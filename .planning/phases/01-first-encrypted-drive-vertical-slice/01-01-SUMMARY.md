---
phase: 01-first-encrypted-drive-vertical-slice
plan: "01"
subsystem: portable-contracts
tags: [rust, policy, protocol, ed25519, aes-gcm, encrypted-storage]
requires:
  - "01-03 approved dependency and encrypted-store format decisions"
provides:
  - "Five portable Rust workspace crates with typed, redacted, versioned contracts"
  - "Deterministic policy selection and strict Ed25519 configuration verification"
  - "Captured-identity storage interfaces with no persisted record writer"
affects: [01-02, 01-04, 01-05, 01-06, 01-07, 01-08, 01-09, 01-10, 01-11, 01-12]
tech-stack:
  added: [ed25519-dalek@3.0.0, aes-gcm@0.11.0]
  patterns:
    - "Fixed-field length-delimited canonical configuration bytes"
    - "Strict signature verification before activation callbacks"
    - "Captured SID/store/file identities at storage ports"
key-files:
  created:
    - Cargo.toml
    - rust-toolchain.toml
    - crates/dlp-domain/src/lib.rs
    - crates/dlp-protocol/src/lib.rs
    - crates/dlp-policy/src/lib.rs
    - crates/dlp-crypto/src/lib.rs
    - crates/dlp-storage/src/lib.rs
  modified:
    - Cargo.lock
    - crates/dlp-domain/Cargo.toml
    - crates/dlp-protocol/Cargo.toml
    - crates/dlp-policy/Cargo.toml
    - crates/dlp-crypto/Cargo.toml
    - crates/dlp-storage/Cargo.toml
key-decisions:
  - "Use fixed-field canonical bytes rather than arbitrary map serialization for signed configuration envelopes."
  - "Use ed25519-dalek@3.0.0 verify_strict and reject weak signing keys before configuration activation."
  - "Reserve persisted encrypted-record encoding and durable format writing for 01-04 under dlp-store/aes256gcm-4m/v1."
actuals:
  tokens: 12044
  tasks: 3
  commits: 6
metrics:
  duration: 31m
  completed: 2026-08-08
status: complete
---

# Phase 01 Plan 01: Portable Contracts Summary

**Five portable crates now provide redacted domain values, versioned fixed-field protocol DTOs, deterministic policy decisions, strict signed-configuration verification, and storage durability ports without any persisted record writer.**

## Tasks Completed

1. **Compile one typed domain value through the workspace boundary**
   - Created the Rust 1.97 workspace and portable crate set with unsafe Rust forbidden.
   - Added typed, redacted identifiers, domain errors, and shared policy values plus safety fixtures.
   - Commits: `ebc0396`, `95898cb`.

2. **Versioned protocol and deterministic policy contracts**
   - Added version-rejecting `/api/v1` enrollment, configuration, signed-envelope, and health DTOs.
   - Canonical signing input is fixed-field and length-delimited; the policy evaluator is deterministic across matching, priority, conflict, default, and empty cases.
   - Commits: `09b6ef5`, `c74d36e`.

3. **Strict signing and storage interface contracts without persisted bytes**
   - Added strict Ed25519 verification, key-ID/schema gates, weak-key rejection, and an activation callback that cannot run before verification succeeds.
   - Added the audited AES-256-GCM primitive boundary and captured SID/store/file storage ports for flush, close, integrity, and no-space semantics.
   - Commits: `b03c145`, `08e5294`.

## Approval Amendment

The original 01-03 package approval record remains intact. During Task 3, the user explicitly amended the approved direct dependency allowlist with:

- `ed25519-dalek@3.0.0` — required by the locked plan for `VerifyingKey::verify_strict` configuration-signature verification.
- `aes-gcm@0.11.0` — required by the locked plan for the audited AES-256-GCM primitive boundary.

Only these exact direct versions were added; `Cargo.lock` records their resolved dependency graph. The approved persisted format remains unchanged: `dlp-store/aes256gcm-4m/v1`, with its writer deliberately deferred to 01-04.

## Verification Evidence

- `cargo fmt --check` passed.
- `cargo test --workspace` passed: 15 unit tests, including all named policy and strict-signature negative cases.
- `cargo clippy --workspace --all-targets -- -D warnings` passed.
- `cargo metadata --no-deps --format-version 1` confirmed exactly five portable workspace members.
- `cargo tree --workspace --edges normal` confirmed no Windows or WinFsp runtime dependency.
- Source checks confirmed no production encrypted-record writer, persistence call, or Windows reference in `dlp-crypto` and `dlp-storage`.

## Decisions Made

- Configuration signatures cover only repeatable fixed-field canonical bytes, never arbitrary map ordering.
- Invalid schema, key identifier, key material, signature length, tampering, wrong key, and weak-key inputs fail before activation.
- Storage routing begins only from captured SID/store/file identities; the portable surface contains no Windows types.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Corrected the protocol source-scan test so it excludes its own negative-match literals.**
- **Found during:** Task 2 verification.
- **Issue:** The anti-map test matched the forbidden string inside its own assertion rather than production code.
- **Fix:** Restricted the scan to the pre-test source section.
- **Files modified:** `crates/dlp-protocol/src/lib.rs`.
- **Verification:** Protocol tests and clippy passed after the correction.
- **Commit:** `c74d36e`.

**Total deviations:** 1 auto-fixed (1 test-correctness bug).

## Known Stubs

None. The absence of a persisted encrypted-record writer is intentional and assigned to 01-04 by the approved format decision.

## Self-Check: PASSED

- All declared portable source files exist.
- All six task commits exist in git history.
- Final workspace formatting, tests, linting, membership, dependency, and no-writer checks passed.

