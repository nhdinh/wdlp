---
phase: 01-first-encrypted-drive-vertical-slice
plan: "05"
subsystem: portable-walking-skeleton
tags: [rust, sqlite, axum, signed-configuration, encrypted-store, tracer]
requires:
  - "01-02 server composition and migration ledger"
  - "01-04 durable encrypted-store implementation"
provides:
  - "Development-only phase1-smoke command crossing a bound versioned router, SQLite ledger, signed activation, and encrypted-store readback"
  - "Replay, token-race, activation-race, AEAD-tamper, nonce-duplication, and plaintext-marker evidence"
affects: [01-06, 01-07, 01-08, 01-09, 01-10, 01-12]
tech-stack:
  added: []
  patterns:
    - "SQLite is a local, ignored verification substitute only; production server composition remains PostgreSQL."
    - "Configuration activation verifies strict Ed25519 bytes before monotonically increasing current/LKG selection."
key-files:
  created:
    - crates/dlpctl/src/lib.rs
    - tests/e2e/walking_skeleton.rs
  modified:
    - Cargo.lock
    - crates/dlp-protocol/src/lib.rs
    - crates/dlp-agent-core/src/lib.rs
    - crates/dlp-server/src/lib.rs
    - crates/dlpctl/Cargo.toml
    - crates/dlpctl/src/main.rs
key-decisions:
  - "Use the user-authorized ignored SQLite database only for 01-05 tracer evidence; PostgreSQL evidence remains open."
  - "Reject non-numeric, replayed, or lower signed-bundle versions before changing current/LKG."
metrics:
  duration: 10m
  completed: 2026-08-08
actuals:
  tokens: 7583
  tasks: 2
  commits: 4
status: complete
---

# Phase 01 Plan 05: Production-Quality Tracer Summary

**A runnable development tracer now binds the versioned router, proves SQLite ledger/token state, strictly activates Ed25519 bundles, commits encrypted content, survives encrypted-store reopen, and rejects plaintext marker leakage.**

## Accomplishments

- Added `dlpctl phase1-smoke`, using an ignored SQLite database under `target/` by default, a bound development-only `/api/v1/tracer` listener, and the existing encrypted store's durable flush/close/read path.
- Added monotonic configuration activation: strict verification must succeed, and replayed, lower, or malformed bundle versions cannot replace current/LKG.
- Added executable race and integrity coverage for one-time token consumption, concurrent activation, wrong-key/truncated/replayed bundles, AEAD tag corruption, duplicate nonces, and a non-vacuous backing/cache/log/evidence plaintext marker scan.

## Verification Evidence

- `cargo run -p dlpctl -- phase1-smoke` passed using the ignored SQLite tracer database.
- `cargo test -p dlpctl --test walking_skeleton -- --nocapture` passed (happy path and hardening cases).
- `cargo test -p dlp-agent-core` and `cargo test -p dlp-storage --test roundtrip` passed.
- `cargo fmt --all -- --check` and `cargo clippy -p dlp-server -p dlp-agent-core -p dlpctl --all-targets -- -D warnings` passed.

## PostgreSQL Verification Limitation

Per the user's standing explicit direction, this plan used an ignored SQLite file under `target/` because `DATABASE_URL` was unavailable. PostgreSQL migration application, production `PgPool` repository reads/writes, SQLx migration-ledger compatibility, and migration-before-listener runtime evidence were **not run** and remain open before production acceptance.

## TDD Gate Compliance

- RED: `9792f35` and `5939ace` added failing happy-path and hardening expectations.
- GREEN: `e29373e` and `dfa9a4c` implemented the tracer and failure-path protections after those tests failed as expected.

## Task Commits

1. **Task 1: One real PostgreSQL/API/signed-activation/encrypted-file path** — `9792f35` (RED), `e29373e` (GREEN)
2. **Task 2: Harden tracer replay, concurrency, invalid-bundle, and record-integrity behavior** — `5939ace` (RED), `dfa9a4c` (GREEN)

## Deviations from Plan

### User-Directed Verification Substitute

**1. [User-directed deviation] Used SQLite under ignored `target/` instead of PostgreSQL.**
- **Reason:** `DATABASE_URL` was not available; the user explicitly authorized the existing SQLite substitute pattern from 01-02.
- **Implementation:** `phase1-smoke` provisions only `migrations-sqlite/` in the ignored tracer database while retaining the production PostgreSQL migration and server startup seam.
- **Limitation:** PostgreSQL runtime and ledger evidence is explicitly open; SQLite is not represented as the product database.

### Auto-fixed Issues

**1. [Rule 1 - Bug] Removed a nested Tokio runtime from the CLI tracer invocation.**
- **Found during:** Task 2 verification.
- **Issue:** The async CLI invoked the synchronous smoke runner, which attempted to create a second runtime and panicked.
- **Fix:** Added an async runner for callers that already own Tokio's runtime.
- **Files modified:** `crates/dlpctl/src/lib.rs`, `crates/dlpctl/src/main.rs`.
- **Verification:** `cargo run -p dlpctl -- phase1-smoke` passed.
- **Commit:** `dfa9a4c`.

## Known Stubs

None. The SQLite ledger is an explicitly bounded verification substitute, not a production storage implementation.

## Deferred Issues

- A reachable PostgreSQL `DATABASE_URL` is still required to run the production migration, repository, and migration-before-listener evidence. This is recorded in `.planning/WINDOWS.md` as an open unrun verification item.

## Self-Check: PASSED

- Tracer source, E2E test, and all declared modified files exist.
- Commits `9792f35`, `e29373e`, `5939ace`, and `dfa9a4c` exist in git history.
- No task commit deleted tracked files.
