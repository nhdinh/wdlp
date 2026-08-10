---
phase: 01-first-encrypted-drive-vertical-slice
plan: "07"
subsystem: authenticated-server-api-and-deployment
tags: [rust, axum, rustls, mtls, signed-configuration, postgres, docker-compose]
requires:
  - phase: 01-06
    provides: enrollment authority, device certificate profile, and active/revoked credential contract
provides:
  - rustls listener metadata bound to Axum administrator/device route middleware
  - immutable audience-bound signed configuration selection and device-bound health persistence
  - process liveness, dependency readiness contract, and PostgreSQL Compose deployment shape
affects: [01-08, 01-10, 01-11, 01-12]
actuals:
  tokens: 14464
  tasks: 2
  commits: 10
tech-stack:
  added: [dlp-crypto path dependency, sha2@0.11.0]
  patterns:
    - TLS listener establishes a verified connection identity before Axum request middleware.
    - Configuration selection stores immutable signed versions and selects the greatest accepted version.
    - Readiness uses a read-only dependency snapshot; liveness is process-only.
key-files:
  created:
    - crates/dlp-server/src/routes.rs
    - crates/dlp-server/src/tls.rs
    - crates/dlp-server/src/health.rs
    - migrations/202608070003_authenticated_routes.sql
    - deploy/compose.yaml
  modified:
    - crates/dlp-server/src/lib.rs
    - crates/dlp-server/src/repository.rs
    - crates/dlp-protocol/src/lib.rs
    - config/server.env.example
    - tests/e2e/server_enrollment.rs
key-decisions:
  - Distinguish administrator and device identities using the issuer subject from configured trust anchors after rustls verification.
  - Persist only monotonic signed configuration versions; equal or lower versions are rejected before selection changes.
  - Keep Compose PostgreSQL evidence explicitly open where Docker/PostgreSQL are unavailable, rather than treating SQLite evidence as equivalent.
requirements-completed: [SRV-01, SRV-11, SRV-12, CRY-02, AGT-07, TST-05]
coverage:
  - id: D1
    description: Device mTLS identity, revoked credential denial, signed configuration, and device-bound health tracer.
    requirement: SRV-01
    verification:
      - kind: integration
        ref: cargo test -p dlp-server --test server_enrollment
        status: pass
    human_judgment: false
  - id: D2
    description: Immutable digest/audience configuration selection and read-only readiness contract.
    requirement: CRY-02
    verification:
      - kind: unit
        ref: tests/e2e/server_enrollment.rs#signed_configuration_is_audience_bound_hashed_and_replay_safe
        status: pass
      - kind: unit
        ref: tests/e2e/server_enrollment.rs#readiness_is_read_only_and_requires_every_dependency
        status: pass
    human_judgment: false
  - id: D3
    description: PostgreSQL Compose topology and runtime migration evidence.
    requirement: SRV-11
    verification:
      - kind: other
        ref: docker compose -f deploy/compose.yaml config
        status: unknown
    human_judgment: true
    rationale: Docker Compose and a PostgreSQL service are unavailable locally; SQLite evidence is deliberately not substituted for production runtime verification.
metrics:
  duration: 3h 20m
  completed: 2026-08-10
status: complete
---

# Phase 01 Plan 07: Authenticated Server API and Deployment Summary

**Rustls mTLS identity is bound to Axum routes, with replay-safe signed configuration selection, device-bound health recording, readiness contracts, and a durable PostgreSQL Compose topology.**

## Accomplishments

- Added a rustls/Tokio listener that rejects invalid client certificates before HTTP, carries the verified peer identity into Axum middleware, separates administrator and device issuers, and rejects revoked device serials before configuration or health handlers.
- Extended signed configuration with a SHA-256 digest and authenticated device audience; immutable repository selection retains only increasing bundle versions and rejects equal/lower replay.
- Added process-only liveness, a pure/read-only readiness dependency report, environment-shape preflight, one-shot migration entry point, and Compose services that require PostgreSQL health and migration completion before server startup.

## Verification Evidence

- Passed `cargo fmt --all -- --check`.
- Passed `cargo test -p dlp-server` and `cargo test -p dlp-protocol`.
- Passed `cargo run -p dlp-server -- --check-config --env-file config/server.env.example`.
- Passed `cargo clippy -p dlp-server -p dlp-protocol --all-targets -- -D warnings`.
- `docker compose -f deploy/compose.yaml config` was not run because Docker Compose is unavailable. PostgreSQL migration, real PgPool repository, and runtime readiness evidence remain open under the user-authorized SQLite-only development substitute.

## Task Commits

1. **Task 1: Device mTLS fetches one signed configuration and posts health** — `92218c5` (RED), `30117b3`, `291ad3b`, `1b5bc0b`, `665ac11`, `a4d6ce3` (RED), `d029721` (GREEN)
2. **Task 2: Replay-safe selection, dependency-aware readiness, and Compose deployment** — `6d0b4fd` (RED), `b7492ff` (GREEN), `4d3c980` (format)

## Deviations from Plan

### Auto-fixed Issues

1. **[Rule 2 - Missing critical functionality] Added a narrow forward-only authenticated-route migration.**
   - **Found during:** Task 1
   - **Issue:** The plan required durable credential/configuration persistence but the artifact inventory omitted the new migration path.
   - **Fix:** Added `202608070003_authenticated_routes.sql` without seed data or secret content.
   - **Committed in:** `d029721`

2. **[Rule 1 - Security] Preserved the authenticating trust-root role in the TLS listener.**
   - **Found during:** Task 1 verification
   - **Issue:** A single verifier accepted both roots but did not retain which configured issuer authenticated the leaf.
   - **Fix:** Bound leaf issuer matching to the configured administrator/device trust anchors before route middleware classification.
   - **Committed in:** `d029721`

## Known Limitations

- Docker Compose rendering and PostgreSQL runtime evidence are unrun because neither Docker Compose nor `DATABASE_URL` is available locally. Both are recorded in `.planning/WINDOWS.md`; SQLite remains a development-only substitute.
- Phase 1 excludes configuration push, policy authoring, event upload, fleet lifecycle, audit routes, WebSockets, and gRPC according to `COVERAGE.md`.

## Next Phase Readiness

The next server/agent work can consume distinct TLS identities, selected signed configuration metadata, the migration command, and the Compose secret-mount contract. Production acceptance still requires PostgreSQL and Docker Compose verification.

## Self-Check: PASSED

- Created route, TLS, health, migration, and Compose files exist.
- Task commits `92218c5`, `30117b3`, `291ad3b`, `1b5bc0b`, `665ac11`, `a4d6ce3`, `d029721`, `6d0b4fd`, `b7492ff`, and `4d3c980` exist in git history.
- No task commit deleted tracked files.
