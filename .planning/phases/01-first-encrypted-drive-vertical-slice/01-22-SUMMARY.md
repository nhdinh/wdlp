---
phase: 01-first-encrypted-drive-vertical-slice
plan: "22"
subsystem: enrollment-authority
tags: [postgresql, sqlx, enrollment, mtls, pki, provenance]
requires:
  - "01-17 evidence and digest-bound privilege-control contract"
provides:
  - "PostgreSQL-native digest-only device authority and protected-route credential schema"
  - "Row-locked token consumption and atomic prior-serial revocation/new-serial activation"
  - "Constrained ECDSA P-256 CSR device-leaf issuer and redacted enrollment input"
affects: [01-13, 01-14, 01-23]
tech-stack:
  added: []
  patterns:
    - "SQLx PgPool authority adapters with FOR UPDATE transaction boundaries"
    - "CSPRNG single-use token returned once and persisted as SHA-256 only"
    - "Public certificate digest persistence without endpoint or CA private-key retention"
key-files:
  created: []
  modified:
    - crates/dlp-protocol/src/lib.rs
    - crates/dlp-server/src/repository.rs
    - crates/dlp-server/src/enrollment.rs
    - crates/dlp-server/src/pki.rs
    - migrations/202608070002_enrollment_authority.sql
    - migrations/202608070003_authenticated_routes.sql
    - tests/e2e/server_enrollment.rs
key-decisions:
  - "Production enrollment authority is constructed only from a supplied PgPool; deterministic mutex authority is explicitly named as a test fixture."
  - "A locked authority transaction validates the digest and corroborated AD identity before issuing, revoking, consuming, and activating credential state."
  - "Device leaves require endpoint-signed ECDSA P-256 CSRs, CA:false, digitalSignature, clientAuth, URI SAN, and the bounded 30-day profile."
requirements-completed: [WRK-03, SRV-03, SRV-11, CRY-04, TST-05]
coverage:
  - deliverable: "PostgreSQL authority source contract"
    verification:
      - kind: command
        ref: "cargo test --locked -p dlp-server --test server_enrollment repository_"
        status: pass
      - kind: command
        ref: "scripts/verify-phase1-evidence.ps1 ServerAuthoritySource"
        status: pass
    human_judgment: false
  - deliverable: "Transactional device credential source contract"
    verification:
      - kind: command
        ref: "cargo test --locked -p dlp-server --test server_enrollment enrollment_"
        status: pass
      - kind: command
        ref: "scripts/verify-phase1-evidence.ps1 ServerEnrollmentSource"
        status: pass
    human_judgment: false
metrics:
  duration: 40m
  completed: 2026-08-10
status: complete
actuals:
  tokens: 20685
  tasks: 2
  commits: 5
---

# Phase 01 Plan 22: PostgreSQL Enrollment Authority Summary

**The server now has PostgreSQL-native, digest-only enrollment authority source contracts that atomically consume tokens, revoke predecessor credentials, and activate constrained device leaves.**

## Tasks Completed

1. **Persisted the provisioning authority source contract**
   - Added redacted version-1 provisioning DTOs and PgPool-backed authority/route adapters.
   - Replaced SQLite-style authority schema with PostgreSQL `BYTEA`, `TIMESTAMPTZ`, strict identity/token constraints, and row-locking source operations.
   - Commits: `75d7a4b`, `1f95b1f`.

2. **Added atomic device credential activation source contract**
   - Split deterministic enrollment fixtures from the production `EnrollmentService` and added a redacted CSR/token submission type.
   - The authority transaction validates exact stored fingerprint/AD identity, calls the constrained issuer under lock, records prior revocation, consumes the token, and creates one active route credential before commit.
   - Commits: `e41bf4f`, `b4a9fce`, `96b9cd3`.

## Verification

- `cargo test --locked -p dlp-server --test server_enrollment repository_` passed.
- `cargo test --locked -p dlp-server --test server_enrollment enrollment_` passed.
- `cargo test --locked -p dlp-server pki` passed.
- `cargo test --locked -p dlp-protocol`, `cargo clippy --locked -p dlp-server -p dlp-protocol --all-targets -- -D warnings`, and `cargo fmt --check` passed.
- `ServerAuthoritySource` and `ServerEnrollmentSource` evidence gates passed on `hungdinh-lt`.

## Decisions Made

- Portable source checks establish implementation provenance only; Plan 01-13 must still execute migrations and transactions against LAB-DC01 PostgreSQL.
- Tokens, raw fingerprint inputs, CSRs, endpoint private keys, and CA private material are excluded from persistence and diagnostic output.
- A replacement can become visible only when revocation, route credential state, token consumption, and the new active serial commit together.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added server authority source scenarios to the Phase 1 evidence verifier.**
- **Found during:** Task 1 verification.
- **Issue:** The shared evidence verifier did not yet expose the two plan-mandated source scenarios.
- **Fix:** Added fail-closed PostgreSQL/migration and enrollment/PKI source checks.
- **Files modified:** `scripts/verify-phase1-evidence.ps1`.

**2. [Rule 2 - Test boundary] Explicitly renamed the mutex-backed authority adapter as a deterministic test fixture.**
- **Found during:** Task 1 implementation.
- **Issue:** Its production-neutral name made accidental authority selection too easy to miss in review.
- **Fix:** Renamed it `TestAuthorityRepository` and isolated test enrollment callers from the PgPool production service.
- **Files modified:** `crates/dlp-server/src/{repository,enrollment,lib}.rs`.

**3. [Rule 3 - Blocking] Repaired visible planning position after the state SDK could not parse legacy position fields.**
- **Found during:** Plan close-out.
- **Fix:** Aligned the visible position to 2/11 completed plans and selected 01-23 as the Wave 3 next plan while retaining the SDK-recorded metrics/session updates.
- **Files modified:** `.planning/STATE.md`.

**4. [Rule 2 - Evidence integrity] Left shared requirements open pending all declaring plans and real LAB-DC01 evidence.**
- **Found during:** Plan close-out.
- **Reason:** `requirements.ready-ids` reported 0/5 ready. Marking source-only implementations complete would promote portable evidence into the infrastructure boundary.

**Total deviations:** 2 auto-fixed. **Impact:** The implementation is more explicit about the portable-versus-LAB-DC01 verification boundary.

## Known Stubs

None.

## Self-Check: PASSED

- All declared protocol, repository, enrollment, PKI, migration, verifier, and test files exist.
- Task commits `75d7a4b`, `1f95b1f`, `e41bf4f`, `b4a9fce`, and `96b9cd3` exist in git history.
