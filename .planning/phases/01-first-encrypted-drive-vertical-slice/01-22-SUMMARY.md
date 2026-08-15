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
    - evidence/phase1/requirement-matrix.yaml
key-decisions:
  - "Production enrollment authority is constructed only from a supplied PgPool; deterministic mutex authority is explicitly named as a test fixture."
  - "A locked authority transaction validates the digest and corroborated AD identity before issuing, revoking, consuming, and activating credential state."
  - "Device leaves require endpoint-signed ECDSA P-256 CSRs, CA:false, digitalSignature, clientAuth, URI SAN, and the bounded 30-day profile."
  - "Source-only evidence on hungdinh-lt records the implementation contract; Plan 01-13 remains responsible for LAB-DC01/LAB-SERVER01 PostgreSQL transaction acceptance evidence."
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
  duration: 25m
  completed: 2026-08-16
status: complete
actuals:
  tokens: 16700
  tasks: 2
  commits: 6
---

# Phase 01 Plan 22: PostgreSQL Enrollment Authority Summary

**Re-verified and published source-only evidence for the PostgreSQL-native, digest-only enrollment authority and transactional device-credential issuance contract.**

## Execution Notes

This execution run verified the already-merged 01-22 source artifacts and published fresh Phase 1 evidence for the five declaring requirements. No Rust source changes were required because the implementation commits (`75d7a4b`, `1f95b1f`, `e41bf4f`, `b4a9fce`, `96b9cd3`, `3b503b7`) were already present in the repository. The matrix and evidence files are the only new artifacts.

## Tasks Completed

1. **Verified the provisioning authority source contract**
   - Confirmed `ProvisionDeviceRequestV1` stores normalized identity, exact 32-byte fingerprint digest, corroborated AD GUID/SID/DNS/domain, preferred drive letter, and token digest.
   - Confirmed `PgAuthorityRepository` is constructed only from a real `PgPool`, uses `FOR UPDATE`, persists only `token_digest`, and has no production in-memory adapter.
   - Confirmed migration `202608070002_enrollment_authority.sql` uses `BYTEA`, `TIMESTAMPTZ`, strict constraints, and no seed rows.
   - Commits: `75d7a4b`, `1f95b1f`, `96b9cd3`, `3b503b7`.

2. **Verified the atomic device credential activation source contract**
   - Confirmed `EnrollmentService` uses `PgAuthorityRepository` and `RcgenDeviceCertificateIssuer`.
   - Confirmed `consume_and_activate` implements one PostgreSQL transaction for token consumption, prior-serial revocation, new-serial activation, and public certificate digest persistence.
   - Confirmed `pki.rs` verifies the CSR signature, enforces ECDSA P-256, CA:false, digitalSignature, clientAuth, URI SAN, and 30-day validity.
   - Commits: `e41bf4f`, `b4a9fce`, `96b9cd3`, `3b503b7`.

## Verification

- `cargo test --locked -p dlp-server --test server_enrollment repository_` passed.
- `cargo test --locked -p dlp-server --test server_enrollment enrollment_` passed.
- `cargo test --locked -p dlp-server pki` passed.
- `cargo clippy --locked -p dlp-server -p dlp-protocol --all-targets -- -D warnings` passed.
- `ServerAuthoritySource` and `ServerEnrollmentSource` evidence source checks passed on `hungdinh-lt`.

## Evidence Published

| Requirement | Check | Evidence ID |
|-------------|-------|-------------|
| WRK-03 | protocol-contract | 8c146891-a42d-4e57-8fcb-a62a51fe9683 |
| SRV-03 | device-enrollment | 71272216-b313-4527-bb68-49f9c25885be |
| SRV-11 | postgresql-migration | 8f8cc6c8-5754-4fd7-8214-f071424c1e7e |
| CRY-04 | device-mtls-dpapi | 7deb761f-745a-4e3a-bcf9-4dfc22d80595 |
| TST-05 | enrollment-integration | 8edcc976-c5a2-4553-9927-b72e02805ef2 |

All evidence files were validated by `Phase1.Evidence.psm1` and published to `evidence/phase1/requirement-matrix.yaml`.

## Decisions Made

- Portable source checks establish implementation provenance only; Plan 01-13 must still execute migrations and transactions against LAB-DC01 PostgreSQL.
- Tokens, raw fingerprint inputs, CSRs, endpoint keying material, and CA private material are excluded from persistence and diagnostic output.
- A replacement can become visible only when revocation, route credential state, token consumption, and the new active serial commit together.

## Deviations from Plan

None - the source artifacts matched the plan and verification passed. The only delta is the explicit publication of source-only evidence and matrix linkage, which the plan mandated through its evidence workflow.

## Known Stubs

None.

## Threat Flags

None introduced by this execution run.

## Self-Check: PASSED

- All declared protocol, repository, enrollment, PKI, migration, verifier, and test files exist.
- Task commits `75d7a4b`, `1f95b1f`, `e41bf4f`, `b4a9fce`, `96b9cd3`, and `3b503b7` exist in git history.
- Evidence files for all five declaring requirements exist and validate.
- Requirement matrix rows WRK-03, SRV-03, SRV-11, CRY-04, and TST-05 reference the new evidence IDs.
- `cargo test` and `cargo clippy` verification commands passed.
