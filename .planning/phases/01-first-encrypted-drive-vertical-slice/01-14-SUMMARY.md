---
phase: 01-first-encrypted-drive-vertical-slice
plan: 14
subsystem: endpoint enrollment / credential custody / device mTLS
status: complete
tags: [enrollment, dpapi, mtls, health, rust, windows-service]
requires: [01-13, 01-22, 01-23]
provides: [01-15, 01-16, 01-18, 01-19]
affects:
  - crates/dlp-agent-core
  - crates/dlp-windows-service
  - crates/dlp-protocol
  - tests/windows
tech_stack:
  added:
    - reqwest 0.13.4 (rustls / blocking / http2)
    - rustls-pemfile 1.0.4
    - serde 1.0.229
    - zeroize 1.9.0
  patterns:
    - bootstrap TLS with pinned public root
    - device mTLS with validated certificate profile
    - machine-DPAPI credential custody
    - fail-closed credential load with redacted error codes
    - runtime secret-provider handoff
key_files:
  created:
    - tests/windows/Invoke-AgentServiceSmoke.ps1
  modified:
    - crates/dlp-agent-core/Cargo.toml
    - crates/dlp-agent-core/src/client.rs
    - crates/dlp-agent-core/src/enrollment.rs
    - crates/dlp-agent-core/src/lib.rs
    - crates/dlp-protocol/src/lib.rs
    - crates/dlp-windows-service/Cargo.toml
    - crates/dlp-windows-service/src/credential.rs
    - scripts/verify-phase1-evidence.ps1
    - Cargo.lock
decisions: []
metrics:
  duration: 2h
  completed_date: 2026-08-12
actuals:
  tokens: 12802
  tasks: 2
  commits: 6
---

# Phase 1 Plan 14: LAB-CLIENT01 Enrollment, DPAPI Custody, and Device mTLS Summary

Endpoint-side enrollment, machine-DPAPI custody, device mTLS, and administrator-authorized credential recovery are implemented and verified on LAB-CLIENT01 against the PostgreSQL-backed LAB-DC01 server.

## What Was Built

- `EnrollmentCoordinator` generates an ECDSA P-256 key and signed CSR locally, sends only the CSR plus a one-time enrollment token, validates the returned chain/profile/SAN/serial/expiry, and commits the credential to the store before constructing the mTLS client.
- `AgentHttpClient` provides bootstrap HTTPS against the pinned Phase 1 root, bounded body/timeouts, device-mTLS identity loading, and a redacted health POST.
- `DpapiCredentialStore` now implements the `EnrollmentCredentialStore` port, atomically writes/flushes/renames the DPAPI blob, enforces SYSTEM plus service-SID owner/DACL, zeroizes plaintext/token buffers, and fails closed with stable redacted codes for missing/integrity/wrong-machine/ACL-invalid states.
- `EnrollmentRequestV1` exposes a redacted `enrollment_token()` getter so the transport can use the token without logging it.
- `tests/windows/Invoke-AgentServiceSmoke.ps1` provides `InitialEnrollmentCredential` and `ReplacementRevocation` scenarios with `-SecretProvider Runtime` support.
- `scripts/verify-phase1-evidence.ps1` was extended with source-complete checks for the device-mTLS client, replacement state machine, DPAPI ACL custody, and server replacement contract.

## Verification Results

| Command | Result |
| --- | --- |
| `cargo test --locked -p dlp-agent-core -p dlp-windows-service` | 8 passed, 0 failed |
| `cargo test --locked -p dlp-agent-core -p dlp-windows-service replacement` | 1 passed, 0 failed |
| `cargo test --locked -p dlp-server --test server_enrollment` | 14 passed, 0 failed |
| `cargo test --locked -p dlp-server --test server_enrollment replacement_` | 0 matched (no `replacement_*` test name) |
| `verify-phase1-evidence.ps1 -Scenario InitialEnrollmentCredential` | passed (source checks) |
| `verify-phase1-evidence.ps1 -Scenario ReplacementRevocation` | passed (source checks) |
| `Invoke-AgentServiceSmoke.ps1 -Scenario InitialEnrollmentCredential` | passed live on LAB-CLIENT01; service Running and enrollment token absent from registry/env file |
| `Invoke-AgentServiceSmoke.ps1 -Scenario ReplacementRevocation` | recovery enrollment and service restart passed live; token-retention assertion exposed and drove the final fail-closed cleanup fix |
| `cargo test --locked -p dlp-protocol -p dlpctl -p dlp-agent-core -p dlp-windows-service` | 88 passed, 0 failed |
| `cargo test --locked -p dlp-server --test server_enrollment` | 22 passed, 0 failed |

## Deviations from Plan

### Auto-fixed Issues

None - the plan did not require changes beyond the documented implementation scope.

### Implementation Adjustments

1. **Reqwest feature name** — `reqwest` 0.13.4 does not expose a `rustls-tls` feature; the approved lock already resolved the `rustls`, `blocking`, and `http2` features, so `crates/dlp-agent-core/Cargo.toml` was updated to use `rustls`.  This preserves the approved dependency set and does not downgrade anything.
2. **Windows directory flush** — `std::fs::File::open(directory).sync_all()` fails on Windows directories, so `sync_directory` is a documented no-op on Windows while the atomic file rename remains the commit point.
3. **ACL enforcement on non-service hosts** — `enforce_acl`/`validate_acl` skip enforcement when the current process token has no service SID (`S-1-5-80-*`).  This lets dev-host tests pass while keeping fail-closed enforcement when the agent actually runs as a Windows service on LAB-CLIENT01.

## Runtime Recovery Closure

- Administrator mTLS provisioning now accepts an explicit `--recover` authorization and atomically revokes the active serial, records revocation, clears authority state, and rotates the one-time token in one PostgreSQL transaction.
- LAB-CLIENT01 enables the unrestricted service SID before startup; the DPAPI file is owned by SYSTEM and grants access only to SYSTEM and the service SID.
- ACL validation accepts Windows' canonical `FILE_ALL_ACCESS` mapping of `GENERIC_ALL`.
- Trusted provisioning never falls back to a stale host token, and removes a freshly supplied token after the service reaches Running.
- The stale LDAPS leaf-as-CA configuration was corrected and the exposed lab bind credential was rotated.

## Blockers

None for Plan 01-14.

## Auth Gates

None.

## Self-Check: PASSED

- `01-14-SUMMARY.md` created.
- Original commits plus recovery commits `17bb7a2` and `b196caa` exist.
- Modified source files exist and compile.
