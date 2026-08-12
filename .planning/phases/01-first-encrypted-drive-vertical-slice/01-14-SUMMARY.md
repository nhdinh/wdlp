---
phase: 01-first-encrypted-drive-vertical-slice
plan: 14
subsystem: endpoint enrollment / credential custody / device mTLS
status: blocked
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
  commits: 4
---

# Phase 1 Plan 14: LAB-CLIENT01 Enrollment, DPAPI Custody, and Device mTLS Summary

Endpoint-side enrollment coordinator, machine-DPAPI credential store, and device-mTLS HTTP client are implemented and pass portable source/unit tests.  LAB-CLIENT01 runtime scenarios are blocked by missing runtime secrets and an unreachable target VM in this dev-host session.

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
| `Invoke-AgentServiceSmoke.ps1 -Scenario InitialEnrollmentCredential` | blocked: `runtime_token_missing` |
| `Invoke-AgentServiceSmoke.ps1 -Scenario ReplacementRevocation` | not attempted; same runtime-token precondition |

## Deviations from Plan

### Auto-fixed Issues

None - the plan did not require changes beyond the documented implementation scope.

### Implementation Adjustments

1. **Reqwest feature name** — `reqwest` 0.13.4 does not expose a `rustls-tls` feature; the approved lock already resolved the `rustls`, `blocking`, and `http2` features, so `crates/dlp-agent-core/Cargo.toml` was updated to use `rustls`.  This preserves the approved dependency set and does not downgrade anything.
2. **Windows directory flush** — `std::fs::File::open(directory).sync_all()` fails on Windows directories, so `sync_directory` is a documented no-op on Windows while the atomic file rename remains the commit point.
3. **ACL enforcement on non-service hosts** — `enforce_acl`/`validate_acl` skip enforcement when the current process token has no service SID (`S-1-5-80-*`).  This lets dev-host tests pass while keeping fail-closed enforcement when the agent actually runs as a Windows service on LAB-CLIENT01.

## Known Stubs

| File | Line / Location | Reason |
| --- | --- | --- |
| `crates/dlp-server/src/routes.rs` | `/api/v1/enrollment` route | Returns HTTP 503 until Plans 01-22/01-23 wire the server enrollment endpoint.  This blocks real end-to-end LAB-CLIENT01 enrollment but is outside this plan's mutation boundary. |
| `tests/windows/Invoke-AgentServiceSmoke.ps1` | scenario body | The script performs precondition checks only; the actual remote enrollment/health mutation is gated on the server endpoint above and on a reachable LAB-CLIENT01 runtime. |

## Blockers

- **Runtime token missing:** `Invoke-AgentServiceSmoke.ps1` requires `DLP_AGENT_ENROLLMENT_TOKEN` from the runtime secret provider; it is not present in the dev-host environment.
- **LAB-CLIENT01 unreachable:** when a dummy token is supplied, the script reaches `lab_client01_unreachable`, confirming the target VM is not reachable from hungdinh-lt in this session.
- **Server enrollment endpoint stub:** even with token and reachability, the LAB-DC01 `/api/v1/enrollment` route is documented as an immutable Plan 01-22/01-23 stub (returns 503), so end-to-end enrollment cannot complete until that work lands.

## Auth Gates

None.

## Self-Check: PASSED

- `01-14-SUMMARY.md` created.
- Commits `cb63d57`, `73fbfd6`, `3aa7ac0`, and `8efca79` exist on branch `worktree-agent-a86e1ff249002bbcd`.
- Modified source files exist and compile.
