---
phase: 01-first-encrypted-drive-vertical-slice
plan: 23
subsystem: enrollment-transport
tags: [postgresql, mtls, ldaps, kerberos, reqwest, provisioning]
requires:
  - phase: 01-22
    provides: PostgreSQL authority, enrollment transaction, and constrained device issuer
provides:
  - Bootstrap, administrator, and device route-policy source contracts
  - Pinned typed trusted-provisioning HTTP client boundary
  - LAB-DC01 dual-DC Kerberos CIM preflight procedure
affects: [01-13, deployment, enrollment]
actuals:
  tokens: 19088
  tasks: 3
  commits: 3
tech-stack:
  added: [reqwest@0.13.4, serde@1.0.229, serde_json@1.0.151]
  patterns: [optional bootstrap TLS peer, fail-closed route middleware, redacted runtime token handoff, explicit dual-DC corroboration]
key-files:
  created: []
  modified: [crates/dlp-server/src/{ad,routes,tls,lib,main}.rs, crates/dlpctl/{Cargo.toml,src/lib.rs,src/main.rs}, crates/dlp-protocol/src/lib.rs, scripts/lab/Invoke-TrustedProvisioning.ps1, config/server.env.example, tests/e2e/server_enrollment.rs]
key-decisions:
  - "Use an optional client peer only at the TLS boundary; administrator and device middleware require a verified peer."
  - "Return a versioned JSON provisioning response from the administrator route so the client can validate device identity before token handoff."
  - "Use only the approved reqwest@0.13.4 dependency with HTTPS hostname validation, bounded timeouts, and administrator mTLS identity."
  - "Keep LAB-DC01 provisioning source-only; Plan 01-13 remains the authorized lab-mutation owner."
patterns-established:
  - "Treat forwarded certificate headers and bearer provisioning fallback as unauthorized identity sources."
  - "Collect only normalized fingerprint fields remotely and publish allowlisted digest/provenance output."
requirements-completed: [SRV-01, SRV-03, SRV-12, TST-05]
coverage:
  - id: D1
    description: Route and provider composition source contract
    requirement: SRV-01
    verification:
      - kind: integration
        ref: cargo test --locked -p dlp-server --test server_enrollment
        status: pass
      - kind: integration
        ref: cargo clippy --locked -p dlp-server --all-targets -- -D warnings
        status: pass
      - kind: other
        ref: scripts/verify-phase1-evidence.ps1 ServerRouteSource
        status: pass
    human_judgment: false
  - id: D2
    description: Typed trusted provisioning client and pinned dependency
    requirement: SRV-03
    verification:
      - kind: unit
        ref: cargo test --locked -p dlpctl provisioning_
        status: pass
      - kind: other
        ref: cargo tree --locked -p dlpctl -i reqwest@0.13.4
        status: pass
      - kind: other
        ref: scripts/verify-phase1-evidence.ps1 TrustedProvisioningClientSource
        status: pass
    human_judgment: false
  - id: D3
    description: LAB-DC01 dual-DC Kerberos source preflight
    requirement: SRV-12
    verification:
      - kind: integration
        ref: cargo test --locked -p dlp-server --test server_enrollment trusted_provisioning_
        status: pass
      - kind: other
        ref: scripts/verify-phase1-evidence.ps1 TrustedProvisioningSource
        status: pass
    human_judgment: true
    rationale: The privileged DC/WinRM execution is reserved for Plan 01-13.
duration: 45m
completed: 2026-08-12
status: complete
---

# Phase 01 Plan 23: Production Route and Trusted Provisioning Summary

**Bootstrap TLS route partitioning, a pinned redacted provisioning client, and a LAB-DC01 dual-DC Kerberos preflight source contract are now present.**

## Performance

- **Duration:** 45m
- **Tasks:** 3/3
- **Files modified:** 13

## Accomplishments

- Wired production route/TLS/directory contracts with optional bootstrap peer handling, administrator/device middleware, bounded endpoint DTOs, provider validation, and PostgreSQL-backed enrollment authority.
- Completed the typed administrator-mTLS provisioning client with root-CA pinning, admin client identity, HTTPS-only hostname validation, bounded timeouts, response validation, and runtime-only token handoff.
- Completed the LAB-DC01 trusted provisioning preflight with dlpctl invocation, dual-DC equality checks, Kerberos WinRM-over-HTTPS CIM collection, fixed fingerprint digest construction, and sanitized output.

## Task Commits

1. **Task 1: Wire production route, TLS partition, and PostgreSQL enrollment authority** — `26e4d04` (feat)
2. **Task 2: Complete typed administrator-mTLS provisioning client** — `e3358ca` (feat)
3. **Task 3: Complete LAB-DC01 dual-DC Kerberos provisioning preflight** — `2d80f27` (feat)

## Verification

- Passed: `cargo test --locked -p dlp-server --test server_enrollment` (20 passed).
- Passed: `cargo clippy --locked -p dlp-server --all-targets -- -D warnings`.
- Passed: `cargo test --locked -p dlpctl provisioning_` (6 passed).
- Passed: `cargo tree --locked -p dlpctl -i reqwest@0.13.4`.
- Passed: `ServerRouteSource`, `TrustedProvisioningClientSource`, and `TrustedProvisioningSource` evidence checks.

## Known Stubs

| File | Line | Reason |
| --- | --- | --- |
| `crates/dlp-server/src/routes.rs` | `admin_provisioning_contract` | Returns a real provisioning response, but the underlying `AdminProvisioningService` still delegates to the stub `PgAuthorityRepository::provision` until Plan 01-13 runtime evidence validates the full PostgreSQL transaction. |
| `scripts/lab/Invoke-TrustedProvisioning.ps1` | dlpctl invocation | The script invokes `dlpctl provision-device`, but real DC/WinRM/database mutation is reserved for Plan 01-13. |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added direct serde/serde_json dependencies to dlpctl and enabled reqwest `json` feature.**
- **Found during:** Task 2
- **Issue:** The typed provisioning client needed to serialize the request and deserialize the JSON response, but dlpctl did not directly depend on serde/serde_json and reqwest was built without the `json` feature.
- **Fix:** Added `serde@1.0.229` and `serde_json@1.0.151` as direct dlpctl dependencies and added the `json` feature to the approved `reqwest@0.13.4` dependency.
- **Files modified:** `crates/dlpctl/Cargo.toml`
- **Verification:** `cargo test --locked -p dlpctl provisioning_` passes; `cargo tree --locked -p dlpctl -i reqwest@0.13.4` confirms the pinned version.
- **Committed in:** `e3358ca` (Task 2)

**2. [Rule 2 - Missing Critical] Added a versioned provisioning response type and returned it from the administrator route.**
- **Found during:** Task 2
- **Issue:** The administrator route returned `200 OK` with no body, so the client had no token or device identity to validate before runtime handoff.
- **Fix:** Added `ProvisionDeviceResponseV1` to `dlp-protocol`, updated `ProvisioningServicePort` to return it, and changed `admin_provisioning_contract` to serialize a JSON response containing version, device_id, and enrollment_token.
- **Files modified:** `crates/dlp-protocol/src/lib.rs`, `crates/dlp-server/src/enrollment.rs`, `crates/dlp-server/src/routes.rs`, `crates/dlp-server/src/lib.rs`
- **Verification:** `cargo test --locked -p dlp-server --test server_enrollment` passes.
- **Committed in:** `e3358ca` (Task 2)

**3. [Rule 2 - Missing Critical] Made the PowerShell preflight invoke the typed dlpctl client instead of only emitting a digest.**
- **Found during:** Task 3
- **Issue:** The source-complete preflight computed and emitted the digest but did not hand it (plus corroborated AD identity) to the Task 2 client, leaving the trusted-provisioning workflow incomplete.
- **Fix:** Added AD GUID/SID hex encoding, set the runtime-provider environment variables, and invoked `dlpctl provision-device --computer <FQDN>` before emitting sanitized provenance.
- **Files modified:** `scripts/lab/Invoke-TrustedProvisioning.ps1`
- **Verification:** `TrustedProvisioningSource` evidence check passes.
- **Committed in:** `2d80f27` (Task 3)

**4. [Rule 3 - Blocking] Removed the obsolete bearer-style `DLP_ADMIN_PROVISIONING_KEY` from server.env.example and documented the mTLS provisioning material.**
- **Found during:** Task 3
- **Issue:** The example environment file still referenced a bearer provisioning key, which conflicts with the mTLS administrator-certificate design.
- **Fix:** Replaced `DLP_ADMIN_PROVISIONING_KEY` with documented `DLP_PROVISIONING_*` runtime-provider paths and `DLP_APPROVED_PRIVILEGE_MANIFEST_DIGEST`.
- **Files modified:** `config/server.env.example`
- **Verification:** File review.
- **Committed in:** `2d80f27` (Task 3)

## Issues Encountered

None - all verification commands passed on the execution machine.

## Next Phase Readiness

- Plan 01-13 can execute the trusted preflight against LAB-DC01 once the approved privilege manifest and mounted runtime material are available.
- The underlying PostgreSQL provisioning transaction remains to be validated in Plan 01-13's lab environment.

## Self-Check: PASSED

- `01-23-SUMMARY.md` exists.
- Task commits `26e4d04`, `e3358ca`, and `2d80f27` exist; docs commit `2ccd0af` exists.
- `scripts/lab/Invoke-TrustedProvisioning.ps1` exists.
- All verification commands and evidence checks passed.
