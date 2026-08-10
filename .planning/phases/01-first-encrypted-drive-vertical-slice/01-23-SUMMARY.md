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
  tokens: 52219
  tasks: 3
  commits: 6
tech-stack:
  added: [reqwest@0.13.4]
  patterns: [optional bootstrap TLS peer, fail-closed route middleware, redacted runtime token handoff, explicit dual-DC corroboration]
key-files:
  created: [scripts/lab/Invoke-TrustedProvisioning.ps1]
  modified: [crates/dlp-server/src/{ad,routes,tls,lib,main}.rs, crates/dlpctl/{Cargo.toml,src/lib.rs}, tests/e2e/server_enrollment.rs]
key-decisions:
  - "Use an optional client peer only at the TLS boundary; administrator and device middleware require a verified peer."
  - "Use only the approved reqwest@0.13.4 dependency with HTTPS hostname validation and bounded timeouts."
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
        ref: scripts/verify-phase1-evidence.ps1 ServerRouteSource
        status: pass
    human_judgment: true
    rationale: Mounted TLS and PostgreSQL dependencies were unavailable on the execution machine.
  - id: D2
    description: Typed trusted provisioning client and pinned dependency
    requirement: SRV-03
    verification:
      - kind: unit
        ref: cargo test --locked -p dlpctl provisioning_
        status: pass
    human_judgment: false
  - id: D3
    description: LAB-DC01 dual-DC Kerberos source preflight
    requirement: SRV-12
    verification:
      - kind: other
        ref: scripts/verify-phase1-evidence.ps1 TrustedProvisioningSource
        status: pass
    human_judgment: true
    rationale: The privileged DC/WinRM execution is reserved for Plan 01-13.
duration: 55m
completed: 2026-08-10
status: complete
---

# Phase 01 Plan 23: Production Route and Trusted Provisioning Summary

**Bootstrap TLS route partitioning, a pinned redacted provisioning client, and a LAB-DC01 dual-DC Kerberos preflight source contract are now present.**

## Performance

- **Duration:** 55m
- **Tasks:** 3/3
- **Files modified:** 12

## Accomplishments

- Added optional bootstrap client-peer handling, administrator/device middleware, bounded endpoint DTOs, provider validation, and independent two-DC corroboration API.
- Added the human-approved `reqwest@0.13.4` client boundary with HTTPS-only hostname validation, bounded timeouts, redacted request Debug, and runtime-only token handoff.
- Added source-complete LAB-DC01 procedure guards for exact machine/target/manifest, explicit two-DC equality, Kerberos CIM over TLS, fixed fingerprint digest construction, and sanitized output.

## Task Commits

1. **Task 1: Production route/TLS/directory contracts** — `d75d674` (test), `4fd3180` (feat)
2. **Task 2: Typed administrator provisioning client** — `d28c00c` (test), `bf9c0df` (feat)
3. **Task 3: LAB-DC01 trusted provisioning preflight** — `9568c49` (test), `c7a66b9` (feat)

## Verification

- Passed: `cargo clippy --locked -p dlp-server --all-targets -- -D warnings`
- Passed: `cargo test --locked -p dlpctl provisioning_`
- Passed: `cargo tree --locked -p dlpctl -i reqwest@0.13.4`
- Passed: `ServerRouteSource`, `TrustedProvisioningClientSource`, and `TrustedProvisioningSource` evidence checks.
- Not runnable locally: the complete `server_enrollment` integration suite has two fixture failures because the required mounted TLS environment variables, including `DLP_DEVICE_ISSUING_CA_CERT_PEM`, are absent. The other 12 tests passed.

## Known Stubs

| File | Line | Reason |
| --- | --- | --- |
| `crates/dlp-server/src/routes.rs` | bootstrap and administrator handlers | Both handlers validate bounded input but return `503` until real `PgAuthorityRepository`/`EnrollmentService` route-state wiring is completed. |
| `crates/dlp-server/src/lib.rs` | `RuntimeRepository` | Production composition creates PostgreSQL authority/route adapters but protected routes still receive the in-memory `RouteRepository` adapter. |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added missing source evidence scenarios.**
- **Found during:** Tasks 1–3
- **Issue:** The plan required three source-verification scenarios not accepted by the existing evidence runner.
- **Fix:** Added route, client, and trusted-preflight source scenarios.
- **Files modified:** `scripts/verify-phase1-evidence.ps1`
- **Verification:** All three scenarios pass.

**2. [Rule 1 - Bug] Corrected the token-handoff test fixture.**
- **Found during:** Task 2
- **Issue:** The test used a hyphenated value that intentionally violates opaque token validation.
- **Fix:** Replaced it with an alphanumeric opaque test token.
- **Files modified:** `crates/dlpctl/src/lib.rs`
- **Verification:** `cargo test --locked -p dlpctl provisioning_` passes.

## Issues Encountered

The local execution machine does not mount the Phase 1 TLS fixture material, so the full server integration command cannot validate certificate parsing. No lab/DC/WinRM mutation was attempted; that remains Plan 01-13 authority.

## Next Phase Readiness

- Plan 01-13 can use the source preflight only after its approved privilege manifest and mounted runtime material are available.
- The Known Stubs must be wired to the PostgreSQL authority/enrollment transaction before this route surface is accepted as production-complete.

## Self-Check: PASSED

- Task commits `d75d674`, `4fd3180`, `d28c00c`, `bf9c0df`, `9568c49`, and `c7a66b9` exist.
- `scripts/lab/Invoke-TrustedProvisioning.ps1` exists.
- The passing verification commands and the fixture limitation above are recorded.
