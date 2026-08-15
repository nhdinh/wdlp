---
phase: 01-first-encrypted-drive-vertical-slice
plan: 23
subsystem: server
tags: [rust, axum, rustls, ldap3, reqwest, winrm, kerberos, mtls, enrollment]

requires:
  - phase: 01-first-encrypted-drive-vertical-slice
    plan: 22
    provides: "PostgreSQL enrollment authority, transactional device credential issuance, and signed configuration DTOs"

provides:
  - "Async production directory verifier querying two configured DCs over hostname LDAPS with custom CA"
  - "TLS/route partition: optional peer on bootstrap enrollment, administrator mTLS on provisioning, active-device mTLS on configuration/health"
  - "Production provider composition from runtime environment before PostgreSQL migration or listener binding"
  - "Typed dlpctl administrator-mTLS provisioning client using approved reqwest@0.13.4"
  - "LAB-DC01 dual-DC/Kerberos WinRM-over-HTTPS trusted-provisioning preflight with domain-time skew guard"
  - "Source-only evidence manifests for SRV-01, SRV-03, SRV-12, and TST-05"

affects:
  - 01-13
  - 01-14
  - 01-16
  - 01-21

actuals:
  tokens: 73329
  tasks: 3
  commits: 5

tech-stack:
  added:
    - "rustls-ldap (renamed rustls 0.21.12) for ldap3 TLS CA loading"
    - "rustls-pemfile 1.0.4 for AD CA certificate parsing"
  patterns:
    - "Fail-closed provider validation before migration/listener binding"
    - "Dual-DC independent LDAPS corroboration with GUID/SID/DNS/domain/enabled equality"
    - "Route-role middleware using rustls peer identity, no forwarded headers"
    - "Runtime-secret-provider token handoff with no stdout/argv/env-file/evidence exposure"

key-files:
  created:
    - "scripts/lab/Invoke-TrustedProvisioning.ps1"
    - "evidence/phase1/01-23-srv-01.json"
    - "evidence/phase1/01-23-srv-03.json"
    - "evidence/phase1/01-23-srv-12.json"
    - "evidence/phase1/01-23-tst-05.json"
  modified:
    - "crates/dlp-server/src/ad.rs"
    - "crates/dlp-server/src/enrollment.rs"
    - "crates/dlp-server/src/lib.rs"
    - "crates/dlp-server/src/routes.rs"
    - "crates/dlp-server/src/tls.rs"
    - "crates/dlpctl/src/lib.rs"
    - "Cargo.lock"
    - "config/server.env.example"
    - "tests/e2e/server_enrollment.rs"
    - "evidence/phase1/requirement-matrix.yaml"

key-decisions:
  - "Production startup must construct and validate every provider (directory, PostgreSQL pool, certificate issuer, signer, repository, services, TLS paths) before running migrations or binding the listener."
  - "Bootstrap peer identity may be absent only at the TLS boundary; administrator and device route middleware require verified certificate roles."
  - "Trusted provisioning hands the one-time token only to a runtime secret provider; it is never written to stdout, argv, environment files, logs, Debug output, or evidence."

patterns-established:
  - "DirectoryVerifier trait seam: production LdapDirectoryAdapter and test stubs share the same fail-closed corroboration contract."
  - "Renamed rustls dependency (rustls-ldap) resolves version mismatch between server TLS (0.23) and ldap3 internal TLS (0.21) without affecting other crates."
  - "PowerShell preflight asserts execution machine, target, privilege digest, domain time skew, dual-DC equality, and Kerberos-over-HTTPS CIM before invoking dlpctl."

requirements-completed:
  - SRV-01
  - SRV-03
  - SRV-12
  - TST-05

coverage:
  - id: D1
    description: "Production directory adapter corroborates LAB-CLIENT01 against two configured DCs over hostname LDAPS and denies single, disabled, disagreeing, or wrong-domain results."
    requirement: SRV-03
    verification:
      - kind: integration
        ref: "tests/e2e/server_enrollment.rs#production_directory_contract_requires_two_hostname_results_and_denies_failures"
        status: pass
      - kind: unit
        ref: "crates/dlp-server/src/ad.rs#requires_two_hostname_verified_ldaps_endpoints_to_agree"
        status: pass
    human_judgment: false

  - id: D2
    description: "TLS route partition exposes bootstrap enrollment with optional peer certificate and enforces administrator/device certificate roles on provisioning/configuration/health routes."
    requirement: SRV-01
    verification:
      - kind: integration
        ref: "tests/e2e/server_enrollment.rs#production_route_contract_partitions_bootstrap_admin_and_active_device_access"
        status: pass
      - kind: integration
        ref: "tests/e2e/server_enrollment.rs#mtls_routes_reject_cross_role_revoked_and_forwarded_identities"
        status: pass
    human_judgment: false

  - id: D3
    description: "Production startup constructs all runtime providers from mounted secrets and environment variables, validates them, and fails closed before migration or listener binding."
    requirement: SRV-12
    verification:
      - kind: integration
        ref: "tests/e2e/server_enrollment.rs#production_startup_contract_constructs_runtime_providers_before_binding"
        status: pass
      - kind: unit
        ref: "crates/dlp-server/src/lib.rs#production_state_rejects_missing_required_providers"
        status: pass
    human_judgment: false

  - id: D4
    description: "dlpctl provision-device is a typed administrator-mTLS client that rejects raw serial/MAC arguments and hands the plaintext token only to a runtime secret provider."
    requirement: SRV-03
    verification:
      - kind: unit
        ref: "crates/dlpctl/src/lib.rs#provisioning_client_hands_plaintext_token_only_to_runtime_secret_provider"
        status: pass
      - kind: unit
        ref: "crates/dlpctl/src/lib.rs#provisioning_request_rejects_raw_machine_observations_and_redacts_token"
        status: pass
      - kind: command
        ref: "cargo tree --locked -p dlpctl -i reqwest@0.13.4"
        status: pass
    human_judgment: false

  - id: D5
    description: "Invoke-TrustedProvisioning.ps1 restricts execution to LAB-DC01, validates domain time skew, corroborates both DCs, collects the normalized v1 fingerprint over Kerberos WinRM HTTPS, and invokes dlpctl without exposing secrets."
    requirement: TST-05
    verification:
      - kind: integration
        ref: "tests/e2e/server_enrollment.rs#trusted_provisioning_preflight_requires_named_lab_roles_and_kerberos_tls"
        status: pass
      - kind: integration
        ref: "tests/e2e/server_enrollment.rs#trusted_provisioning_preflight_compares_both_domain_controllers"
        status: pass
      - kind: integration
        ref: "tests/e2e/server_enrollment.rs#trusted_provisioning_preflight_rejects_excessive_domain_time_skew"
        status: pass
    human_judgment: false

duration: 45min
completed: 2026-08-16
status: complete
---

# Phase 1 Plan 23: Production TLS/Routes and Trusted Provisioning Summary

**Production directory corroboration, TLS route partitions, mandatory provider composition, typed administrator-mTLS provisioning client, and LAB-DC01 dual-DC/Kerberos provisioning preflight.**

## Performance

- **Duration:** 45 min
- **Started:** 2026-08-15T18:00:00Z
- **Completed:** 2026-08-16T18:30:00Z
- **Tasks:** 3
- **Files modified:** 14

## Accomplishments

- Added `DirectoryVerifier` async trait and `LdapDirectoryAdapter` that queries two configured hostname LDAPS DCs, verifies GUID/SID/DNS/domain/enabled equality, and denies single, disabled, disagreeing, or misconfigured results.
- Made `LdapDirectoryAdapter` mandatory in `ProductionProviders::from_environment` and `validate_providers`, ensuring no default/test provider path can start production.
- Partitioned TLS/route authentication so bootstrap enrollment accepts an optional peer certificate, administrator provisioning requires a verified administrator issuer, and configuration/health require an active device certificate with URI-SAN serial lookup.
- Completed `dlpctl provision-device` as a typed reqwest@0.13.4 administrator-mTLS client that accepts only normalized identity/digest input and hands the plaintext token to a runtime secret provider.
- Hardened `scripts/lab/Invoke-TrustedProvisioning.ps1` with real `w32tm /stripchart` domain-time skew validation, LAB-DC01 role guard, dual-DC `Get-ADComputer` corroboration, and Kerberos WinRM-over-HTTPS CIM fingerprint collection.
- Published source-only Phase 1 evidence for SRV-01, SRV-03, SRV-12, and TST-05 and updated `evidence/phase1/requirement-matrix.yaml`.

## Task Commits

1. **Task 1: Wire one bootstrap enrollment through production TLS, directory, PostgreSQL, and PKI** - `ca9004e` (test)
2. **Task 1 (continued)** - `b3de10e` (feat)
3. **Task 1 (continued)** - `e86a745` (style)
4. **Task 3: Build the LAB-DC01 dual-DC and Kerberos provisioning preflight** - `e18bafe` (feat)

**Plan metadata:** pending final docs commit

## Files Created/Modified

- `crates/dlp-server/src/ad.rs` - `DirectoryVerifier` trait and `LdapDirectoryAdapter` with dual-DC LDAPS corroboration.
- `crates/dlp-server/src/enrollment.rs` - Injected directory verifier into `EnrollmentService` and calls corroboration before repository transaction.
- `crates/dlp-server/src/lib.rs` - Mandatory production provider composition and validation; re-exported directory types.
- `crates/dlp-server/src/routes.rs` - Bootstrap/admin/device route partitions and role-enforcing middleware.
- `crates/dlp-server/src/tls.rs` - Peer identity extraction and issuer/profile distinction.
- `crates/dlpctl/src/lib.rs` - Typed `provision-device` client with runtime-secret-provider token handoff.
- `Cargo.lock` - Locked rustls-ldap (renamed rustls 0.21.12) and rustls-pemfile 1.0.4.
- `config/server.env.example` - Added `DLP_AD_DOMAIN` and commented provisioning admin CA path.
- `scripts/lab/Invoke-TrustedProvisioning.ps1` - LAB-DC01 dual-DC/Kerberos WinRM HTTPS provisioning preflight.
- `tests/e2e/server_enrollment.rs` - Route, directory, and trusted-provisioning contract tests.
- `evidence/phase1/01-23-srv-01.json`, `01-23-srv-03.json`, `01-23-srv-12.json`, `01-23-tst-05.json` - Published evidence manifests.
- `evidence/phase1/requirement-matrix.yaml` - Updated current evidence IDs and statuses.

## Decisions Made

- **Production startup must validate every provider before migration or listener binding.** This prevents a missing directory, TLS material, or signing key from silently selecting an in-memory default.
- **Bootstrap peer identity is optional only at the TLS connection boundary.** Administrator and device routes enforce verified certificate roles in middleware and never accept forwarded identity headers.
- **Trusted provisioning token is handed only to a runtime secret provider.** The token never appears in stdout, argv, environment files, logs, Debug output, or evidence structures.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- `cargo test --locked` initially failed because `Cargo.lock` was stale after adding `rustls-ldap` and `rustls-pemfile`; resolved by running `cargo check -p dlp-server` to refresh the lockfile.
- `rustls_pemfile::certs` returns `Result<Vec<Vec<u8>>, _>` rather than an iterator of `Result`; fixed by collecting the vector before iterating.
- `rustls_ldap::ClientConfig::builder()...with_no_client_auth()` returns `ClientConfig` directly, not `Result`; removed the erroneous `.map_err(...)`.
- `ldap3::SearchResult` is a tuple struct, so `let (entries, _result) = ...` failed; fixed by binding the struct and accessing `.0`.
- Clippy rejected `LdapDirectoryAdapter::new` for having 8 arguments; added `#[allow(clippy::too_many_arguments)]` because the constructor maps directly to required environment variables.

## User Setup Required

None - no external service configuration required for this source-only plan.

## Next Phase Readiness

- Plan 01-13 can now deploy the management server on LAB-DC01 against LAB-SERVER01 PostgreSQL and execute the approved trusted provisioning procedure before enrollment.
- All route, TLS, directory, provider, and provisioning client source artifacts are complete and tested.

## Self-Check: PASSED

- `01-23-SUMMARY.md` exists.
- Task commits `ca9004e`, `b3de10e`, `e86a745`, and `e18bafe` exist.
- Evidence manifests exist and are validated by `Test-Phase1Evidence`.
- Requirement matrix updated.
- All verification commands passed.

---
*Phase: 01-first-encrypted-drive-vertical-slice*
*Completed: 2026-08-16*
