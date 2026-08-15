---
phase: 01-first-encrypted-drive-vertical-slice
reviewed: 2026-08-15T02:08:13Z
depth: standard
files_reviewed: 68
files_reviewed_list:
  - .cargo/config.toml
  - .gitignore
  - Cargo.toml
  - check-env.ps1
  - config/agent.toml.example
  - config/lab.env.example
  - config/lab.phase1.example.yaml
  - config/lab.roles.example.json
  - config/server.env.example
  - crates/dlp-agent-core/Cargo.toml
  - crates/dlp-agent-core/src/client.rs
  - crates/dlp-agent-core/src/config_cache.rs
  - crates/dlp-agent-core/src/enrollment.rs
  - crates/dlp-agent-core/src/health.rs
  - crates/dlp-agent-core/src/lib.rs
  - crates/dlp-agent-core/tests/enrollment_activation.rs
  - crates/dlp-log-debug-service/Cargo.toml
  - crates/dlp-log-debug-service/config.example.json
  - crates/dlp-log-debug-service/src/config.rs
  - crates/dlp-log-debug-service/src/http.rs
  - crates/dlp-log-debug-service/src/lib.rs
  - crates/dlp-log-debug-service/src/main.rs
  - crates/dlp-log-debug-service/src/paths.rs
  - crates/dlp-log-debug-service/src/service.rs
  - crates/dlp-log-debug-service/src/tail.rs
  - crates/dlp-log-debug-service/tests/endpoint_contract.rs
  - crates/dlp-log-debug-service/tests/service_contract.rs
  - crates/dlp-protocol/src/lib.rs
  - crates/dlp-server/Cargo.toml
  - crates/dlp-server/src/ad.rs
  - crates/dlp-server/src/enrollment.rs
  - crates/dlp-server/src/lib.rs
  - crates/dlp-server/src/main.rs
  - crates/dlp-server/src/pki.rs
  - crates/dlp-server/src/repository.rs
  - crates/dlp-server/src/routes.rs
  - crates/dlp-server/src/tls.rs
  - crates/dlp-windows-service/Cargo.toml
  - crates/dlp-windows-service/src/credential.rs
  - crates/dlp-windows-service/src/fingerprint.rs
  - crates/dlp-windows-service/src/service.rs
  - crates/dlpctl/Cargo.toml
  - crates/dlpctl/src/lib.rs
  - crates/dlpctl/src/main.rs
  - deploy/compose.yaml
  - evidence/phase1/README.md
  - evidence/phase1/manifests/tst-01-portable-policy.json
  - evidence/phase1/requirement-matrix.yaml
  - evidence/phase1/schema/evidence-manifest.schema.json
  - migrations/202608070002_enrollment_authority.sql
  - migrations/202608070003_authenticated_routes.sql
  - scripts/evidence/Phase1.Evidence.Tests.ps1
  - scripts/evidence/Phase1.Evidence.psm1
  - scripts/evidence/Phase1.Privilege.Tests.ps1
  - scripts/lab/Debug-Fingerprint.ps1
  - scripts/lab/Initialize-DlpEnvironment.ps1
  - scripts/lab/Invoke-Client01Runtime.ps1
  - scripts/lab/Invoke-Dc01Server.ps1
  - scripts/lab/Invoke-Phase1EnvironmentReconcile.ps1
  - scripts/lab/Invoke-TrustedProvisioning.ps1
  - scripts/lab/README.md
  - scripts/lab/Reset-DlpPostgres.py
  - scripts/lab/Set-DlpEnvironment.ps1
  - scripts/verify-phase1-evidence.ps1
  - tests/e2e/compose.rs
  - tests/e2e/server_enrollment.rs
  - tests/windows/Invoke-AgentServiceSmoke.ps1
  - tests/windows/Test-DlpLogDebugRunbookSyntax.ps1
findings:
  critical: 5
  warning: 5
  info: 0
  total: 10
status: issues_found
---

# Phase 01: Code Review Report

**Reviewed:** 2026-08-15T02:08:13Z
**Depth:** standard
**Files Reviewed:** 68
**Status:** issues_found

## Summary

Final re-review of the live worktree confirms that CR-01, CR-06, CR-07, and WR-06 remain fixed. The ten findings below remain reproducible: they leave provisioning/enrollment authority unauthenticated or unavailable, and weaken credential, configuration, or TLS trust boundaries.

`cargo test -p dlp-agent-core -p dlp-server -p dlp-log-debug-service -p dlpctl -p dlp-windows-service` passed (89 tests, 21 suites), and `git diff --check` passed. `cargo fmt --check` reports worktree formatting drift; it is not a correctness or security finding.

## Narrative Findings (AI reviewer)

## Critical Issues

### CR-02 [BLOCKER]: Production provisioning never performs directory corroboration

**File:** `crates/dlp-server/src/lib.rs:128-174,216-250`; `crates/dlp-server/src/enrollment.rs:201-225`; `crates/dlp-server/src/routes.rs:266-309`
**Issue:** `RuntimeDirectory` implements an empty marker trait and is never passed to `AdminProvisioningService`; that service writes the administrator request straight to PostgreSQL. The production route therefore accepts caller-provided GUID, SID, and fingerprint without an LDAP lookup or two-controller corroboration. `LdapDirectoryVerifier::corroborate_computer` has no production caller.
**Fix:** Give `DirectoryVerifier` a real lookup/corroboration operation, inject it into provisioning, derive all AD fields from matching results from both configured LDAPS servers, and fail closed when unavailable.

### CR-03 [BLOCKER]: Replacement enrollment cannot supply the active credential serial

**File:** `crates/dlp-windows-service/src/service.rs:159-173`
**Issue:** A failed protection check always calls `EnrollmentCoordinator::startup(..., None)`. The server requires the active serial for a replacement, so an expired or damaged credential cannot renew. A merely decryptable credential is accepted as `Existing` without lifetime or profile verification.
**Fix:** Validate the stored credential first, extract and send its serial on the renewal path, and define an authenticated recovery/re-provisioning flow for unrecoverable credentials.

### CR-04 [BLOCKER]: DPAPI credential custody is bypassable through ACL handling

**File:** `crates/dlp-windows-service/src/credential.rs:175-247,311-505`
**Issue:** The credential directory and temporary file are created with inherited access before ACL hardening. `validate_protection` decrypts without calling `validate_acl`; `validate_acl` checks only SYSTEM ownership, not the DACL or parent directory; and a missing service SID makes both ACL functions silently succeed. A local principal with file access can replace or decrypt the machine-scope DPAPI blob.
**Fix:** Fail closed if the service SID cannot be resolved. Create and validate protected directory/file DACLs for SYSTEM plus the service SID before persistence or decryption, and validate those DACLs on every load/protection path.

### CR-05 [BLOCKER]: Any certificate under the administrator CA is an administrator

**File:** `crates/dlp-server/src/tls.rs:174-210,449-494`
**Issue:** Administrator identity is assigned from an issuer-subject string alone after a leaf chains to either configured root. There is no administrator EKU, constrained SAN/subject, exact trust-anchor key, or allowlist/role mapping before `AuthenticatedAdmin` authorizes provisioning.
**Fix:** Validate a dedicated administrator client-certificate profile against the exact anchor, then map an allowed identity or directory role before granting the administrator capability.

### CR-08 [BLOCKER]: Log authorization has a canonicalization-to-open race

**File:** `crates/dlp-log-debug-service/src/paths.rs:56-65`; `crates/dlp-log-debug-service/src/http.rs:168-176`; `crates/dlp-log-debug-service/src/tail.rs:22-40`
**Issue:** The service canonicalizes and authorizes a pathname, then re-opens it in `read_bounded_tail`. A writer able to replace the checked file with a reparse point/symlink between those operations can disclose an outside file.
**Fix:** Open once with platform APIs that reject reparse-point traversal and validate handle identity/parent before reading; never authorize one pathname and subsequently reopen it.

## Warnings

### WR-01 [WARNING]: Cached configuration is trusted after restart without signature verification

**File:** `crates/dlp-agent-core/src/config_cache.rs:177-226`
**Issue:** `current_bundle` and `lkg_bundle` only deserialize and compare content digest to the pointer. They do not call `ConfigurationVerifier` or re-check key ID, signature, audience, schema, and monotonic version. A local replacement of the pointer and staged bundle can become current after restart.
**Fix:** Require the verifier and expected device/version state on reads and run the full activation validation sequence before returning persisted bundles.

### WR-02 [WARNING]: Existing credentials are not verified for device binding or validity

**File:** `crates/dlp-windows-service/src/service.rs:164-184`
**Issue:** Any decryptable, non-empty blob selects `Existing`; the code does not compare device ID or verify chain anchoring, private-key match, EKU, or expiry before constructing the mTLS client.
**Fix:** Parse and verify the credential against the configured root, device ID, private key, EKU, and validity period before accepting it.

### WR-03 [WARNING]: Enrollment response chain check trusts only a textual subject

**File:** `crates/dlp-agent-core/src/client.rs:270-363`
**Issue:** `validate_device_chain` accepts a chain when any certificate's textual subject equals the configured root's textual subject. It does not validate signatures or pin the exact root DER/public key.
**Fix:** Perform WebPKI/rustls path validation anchored to the configured root, including client EKU, URI SAN, validity, and CSR-public-key binding.

### WR-04 [WARNING]: Enrollment E2E tests bypass every production authority and issuance path

**File:** `tests/e2e/server_enrollment.rs:1-7,99-107`; `crates/dlp-server/src/routes.rs:410-443`
**Issue:** The route tests use a placeholder CSR and `RouteState::for_test()`, whose services always succeed. They cannot detect authority-row mismatches, PostgreSQL token consumption, certificate issuance, replacements, or client response parsing.
**Fix:** Exercise router-to-client enrollment with an isolated PKI fixture and transactional repository implementing production authority semantics; cover initial and replacement flows.

### WR-05 [WARNING]: TLS readiness evidence disables certificate validation

**File:** `scripts/lab/Invoke-Dc01Server.ps1:560-580,611-629`; `scripts/lab/Invoke-Client01Runtime.ps1:1236-1255`
**Issue:** The probes install `TrustAllCertsPolicy`, which accepts every certificate failure, while emitting evidence that TLS was validated. An untrusted, expired, or hostname-mismatched endpoint passes.
**Fix:** Trust/pin the Phase 1 root CA, probe a DNS SAN hostname, remove the permissive policy, and add negative tests for untrusted roots and name mismatches.

---

_Reviewed: 2026-08-15T02:08:13Z_
_Reviewer: the agent (gsd-code-reviewer)_
_Depth: standard_
