---
phase: 01-first-encrypted-drive-vertical-slice
reviewed: 2026-08-15T00:00:00Z
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
  critical: 7
  warning: 6
  info: 0
  total: 13
status: issues_found
---

# Phase 01: Code Review Report

**Reviewed:** 2026-08-15T00:00:00Z
**Depth:** standard (with cross-file call-path tracing)
**Files Reviewed:** 68
**Status:** issues_found

## Summary

All 68 scoped files were reviewed, including the server-to-agent enrollment, TLS, configuration-cache, DPAPI, log-service, and lab-provisioning call paths. The implementation has ship-blocking authorization and secret-custody failures. Passing unit tests do not exercise the production directory, database, certificate, or deployment authority paths (`cargo test -p dlp-agent-core -p dlp-server -p dlp-log-debug-service -p dlpctl -p dlp-windows-service`: 89 passed).

## Narrative Findings (AI reviewer)

## Critical Issues

### CR-01 [BLOCKER]: Production provisioning never performs directory corroboration

**File:** `crates/dlp-server/src/lib.rs:128-174, 216-250`; `crates/dlp-server/src/enrollment.rs:201-225`; `crates/dlp-server/src/routes.rs:266-309`
**Issue:** `RuntimeDirectory` is an empty marker trait and is never passed to `AdminProvisioningService`. The route persists caller-supplied GUID, SID, and fingerprint without an LDAP lookup or two-controller comparison; `LdapDirectoryVerifier::corroborate_computer` has no production caller.
**Fix:** Make the directory-verifier trait expose corroboration, inject it into provisioning, derive AD attributes from two matching LDAPS results, and fail closed on lookup failure.

### CR-02 [BLOCKER]: Replacement enrollment cannot provide its required active serial

**File:** `crates/dlp-windows-service/src/service.rs:159-173`
**Issue:** A failed credential check invokes `EnrollmentCoordinator::startup(..., None)`, while `PgAuthorityRepository::consume_and_activate` requires the active serial to replace an existing credential. Expired or damaged credentials therefore cannot renew, and a decryptable blob is treated as existing without profile verification.
**Fix:** Validate and load the prior credential, send its serial for replacement, and provide a separately authenticated recovery/re-provisioning path for unrecoverable credentials.

### CR-03 [BLOCKER]: DPAPI credential custody fails open before ACL protection

**File:** `crates/dlp-windows-service/src/credential.rs:175-247, 311-505`; `scripts/lab/Invoke-Client01Runtime.ps1:1073-1083`
**Issue:** The credential directory and temporary file are created with inherited access, then hardened only after rename. Missing service-SID discovery silently skips both enforcement and validation; the installer never enables a service SID. A local principal can copy a machine-DPAPI blob before hardening and decrypt it under machine scope.
**Fix:** Configure the service SID at installation, fail closed if it cannot be resolved, create the directory and temporary file with SYSTEM/service-SID-only DACLs before writing, and validate directory and file DACLs on every use.

### CR-04 [BLOCKER]: Any certificate under the administrator CA receives administrator authority

**File:** `crates/dlp-server/src/tls.rs:174-210, 449-494`
**Issue:** Administrator identity is determined from issuer-subject text after a chain is accepted. There is no administrator EKU, constrained SAN/subject, exact-anchor key pin, allowlist, or directory role mapping before `AuthenticatedAdmin` authorizes provisioning.
**Fix:** Define and validate a dedicated administrator client-certificate profile against the exact anchor, then map only an allowlisted identity or directory role to administrator capability.

### CR-05 [BLOCKER]: Log authorization has a check-to-open path race

**File:** `crates/dlp-log-debug-service/src/paths.rs:56-65`; `crates/dlp-log-debug-service/src/http.rs:168-176`; `crates/dlp-log-debug-service/src/tail.rs:22-40`
**Issue:** The service canonicalizes and authorizes one pathname, then reopens it in `read_bounded_tail`. A writer able to replace that file with a reparse point/symlink between the two operations can disclose a file outside the allowlist.
**Fix:** Open once with platform APIs that reject reparse-point traversal, validate the opened handle's identity and parent, and read through that same handle.

### CR-06 [BLOCKER]: Agent enrollment token is persisted and emitted in diagnostics

**File:** `scripts/lab/Invoke-Client01Runtime.ps1:1042-1058, 1108-1123, 1145-1166`
**Issue:** The one-time enrollment token is written to `C:\dlp\agent\agent.env`, persisted in the service registry environment, then the full file is copied into `$diag.env_file` and printed when service start fails. No restrictive DACL is applied. An unprivileged local reader or anyone receiving deployment diagnostics can race the intended endpoint and redeem the token with its own CSR.
**Fix:** Do not place enrollment tokens in a readable env file or service registry. Use a short-lived SYSTEM/service-SID-only secret file or protected runtime provider, redact diagnostics, and remove the token before starting the service.

### CR-07 [BLOCKER]: Management-server deployment writes private keys and credentials with inherited ACLs

**File:** `scripts/lab/Invoke-Dc01Server.ps1:353-361, 384-402`; `scripts/lab/Invoke-Client01Runtime.ps1:423-431, 512-529`
**Issue:** Deployment creates `C:\dlp\secrets` and `C:\dlp\server\server.env` without setting DACLs, then writes the device-issuing CA private key, server private key, AD bind password, database URL, and configuration signing seed. On a fresh directory these inherit broad parent permissions, exposing material that can issue device certificates or sign policy.
**Fix:** Create these directories with protected SYSTEM/service-account-only DACLs before any writes, set restrictive ACLs on each secret file, and verify the ACLs before launching the server. Keep secrets out of diagnosable env files where possible.

## Warnings

### WR-01 [WARNING]: Cached configuration is trusted after restart without signature verification

**File:** `crates/dlp-agent-core/src/config_cache.rs:177-226`
**Issue:** `current_bundle` and `lkg_bundle` deserialize a pointed bundle and compare only its digest. They do not invoke `ConfigurationVerifier` or re-check key ID, signature, audience, schema, or monotonic version; a local replacement can become current after restart.
**Fix:** Require the verifier and expected device/version state for reads and repeat the complete activation validation before returning persisted bundles.

### WR-02 [WARNING]: Existing credentials are not validated for binding or validity

**File:** `crates/dlp-windows-service/src/service.rs:164-184`
**Issue:** Any decryptable non-empty blob chooses `Existing`. It does not validate certificate chain, private-key match, client EKU, URI SAN/device binding, or expiry before building the mTLS client.
**Fix:** Parse and validate the stored credential against the configured root, device ID, private key, EKU, and validity interval before accepting it.

### WR-03 [WARNING]: Enrollment response chain validation trusts a textual subject

**File:** `crates/dlp-agent-core/src/client.rs:270-363`
**Issue:** `validate_device_chain` accepts a chain when any certificate subject text equals the configured root's subject. It neither verifies signatures nor pins root DER/public-key material.
**Fix:** Use rustls/WebPKI path validation anchored to the configured root and check client EKU, URI SAN, validity, and CSR-public-key binding.

### WR-04 [WARNING]: Enrollment route tests bypass production authority and issuance paths

**File:** `tests/e2e/server_enrollment.rs:99-107, 368-443`; `crates/dlp-server/src/routes.rs:410-443`
**Issue:** Route tests use a placeholder CSR and `RouteState::for_test()`, whose enrollment and provisioning services always succeed. They cannot detect database token consumption, issuance, replacement, directory authority, or client parsing regressions.
**Fix:** Add isolated router-to-client integration tests using a real PKI fixture and transactional repository, covering initial enrollment, replacement, revocation, and invalid chains.

### WR-05 [WARNING]: TLS readiness evidence disables certificate validation

**File:** `scripts/lab/Invoke-Dc01Server.ps1:560-580, 611-629`; `scripts/lab/Invoke-Client01Runtime.ps1:1236-1255`
**Issue:** Readiness probes install `TrustAllCertsPolicy`, accepting every certificate failure while reporting validated TLS evidence. An untrusted, expired, or hostname-mismatched endpoint passes.
**Fix:** Trust or pin the Phase 1 root, probe a DNS-SAN hostname, remove the permissive policy, and add negative trust/name tests.

### WR-06 [WARNING]: The shipped debug-service example always falls back to localhost-only mode

**File:** `crates/dlp-log-debug-service/config.example.json:1-7`; `crates/dlp-log-debug-service/src/config.rs:45-64`
**Issue:** `FileConfig` requires `max_tail_lines`, but the example omits it. Parsing consequently fails and `load_runtime_config` silently uses an empty-folder localhost-only fallback instead of the documented allowlist configuration.
**Fix:** Add a positive `max_tail_lines` field to the example and test that the example itself parses into `RuntimeConfig`.

---

_Reviewed: 2026-08-15T00:00:00Z_
_Reviewer: the agent (gsd-code-reviewer)_
_Depth: standard_
