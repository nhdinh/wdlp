---
phase: 01-first-encrypted-drive-vertical-slice
reviewed: 2026-08-15T02:42:33Z
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
  warning: 5
  info: 0
  total: 12
status: issues_found
---

# Phase 01: Code Review Report

**Reviewed:** 2026-08-15T02:42:33Z
**Depth:** standard (with requested cross-file call-path tracing)
**Files Reviewed:** 68
**Status:** issues_found

## Summary

The re-review confirms that the iteration fixed the shipped debug-service example configuration, but the remaining findings are still present. The highest-risk paths are production provisioning, enrollment, TLS administrator authorization, on-disk secret custody, and log-file authorization. Test suites pass, but their route fixtures bypass the production directory, repository, and certificate-issuance paths.

Verification performed: `cargo test -p dlp-agent-core -p dlp-server -p dlp-log-debug-service -p dlpctl -p dlp-windows-service` (90 passed); all scoped PowerShell source files parse successfully.

## Narrative Findings (AI reviewer)

## Critical Issues

### CR-01 [BLOCKER]: Production provisioning never corroborates the directory record

**File:** `crates/dlp-server/src/lib.rs:128-174, 216-250`; `crates/dlp-server/src/enrollment.rs:201-226`; `crates/dlp-server/src/routes.rs:266-303`

**Issue:** `RuntimeDirectory` is an empty marker trait and is not supplied to `AdminProvisioningService`. Consequently, the provisioning route persists the administrator client's request-supplied fingerprint, GUID, and SID without an LDAP lookup or two-controller comparison. `LdapDirectoryVerifier::corroborate_computer` has no production call path. A trusted-but-overbroad administrator certificate can therefore mint an enrollment token for an arbitrary device identity and observation.

**Fix:** Give the injected directory port a corroboration operation; invoke it in `AdminProvisioningService`, construct the authority record only from two matching LDAPS results, and reject missing/unavailable directory providers before issuing a token.

### CR-02 [BLOCKER]: Replacement enrollment cannot provide the required active serial

**File:** `crates/dlp-windows-service/src/service.rs:159-173`; `crates/dlp-server/src/repository.rs:152-168`

**Issue:** When local credential validation fails, `ensure_credential` calls `EnrollmentCoordinator::startup(..., None)`. The repository requires `prior_serial` to equal the active serial, so a damaged or expired stored credential cannot be renewed. The service becomes permanently unable to recover through its advertised enrollment flow.

**Fix:** Validate and load the prior credential before renewal, pass its serial when appropriate, and define a separate authenticated reprovisioning flow for cases where the serial cannot be recovered.

### CR-03 [BLOCKER]: DPAPI credential custody is writable/readable before protection and fails open without a service SID

**File:** `crates/dlp-windows-service/src/credential.rs:175-205, 320-324, 387-391`; `scripts/lab/Invoke-Client01Runtime.ps1:1072-1094`

**Issue:** The credential directory and temporary file are created using inherited ACLs, then the final path is hardened only after the write and rename. Further, missing service-SID discovery returns success from both ACL enforcement and validation, while installation never configures a service SID. Machine-scope DPAPI lets another local principal decrypt a copied blob, so the pre-hardening interval exposes the private key.

**Fix:** Enable/configure the service SID during installation, fail closed if it cannot be resolved, and create both the directory and temporary file with protected SYSTEM/service-SID DACLs before writing. Validate the complete DACL (not only ownership) for directory and file on every use.

### CR-04 [BLOCKER]: Every non-device leaf under the administrator CA is an administrator

**File:** `crates/dlp-server/src/tls.rs:174-210, 449-494`; `crates/dlp-server/src/routes.rs:189-203`

**Issue:** The handshake trusts the configured administrator CA, then assigns administrator capability solely when the leaf's issuer subject text matches that CA's subject. There is no administrator EKU, SAN/subject profile, exact-anchor key/DER pin, or identity allowlist/role mapping. Any certificate issued by that CA that is not recognized as a device leaf can call provisioning.

**Fix:** Define a dedicated administrator client-certificate profile and validate it against the exact configured trust anchor, then authorize only an allowlisted identity or directory-backed administrator role.

### CR-05 [BLOCKER]: Log authorization has a check-to-open race

**File:** `crates/dlp-log-debug-service/src/paths.rs:56-65`; `crates/dlp-log-debug-service/src/http.rs:168-176`; `crates/dlp-log-debug-service/src/tail.rs:22-40`

**Issue:** The service canonicalizes and authorizes a pathname, then opens that pathname later in `read_bounded_tail`. A local actor able to replace it with a reparse point/symlink between those operations can cause a trusted remote client to receive a file outside the configured folder.

**Fix:** Open once with platform APIs that reject reparse traversal, validate the opened handle's final identity/parent, and read through that same handle rather than reopening by path.

### CR-06 [BLOCKER]: The enrollment token is persisted and leaked through diagnostics

**File:** `scripts/lab/Invoke-Client01Runtime.ps1:1042-1058, 1088-1094, 1122-1129, 1164-1167`

**Issue:** The one-time token is placed in `C:\dlp\agent\agent.env`, copied to the service registry `Environment` value, and emitted verbatim in start-failure diagnostics. Neither the file nor the registry value is restricted here. A local reader, or anyone who receives deployment diagnostics, can redeem the token with their own CSR before the intended endpoint does.

**Fix:** Use a short-lived SYSTEM/service-SID-only runtime secret file/provider, never copy the token into registry environment values, redact or omit the env file from diagnostics, and delete the handoff material before starting the service.

### CR-07 [BLOCKER]: Deployment writes server private keys and credentials with inherited ACLs

**File:** `scripts/lab/Invoke-Dc01Server.ps1:352-361, 398-402`; `scripts/lab/Invoke-Client01Runtime.ps1:1020-1029`

**Issue:** Deployment creates `C:\dlp\secrets` and the server env file without first applying protected DACLs, then writes the device-issuing CA private key, server key, database URL, AD bind password, and configuration-signing seed. On a fresh directory, inherited ACLs can expose material that issues device certificates or signs policy.

**Fix:** Create protected secret directories before any write, apply and verify least-privilege DACLs on every secret/env file, and run the server under the explicitly authorized service identity.

## Warnings

### WR-01 [WARNING]: Cached configurations are accepted after restart without verification

**File:** `crates/dlp-agent-core/src/config_cache.rs:176-226`

**Issue:** `current_bundle` and `lkg_bundle` only deserialize the referenced bytes and compare the embedded digest to the filename pointer. They do not verify the signature, signer key ID, audience, schema, or monotonic version. A local replacement of pointer/staging state can reactivate an old signed configuration after restart.

**Fix:** Require the configured `ConfigurationVerifier` and expected device/version state for cache reads, and run the full activation validation before returning persisted bundles.

### WR-02 [WARNING]: A decryptable credential is treated as usable without profile validation

**File:** `crates/dlp-windows-service/src/service.rs:159-184`; `crates/dlp-windows-service/src/credential.rs:235-247`

**Issue:** `validate_protection` checks only that the DPAPI blob decodes to a non-empty private key. It does not validate the device ID, private-key/certificate match, chain, client EKU, URI SAN, expiry, or even the file ACL. The service consequently selects `Existing` for an invalid identity and only fails later during network activity.

**Fix:** Parse and validate the stored credential against the configured root, device ID, key match, EKU, SAN, validity period, and expected serial before choosing `EnrollmentMode::Existing`.

### WR-03 [WARNING]: Enrollment-chain validation trusts only a textual root subject

**File:** `crates/dlp-agent-core/src/client.rs:270-356`

**Issue:** `validate_device_chain` accepts a response when any certificate in the PEM bundle has the same subject text as the configured root. It does not verify certificate signatures or pin the root DER/public key; a forged chain with a copied subject is accepted as long as the leaf profile looks plausible.

**Fix:** Use WebPKI/rustls path validation anchored to the configured root DER, then verify the leaf's client profile, exact URI SAN, validity, and CSR public-key binding.

### WR-04 [WARNING]: Enrollment tests do not exercise the production authority or issuance path

**File:** `tests/e2e/server_enrollment.rs:84-122, 350-444`; `crates/dlp-server/src/routes.rs:41-50, 410-442`

**Issue:** The tests assert source-code strings or run `RouteState::for_test()`, whose enrollment and provisioning services always succeed with a placeholder CSR. They cannot detect regressions in token consumption, database activation/revocation, certificate issuance, directory corroboration, or client-side chain validation.

**Fix:** Add a router-to-client integration suite with real PKI fixtures and a transactional PostgreSQL test database, covering initial enrollment, replacement, revocation, invalid CSR/chain, and directory disagreement.

### WR-05 [WARNING]: TLS readiness evidence explicitly disables certificate validation

**File:** `scripts/lab/Invoke-Dc01Server.ps1:560-580, 611-629`; `scripts/lab/Invoke-Client01Runtime.ps1:1233-1255`

**Issue:** The readiness probes install `TrustAllCertsPolicy`, which accepts all trust, expiry, and hostname failures, while emitting evidence that describes the connection as validated TLS. A man-in-the-middle or misconfigured endpoint therefore passes the evidence gate.

**Fix:** Trust/pin the Phase 1 root, probe a DNS-SAN hostname rather than an IP address, remove `TrustAllCertsPolicy`, and add negative trust and hostname checks.

---

_Reviewed: 2026-08-15T02:42:33Z_
_Reviewer: the agent (gsd-code-reviewer)_
_Depth: standard_
