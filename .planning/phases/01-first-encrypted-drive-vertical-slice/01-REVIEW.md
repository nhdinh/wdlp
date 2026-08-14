---
phase: 01-first-encrypted-drive-vertical-slice
reviewed: 2026-08-14T19:52:43Z
depth: deep
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
  warning: 4
  info: 0
  total: 9
status: issues_found
---

# Phase 01: Code Review Report

**Reviewed:** 2026-08-14T19:52:43Z
**Depth:** deep
**Files Reviewed:** 68
**Status:** issues_found

## Summary

The attempted reset-script fix is present: `Reset-DlpPostgres.py` now pins a known SSH host key, confines PostgreSQL identifiers, and passes password and SQL through SSH stdin. The prior focused suite now passes (82 tests). The full workspace run executes 104 passing tests but ends nonzero because the out-of-scope `dlp-windows-drive` `mounted_smoke` process terminates with `0xc06d007e` after the WinFsp delay-load warning.

The vertical slice is still not shippable. Five authority and credential-custody blockers remain unchanged in the live worktree: real bootstrap enrollment cannot match a provisioned authority row; directory corroboration is never used to provision; replacement enrollment cannot supply its active serial; credential ACL verification remains insufficient; and administrator authorization is inferred from the issuing CA subject. Four verification and test-reliability warnings also remain.

## Narrative Findings (AI reviewer)

## Critical Issues

### CR-01 [BLOCKER]: Bootstrap enrollment fabricates observations that cannot match the authority row

**File:** `crates/dlp-server/src/routes.rs:247-265`

**Issue:** The unauthenticated enrollment route creates a `ProvisionDeviceRequestV1` with an all-zero fingerprint, GUID, and SID and fixed DNS/domain values. `PgAuthorityRepository::consume_and_activate` compares the full request to the administrator-provisioned row. Therefore, a production provisioned device cannot complete bootstrap enrollment. The route test passes only because `RouteState::for_test()` uses a test service that does not exercise the PostgreSQL comparison.

**Fix:** Change the enrollment contract so the locked authority row supplies the trusted provisioned observations. The bootstrap input should contain only device ID, one-time token, CSR, and any required prior serial; never synthesize identity observations in the route.

### CR-02 [BLOCKER]: Directory corroboration is disconnected from the provisioning authority path

**File:** `crates/dlp-server/src/lib.rs:128-146,168-185,215-217`; `crates/dlp-server/src/routes.rs:292-305`

**Issue:** Production composition creates `RuntimeDirectory`, but its trait has no operation and the verifier is not injected into `AdminProvisioningService`. The provisioning route accepts administrator-supplied GUID, SID, and fingerprint values and uses fixed DNS/domain strings. As a result, an accepted administrator certificate can create authority records for arbitrary device identity facts without either configured LDAPS controller being consulted.

**Fix:** Give `DirectoryVerifier` an async corroboration method, inject it into the provisioning service, and construct the persisted identity strictly from two-controller corroboration plus a trusted station fingerprint. Fail closed when directory configuration is absent for provisioning.

### CR-03 [BLOCKER]: Replacement enrollment never provides the active credential serial

**File:** `crates/dlp-windows-service/src/service.rs:159-184`

**Issue:** `ensure_credential` calls `EnrollmentCoordinator::startup(..., None)` whenever protection validation fails. The server requires a replacement request's prior serial to equal the active serial. A damaged or expired credential thus cannot be replaced, while any decryptable credential is immediately accepted as `Existing` with no renewal flow.

**Fix:** Validate and load the existing credential before renewal, extract and send its serial in a dedicated replacement-enrollment flow, and define a separate authenticated recovery/re-provisioning path for irrecoverable credentials.

### CR-04 [BLOCKER]: Machine-DPAPI credential custody is bypassable through incomplete ACL validation

**File:** `crates/dlp-windows-service/src/credential.rs:193-205,235-247,321-323,388-433`

**Issue:** Startup's `validate_protection` decrypts the blob without ACL validation. The later `validate_acl` checks only that SYSTEM owns the file, not its DACL; it neither protects nor validates the containing directory; and `enforce_acl` silently succeeds when the service SID cannot be obtained. The file is also first written and renamed with inherited access before the DACL is set. On Windows, machine-scope DPAPI does not prevent another local principal with file access from reading or replacing the blob.

**Fix:** Fail closed when the service SID cannot be resolved. Create and validate both credential directory and file with a protected DACL granting only SYSTEM and the service SID before persistence/decryption; validate the DACL (not merely owner) in every load and protection-check path.

### CR-05 [BLOCKER]: Any leaf chained to the administrator CA is a provisioning administrator

**File:** `crates/dlp-server/src/tls.rs:174-209,376-383`

**Issue:** After rustls accepts a client chain, `IdentityRoots::peer_identity` assigns the Administrator role solely when the leaf issuer's display string equals the configured administrator CA subject. It does not enforce an administrator EKU, a constrained SAN/subject, the exact CA key, or an administrator allowlist/role. `require_administrator` then authorizes this role for provisioning. Any unrelated client-auth certificate issued under that CA can mint enrollment tokens and authority rows.

**Fix:** Define and verify a dedicated administrator certificate profile: exact trust anchor/key, client-auth EKU, and a provisioning-admin SAN/subject policy. Authorize the resulting principal against an explicit allowlist or directory role before adding `AuthenticatedAdmin`.

## Warnings

### WR-01 [WARNING]: Persisted configurations are returned after restart without complete re-verification

**File:** `crates/dlp-agent-core/src/config_cache.rs:171-192,217-226`

**Issue:** `current_bundle` and `lkg_bundle` deserialize a stored bundle and compare only its content digest to the pointer. They do not invoke `ConfigurationVerifier` or recheck trusted key ID, signature, audience, schema, or monotonic version. An attacker able to modify both pointer and staging files can make a substituted configuration appear current after restart.

**Fix:** Require the verifier and expected device/version state for cache reads, then perform the same full activation validation sequence before returning persisted bundles.

### WR-02 [WARNING]: Existing device credentials are not bound to the configured device or validated for expiry

**File:** `crates/dlp-windows-service/src/service.rs:164-184`

**Issue:** Any decryptable credential with a non-empty key becomes `EnrollmentMode::Existing`. The service neither compares its device ID to `config.device_id` nor cryptographically validates its certificate chain, key binding, profile, or lifetime before constructing the mTLS client. A stale or wrong-device identity reaches runtime and fails only later during transport.

**Fix:** Parse and validate the credential chain against the configured root, device ID, serial/key binding, EKU, and validity period before selecting `Existing`; enter an explicit replacement flow when it is expired or invalid.

### WR-03 [WARNING]: Enrollment response validation compares a textual root subject instead of validating the chain

**File:** `crates/dlp-agent-core/src/client.rs:341-356`

**Issue:** `validate_device_chain` accepts the response when any certificate in it has the same textual subject as the configured root. It neither verifies certificate signatures nor anchors the path to the exact trusted root DER/public key. A same-subject chain can be persisted as the device identity and later authenticate to the wrong issuer or simply fail mTLS.

**Fix:** Use rustls/webpki path validation anchored in the configured root certificate and enforce leaf EKU, SAN, validity, and generated-CSR key binding on the verified chain.

### WR-04 [WARNING]: Enrollment E2E tests still depend on ambient PKI and do not cover the real enrollment path

**File:** `tests/e2e/server_enrollment.rs:33-50,351-376`

**Issue:** The fixture helper writes CA/server material only if environment variables are supplied; on a clean checkout it then fails when reading the missing device issuing CA. The route test sends a placeholder CSR and asserts only `200 OK` against `RouteState::for_test()`, so it cannot detect the production authority-row mismatch, response parsing, replacement serial flow, or PostgreSQL persistence failure.

**Fix:** Generate a complete isolated root, issuing CA, server, administrator, and device fixture in the test. Exercise router-to-client enrollment with the real repository adapter (or a faithful transactional test adapter), assert the returned credential body is parseable, then cover replacement and configuration fetches.

---

_Reviewed: 2026-08-14T19:52:43Z_
_Reviewer: the agent (gsd-code-reviewer)_
_Depth: deep_
