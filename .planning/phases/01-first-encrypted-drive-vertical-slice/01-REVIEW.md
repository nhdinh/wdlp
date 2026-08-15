---
phase: 01-first-encrypted-drive-vertical-slice
reviewed: 2026-08-15T01:50:02Z
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
  critical: 8
  warning: 6
  info: 0
  total: 14
status: issues_found
---

# Phase 01: Code Review Report

**Reviewed:** 2026-08-15T01:50:02Z
**Depth:** standard (requested `deep`; reduced by the workflow's large-scope safeguard)
**Files Reviewed:** 68
**Status:** issues_found

## Summary

The persisted 68-file scope was re-reviewed against the live worktree. The prior authority, credential-custody, and certificate-validation blockers are still present. This pass also found that the trusted-provisioning workflow destroys the only enrollment-token handoff before its caller can consume it, and that the log-debug service has a check/use race that can disclose a replaced file outside its allowlist.

Targeted suites passed: `cargo test -p dlp-agent-core -p dlp-server -p dlp-log-debug-service -p dlpctl` (82 tests) and `cargo test -p dlp-windows-service` (7 tests). These tests do not exercise the production authority, Windows ACL, or provisioning handoff paths below.

## Narrative Findings (AI reviewer)

## Critical Issues

### CR-01 [BLOCKER]: Bootstrap enrollment fabricates observations that cannot match the authority row

**File:** `crates/dlp-server/src/routes.rs:247-265`

**Issue:** The unauthenticated enrollment route constructs an authority observation with zero fingerprint, GUID, and SID plus fixed DNS/domain values. `PgAuthorityRepository::consume_and_activate` compares every one of those fields to the administrator-provisioned row. A normally provisioned device therefore cannot bootstrap; the route test succeeds only because it uses `AlwaysOkEnrollmentService`.

**Fix:** Have the locked authority record provide the trusted observations. Limit bootstrap input to the device ID, one-time token, CSR, and (for replacement) prior serial; never synthesize identity facts in the HTTP handler.

### CR-02 [BLOCKER]: Directory corroboration is not connected to provisioning

**File:** `crates/dlp-server/src/lib.rs:128-146,172-185,215-217`; `crates/dlp-server/src/enrollment.rs:202-227`; `crates/dlp-server/src/routes.rs:292-305`

**Issue:** Production creates a `RuntimeDirectory`, but `DirectoryVerifier` has no verification operation and `AdminProvisioningService` never receives it. The provisioning route persists administrator-supplied GUID, SID, and fingerprint with fixed DNS/domain values, without querying either configured LDAPS server.

**Fix:** Add a real corroboration method to `DirectoryVerifier`, inject it into `AdminProvisioningService`, and derive the persisted GUID/SID/DNS/domain only from two-controller corroboration. Fail closed when that verifier is unavailable.

### CR-03 [BLOCKER]: Replacement enrollment never sends the active serial

**File:** `crates/dlp-windows-service/src/service.rs:159-173`

**Issue:** When protection validation fails, `ensure_credential` calls `EnrollmentCoordinator::startup(..., None)`. The server requires `prior_serial` to equal the active serial for a replacement, so an expired/damaged credential cannot be renewed. A decryptable credential is instead immediately treated as `Existing`, without any expiry or profile validation.

**Fix:** Load and validate the credential before replacement, extract its serial, and pass it to a dedicated renewal path. Define a separately authenticated recovery/re-provisioning path for irrecoverable credentials.

### CR-04 [BLOCKER]: Machine-DPAPI credential custody can be bypassed by ACL handling

**File:** `crates/dlp-windows-service/src/credential.rs:193-205,235-247,321-324,388-433`

**Issue:** `validate_protection` decrypts the blob before checking its ACL. `validate_acl` checks only SYSTEM ownership, never the DACL or containing directory; `enforce_acl` silently succeeds when no service SID is found; and the temporary file is written with inherited access before its ACL is applied. Machine-scope DPAPI alone permits other local principals with file access to decrypt or replace the blob.

**Fix:** Fail closed if the service SID cannot be resolved. Create and validate the credential directory and file with protected SYSTEM-plus-service-SID DACLs before persistence or decryption, and validate the actual DACL in every load/protection-check path.

### CR-05 [BLOCKER]: Any certificate under the administrator CA becomes a provisioning administrator

**File:** `crates/dlp-server/src/tls.rs:187-210,376-383`

**Issue:** `IdentityRoots::peer_identity` labels every non-device leaf whose issuer subject string matches the administrator CA subject as an administrator. It does not enforce an administrator EKU, constrained SAN/subject, exact anchor key, or an allowlist. `AuthenticatedAdmin` then authorizes that role for provisioning.

**Fix:** Verify a dedicated provisioning-administrator profile: exact administrator trust anchor/key, client-auth EKU, and a constrained SAN/subject. Map that principal through an explicit allowlist or directory role before granting `AuthenticatedAdmin`.

### CR-06 [BLOCKER]: Trusted provisioning deletes the one-time token before the caller can hand it off

**File:** `scripts/lab/Invoke-TrustedProvisioning.ps1:228-244`; `scripts/lab/Invoke-Client01Runtime.ps1:963-969`

**Issue:** The helper reads the `dlpctl` token file, deletes it, nulls `$token`, then returns JSON deliberately omitting `enrollment_token`. Its only phase caller parses that JSON and requires `$result.enrollment_token`, so every trusted-provisioning enrollment fails with `trusted_provisioning_returned_empty_token`.

**Fix:** Implement a protected handoff rather than sanitizing away the required value: transfer the token directly to LAB-CLIENT01 through the existing privileged remote session, or return it only through a secret-capable channel that the caller consumes immediately and redacts. Update the caller and tests to verify the token reaches the service environment and is removed after enrollment.

### CR-07 [BLOCKER]: The DC01 provisioning scenario cannot invoke its required administrator CA input

**File:** `scripts/lab/Invoke-Dc01Server.ps1:646-655`; `scripts/lab/Invoke-TrustedProvisioning.ps1:1-8,92-94`

**Issue:** `Invoke-TrustedProvisioning.ps1` declares mandatory `-AdminCaPem` and rejects an absent/non-PEM value, but `Invoke-TrustedProvisioningScenario` invokes it without that argument and does not pass the CA in its remote argument list. PowerShell prompts or errors before provisioning can run.

**Fix:** Resolve and validate the administrator CA in `Invoke-Dc01Server.ps1`, add it to the remote argument list, and invoke the helper with `-AdminCaPem $ProvisioningAdminCa`. Add a noninteractive regression test of this exact scenario.

### CR-08 [BLOCKER]: Log-file authorization is vulnerable to a canonicalization-to-open race

**File:** `crates/dlp-log-debug-service/src/paths.rs:56-65`; `crates/dlp-log-debug-service/src/http.rs:168-178`

**Issue:** The service canonicalizes and authorizes a requested path, returns that path, and only later opens it in `read_bounded_tail`. A principal able to replace the authorized log path between those operations can replace it with a reparse point/symlink to an outside file; the subsequent open follows the replacement and returns its contents.

**Fix:** Open the file once with platform APIs that disallow reparse-point traversal (for example `FILE_FLAG_OPEN_REPARSE_POINT` plus file-ID/parent validation), then read from that validated handle. Do not re-resolve/re-open an attacker-controlled pathname after authorization.

## Warnings

### WR-01 [WARNING]: Cached bundles are trusted after restart without cryptographic re-verification

**File:** `crates/dlp-agent-core/src/config_cache.rs:171-192,217-226`

**Issue:** `current_bundle` and `lkg_bundle` deserialize content and compare only its digest to the pointer. They do not invoke `ConfigurationVerifier` or check key ID, signature, audience, schema, and monotonic version. Replacing both the pointer and staged bundle can make a substituted configuration appear current after restart.

**Fix:** Require the verifier and expected device/version state for reads, then run the same complete validation sequence as activation before returning a persisted bundle.

### WR-02 [WARNING]: Existing credentials are not bound to this device or validated for lifetime/profile

**File:** `crates/dlp-windows-service/src/service.rs:164-184`

**Issue:** Any decryptable non-empty credential becomes `Existing`; the service does not compare its device ID to configuration or validate chain anchoring, key binding, EKU, or expiry before using it for mTLS.

**Fix:** Parse and verify the credential against the configured root, configured device ID, private key, EKU, and validity period before selecting `Existing`; use the replacement flow when it is invalid or expired.

### WR-03 [WARNING]: Enrollment response checking compares a root subject string instead of verifying the chain

**File:** `crates/dlp-agent-core/src/client.rs:341-356`

**Issue:** `validate_device_chain` accepts a response if any certificate's textual subject equals the configured root's textual subject. It does not validate signatures or anchor to the exact trusted root DER/public key.

**Fix:** Validate the chain with webpki/rustls anchored to the configured root, including leaf EKU, URI SAN, validity, and CSR-public-key binding.

### WR-04 [WARNING]: Enrollment end-to-end coverage does not exercise production issuance or authority checks

**File:** `tests/e2e/server_enrollment.rs:351-376`; `crates/dlp-server/src/routes.rs:417-449`

**Issue:** The route test sends a placeholder CSR to `RouteState::for_test()`, whose services always succeed. It cannot detect the production authority-row mismatch, CSR issuance, PostgreSQL persistence, replacement serial, or client response parsing failures.

**Fix:** Generate an isolated PKI fixture and execute router-to-client enrollment through a transactional repository adapter that enforces the production authority semantics; assert a parseable issued chain and cover replacement and configuration retrieval.

### WR-05 [WARNING]: TLS “validated” readiness evidence explicitly disables certificate validation

**File:** `scripts/lab/Invoke-Dc01Server.ps1:560-580,612-629`; `scripts/lab/Invoke-Client01Runtime.ps1:1236-1255`

**Issue:** Both probes install `TrustAllCertsPolicy`, returning true for every certificate error, yet their evidence claims “validated TLS.” An untrusted, expired, or hostname-mismatched server passes these checks.

**Fix:** Install/pin the Phase 1 root CA and call the server by its DNS SAN; remove `TrustAllCertsPolicy`. Add negative tests for an untrusted root and hostname mismatch.

### WR-06 [WARNING]: Windows service startup failure is reported as process success

**File:** `crates/dlp-windows-service/src/main.rs:45-60`

**Issue:** `main` logs `run_scm_service` failure but returns normally, yielding exit code 0. SCM/deployment automation can treat a dispatcher failure as a clean process exit.

**Fix:** Return a nonzero `ExitCode` (or a `Result` from `main`) on dispatcher failure after logging the error.

---

_Reviewed: 2026-08-15T01:50:02Z_
_Reviewer: the agent (gsd-code-reviewer)_
_Depth: standard_
