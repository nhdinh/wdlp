---
phase: 01-first-encrypted-drive-vertical-slice
reviewed: 2026-08-14T19:17:34Z
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
  critical: 8
  warning: 5
  info: 0
  total: 13
status: issues_found
---

# Phase 01: Code Review Report

**Reviewed:** 2026-08-14T19:17:34Z
**Depth:** deep
**Files Reviewed:** 68
**Status:** issues_found

## Summary

The deep review traced the enrollment, provisioning, TLS, configuration-cache, and persistence call chains. The production agent and server do not share working enrollment or configuration contracts; replacement enrollment and directory corroboration are disconnected; and credential/token custody controls are ineffective. `cargo test --workspace` also ends unsuccessfully because `dlp-windows-drive --test mounted_smoke` exits abnormally (`0xc06d007e`), despite the other suites reporting passes.

## Narrative Findings (AI reviewer)

## Critical Issues

### CR-01 [BLOCKER]: Enrollment endpoint consumes the credential and returns an empty response

**File:** `C:/Users/nhdinh/dev/dleakprevention/crates/dlp-server/src/routes.rs:260-265`

**Issue:** The route discards `IssuedDeviceCredential` and returns only `200 OK`. Its caller, `AgentHttpClient::post_enrollment`, requires a JSON object containing `credential_chain` at `crates/dlp-agent-core/src/client.rs:185-187,260-262`. A successful server enrollment therefore always fails at the client before it can persist its private key and certificate.

**Fix:** Return a versioned JSON enrollment response carrying the issued public chain, then contract-test the server route through `AgentHttpClient`.

```rust
let issued = state.enrollment_service.enroll(submission).await
    .map_err(|_| StatusCode::UNAUTHORIZED)?;
Ok(Json(EnrollmentResponse { credential_chain: issued.certificate_chain_pem }))
```

### CR-02 [BLOCKER]: Bootstrap enrollment fabricates identity observations that cannot match provisioned authority data

**File:** `C:/Users/nhdinh/dev/dleakprevention/crates/dlp-server/src/routes.rs:246-259`

**Issue:** The bootstrap handler constructs a `ProvisionDeviceRequestV1` with a zero fingerprint/GUID/SID and fixed DNS/domain values. `PgAuthorityRepository::consume_and_activate` requires all of those values to exactly equal the authority row at `crates/dlp-server/src/repository.rs:169-185`. Real provisioned devices therefore cannot enroll.

**Fix:** Make the bootstrap DTO contain only device ID, token, CSR, and optional previous serial. Load the authoritative observation by device ID inside the transactional repository and compare only server-held values there.

### CR-03 [BLOCKER]: Replacement enrollment drops the client’s prior credential serial

**File:** `C:/Users/nhdinh/dev/dleakprevention/crates/dlp-server/src/routes.rs:247-258`

**Issue:** The client serializes `prior_serial` at `crates/dlp-agent-core/src/client.rs:166-171`, but `BootstrapEnrollmentRequest` has no corresponding field (line 392) and the route always passes `None`. The repository requires `active_serial == prior_serial` before replacement at `crates/dlp-server/src/repository.rs:176-185`; replacement and revocation are consequently impossible.

**Fix:** Add a bounded hexadecimal `prior_serial` field, decode it strictly, and pass it to `EnrollmentSubmission::new`. Reject malformed serials rather than silently treating them as absent.

### CR-04 [BLOCKER]: Server configuration response is not the agent’s signed-configuration wire format

**File:** `C:/Users/nhdinh/dev/dleakprevention/crates/dlp-server/src/routes.rs:351-375`

**Issue:** The endpoint returns a JSON `ConfigurationResponse`, while `AgentConfigurationTransport` returns those raw bytes to `ConfigurationCache::deserialize_signed_configuration`, which requires the custom binary record beginning with `WIRE_FORMAT_VERSION` (`crates/dlp-agent-core/src/config_cache.rs:318-336`). The JSON `{` byte is rejected as `InvalidWireFormat`, so no polled configuration can activate.

**Fix:** Send `serialize_signed_configuration(&configuration)` with a declared binary media type, or replace the cache decoder with a strict JSON decoder that reconstructs and verifies the identical signed envelope. Cover the actual route-to-transport flow with an integration test.

### CR-05 [BLOCKER]: PostgreSQL configuration retrieval destroys the signed envelope

**File:** `C:/Users/nhdinh/dev/dleakprevention/crates/dlp-server/src/repository.rs:368-411`

**Issue:** `persist_configuration` stores `canonical_bundle`, `content_digest`, and `audience` (lines 349-360), but `selected_configuration` never reads them. It creates a new envelope with fixed timestamp `1_754_568_000` and payload `{}` (lines 391-398), then attaches the old signature (lines 405-410). On every poll after the initial creation response, the agent receives bytes whose signature/digest cannot correspond to the stored configuration.

**Fix:** Persist and retrieve a lossless signed envelope (or the existing cache wire bytes), reconstruct it exactly, validate the stored digest/audience, and test a second fetch after a server restart.

### CR-06 [BLOCKER]: Production provisioning never uses the two-controller directory verifier

**File:** `C:/Users/nhdinh/dev/dleakprevention/crates/dlp-server/src/lib.rs:215-217`

**Issue:** `RuntimeDirectory` wraps `LdapDirectoryVerifier` but implements only an empty marker trait. Nothing injects or calls `corroborate_computer`; the provisioning route instead accepts GUID, SID, and fingerprint bytes from the mTLS caller and substitutes constant DNS/domain (`crates/dlp-server/src/routes.rs:275-301`). An administrator certificate can provision arbitrary device facts without the promised independent two-DC corroboration.

**Fix:** Add an async corroboration method to `DirectoryVerifier`, make it required for the production provisioning route, obtain the two LDAPS results using the requested DNS name, and build `ProvisionDeviceRequestV1` exclusively from that verified result.

### CR-07 [BLOCKER]: Credential-custody ACL check is bypassed and does not inspect the DACL

**File:** `C:/Users/nhdinh/dev/dleakprevention/crates/dlp-windows-service/src/credential.rs:175-180,235-247,388-433`

**Issue:** Startup uses `validate_protection` (`crates/dlp-windows-service/src/service.rs:159-166`), which decrypts without calling `validate_acl`. Even paths using `load` get an inadequate check: `validate_acl` requests only `OWNER_SECURITY_INFORMATION` and accepts any DACL as long as SYSTEM owns the file. The containing directory is created with inherited ACLs and never secured. Since machine-scope DPAPI permits other local accounts to decrypt, an untrusted local account with inherited directory/file access can read or replace the credential while the service treats it as valid.

**Fix:** Secure the directory before creating files; apply a protected DACL granting only SYSTEM and the service SID; validate both file and directory DACLs before every read/decrypt; and call that validation from `validate_protection`.

### CR-08 [BLOCKER]: Provisioning material and one-time token are exposed to ordinary files and logs

**File:** `C:/Users/nhdinh/dev/dleakprevention/scripts/lab/Invoke-TrustedProvisioning.ps1:139-160,202-208,213-228`

**Issue:** The script writes the provisioning administrator key and enrollment token under `C:\dlp\provisioning` without an explicit restrictive ACL. On failure it prints the first line of every file in that directory, and on success emits the plaintext token in its JSON output (`enrollment_token = $token`). This leaks reusable credential material and a usable token to transcripts, CI captures, and inherited-ACL locations.

**Fix:** Create a protected per-run directory restricted to SYSTEM and the provisioning identity before writing any secret; never enumerate or print its contents; move the token through an approved secret provider; delete the handoff file immediately after delivery; and omit the token from all stdout/stderr objects.

## Warnings

### WR-01 [WARNING]: Persisted cache bundles are trusted after only a digest comparison

**File:** `C:/Users/nhdinh/dev/dleakprevention/crates/dlp-agent-core/src/config_cache.rs:177-189,217-226`

**Issue:** `current_bundle` and `lkg_bundle` deserialize disk bytes and compare their digest with the pointer, but do not verify the Ed25519 signature, trusted key ID, audience, or version. A modified pointer and bundle with matching digest can be returned as authenticated after restart.

**Fix:** Require `ConfigurationVerifier` for cache-load operations and repeat signature, key-ID, schema, audience, digest, and monotonic-version checks before returning a bundle.

### WR-02 [WARNING]: Cache decoder ignores the serialized API version

**File:** `C:/Users/nhdinh/dev/dleakprevention/crates/dlp-agent-core/src/config_cache.rs:324-325`

**Issue:** The decoder reads the API version into `_api_version` and never checks it. A different API version is treated as V1 if the remaining fields happen to parse.

**Fix:** Reject values other than `dlp_protocol::API_VERSION_V1` before constructing the envelope.

### WR-03 [WARNING]: Existing service credentials are neither identity- nor expiry-validated at startup

**File:** `C:/Users/nhdinh/dev/dleakprevention/crates/dlp-windows-service/src/service.rs:159-184`

**Issue:** Any decryptable blob containing a non-empty private key selects `EnrollmentMode::Existing`. `client_with_identity` only checks PEM markers; it does not compare the credential device ID to `config.device_id`, validate the certificate chain/profile, or detect expiry. A stale or wrong-device credential leaves the service running until later mTLS failures instead of triggering replacement enrollment.

**Fix:** Validate the stored chain against the configured root and device ID, including validity period and client-auth profile, before returning `Existing`; treat validation failure/expiry as replacement enrollment.

### WR-04 [WARNING]: Device-certificate acceptance relies on subject-string matching for the trust anchor

**File:** `C:/Users/nhdinh/dev/dleakprevention/crates/dlp-agent-core/src/client.rs:298-311`

**Issue:** `validate_device_chain` accepts a returned chain when any certificate’s textual subject equals the configured root’s textual subject. It does not validate the certificate path/signatures or require the configured root’s exact DER/public key. A same-subject certificate chain can be accepted as an issued device credential.

**Fix:** Build a rustls/webpki verification path anchored in the configured root certificate, enforce the expected EKU/SAN on the verified leaf, and reject chains that do not cryptographically chain to that exact anchor.

### WR-05 [WARNING]: The integration tests assert source text and in-memory stubs, not the real protocol contract

**File:** `C:/Users/nhdinh/dev/dleakprevention/tests/e2e/server_enrollment.rs:93-108,228-273`

**Issue:** The purported production tests mostly use `include_str!` checks and `RouteState::for_test()` stubs. The bootstrap test asserts only an OK status and never parses the response through `AgentHttpClient`; thus it cannot catch the missing enrollment body, dropped replacement serial, JSON/binary configuration mismatch, or PostgreSQL reconstruction defect.

**Fix:** Add a test with production service/repository adapters (or faithful fakes), invoke the actual router over HTTP, parse enrollment via `AgentHttpClient`, then fetch and activate a configuration twice through `AgentConfigurationTransport` and `ConfigurationCache`.

---

_Reviewed: 2026-08-14T19:17:34Z_
_Reviewer: the agent (gsd-code-reviewer)_
_Depth: deep_
