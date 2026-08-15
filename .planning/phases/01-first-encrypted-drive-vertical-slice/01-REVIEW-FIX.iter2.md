---
phase: 01
fixed_at: 2026-08-15T02:26:43Z
review_path: C:/Users/nhdinh/dev/dleakprevention/.planning/phases/01-first-encrypted-drive-vertical-slice/01-REVIEW.md
iteration: 1
findings_in_scope: 13
fixed: 1
skipped: 12
status: partial
---

# Phase 01: Code Review Fix Report

**Fixed at:** 2026-08-15T02:26:43Z
**Source review:** `01-REVIEW.md`
**Iteration:** 1

## Summary

- Findings in scope: 13
- Fixed: 1
- Skipped: 12

## Fixed Issues

### WR-06: Debug-service example falls back to localhost-only mode

**Files modified:** `crates/dlp-log-debug-service/config.example.json`, `crates/dlp-log-debug-service/tests/endpoint_contract.rs`
**Commit:** `f5dba84`
**Applied fix:** Added the required positive `max_tail_lines` value to the shipped example and a regression test that deserializes the example and verifies the configured tail limit.

## Skipped Issues

### CR-01: Production provisioning never performs directory corroboration

**File:** `crates/dlp-server/src/lib.rs:128`
**Reason:** Requires a production two-controller LDAP corroboration operation, authority-derived request construction, dependency injection, and integration tests. A narrow change would not safely replace caller-controlled identity data.
**Original issue:** Provisioning persists caller-supplied directory identity attributes without a production directory lookup.

### CR-02: Replacement enrollment cannot provide its required active serial

**File:** `crates/dlp-windows-service/src/service.rs:159`
**Reason:** Requires a complete credential-validation and recovery policy. Passing a stored serial alone would leave binding, expiry, and irrecoverable-credential paths unsafe.
**Original issue:** Failed credential checks start enrollment without the serial required for replacement.

### CR-03: DPAPI credential custody fails open before ACL protection

**File:** `crates/dlp-windows-service/src/credential.rs:175`
**Reason:** Requires protected directory and temporary-file creation, service-SID installation/configuration, complete DACL validation, and Windows-host verification. Partial ACL changes would not close the pre-hardening exposure.
**Original issue:** DPAPI blobs are created with inherited access and service-SID failures silently bypass enforcement.

### CR-04: Any certificate under the administrator CA receives administrator authority

**File:** `crates/dlp-server/src/tls.rs:174`
**Reason:** Requires an agreed administrator certificate profile, exact-anchor validation, and identity/role authorization policy; issuer-text matching cannot safely be adjusted in isolation.
**Original issue:** Administrator capability is granted from an accepted chain's issuer and subject text.

### CR-05: Log authorization has a check-to-open path race

**File:** `crates/dlp-log-debug-service/src/paths.rs:56`
**Reason:** Requires platform-specific no-reparse open-by-handle support plus opened-handle identity/parent validation. Pathname-only changes do not eliminate the race.
**Original issue:** The service authorizes one path and then reopens it, allowing replacement with a reparse point or symlink.

### CR-06: Agent enrollment token is persisted and emitted in diagnostics

**File:** `scripts/lab/Invoke-Client01Runtime.ps1:298`
**Reason:** Requires redesigning the service's runtime secret interface and provisioning handoff so the token is never stored in a readable environment file or registry value. Removing the current handoff alone would break enrollment.
**Original issue:** The one-time token is written to an env file/registry and can be copied into diagnostics.

### CR-07: Management-server deployment writes private keys and credentials with inherited ACLs

**File:** `scripts/lab/Invoke-Dc01Server.ps1:310`
**Reason:** Requires determining the target server process identity and implementing pre-write protected DACLs and validation for every secret path. Applying an arbitrary ACL could prevent the server from starting without securing the intended principal.
**Original issue:** Server private keys and credentials are written into directories and env files with inherited ACLs.

### WR-01: Cached configuration is trusted after restart without signature verification

**File:** `crates/dlp-agent-core/src/config_cache.rs:173`
**Reason:** Requires changing the persisted-cache read API to receive the verifier and expected device/version state, then covering restart activation paths. A digest-only check is insufficient.
**Original issue:** Cached bundles are deserialized after restart without complete signature, audience, schema, or monotonic-version verification.

### WR-02: Existing credentials are not validated for binding or validity

**File:** `crates/dlp-windows-service/src/service.rs:158`
**Reason:** Coupled to CR-02; requires certificate chain, key-match, EKU, device binding, and validity checks before deciding whether renewal or recovery is allowed.
**Original issue:** Any decryptable non-empty blob is considered an existing credential.

### WR-03: Enrollment response chain validation trusts a textual subject

**File:** `crates/dlp-agent-core/src/client.rs:270`
**Reason:** Requires exact-root WebPKI/rustls path validation and CSR-public-key binding with new PKI fixtures. Comparing DER alone would still omit the required profile and binding checks.
**Original issue:** The returned chain is accepted when a certificate's subject text equals the configured root subject.

### WR-04: Enrollment route tests bypass production authority and issuance paths

**File:** `tests/e2e/server_enrollment.rs:99`
**Reason:** Requires an isolated real-PKI and transactional repository fixture covering issuance, replacement, revocation, and invalid-chain behavior; this is not a narrow route-test edit.
**Original issue:** Route tests use placeholder CSRs and always-success services instead of production authority paths.

### WR-05: TLS readiness evidence disables certificate validation

**File:** `scripts/lab/Invoke-Dc01Server.ps1:550`
**Reason:** Requires deploying or pinning the Phase 1 root, using a DNS-SAN endpoint, and adding negative trust/name probes. Removing the permissive callback alone would make the current readiness path nonfunctional.
**Original issue:** Readiness probes accept every certificate validation failure while claiming validated TLS evidence.

## Verification

Verification ran in the isolated review-fix worktree:

- Re-read both changed files to confirm the field and regression test.
- JSON parse check for `config.example.json` passed.
- `cargo test -p dlp-log-debug-service --test endpoint_contract` passed: 10 tests.

---

_Fixed: 2026-08-15T02:26:43Z_
_Fixer: the agent (gsd-code-fixer)_
_Iteration: 1_
