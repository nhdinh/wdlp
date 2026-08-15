---
phase: 01
fixed_at: 2026-08-15T02:11:08Z
review_path: C:/Users/nhdinh/dev/dleakprevention/.planning/phases/01-first-encrypted-drive-vertical-slice/01-REVIEW.md
iteration: 3
findings_in_scope: 14
fixed: 4
skipped: 10
status: partial
---

# Phase 01: Code Review Fix Report

**Fixed at:** 2026-08-15T02:11:08Z
**Source review:** `01-REVIEW.md`
**Iteration:** 3

## Summary

- Cumulative findings in scope: 14
- Cumulative fixed: 4
- Cumulative skipped: 10
- This capped pass: 0 additional fixes; 10 remaining findings reviewed and skipped.
- Commits: none. This pass operated in the requested live worktree, which contains overlapping user changes; no code was staged or committed.

## Fixed Issues

### CR-01: Bootstrap enrollment fabricated observations that could not match the authority row

**Files modified:** `crates/dlp-server/src/routes.rs`, `crates/dlp-server/src/enrollment.rs`, `crates/dlp-server/src/repository.rs`
**Commit:** None (integrated live-worktree change)
**Applied fix:** The bootstrap route now supplies only the untrusted device ID, one-time token, CSR, and optional prior serial. The transactional authority repository locks its server-held row by device ID and validates the token and current credential state; it no longer compares those values with a fabricated HTTP observation.

### CR-06: Trusted provisioning removed the required enrollment-token handoff

**Files modified:** `scripts/lab/Invoke-TrustedProvisioning.ps1`, `scripts/lab/Invoke-Dc01Server.ps1`
**Commit:** None (integrated live-worktree change)
**Applied fix:** The helper removes the protected token file after reading it but returns the one-time token only through the existing authenticated PowerShell Direct result. The caller immediately validates and puts it into the short-lived service-environment handoff, without evidence or diagnostic output.

### CR-07: DC01 provisioning omitted its mandatory administrator CA input

**Files modified:** `scripts/lab/Invoke-Dc01Server.ps1`
**Commit:** None (integrated live-worktree change)
**Applied fix:** The scenario resolves `DLP_ADMIN_CA_CERT_PEM` to PEM content, adds it to the remote argument list, and invokes the helper with `-AdminCaPem`.

### WR-06: Windows service dispatcher failure reported a successful process exit

**Files modified:** `crates/dlp-windows-service/src/main.rs`
**Commit:** None (integrated live-worktree change)
**Applied fix:** `main` now returns `ExitCode::FAILURE` after logging a dispatcher failure, and `ExitCode::SUCCESS` only after normal completion.

## Skipped Issues

### CR-02: Directory corroboration is not connected to provisioning

**File:** `crates/dlp-server/src/lib.rs:128`
**Reason:** Requires a real two-controller verifier operation, service injection, fail-closed behavior, and integration tests across actively edited server files.
**Original issue:** Production provisioning still persists caller-provided directory identity attributes without an LDAP lookup or corroboration.

### CR-03: Replacement enrollment never sends the active serial

**File:** `crates/dlp-windows-service/src/service.rs:159`
**Reason:** Needs a complete validated-credential, renewal, replacement, and irrecoverable-recovery policy. Passing an extracted serial alone would be unsafe; this file also has live user edits.
**Original issue:** A failed protection check starts enrollment without the active credential serial required for replacement.

### CR-04: Machine-DPAPI credential custody can be bypassed by ACL handling

**File:** `crates/dlp-windows-service/src/credential.rs:193`
**Reason:** Requires protected directory/file creation, full DACL validation before decryption, service-SID failure handling, and Windows-host verification. A small validation call would not close the pre-hardening or DACL bypasses.
**Original issue:** Credential-file ACL protections can be bypassed before persistence or during validation.

### CR-05: Any administrator-CA leaf becomes a provisioning administrator

**File:** `crates/dlp-server/src/tls.rs:187`
**Reason:** Needs a specified administrator certificate profile plus explicit authorization policy; changing the issuer comparison alone would not secure authorization. The TLS module has live user edits.
**Original issue:** Administrator capability is granted from issuer-subject matching without a dedicated certificate profile or role mapping.

### CR-08: Log-file authorization has a canonicalization-to-open race

**File:** `crates/dlp-log-debug-service/src/paths.rs:56`
**Reason:** Requires platform-specific no-reparse open-by-handle and handle identity validation, not a safe narrow pathname edit.
**Original issue:** The service authorizes a canonicalized pathname and then reopens it, allowing a replacement race.

### WR-01: Cached bundles lack complete cryptographic re-verification

**File:** `crates/dlp-agent-core/src/config_cache.rs:171`
**Reason:** Requires API/caller changes to provide verifier and expected state, then restart-path tests; the cache is concurrently modified.
**Original issue:** Persisted bundles are accepted after restart without full signature, audience, schema, and version checks.

### WR-02: Existing credentials are not bound to the device or validated for lifetime/profile

**File:** `crates/dlp-windows-service/src/service.rs:164`
**Reason:** Requires chain, key, EKU, device-ID, and validity verification coupled to the replacement policy in CR-03; the service file has live user edits.
**Original issue:** Any decryptable non-empty credential is accepted as existing.

### WR-03: Enrollment response checking compares a root subject string

**File:** `crates/dlp-agent-core/src/client.rs:341`
**Reason:** Needs complete exact-anchor path validation, leaf-profile checks, CSR key binding, and new fixtures. Matching root DER alone would leave the other required trust checks absent.
**Original issue:** The response chain is trusted when a certificate's textual subject equals the configured root subject.

### WR-04: E2E coverage does not exercise production issuance or authority checks

**File:** `tests/e2e/server_enrollment.rs:351`
**Reason:** Requires an isolated PKI plus transactional production-semantics repository fixture; the test is concurrently modified.
**Original issue:** Route tests use placeholder CSRs and always-success test services, bypassing authority and issuance paths.

### WR-05: TLS readiness evidence disables certificate validation

**File:** `scripts/lab/Invoke-Dc01Server.ps1:560`
**Reason:** Requires root installation/pinning, DNS-SAN endpoint changes, and negative lab tests; it cannot be safely corrected by deleting the permissive callback alone. The lab script has live user edits.
**Original issue:** Readiness probes accept all TLS certificate failures while recording validation evidence.

## Verification

Verification ran in the main checkout (the requested live worktree):

- `cargo test -p dlp-agent-core -p dlp-server -p dlp-log-debug-service -p dlpctl -p dlp-windows-service` passed: 89 tests across 21 suites.
- `cargo fmt --check -p dlp-windows-service` passed.
- `git diff --check` passed after this iteration removed trailing whitespace from the prior uncommitted report. No source-code fix was applied in this capped pass.

The remaining findings require security-policy decisions, production AD/PKI integration, or Windows-specific handle/DACL controls that are not safe narrow edits in the shared live worktree.

---

_Fixed: 2026-08-15T02:11:08Z_
_Fixer: the agent (gsd-code-fixer)_
_Iteration: 3_
