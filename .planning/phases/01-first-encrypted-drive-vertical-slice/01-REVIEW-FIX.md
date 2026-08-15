---
phase: 01
fixed_at: 2026-08-15T00:00:00Z
review_path: C:/Users/nhdinh/dev/dleakprevention/.planning/phases/01-first-encrypted-drive-vertical-slice/01-REVIEW.md
iteration: 3
findings_in_scope: 12
fixed: 1
skipped: 11
status: partial
---

# Phase 01: Code Review Fix Report

**Fixed at:** 2026-08-15T00:00:00Z  
**Source review:** `01-REVIEW.md`  
**Iteration:** 3

**Summary:**

- Findings in scope: 12
- Fixed: 1
- Skipped: 11
- Verification ran in the isolated worktree. `cargo test -p dlp-windows-service` passed (7 tests).
- The shared checkout has local edits to the same service file, so the committed fix could not be fast-forwarded. It is retained on `gsd-reviewfix/01-8992` for a deliberate merge.

## Fixed Issues

### CR-02: Replacement enrollment cannot provide the required active serial

**Files modified:** `crates/dlp-windows-service/src/service.rs`  
**Commit:** `70db28b` (`gsd-reviewfix/01-8992`)  
**Status:** fixed: requires human verification

**Applied fix:** When protection validation fails but the existing credential can still be read, the service now supplies its serial to replacement enrollment. This preserves the server-side active-credential comparison while allowing renewal.

## Skipped Issues

### CR-01: Production provisioning never corroborates the directory record

**Reason:** Requires a new production directory port, concrete LDAP transport integration, and route wiring; no narrow safe change was available.

### CR-03: DPAPI credential custody is writable/readable before protection and fails open without a service SID

**Reason:** Requires Windows service-SID installation changes plus protected directory/temp-file DACL creation and complete DACL validation. Partial changes could break service startup or leave the write race intact.

### CR-04: Every non-device leaf under the administrator CA is an administrator

**Reason:** Requires a dedicated administrator certificate profile and identity/role authorization design; tightening only one handshake condition would not safely establish that model.

### CR-05: Log authorization has a check-to-open race

**Reason:** Requires platform-specific handle-based open, reparse-point rejection, and reading through the validated handle. A pathname-only change would not remove the race.

### CR-06: The enrollment token is persisted and leaked through diagnostics

**Reason:** Requires a service-SID-restricted secret handoff lifecycle and startup contract changes. Redacting diagnostics alone would leave the token exposed at rest.

### CR-07: Deployment writes server private keys and credentials with inherited ACLs

**Reason:** Requires a tested protected-DACL helper and explicit server service identity. Adding unverified ACL commands in deployment scripts risks locking out provisioning.

### WR-01: Cached configurations are accepted after restart without verification

**Reason:** Requires an API redesign so cache reads receive verifier and expected device/version state; changing deserialization locally would leave call sites inconsistent.

### WR-02: A decryptable credential is treated as usable without profile validation

**Reason:** Requires certificate chain, EKU, SAN, key-binding, expiry, and ACL validation against configured trust material; this is not safely reducible to a local predicate.

### WR-03: Enrollment-chain validation trusts only a textual root subject

**Reason:** Requires path validation anchored to root DER/public key and compatible certificate-fixture coverage; no safe minimal replacement was available.

### WR-04: Enrollment tests do not exercise the production authority or issuance path

**Reason:** Requires integration infrastructure (real PKI and transactional PostgreSQL) that exceeds an isolated corrective change.

### WR-05: TLS readiness evidence explicitly disables certificate validation

**Reason:** Requires distributing/pinning the lab root and probing the certificate DNS-SAN hostname across both readiness paths; removing the bypass without that wiring would make the evidence probe nonfunctional.

---

_Fixed: 2026-08-15T00:00:00Z_  
_Fixer: the agent (gsd-code-fixer)_  
_Iteration: 3_
