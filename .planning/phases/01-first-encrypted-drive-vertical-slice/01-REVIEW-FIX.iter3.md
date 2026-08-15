---
phase: 01
fixed_at: 2026-08-15T02:36:42.291Z
review_path: C:/Users/nhdinh/dev/dleakprevention/.planning/phases/01-first-encrypted-drive-vertical-slice/01-REVIEW.md
iteration: 2
findings_in_scope: 12
fixed: 0
skipped: 12
status: none_fixed
---

# Phase 01: Code Review Fix Report

**Fixed at:** 2026-08-15T02:36:42.291Z
**Source review:** `01-REVIEW.md`
**Iteration:** 2

## Summary

- Findings in scope: 12
- Fixed: 0
- Skipped: 12

No source changes were committed. The refreshed review targets an uncommitted, concurrently edited working tree, while the mandated isolated worktree is based on `f5dba84`. The relevant files differ by 1,305 inserted and 260 removed lines, so a commit from the isolated branch would not apply the reviewed source state and could overwrite or subsume user work.

## Fixed Issues

None — all findings were skipped.

## Skipped Issues

### CR-01: Production provisioning never corroborates the directory record

**File:** `crates/dlp-server/src/lib.rs:128`
**Reason:** The current working-tree provisioning, enrollment, repository, and route implementations are all uncommitted and diverge from the isolated branch. The required directory-port injection and authority-derived identity construction cannot be committed without incorporating that concurrent work.
**Original issue:** Production provisioning persists caller-controlled device identity data without two-controller directory corroboration.

### CR-02: Replacement enrollment cannot provide the required active serial

**File:** `crates/dlp-windows-service/src/service.rs:159`
**Reason:** The reviewed service, enrollment, and repository paths are concurrently modified. The remaining recovery behavior also requires an explicit authenticated reprovisioning policy for unrecoverable credentials; passing a serial alone would not safely resolve it.
**Original issue:** Renewal starts without the active serial required by the repository.

### CR-03: DPAPI credential custody is writable/readable before protection and fails open without a service SID

**File:** `crates/dlp-windows-service/src/credential.rs:175`
**Reason:** Requires a coordinated Windows service-SID installation policy, pre-write protected directory/temp-file DACL creation, and full DACL validation. This security design cannot be inferred safely as a narrow source edit.
**Original issue:** DPAPI credential storage permits inherited access before hardening and accepts missing service-SID protection.

### CR-04: Every non-device leaf under the administrator CA is an administrator

**File:** `crates/dlp-server/src/tls.rs:174`
**Reason:** The TLS implementation has 226 uncommitted added lines relative to the isolated branch. A correct fix additionally needs an agreed administrator certificate profile and allowlist or directory-role policy, neither of which is specified by the review.
**Original issue:** Administrator capability is granted from CA issuer/subject text rather than a constrained administrator identity.

### CR-05: Log authorization has a check-to-open race

**File:** `crates/dlp-log-debug-service/src/paths.rs:56`
**Reason:** Eliminating this requires a handle-based, no-reparse open implementation plus final-handle parent/identity validation. Path-level edits would leave the race intact.
**Original issue:** A pathname is authorized and later reopened, allowing a reparse-point or symlink swap.

### CR-06: The enrollment token is persisted and leaked through diagnostics

**File:** `scripts/lab/Invoke-Client01Runtime.ps1:1042`
**Reason:** The reviewed provisioning script has 808 uncommitted added lines. Replacing its token handoff requires a defined SYSTEM/service-SID-only runtime-secret provider and lifecycle; committing the isolated snapshot would discard concurrent work.
**Original issue:** The one-time token is written to an env file and registry, and emitted through diagnostics.

### CR-07: Deployment writes server private keys and credentials with inherited ACLs

**File:** `scripts/lab/Invoke-Dc01Server.ps1:352`
**Reason:** Requires selecting the target server service identity and implementing verified protected DACLs before each secret write. Applying an arbitrary ACL could prevent the intended service from accessing its keys without proving confidentiality.
**Original issue:** Server private keys and credentials are written using inherited ACLs.

### WR-01: Cached configurations are accepted after restart without verification

**File:** `crates/dlp-agent-core/src/config_cache.rs:176`
**Reason:** The cache implementation has uncommitted concurrent changes. A safe remedy changes the read API to receive the verifier and expected device/version state, then needs restart-path coverage; a digest-only patch is insufficient.
**Original issue:** Persisted bundles are returned without full activation validation.

### WR-02: A decryptable credential is treated as usable without profile validation

**File:** `crates/dlp-windows-service/src/service.rs:159`
**Reason:** Coupled to CR-02 and requires root-chain, key-match, EKU, URI-SAN, expiry, and expected-serial validation before selecting the enrollment mode.
**Original issue:** Any decryptable non-empty credential is treated as usable.

### WR-03: Enrollment-chain validation trusts only a textual root subject

**File:** `crates/dlp-agent-core/src/client.rs:270`
**Reason:** Requires a rooted WebPKI/rustls validation design and CSR public-key binding with PKI fixtures. Replacing the textual comparison alone would not establish a complete safe chain-validation path.
**Original issue:** A forged chain can be accepted when a certificate copies the configured root subject.

### WR-04: Enrollment tests do not exercise the production authority or issuance path

**File:** `tests/e2e/server_enrollment.rs:84`
**Reason:** Requires a real PKI fixture and transactional PostgreSQL authority repository that covers issuance, replacement, revocation, directory disagreement, and invalid chains. This is an integration-test architecture task, not a safe localized fix.
**Original issue:** Existing tests use test services that bypass production authority and issuance paths.

### WR-05: TLS readiness evidence explicitly disables certificate validation

**File:** `scripts/lab/Invoke-Dc01Server.ps1:560`
**Reason:** The relevant PowerShell scripts are concurrently modified. The trusted root/pin location, DNS-SAN endpoint, and negative trust/name test contract need to be established before removing the permissive policy without breaking deployment.
**Original issue:** Readiness evidence accepts all TLS certificate failures while claiming validated TLS.

## Verification

Verification ran in the isolated review-fix worktree for the branch comparison. No source file was edited, so no syntax or test command was applicable. `git status --short --branch` confirmed that the isolated branch remained source-clean before writing this report; report publication occurred in the shared checkout as requested and is intentionally uncommitted.

---

_Fixed: 2026-08-15T02:36:42.291Z_
_Fixer: the agent (gsd-code-fixer)_
_Iteration: 2_
