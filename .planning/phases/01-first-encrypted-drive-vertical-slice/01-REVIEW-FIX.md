---
phase: 01
fixed_at: 2026-08-14T19:55:55Z
review_path: C:/Users/nhdinh/dev/dleakprevention/.planning/phases/01-first-encrypted-drive-vertical-slice/01-REVIEW.md
iteration: 3
findings_in_scope: 9
fixed: 0
skipped: 9
status: none_fixed
---

# Phase 01: Code Review Fix Report

**Fixed at:** 2026-08-14T19:55:55Z
**Source review:** `01-REVIEW.md`
**Iteration:** 3 (final capped auto-fix pass)

**Summary:**

- Findings in scope: 9
- Fixed this iteration: 0
- Skipped this iteration: 9
- No source files were changed or committed in this pass; existing live-worktree edits were preserved.

## Fixed Issues

None — no current finding was safely resolved in full during iteration 3.

Earlier fixes remain integrated in the live worktree: iteration 1 addressed enrollment-response JSON, prior-serial decoding, signed-configuration wire responses, PostgreSQL envelope reconstruction, cache API-version validation, and provisioning-script secret output. Iteration 2 committed `731c569` for CR-06, hardening `scripts/lab/Reset-DlpPostgres.py` against SSH-host spoofing and password/SQL interpolation. Those prior fixes are no longer current findings in `01-REVIEW.md`; the counts above reflect the nine remaining in-scope findings.

## Skipped Issues

### CR-01: Bootstrap enrollment fabricates observations that cannot match the authority row

**File:** `crates/dlp-server/src/routes.rs:247`
**Reason:** The live route and production composition are already modified. A correct resolution changes the locked authority-row transaction so it supplies trusted observations; replacing the placeholders only in the route would leave the enrollment contract inconsistent.
**Original issue:** Bootstrap enrollment constructs synthetic device observations that cannot match an administrator-provisioned authority row.

### CR-02: Directory corroboration is disconnected from the provisioning authority path

**File:** `crates/dlp-server/src/lib.rs:128`
**Reason:** Requires an async directory-corroboration operation, two-controller identity comparison, provisioning-service injection, and tests. The affected production server files have live uncommitted changes, so a partial route or constructor edit is unsafe.
**Original issue:** Provisioning persists administrator-supplied identity facts without consulting the configured directory verifier.

### CR-03: Replacement enrollment never provides the active credential serial

**File:** `crates/dlp-windows-service/src/service.rs:159`
**Reason:** Requires an explicit credential-validation, renewal, replacement, and irrecoverable-recovery policy. The service is actively modified; passing a serial without those paths could create an unauthorized or unrecoverable state.
**Original issue:** Replacement enrollment always sends no prior serial, so it cannot meet the server's active-serial check.

### CR-04: Machine-DPAPI credential custody is bypassable through incomplete ACL validation

**File:** `crates/dlp-windows-service/src/credential.rs:193`
**Reason:** The clean credential module was inspected, but the remaining work requires Windows DACL inspection and protected creation for both the directory and file, plus Windows-host verification. The existing owner-only check and service-SID fallback cannot be safely converted into the required custody guarantee with a narrow edit.
**Original issue:** Protection checks can decrypt without validating the DACL, and the credential directory and service-SID failure path remain insufficiently protected.

### CR-05: Any leaf chained to the administrator CA is a provisioning administrator

**File:** `crates/dlp-server/src/tls.rs:174`
**Reason:** Requires a defined administrator certificate profile and explicit authorization policy (allowlist or directory role), not a string-comparison adjustment. TLS and related server files have live uncommitted edits.
**Original issue:** Administrator authorization is inferred solely from an issuer display string after mTLS validation.

### WR-01: Persisted configurations are returned after restart without complete re-verification

**File:** `crates/dlp-agent-core/src/config_cache.rs:171`
**Reason:** Requires cache-read API changes to accept the verifier and expected device/version state, followed by caller and restart-test updates. The cache implementation is actively modified.
**Original issue:** Persisted bundles are accepted after pointer-digest comparison without signature, trusted-key, audience, schema, and monotonic-version validation.

### WR-02: Existing device credentials are not bound to the configured device or validated for expiry

**File:** `crates/dlp-windows-service/src/service.rs:164`
**Reason:** Requires shared cryptographic path validation plus a replacement-enrollment policy; the service contains live edits. A device-ID-only check would not provide the requested credential validation.
**Original issue:** A decryptable credential is accepted without checking configured device identity, chain validity, key binding, or expiry.

### WR-03: Enrollment response validation compares a textual root subject instead of validating the chain

**File:** `crates/dlp-agent-core/src/client.rs:341`
**Reason:** The client module is clean, but a safe fix needs complete path validation anchored in the exact root, leaf EKU/SAN/validity checks, CSR key binding, and fixture coverage. Replacing the subject comparison alone leaves the principal vulnerability unresolved.
**Original issue:** The agent accepts a response chain when any certificate has a textual subject matching the configured root.

### WR-04: Enrollment E2E tests depend on ambient PKI and do not cover the real enrollment path

**File:** `tests/e2e/server_enrollment.rs:33`
**Reason:** Requires a self-contained PKI fixture and a real repository/transport integration path covering parseable responses, replacement serials, and persistence. The E2E test is actively modified.
**Original issue:** The fixture depends on external PKI material and the route test only exercises a test service with a placeholder CSR.

## Verification

Verification ran in the main checkout (the live worktree), without source changes:

- `cargo test -p dlp-windows-service --test credential_protection` passed: 1 test.
- `git diff --check` passed.

No source commit was made: the in-scope production areas contain concurrent live edits, and this final pass did not identify a complete, safely isolatable fix.

---

_Fixed: 2026-08-14T19:55:55Z_
_Fixer: the agent (gsd-code-fixer)_
_Iteration: 3_
