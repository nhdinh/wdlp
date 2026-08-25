---
phase: 01-first-encrypted-drive-vertical-slice
plan: 35
subsystem: security-evidence
tags: [powershell, cms, windows, reparse-points, environment-restoration]
requires:
  - 01-34 hardened signed-off security closure
provides:
  - observed Windows reviewer-context authorization
  - signed ordered historical-CMS envelope
  - handle-contained repository hashing
  - exact verifier environment restoration
affects: [01-36 trusted reviewer ceremony, phase-01 verification]
tech-stack:
  added: []
  patterns: [detached CMS archival commitment, GetFinalPathNameByHandleW containment, snapshot-and-finally environment restoration]
key-files:
  created: []
  modified:
    - scripts/add-security-closure-review.ps1
    - scripts/verify-phase1-security.ps1
    - scripts/evidence/Phase1.Security.Tests.ps1
key-decisions:
  - "Authorize publication from captured WindowsIdentity and COMPUTERNAME before preview, affirmation, locking, signing, or mutation."
  - "Keep the archival envelope additive and outside the protected threat payload; Plan 01-36 must publish the canonical generation."
  - "Hash accepted references from the same FileStream handle whose final Windows path passed repository containment."
requirements-completed: [CRY-04]
coverage:
  - id: D1
    description: Observed reviewer identity and station gate publication before mutation
    requirement: CRY-04
    verification:
      - kind: integration
        ref: scripts/evidence/Phase1.Security.Tests.ps1 -Focus Publication
        status: pass
    human_judgment: false
  - id: D2
    description: Trusted ordered-history envelope detects historical CMS corruption, deletion, and reordering
    requirement: CRY-04
    verification:
      - kind: integration
        ref: scripts/evidence/Phase1.Security.Tests.ps1 -Focus Verifier
        status: pass
    human_judgment: false
  - id: D3
    description: Handle-contained hashing rejects real junction and symbolic-link escapes
    requirement: CRY-04
    verification:
      - kind: integration
        ref: scripts/evidence/Phase1.Security.Tests.ps1 -Focus Verifier
        status: pass
    human_judgment: false
actuals:
  tokens: 15367
  tasks: 3
  commits: 4
duration: 50m
completed: 2026-08-25
status: complete
---

# Phase 01 Plan 35: Security Evidence Boundary Closure Summary

**Observed Windows ceremony authorization, signed complete-history CMS envelopes, and same-handle repository containment close CR-05 through CR-07 while preserving caller environment state.**

## Performance

- **Duration:** 50m
- **Completed:** 2026-08-25T10:15:05Z
- **Tasks:** 3
- **Files modified:** 3

## Accomplishments

- Publication now resolves exactly one CurrentUser signer and policy reviewer, captures the executing Windows identity and machine once, and rejects either mismatch before preview, prompt, lock, signature, or filesystem mutation.
- Each publication writes a versioned detached-CMS archival envelope committing the ordered attestation digests and SHA-256 digest of every decoded historical CMS byte sequence; signed-off verification rejects missing, corrupted, reordered, or removed history.
- Repository references are opened once, canonicalized through `GetFinalPathNameByHandleW`, checked against the repository boundary, and hashed from that same handle; real junction and symbolic-link escapes fail with `reference_reparse_escape`.
- Verifier chain-validation environment variables preserve both original presence and exact values through `finally` cleanup.

## Task Commits

1. **Task 1 RED: observed reviewer-context regressions** — `9f5047c`
2. **Task 1 GREEN: observed execution-context authorization** — `3b7341a`
3. **Task 2: complete historical signature envelope** — `6d6da21`
4. **Task 3: handle-contained hashing and environment restoration** — `5e60d7e`

## Files Created/Modified

- `scripts/add-security-closure-review.ps1` — observed-context gate and atomic archival-envelope publication.
- `scripts/verify-phase1-security.ps1` — envelope validation, final-handle containment, same-stream hashing, and environment restoration.
- `scripts/evidence/Phase1.Security.Tests.ps1` — wrong-context, history-tamper, junction, symbolic-link, and focused regression coverage.

## Decisions Made

- Captured observations, never certificate subject or policy assertions, populate reviewer identity and machine fields.
- The archival envelope is an additive record field, leaving protected mitigation payload bytes unchanged.
- Canonical signed-off verification intentionally fails with `historical_signature_envelope_missing` until the LAB trusted-reviewer ceremony in Plan 01-36.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Support legacy unsigned historical entries in the archival commitment**
- **Found during:** Task 2 fixture construction
- **Issue:** Early append-only entries do not carry CMS bytes, and strict property access prevented envelope construction.
- **Fix:** Commit absent legacy CMS bytes as the SHA-256 digest of the empty byte sequence while preserving every existing entry and ordering.
- **Files modified:** publisher, verifier, security tests
- **Verification:** Focused Verifier suite passes history corruption, deletion, and reorder cases.
- **Committed in:** `6d6da21`

**2. [Rule 3 - Blocking] Use Windows PowerShell-compatible relative-path construction in regressions**
- **Found during:** Task 3 reparse tests
- **Issue:** Windows PowerShell's runtime lacks `Path.GetRelativePath`.
- **Fix:** Added a strict root-prefixed relative-path helper in the test harness.
- **Files modified:** security tests
- **Verification:** Real junction and symbolic-link cases pass.
- **Committed in:** `5e60d7e`

---

**Total deviations:** 2 auto-fixed blocking issues.
**Impact on plan:** Both changes were required for compatibility and complete historical coverage; no production scope was added.

## Issues Encountered

- Task 3 paused at a blocking precondition until the user enabled Windows Developer Mode across the lab. Execution resumed only after explicit confirmation.
- GitNexus did not index the modified PowerShell symbols. Every required impact result was therefore UNKNOWN with no indexed callers/processes; focused adversarial tests and pre-commit `detect_changes` were used as the degraded safety path.

## Known Stubs

None.

## Threat Flags

| Flag | File | Description |
| --- | --- | --- |
| threat_flag: native-file-handle-boundary | scripts/verify-phase1-security.ps1 | Narrow Win32 final-path resolution boundary used to prevent reparse-point and path-replacement escapes. |

## Verification

- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/evidence/Phase1.Security.Tests.ps1 -Focus Publication` — PASS
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/evidence/Phase1.Security.Tests.ps1 -Focus Verifier` — PASS
- Canonical signed-off mode remains intentionally blocked on the missing Plan 01-36 archival-envelope ceremony.

## Next Phase Readiness

- Publisher and verifier are ready for the LAB trusted-reviewer ceremony that adds current archival envelopes to all closure records.
- Phase verification should be rerun after Plan 01-36 publishes that generation.

## Self-Check: PASSED

- All three modified implementation/test files exist.
- All four task commits exist in repository history.
- Both focused verification commands pass.

---
*Phase: 01-first-encrypted-drive-vertical-slice*
*Completed: 2026-08-25*
