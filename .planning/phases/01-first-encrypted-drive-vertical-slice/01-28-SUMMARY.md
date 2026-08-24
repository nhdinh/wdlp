---
phase: 01-first-encrypted-drive-vertical-slice
plan: 28
subsystem: security
tags: [powershell, sha256, attestations, provenance, fail-closed]
requires:
  - phase: 01-27
    provides: current closure artifact hashes and prior review history
provides:
  - deterministic complete-payload digests for all 19 closure records
  - predecessor-linked review attestations with authenticated capture
  - truthful seven-threat open state and structured signed-off diagnostics
affects: [phase-01-security-gate, final-gate, independent-review]
actuals:
  tokens: 69000
  tasks: 3
  commits: 3
tech-stack:
  added: []
  patterns: [ordered JSON canonicalization, append-only hash-linked attestations, atomic drift-checked publication]
key-files:
  created: [scripts/add-security-closure-review.ps1]
  modified: [scripts/verify-phase1-security.ps1, scripts/evidence/Phase1.Security.Tests.ps1, evidence/phase1/security-closure.yaml, .planning/phases/01-first-encrypted-drive-vertical-slice/01-SECURITY.md]
key-decisions:
  - "Use ordered UTF-8/LF JSON as the deterministic v2 closure serialization."
  - "Preserve the seven invalid inherited reviews as legacy/unbound history rather than rebinding them."
patterns-established:
  - "Payload-bound review: signed-off state requires the latest valid attestation to name the current complete payload digest."
  - "Validation failure is machine-readable exit 3; parse/invocation failures use exit 2."
requirements-completed: [CRY-04]
coverage:
  - id: D1
    description: Changed closure payloads and tampered attestations fail closed.
    requirement: CRY-04
    verification:
      - kind: integration
        ref: scripts/evidence/Phase1.Security.Tests.ps1#payload-and-attestation-mutation-cases
        status: pass
    human_judgment: false
  - id: D2
    description: Authenticated append-only review capture rejects developer-workstation identity and publication drift.
    requirement: CRY-04
    verification:
      - kind: integration
        ref: scripts/evidence/Phase1.Security.Tests.ps1#capture-non-mutation-and-identity-check
        status: pass
    human_judgment: false
  - id: D3
    description: Exactly seven current records remain unsigned and open.
    requirement: CRY-04
    verification:
      - kind: integration
        ref: scripts/verify-phase1-security.ps1 -RequireSignedOff -DiagnosticFormat Json
        status: pass
    human_judgment: false
duration: 22min
completed: 2026-08-24
status: complete
---

# Phase 01 Plan 28: Payload-Bound Security Closure Summary

**Versioned SHA-256 payload attestations now prevent inherited reviews from approving changed closure bytes, while seven unreviewed records remain explicitly open.**

## Performance

- **Duration:** 22 min
- **Tasks:** 3
- **Files modified:** 5

## Accomplishments

- Bound complete ordered closure payloads to predecessor-linked review attestations and rejected reseals, identity/timestamp changes, broken links, and deletions.
- Added authenticated Windows/domain review capture with explicit threat selection, dry-run support, drift detection, and atomic publication.
- Migrated all 19 records to v2, retained historical evidence, and reopened exactly the seven records whose current bytes lack independent review.

## Task Commits

1. **Task 1: Make inherited review attestations fail closed** - `248948e`
2. **Task 2: Add authenticated append-only closure review capture** - `f69a966`
3. **Task 3: Migrate safely and reopen seven closures** - `31410d9`

## Files Created/Modified

- `scripts/verify-phase1-security.ps1` - Deterministic payload/attestation validation and structured diagnostics.
- `scripts/evidence/Phase1.Security.Tests.ps1` - End-to-end mutation and exact-set regression checks.
- `scripts/add-security-closure-review.ps1` - Authenticated append-only review capture.
- `evidence/phase1/security-closure.yaml` - Versioned v2 closure records and preserved historical reviews.
- `.planning/phases/01-first-encrypted-drive-vertical-slice/01-SECURITY.md` - Seven-threat truthful open state.

## Decisions Made

- JSON, which is valid YAML, is used for the v2 manifest so field order and UTF-8/LF canonicalization are explicit and stable across PowerShell locales.
- Existing reviews for the seven rebound records are retained only as `legacy_unbound`; no timestamp or new digest is fabricated.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Corrected compressed PowerShell keyword parsing**
- **Found during:** Task 3 overall verification
- **Issue:** Missing whitespace after `throw`/`Write-Host` parsed the keyword and message as a command name.
- **Fix:** Added required token separation and reran the full regression suite.
- **Files modified:** `scripts/verify-phase1-security.ps1`, `scripts/add-security-closure-review.ps1`, `scripts/evidence/Phase1.Security.Tests.ps1`
- **Verification:** Security suite passes; pre-sign-off verifier exits successfully.
- **Committed in:** `31410d9` (verifier correction; capture/test corrections were included in their task commits)

## Issues Encountered

- GitNexus does not currently index the PowerShell functions; impact was conservatively UNKNOWN before edits, while pre-commit change detection reported low risk and no affected indexed flows.

## User Setup Required

Fresh attestations must be captured by an authenticated independent reviewer from the approved lab/domain context; the repository intentionally cannot automate or forge that identity.

## Verification

- `scripts/evidence/Phase1.Security.Tests.ps1`: passed 11 checks.
- Pre-sign-off validation: all 19 target records structurally valid.
- Signed-off validation: exit 3 with exactly seven unique `unsigned_current_attestation` diagnostics and empty stderr (asserted by the suite).

## Self-Check: PASSED

All five planned files exist and task commits `248948e`, `f69a966`, and `31410d9` are present.

## Next Phase Readiness

The authenticated review command can now collect the seven missing current-payload attestations. Until that human review occurs, signed-off security state correctly remains blocked.

---
*Phase: 01-first-encrypted-drive-vertical-slice*
*Completed: 2026-08-24*
