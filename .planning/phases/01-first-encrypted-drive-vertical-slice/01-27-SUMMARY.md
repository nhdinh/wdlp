---
phase: 01-first-encrypted-drive-vertical-slice
plan: 27
subsystem: security
tags: [rust, winfsp, filetime, dpapi, security-closure]

requires:
  - phase: 01-first-encrypted-drive-vertical-slice
    provides: WinFsp timestamp mapping and 19-record signed security closure
provides:
  - Real mounted-directory last-write timestamp regression assertion
  - Current reviewed T-01-15-03 credential implementation binding
  - Current all-19 security closure and append-only re-sign-off
affects: [phase-01-verification, security-audit, encrypted-drive]

actuals:
  tokens: 1800
  tasks: 3
  commits: 5

tech-stack:
  added: []
  patterns:
    - Real Win32 metadata assertions remain inside the live WinFsp runtime branch
    - Security digest reseals require semantic review before byte-hash replacement

key-files:
  created: []
  modified:
    - crates/dlp-windows-drive/tests/mounted_smoke.rs
    - evidence/phase1/security-closure.yaml
    - .planning/phases/01-first-encrypted-drive-vertical-slice/01-SECURITY.md

key-decisions:
  - "Accepted the current credential digest only after confirming DPAPI, ACL, atomic-write, zeroization, and redaction semantics remained intact."
  - "Resealed dependent stale bindings only after focused semantic review restored the all-19 verifier."
  - "Used scripts/verify-phase1.ps1 as the canonical FinalGate because verify-phase1-evidence.ps1 does not accept a FinalGate scenario."

patterns-established:
  - "A closure hash refresh is evidence of review, not a substitute for review."

requirements-completed:
  - CRY-04
  - TST-08

coverage:
  - id: D1
    description: "Real mounted directories expose a non-zero last-write timestamp through WinFsp/Win32"
    requirement: TST-08
    verification:
      - kind: integration
        ref: "cargo test --locked -p dlp-windows-drive --test mounted_smoke"
        status: pass
      - kind: unit
        ref: "cargo clippy --locked -p dlp-windows-drive --test mounted_smoke -- -D warnings"
        status: pass
    human_judgment: false
  - id: D2
    description: "Credential and dependent security closure records bind reviewed current implementation bytes"
    requirement: CRY-04
    verification:
      - kind: integration
        ref: "scripts/evidence/Phase1.Security.Tests.ps1 (18/18)"
        status: pass
      - kind: integration
        ref: "scripts/verify-phase1-security.ps1 -RequireSignedOff (19/19)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Phase 01 complete/zero-open sign-off agrees with FinalGate"
    requirement: CRY-04
    verification:
      - kind: integration
        ref: "scripts/verify-phase1.ps1 (34/34, 30/30 requirements, 7/7 criteria)"
        status: pass
    human_judgment: false

duration: 20min
completed: 2026-08-24
status: complete
---

# Phase 01 Plan 27: Security Closure and Mounted Timestamp Summary

**Locked the WinFsp directory timestamp fix with a real mounted-path assertion and restored a semantically reviewed, all-19 fail-closed Phase 01 security sign-off.**

## Performance

- **Duration:** 20 min
- **Started:** 2026-08-24T03:55:00Z
- **Completed:** 2026-08-24T04:14:50Z
- **Tasks:** 3
- **Files modified:** 3

## Accomplishments

- Added a real Win32 `fs::metadata().modified()` assertion after mounted directory creation while preserving the no-WinFsp runtime skip.
- Re-audited credential custody and bound both T-01-15-03 references to current bytes.
- Restored the complete closure set after reviewing dependent enrollment, storage, mounted-smoke, and lockfile drift.
- Appended a dated security re-audit record and passed tamper, signed-off, mounted-smoke, clippy, and FinalGate checks.

## Task Commits

1. **Task 1: Lock mounted directory timestamp fix** - `3eefb3e` (test)
2. **Task 2: Re-audit and reseal credential closure** - `ef43303` (fix)
3. **Task 2 blocking closure repair** - `ca1bf98` (fix)
4. **Task 3: Restore current security sign-off** - `2b20917` (docs)

## Files Created/Modified

- `crates/dlp-windows-drive/tests/mounted_smoke.rs` - Queries the real mounted directory metadata and rejects zero FILETIME mappings.
- `evidence/phase1/security-closure.yaml` - Current reviewed digests for credential and dependent stale bindings.
- `.planning/phases/01-first-encrypted-drive-vertical-slice/01-SECURITY.md` - Append-only 2026-08-24 re-audit and sign-off basis.

## Decisions Made

- Credential changes strengthened ACL validation and did not weaken any T-01-15-03 property, so resealing was accepted.
- Dependent digest mismatches were repaired only where the reviewed changes preserved or strengthened the recorded mitigations.
- The top-level `verify-phase1.ps1` is the actual FinalGate entry point.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Re-audited and resealed dependent stale closure bindings**
- **Found during:** Task 2 tamper-suite verification
- **Issue:** After T-01-15-03 passed, the all-19 verifier exposed stale T-01-16-02, T-01-16-03, T-01-18-SC, T-01-20-01, T-01-20-02, and T-01-20-05 artifact bindings.
- **Fix:** Reviewed the relevant diffs for security-semantic equivalence and updated only current artifact digests.
- **Files modified:** `evidence/phase1/security-closure.yaml`
- **Verification:** Focused records pass and Pester passes 18/18.
- **Committed in:** `ca1bf98`

**2. [Rule 1 - Bug] Corrected stale FinalGate command in the plan**
- **Found during:** Task 3 overall verification
- **Issue:** `verify-phase1-evidence.ps1 -Scenario FinalGate` is rejected by that script's `ValidateSet`.
- **Fix:** Ran the canonical top-level `scripts/verify-phase1.ps1` with all four machine-role arguments.
- **Files modified:** None
- **Verification:** FinalGate passed 34/34 checks, 30/30 requirements, and 7/7 success criteria.

---

**Total deviations:** 2 auto-fixed (1 blocking closure repair, 1 verification-command bug)
**Impact on plan:** Both were required to establish a truthful all-19 current security sign-off; no production behavior was changed.

## Issues Encountered

- The `slopcheck` executable referenced by T-01-18-SC is not installed and no repository-local slopcheck script exists. The lockfile diff was manually verified to add no package records, versions, or registry sources; only two already-resolved packages were added to an existing crate dependency list.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 01 security evidence is current and FinalGate is green.
- The verification report can be refreshed to clear SEC-01/SEC-03 and the timestamp warning.

## Known Stubs

None.

## Threat Flags

None - no new network, authentication, file-access, schema, or trust-boundary surface was introduced.

## Self-Check: PASSED

- All three modified artifacts exist.
- Task commits `3eefb3e`, `ef43303`, `ca1bf98`, and `2b20917` exist in git history.
- Tamper suite, signed-off verifier, mounted-smoke test, clippy, and canonical FinalGate passed.

---
*Phase: 01-first-encrypted-drive-vertical-slice*
*Completed: 2026-08-24*
