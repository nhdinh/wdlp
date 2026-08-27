---
phase: 01-first-encrypted-drive-vertical-slice
plan: 44
subsystem: testing
tags: [powershell, finalgate, cms, d48, lab-client01]
requires:
  - phase: 01-first-encrypted-drive-vertical-slice
    provides: "Plan 01-43 authenticated FinalGate regression and D-48 history"
provides:
  - "Corrupted-CMS oracle attributable only to detached signature rejection"
  - "Append-only D-48 generations binding the frozen implementation"
  - "Passing focused and full security regressions on LAB-CLIENT01"
affects: [phase-01-verification, TST-08, security-closure]
actuals:
  tokens: 7004
  tasks: 2
  commits: 2
tech-stack:
  added: []
  patterns: ["Specific negative diagnostic oracle", "Disposable trust-handle fixture setup"]
key-files:
  created:
    - .planning/phases/01-first-encrypted-drive-vertical-slice/01-44-SUMMARY.md
    - evidence/phase1/independent-reviews/000003-af5af1e5cd8c37c7/generation.json
    - evidence/phase1/independent-reviews/000004-93e809eea24ef214/generation.json
  modified:
    - scripts/evidence/Phase1.Security.Tests.ps1
    - evidence/phase1/independent-reviews/index.json
key-decisions:
  - "Preserve generation 000003 as immutable history and append generation 000004 for the frozen implementation."
  - "Copy only approved public reviewer handles into disposable FinalGate fixtures."
patterns-established:
  - "Negative CMS tests require signature_invalid and explicitly reject unrelated fixture/setup diagnostics."
requirements-completed: [TST-08]
coverage:
  - id: D1
    description: "Corrupted copied CMS reaches detached verification and cannot pass on digest or setup failures."
    requirement: TST-08
    verification:
      - kind: integration
        ref: "LAB-CLIENT01: scripts/evidence/Phase1.Security.Tests.ps1 -Focus FinalGate"
        status: pass
    human_judgment: false
  - id: D2
    description: "Complete Phase 1 security suite passes against the authenticated successor generation."
    requirement: TST-08
    verification:
      - kind: e2e
        ref: "LAB-CLIENT01: scripts/evidence/Phase1.Security.Tests.ps1 -Focus All"
        status: pass
    human_judgment: false
duration: 75min
completed: 2026-08-28
status: complete
---

# Phase 1 Plan 44: Specific Corrupted-CMS Oracle Summary

**Detached-CMS corruption now passes its negative regression only on `signature_invalid`, backed by append-only D-48 generations and passing binding-endpoint security runs.**

## Performance

- **Duration:** 75 min across the implementation, ceremony checkpoint, and resumed verification
- **Completed:** 2026-08-28
- **Tasks:** 2
- **Implementation/evidence files modified:** 4

## Accomplishments

- Tightened the copied-closure FinalGate oracle to require `signature_invalid` and reject `file digest mismatch` plus stable unrelated setup/execution diagnostics.
- Made disposable FinalGate roots carry only the approved independent reviewer policy/root handles, failing explicitly if either handle is absent.
- Preserved D-48 generation `000003-af5af1e5cd8c37c7` and appended successor `000004-93e809eea24ef214`, binding frozen implementation commit `93e9e37e351a5517cb8529a4f14aba01967e6aba`.
- Passed focused FinalGate and the complete security suite on `LAB-CLIENT01`.

## Task Commits

1. **Task 1: Freeze the specific corrupted-CMS oracle** — `93e9e37` (test)
2. **Task 2: Publish authenticated D-48 successor generations** — `1e28d80` (test)

## Files Created/Modified

- `scripts/evidence/Phase1.Security.Tests.ps1` — Copies approved public trust handles into disposable fixtures and enforces the specific CMS diagnostic oracle.
- `evidence/phase1/independent-reviews/index.json` — Appends generations 000003 and 000004.
- `evidence/phase1/independent-reviews/000003-af5af1e5cd8c37c7/generation.json` — Immutable historical generation binding prior commit `8f10b2f09ac5ad10d9d4bf1b0529e4c093a9624b`.
- `evidence/phase1/independent-reviews/000004-93e809eea24ef214/generation.json` — Immutable successor binding frozen commit `93e9e37e351a5517cb8529a4f14aba01967e6aba`.

## Binding Verification Evidence

| Gate | Machine / role | UTC observed | Build | Exit | Stable result |
|---|---|---|---|---:|---|
| Focused FinalGate | `LAB-CLIENT01` / endpoint_runtime | 2026-08-27T18:10:20Z | `1e28d803a9b08c7ab472fac177bd200699f894b6` | 0 | `Phase 1 FinalGate propagation tests passed.` |
| Complete `All` | `LAB-CLIENT01` / endpoint_runtime | 2026-08-27T18:21:33Z | `1e28d803a9b08c7ab472fac177bd200699f894b6` | 0 | `Phase 1 security closure tests passed.` |

Commands executed in clean PowerShell processes:

```powershell
rtk powershell -NoProfile -ExecutionPolicy Bypass -File scripts/evidence/Phase1.Security.Tests.ps1 -Focus FinalGate
rtk powershell -NoProfile -ExecutionPolicy Bypass -File scripts/evidence/Phase1.Security.Tests.ps1 -Focus All
```

Sanitized environment fingerprint:

- Machine/role: `LAB-CLIENT01` / `endpoint_runtime`
- OS: Microsoft Windows NT 10.0.26200.0
- PowerShell: 5.1.26100.9168
- Domain identity: `LAB` (no personal identity recorded)
- Test script SHA-256: `f32936951d2309308199807edcf5c6c6a2c116c8076adff2947a78975611f769`
- D-48 index head: `93e809eea24ef2149a3c199c3bf3a677eb3577f93fcb32bca3b5d9e121449298`
- Generation 000003 digest: `af5af1e5cd8c37c7c4c31abeaa66eab3faa3c912413cca007f11546f26e8d46e`
- Generation 000004 digest: `93e809eea24ef2149a3c199c3bf3a677eb3577f93fcb32bca3b5d9e121449298`
- D-48 signer: `LAB\d48-reviewer` on `LAB-CLIENT01`, approved policy `phase1-d48-independent-review-2026-08-26`; no certificate or trust bytes are published here.

The focused completion marker is emitted only after the corrupted copied-CMS branch and canonical success assertions execute. The full completion marker follows the same FinalGate block plus all remaining security fixtures.

## Decisions Made

- Kept the ceremony additive: generation 000003 remains byte-identical history and generation 000004 is its authenticated successor.
- Limited disposable fixture trust setup to public policy/root handles already required by the canonical verifier.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Completed the disposable independent-review setup**
- **Found during:** Task 1 focused LAB run
- **Issue:** The copied repository emitted a missing independent-review policy warning alongside `signature_invalid`, allowing an unrelated fixture defect.
- **Fix:** `Invoke-FinalGate` copies the approved public policy/root handles into disposable verifier roots and fails with a specific setup diagnostic when absent.
- **Files modified:** `scripts/evidence/Phase1.Security.Tests.ps1`
- **Verification:** Focused and complete LAB-CLIENT01 runs exit 0.
- **Committed in:** `93e9e37`

**2. [Rule 3 - Blocking] Froze and authenticated the implementation before binding verification**
- **Found during:** Task 1 canonical run
- **Issue:** Existing independent review reported artifact drift after the implementation changed.
- **Fix:** Paused for the authorized D-48 ceremony, preserved generation 000003, and appended generation 000004 for the frozen commit.
- **Files modified:** D-48 index and immutable generation files only.
- **Verification:** Local index validation and both LAB-CLIENT01 security runs passed.
- **Committed in:** `1e28d80`

**Total deviations:** 2 auto-fixed (1 missing critical fixture setup, 1 blocking authenticated-evidence refresh).
**Impact on plan:** Both were required to ensure the negative test is attributable to CMS verification and the binding runs authenticate the exact implementation.

## Issues Encountered

- GitNexus did not index the PowerShell helper/block: impact was `UNKNOWN` with zero represented callers/processes. Staged checks for implementation and evidence were low risk with zero affected processes.
- Literal comparison to `main` was unavailable because the repository default branch is `master`; authorized target-specific staged validation isolated plan files from unrelated user changes.

## Known Stubs

None.

## Authentication Gates

- The D-48 signing ceremony required the authorized `LAB\d48-reviewer` identity and private-key custody on `LAB-CLIENT01`; execution paused and resumed only after the user confirmed the validated successor generation.

## User Setup Required

None — the authorized ceremony is complete and no new persistent configuration is required.

## Next Phase Readiness

- P43-03 is verified by source inspection plus focused/full binding runs.
- TST-08 is satisfied with no remaining corrupted-CMS false-positive path.
- Authenticated history remains append-only and ready for Phase 01 closure.

## Self-Check: PASSED

- Frozen implementation commit `93e9e37e351a5517cb8529a4f14aba01967e6aba` exists.
- Authenticated evidence commit `1e28d803a9b08c7ab472fac177bd200699f894b6` exists.
- D-48 generations 000003 and 000004 exist and local index validation passes.
- Focused FinalGate and complete All runs both exited zero on `LAB-CLIENT01`.

---
*Phase: 01-first-encrypted-drive-vertical-slice*
*Completed: 2026-08-28*
