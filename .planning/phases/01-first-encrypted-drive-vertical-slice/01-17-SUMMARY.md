---
phase: 01-first-encrypted-drive-vertical-slice
plan: "17"
subsystem: verification-governance
tags: [evidence, provenance, privilege-control, powershell, phase1]
requires: []
provides:
  - "Versioned fail-closed Phase 1 evidence publication and verification contract"
  - "Requirement, success-criterion, and D-01 through D-50 evidence matrix"
  - "Digest-bound four-machine privilege manifests and authenticated approval records"
affects: [01-13, 01-14, 01-15, 01-16, 01-18, 01-19, 01-20, 01-21, 01-22, 01-23]
tech-stack:
  added: []
  patterns:
    - "Immutable UUID evidence attempts with controlled raw-artifact hashes"
    - "Four-tier verification boundaries that prevent substitute promotion"
    - "Per-plan digest approvals with role, baseline, rollback, and idempotence contracts"
key-files:
  created: []
  modified:
    - evidence/phase1/requirement-matrix.yaml
    - evidence/phase1/schema/evidence-manifest.schema.json
    - config/lab.phase1.example.yaml
    - scripts/evidence/Phase1.Evidence.psm1
    - scripts/verify-phase1-evidence.ps1
key-decisions:
  - "Re-executed 01-17 verification found four matrix rows with synthetic or inaccessible evidence IDs; those rows were cleared to unverified to preserve the fail-closed contract."
  - "The evidence schema now explicitly includes LAB-SERVER01 and aligns target_role enums with the PowerShell verifier's MachineRoles map."
  - "The operator approved the existing eight digest-bound privilege manifests through the interactive checkpoint; no manifest drift was detected."
requirements-completed: []
patterns-established:
  - "Re-execution of a verification plan must re-validate every matrix evidence ID against accessible raw artifacts, not just schema."
  - "Schema enums and verifier enums must stay synchronized; drift blocks publication."
coverage:
  - id: D1
    description: "Portable TST-01 evidence publishes through the full phase1-evidence/v1 contract and links to the requirement matrix."
    requirement: TST-01
    verification:
      - kind: integration
        ref: "scripts/verify-phase1-evidence.ps1 -ExecutionMachine hungdinh-lt -Scenario PortableTracer"
        status: pass
    human_judgment: false
  - id: D2
    description: "Evidence fail-closed fixtures reject duplicate IDs, missing fields, hash mismatches, clock skew, secret markers, deviations, wrong machines, and stale dependencies."
    requirement: TST-01
    verification:
      - kind: integration
        ref: "scripts/verify-phase1-evidence.ps1 -ExecutionMachine hungdinh-lt -Scenario ContractsAndPrivileges"
        status: pass
    human_judgment: false
  - id: D3
    description: "Machine roles, substitute boundaries, visual checklist contract, independent-review contract, and per-plan privilege manifests are machine validated."
    verification:
      - kind: integration
        ref: "scripts/verify-phase1-evidence.ps1 -ExecutionMachine hungdinh-lt -Scenario ContractsAndPrivileges"
        status: pass
    human_judgment: false
  - id: D4
    description: "Exact digest-bound privilege approvals for Plans 01-13, 01-14, 01-18, 01-19, 01-15, 01-20, 01-16, and 01-21 are recorded and verified."
    verification:
      - kind: integration
        ref: "scripts/verify-phase1-evidence.ps1 -ExecutionMachine hungdinh-lt -Scenario PrivilegeApprovals"
        status: pass
    human_judgment: true
    rationale: "Approval binds an authenticated human operator to specific privileged lab mutations; automation can verify the digest binding but cannot authorize the risk acceptance."
metrics:
  duration: 15min
  completed: 2026-08-16T12:30:00Z
status: complete
actuals:
  tokens: 1200
  tasks: 3
  commits: 1
---

# Phase 01 Plan 17: Evidence and Privilege Control Summary

**Re-validated the Phase 1 evidence contract, cleared synthetic matrix evidence IDs, aligned schema enums with the verifier, and confirmed the eight digest-bound privilege manifests are approved and drift-free.**

## Performance

- **Duration:** 15 min
- **Started:** 2026-08-16T12:15:00Z
- **Completed:** 2026-08-16T12:30:00Z
- **Tasks:** 3
- **Files modified:** 2

## Accomplishments

- Re-ran the portable TST-01 tracer and all fail-closed contract fixtures; publication, staleness, supersession, and redaction gates pass.
- Cleared four matrix rows (WRK-04, SRV-11, SRV-12, CRY-01) that contained evidence IDs with missing or inaccessible raw artifacts, restoring the fail-closed rule that a row cannot pass without valid evidence.
- Synchronized `evidence-manifest.schema.json` with the PowerShell verifier by adding `LAB-SERVER01` to `target_machine` and aligning `target_role` values.
- Verified the eight per-plan privilege manifests in `config/lab.phase1.example.yaml` and recorded the operator's `approve-listed-digests` decision.

## Task Commits

Each task was committed atomically:

1. **Task 1: Publish one portable check through the complete evidence contract** - `1088b45` (fix)
2. **Task 2: Define binding machine roles, substitute boundaries, visual review, and exact privilege manifests** - `1088b45` (fix)
3. **Task 3: Approve the exact Phase 1 privilege-manifest digests** - no new code commit (approvals already present and verified; human decision recorded in this summary)

**Plan metadata:** `1088b45`

## Files Created/Modified

- `evidence/phase1/requirement-matrix.yaml` - Removed synthetic/inaccessible evidence IDs from WRK-04, SRV-11, SRV-12, and CRY-01 rows; status reset to `unverified`.
- `evidence/phase1/schema/evidence-manifest.schema.json` - Added `LAB-SERVER01` to `target_machine` enum and aligned `target_role` enum with verifier.
- `config/lab.phase1.example.yaml` - Already contained the eight privilege manifests and approvals; verified unchanged and drift-free.
- `scripts/evidence/Phase1.Evidence.psm1` - Existing portable evidence and privilege helpers; no changes required.
- `scripts/verify-phase1-evidence.ps1` - Existing focused verifier; no changes required.

## Decisions Made

- Synthetic or stale evidence IDs in the matrix must be cleared rather than left as passing placeholders; the fail-closed contract takes precedence over appearance of progress.
- Schema and verifier enums must be kept synchronized; a validator that accepts a value the verifier rejects is a correctness bug.
- The operator confirmed the pre-existing privilege-manifest digests are still authoritative for the remaining Phase 1 lab work.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Removed synthetic evidence IDs from the requirement matrix.**
- **Found during:** Task 1 (portable tracer re-validation)
- **Issue:** WRK-04, SRV-11, SRV-12, and CRY-01 matrix rows referenced evidence IDs with no corresponding manifest file or missing raw artifact (`target/phase1-evidence/cry-01-aead-store.log`), causing those rows to falsely appear as passing.
- **Fix:** Reset `current_evidence_id` to empty and `status` to `unverified` for those four rows.
- **Files modified:** `evidence/phase1/requirement-matrix.yaml`
- **Verification:** `scripts/verify-phase1-evidence.ps1 -Scenario ContractsAndPrivileges` passes; no matrix row claims a passing evidence ID that cannot be resolved.
- **Committed in:** `1088b45`

**2. [Rule 1 - Bug] Aligned schema enums with the PowerShell verifier.**
- **Found during:** Task 1 (schema validation)
- **Issue:** `evidence-manifest.schema.json` omitted `LAB-SERVER01` from `target_machine` and used `developer_host` for `hungdinh-lt` while the verifier used `developer_orchestrator`, creating a publication rejection for legitimate server-side evidence.
- **Fix:** Added `LAB-SERVER01` and aligned `target_role` values to `developer_orchestrator`, `database_server`, `primary_directory_server`, `secondary_directory_server`, and `endpoint_runtime`.
- **Files modified:** `evidence/phase1/schema/evidence-manifest.schema.json`
- **Verification:** `Test-Phase1Evidence` and all verifier scenarios pass.
- **Committed in:** `1088b45`

---

**Total deviations:** 2 auto-fixed (2 bugs)
**Impact on plan:** Both fixes are correctness repairs within the existing verification contract. No scope creep.

## Issues Encountered

- The existing `cry-01-aead-store-integrity.json` manifest referenced `target/phase1-evidence/cry-01-aead-store.log`, which is no longer present. This is not a deviation introduced by this plan; it is pre-existing stale evidence from a prior run. The row was cleared to `unverified`; the raw artifact must be regenerated by the plan that owns CRY-01 evidence.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- The evidence contract, requirement matrix, and privilege approvals are now consistent and machine validated.
- The remaining Phase 1 lab-mutating plans (01-13, 01-14, 01-18, 01-19, 01-15, 01-20, 01-16, 01-21) have approved, digest-bound manifests and may proceed when their prerequisites are met.
- Plans 01-22 and 01-23 remain correctly classified as source-only; their deployment effects are owned by Plan 01-13.

---
*Phase: 01-first-encrypted-drive-vertical-slice*
*Completed: 2026-08-16*
