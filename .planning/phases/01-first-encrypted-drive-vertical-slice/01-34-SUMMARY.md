---
phase: 01-first-encrypted-drive-vertical-slice
plan: 34
subsystem: security-closure
tags: [powershell, cms, x509, revocation, path-containment, finalgate]
requires:
  - 01-33 authenticated security closure
provides:
  - consent-bound mutex publication
  - purpose-authorized process-scoped external-root validation
  - repository-contained manifest references
  - behavioral adversarial and FinalGate propagation proof
affects:
  - Phase 1 signed-off security verification
  - Phase 1 FinalGate
tech-stack:
  added: [pwsh CustomRootTrust chain subprocess]
  patterns: [immutable consent snapshots, process-scoped trust, temporary copied FinalGate fixture]
key-files:
  created:
    - .planning/phases/01-first-encrypted-drive-vertical-slice/01-34-SUMMARY.md
  modified:
    - scripts/add-security-closure-review.ps1
    - scripts/verify-phase1-security.ps1
    - scripts/evidence/Phase1.Security.Tests.ps1
    - evidence/phase1/security-closure.yaml
    - .planning/phases/01-first-encrypted-drive-vertical-slice/01-SECURITY.md
    - .planning/phases/01-first-encrypted-drive-vertical-slice/01-REVIEW.md
decisions:
  - Preserve Windows PowerShell as the canonical CMS byte runtime and isolate modern CustomRootTrust chain construction in a short-lived pwsh process.
  - Treat LAB-DC02 as the D-22 trusted reviewer signing station while retaining LAB-DC01 management, CA, and FinalGate roles.
  - Commit the user-generated public ceremony manifest only after signed-off verification and FinalGate passed.
metrics:
  duration: 5h28m
  completed: 2026-08-25
status: complete
actuals:
  tokens: 85781
  tasks: 3
  commits: 11
---

# Phase 01 Plan 34: Hardened Security Trust-Boundary Closure Summary

Consent-bound CMS publication, purpose-authorized external-root validation with online revocation, repository-contained references, and executable FinalGate failure propagation.

## Performance

- **Duration:** 5h28m across external PKI and signing checkpoints
- **Tasks:** 3 completed
- **Commits:** 11 task/remediation commits
- **Files changed:** 7 implementation, evidence, audit, and plan files

## Accomplishments

- Bound every exact-YES affirmation to immutable payload and predecessor digests, then revalidated both under the publication mutex before any signature or write.
- Enforced digital-signature usage, policy-required EKU, approved reviewer context, process-scoped external-root anchoring, and fail-closed online non-root revocation.
- Rejected rooted, traversing, prefix-collision, and mixed-separator manifest references before existence or hashing outside the repository.
- Replaced source-presence claims with spawned-process consent drift, two-publisher, crash, valid-trust forgery, and canonical FinalGate propagation tests.
- Preserved the failed/superseded intervals and appended 19 LAB-DC02 replacement-certificate attestations.

## Verification Results

- Full `Phase1.Security.Tests.ps1`: passed.
- Signed-off security verifier: `valid`, zero diagnostics, 19/19 current attestations.
- Manifest identity: `4b30d328d5967f8f2346be1d61811b8ae56b26404dc8bef0150e61ba1619c591`.
- Reviewer-policy identity: `edfa1018ee5c9fbb5073af0a16b71bf82e83f144a48568164b8a691fdff960fd`.
- Canonical FinalGate: passed 34/34 checks, 30/30 requirements, 7/7 success criteria, 50/50 decisions, and 9/9 privilege manifests.
- FinalGate emitted the same manifest and policy identities as the direct security subgate.
- GitNexus pre-edit impacts were UNKNOWN/unindexed with zero graph-resolved callers/processes. Every pre-commit `detect_changes(scope: all)` result was LOW risk with zero affected indexed processes; unrelated dirty files were preserved.

## Task Commits

1. `c58c197` — failing publication regressions.
2. `cb82615` — consent-bound locked publication.
3. `441c4cc` — failing containment regressions.
4. `a5517d0` — purpose, revocation, and containment enforcement.
5. `eaa1cb5` — stable legacy-policy diagnostic.
6. `d41150c` — valid-trust forgery oracle.
7. `f4ad69d` — LAB-DC02 D-22 topology correction.
8. `26b2cc8` — real external-root chain RED regression.
9. `94a8450` — process-scoped CustomRootTrust chain fix.
10. `1d15e58` — canonical FinalGate propagation regression.
11. `cfbcf69` — ceremony manifest and append-only audit closure.

## Decisions Made

- Kept signature/digest canonicalization in Windows PowerShell 5.1 because moving the whole verifier to PowerShell 7 changes JSON bytes and invalidates historical signatures.
- Passed only exported public certificates to a temporary PowerShell 7 chain subprocess; no private keys or persistent trust-store entries are used.
- Accepted the replacement-certificate ceremony only after HTTP base and delta CRLs produced a clean custom-root chain and the canonical verifier returned zero diagnostics.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed false revocation indeterminacy from ExtraStore chain construction**

- **Found during:** Task 3 signed-off verification
- **Issue:** .NET Framework treated the approved external root as untrusted and reported Offline/Unknown even after fetching current HTTP CRLs.
- **Fix:** Preserve Windows PowerShell canonical bytes while delegating only chain construction to `pwsh` with process-scoped `CustomRootTrust`.
- **Files modified:** `scripts/verify-phase1-security.ps1`, verifier regression tests
- **Commits:** `26b2cc8`, `94a8450`

**2. [Rule 1 - Bug] Stabilized missing policy-EKU schema handling**

- **Found during:** Task 2 external policy hardening
- **Issue:** Strict mode leaked a property-access runtime error for legacy policy files.
- **Fix:** Detect the property through `PSObject.Properties` and return `reviewer_policy_invalid`.
- **Commit:** `eaa1cb5`

## Authentication and Human Gates

- The external PKI/revocation precondition was verified in the authenticated reviewer context.
- The D-22 replacement-certificate signing ceremony ran on `LAB-DC02` as `LAB\dlp-reviewer`; private key material never moved to `hungdinh-lt`.
- Nineteen affected threat IDs were re-affirmed and appended; superseded signatures remain present.

## Known Stubs

None.

## Threat Flags

| Flag | File | Description |
|---|---|---|
| threat_flag: process-boundary | scripts/verify-phase1-security.ps1 | Launches installed `pwsh` with temporary public certificate files for custom-root chain validation; all statuses remain fail-closed and files are removed in `finally`. |

## Self-Check: PASSED

- All modified implementation, test, evidence, and audit files exist.
- All 11 listed commits exist in repository history.
- Full security suite, signed-off verifier, and canonical FinalGate passed after the final code and ceremony manifest changes.
