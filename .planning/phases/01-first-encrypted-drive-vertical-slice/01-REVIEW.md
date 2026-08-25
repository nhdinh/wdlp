---
phase: 01-first-encrypted-drive-vertical-slice
reviewed: 2026-08-25T00:00:00Z
depth: standard
files_reviewed: 5
files_reviewed_list:
  - evidence/phase1/security-closure.yaml
  - scripts/add-security-closure-review.ps1
  - scripts/evidence/Phase1.Security.Tests.ps1
  - scripts/verify-phase1-security.ps1
  - scripts/verify-phase1.ps1
findings:
  critical: 4
  warning: 1
  info: 0
  total: 5
status: issues_found
---

# Phase 01: Code Review Report

**Reviewed:** 2026-08-25T00:00:00Z
**Depth:** standard
**Files Reviewed:** 5
**Status:** issues_found

## Summary

The authenticated review closure is not safe to ship. Direct review found four blocker-tier defects in the approval, trust-policy, artifact-boundary, and regression-test contracts. The checked-in security suite exits successfully, but key tests do not execute the security properties their names and Phase 01-33 evidence claim. GitNexus reported low graph blast radius and no persisted taint findings for the scripts; its PowerShell index did not expose the dense script functions as changed symbols, so the narrative findings below come from direct call-path and data-flow tracing.

## Narrative Findings (AI reviewer)

## Critical Issues

### CR-01: Approved payload is discarded and a different locked payload is signed (BLOCKER)

**File:** `scripts/add-security-closure-review.ps1:15-21`
**Issue:** The reviewer sees and approves `$initial`, but after acquiring the mutex the script re-reads `$closure` and recomputes `$pd` from that new object without comparing it to the approved digest. A concurrent editor can change any protected field between confirmation and lock acquisition; the script will then sign and publish the unreviewed replacement payload. The mutex only serializes cooperating publishers and does not close this consent TOCTOU boundary.
**Fix:** Store each displayed canonical payload digest and predecessor digest. Under the mutex, re-read the manifest and require both values to remain identical before signing. On drift, return `publication_conflict:<threat>` without writing; alternatively render and require fresh confirmation while the lock is held.

### CR-02: Signed-off verification ignores certificate EKU and disables revocation (BLOCKER)

**File:** `scripts/verify-phase1-security.ps1:24-27`
**Issue:** The verifier matches thumbprint/identity and builds a chain, but never checks the certificate EKU or key-usage policy. It also hard-codes `RevocationMode='NoCheck'`. A compromised/revoked certificate, or a certificate not authorized for reviewer signing, can therefore produce a `valid` result despite Plan 01-31 requiring EKU/validity policy enforcement.
**Fix:** Validate required EKU OIDs and digital-signature key usage from the external policy, configure revocation according to that policy, and add stable diagnostics for EKU, key usage, revoked, and revocation-unknown outcomes.

### CR-03: Artifact references can escape the repository (BLOCKER)

**File:** `scripts/verify-phase1-security.ps1:31`
**Issue:** Manifest-controlled `implementation_refs` and `artifact_refs` are appended to `$repoRoot` without resolving and enforcing repository containment. Values containing `..` can make the verifier hash files outside the repository, allowing unrelated external files to satisfy the artifact-integrity gate.
**Fix:** Resolve every candidate with `[IO.Path]::GetFullPath`, reject rooted child paths, enforce containment beneath a normalized repository root with a trailing separator, and hash only the validated path.

### CR-04: Security regressions pass without exercising forgery or concurrency (BLOCKER)

**File:** `scripts/evidence/Phase1.Security.Tests.ps1:15-17,35-37`
**Issue:** The forgery test supplies an invalid root and `{}` policy, so verification exits during trust-input parsing before examining the mutated signature; `Exit -ne 0` proves only malformed configuration fails. The two-writer, crash-before-replace, and FinalGate-subgate claims are regex/source-presence assertions—no two processes run, no barrier or crash is exercised, and no forced FinalGate failure is executed. The suite passes while CR-01 remains present, making Phase 01-33 evidence false-positive.
**Fix:** Run forgery with the valid canonical trust inputs and assert `signature_invalid`. Launch two publisher processes with the barrier, execute the crash hook and verify byte identity, and invoke FinalGate with a deterministically failing security subgate plus identity equality on success.

## Warnings

### WR-01: Capture writes before validating the signer against the full trust contract (WARNING)

**File:** `scripts/add-security-closure-review.ps1:13,21-22`
**Issue:** Capture checks only for a private key and a thumbprint entry in JSON. It does not validate policy schema, chain/root, EKU, validity, reviewer context, or the candidate attestation with the canonical verifier before replacement. Invalid-signer paths can mutate the append-only file despite the plan requiring byte-identical non-mutation.
**Fix:** Accept the trusted-root path, validate signer and policy before prompting, verify the complete candidate manifest with the canonical verifier before replacement, and leave the canonical file unchanged on any diagnostic.

---

_Reviewed: 2026-08-25T00:00:00Z_
_Reviewer: the agent (gsd-code-reviewer)_
_Depth: standard_

## Plan 01-34 Resolution — 2026-08-25

The blocker findings above remain verbatim as the failed review interval. Plan 01-34 resolves them with executable evidence and preserves every superseded attestation.

### CR-01 Resolved — affirmed bytes equal signed bytes

Commit `cb82615` retains each displayed canonical payload digest and predecessor digest, re-reads both under the canonical-path publication mutex, and rejects any difference with `publication_conflict:<threat>` before signing or writing. Spawned regressions prove protected-field drift is byte-preserving, two publishers serialize with exactly one valid append and intact predecessor, and `CrashBeforeReplace` preserves original bytes while cleaning temporary files.

### CR-02 Resolved — authorized purpose and current revocation

Commit `a5517d0` requires policy-declared EKUs, digital-signature key usage, approved identity/context, and online full non-root-chain revocation. Commit `94a8450` keeps Windows PowerShell canonical bytes while running only chain construction in a short-lived `pwsh` process with `CustomRootTrust`, online `ExcludeRoot` revocation, no ignored statuses, temporary public certificates, and no persistent trust-store import. Regressions distinguish `signer_key_usage_invalid`, `signer_eku_invalid`, `signer_revoked`, and `signer_revocation_indeterminate`. The LAB-DC02 replacement certificate ceremony appended 19 current attestations signed by `E9407299128C7A1292E3B78F7F2E369CB71B67A5`; the signed-off verifier returned `valid` with zero diagnostics.

### CR-03 Resolved — repository-contained references

Commit `a5517d0` rejects rooted children, normalizes the repository root with a trailing separator, resolves the full candidate before access, compares with Windows ordinal-ignore-case semantics, and hashes only strictly contained files. Behavioral cases cover rooted paths, parent traversal, sibling prefix collision, and mixed separators.

### CR-04 Resolved — attacks execute, not source-match

Commits `c58c197`, `441c4cc`, `d41150c`, `26b2cc8`, and `1d15e58` replace false-positive source assertions with child-process behavior. The suite proves real concurrency/crash behavior, valid-trust recomputed forgery reaches `signature_invalid`, the ceremony closure passes process-scoped external-root validation, and canonical FinalGate fails specifically when its copied security fixture fails. The successful FinalGate and direct subgate both report manifest `4b30d328d5967f8f2346be1d61811b8ae56b26404dc8bef0150e61ba1619c591` and policy `edfa1018ee5c9fbb5073af0a16b71bf82e83f144a48568164b8a691fdff960fd`.

**Resolution status:** CR-01 through CR-04 closed. Exact commands and counts are appended to `01-SECURITY.md`; remediation topology correction is `f4ad69d`.
