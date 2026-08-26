---
phase: 01-first-encrypted-drive-vertical-slice
reviewed: 2026-08-25T15:10:00Z
depth: standard
files_reviewed: 3
files_reviewed_list:
  - scripts/add-security-closure-review.ps1
  - scripts/evidence/Phase1.Security.Tests.ps1
  - scripts/verify-phase1-security.ps1
findings:
  critical: 3
  warning: 1
  info: 0
  total: 4
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

## Plan 01-34 Advisory Code Review — 2026-08-25

This standard-depth adversarial review covers the three Plan 01-34 PowerShell source files listed in the current frontmatter. The historical findings and resolution record above remain append-only. Four additional defects remain open.

### Critical Issues

#### CR-05: Signing station identity is asserted from policy instead of the executing machine (BLOCKER)

**File:** `scripts/add-security-closure-review.ps1:16,22`
**Issue:** The preview displays `$env:COMPUTERNAME`, but publication never compares the executing machine or user to the selected policy reviewer. The signed attestation instead copies `machine_identity`, role, domain, and reviewer name directly from the policy. Anyone who obtains the reviewer's certificate/private-key access can run the script on another host and produce an attestation that falsely claims it was created on `LAB-DC02`; the verifier later compares the claim to the same policy data and accepts it. This defeats the D-22 station restriction and makes `environment_fingerprint` self-asserted rather than observed.
**Fix:** Before prompting or signing, resolve exactly one policy reviewer and require the observed `$env:COMPUTERNAME` and `[Security.Principal.WindowsIdentity]::GetCurrent().Name` to match the approved machine and identity. Populate the attestation from those observed values, not copied policy values, and add a child-process regression proving signing from a non-D-22 machine fails without mutation.

#### CR-06: Historical CMS signatures are not verified (BLOCKER)

**File:** `scripts/verify-phase1-security.ps1:43-44`
**Issue:** `Test-Record` checks digest/predecessor linkage for every attestation, but calls `Test-SignedAttestation` only for the latest entry. `signature_cms_base64` is deliberately excluded from `attestation_digest`, so an attacker can replace or corrupt any superseded signature without changing its digest or the latest signed predecessor. Signed-off verification still returns valid, even though the append-only historical evidence is no longer authentic or auditable.
**Fix:** In signed-off mode, verify the CMS signature and applicable trust contract for every attestation in the chain (or define and verify a separately signed archival envelope that commits to historical signature bytes). Add a regression that flips one byte in a non-latest CMS signature and requires `signature_invalid` for that historical entry.

#### CR-07: Lexical containment follows reparse points outside the repository (BLOCKER)

**File:** `scripts/verify-phase1-security.ps1:15-19,42`
**Issue:** `GetFullPath` plus `StartsWith` rejects textual `..` traversal but does not resolve directory junctions or symbolic links. A manifest reference such as `evidence/link/outside.bin` passes the prefix check when `link` is an in-repository reparse point targeting an external directory; `ReadAllBytes` then hashes the external file. This reopens the artifact-boundary bypass under a Windows-native path mechanism not covered by the four lexical tests.
**Fix:** Walk each existing path component from the repository root and reject reparse points, or resolve the final filesystem target/handle and prove it remains beneath the canonical repository root before hashing. Add junction and symlink regression cases that point to an external sentinel file and require a stable containment diagnostic.

### Warnings

#### WR-02: Chain helper destroys pre-existing caller environment variables (WARNING)

**File:** `scripts/verify-phase1-security.ps1:21-22`
**Issue:** `Invoke-CustomRootChainValidation` overwrites `PHASE1_CHAIN_CERT` and `PHASE1_CHAIN_ROOTS`, then unconditionally removes both in `finally`. If the caller already defined either variable, invoking the verifier silently destroys caller state. This can break nested verification/tooling and makes the helper non-composable.
**Fix:** Snapshot whether each variable exists and its prior value before assignment, then restore the original value (or remove only variables that were previously absent) in `finally`. Prefer passing values directly in a process start environment map when available.

---

_Reviewed: 2026-08-25T15:10:00Z_  
_Reviewer: the agent (gsd-code-reviewer)_  
_Depth: standard_
