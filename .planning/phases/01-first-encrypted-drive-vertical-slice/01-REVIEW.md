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

## Plan 01-36 Resolution — 2026-08-26

The CR-05 through CR-07 findings above remain verbatim as the failed review interval. They are now resolved with authenticated, append-only evidence; no earlier finding, attestation, signature, or superseded interval was deleted or rewritten.

### CR-05 Resolved — observed reviewer identity and station

Commit `3b7341a` captures `[Security.Principal.WindowsIdentity]::GetCurrent().Name` and `COMPUTERNAME`, requires them to match the sole policy reviewer before preview, affirmation, locking, signing, or mutation, and writes the observed values into the signed record. The authenticated Plan 01-36 ceremony ran as `LAB\dlp-reviewer` on the policy-approved `LAB-DC02` reviewer station and signed with thumbprint `E9407299128C7A1292E3B78F7F2E369CB71B67A5`. Wrong-user and wrong-machine behavioral regressions pass without mutation.

### CR-06 Resolved — complete historical CMS commitment

Commit `6d6da21` adds a signed `phase1-history-envelope/v1` commitment over the ordered attestation digests and SHA-256 digest of every historical CMS byte sequence. Commit `3610c57` publishes that envelope for all 19 records. The pre/post inventory proves all 76 prior attestations are byte-identical; exactly 19 additive attestations and 19 envelopes were added. Superseded CMS byte mutation, history removal, and history reordering each fail closed in the complete security suite.

### CR-07 Resolved — final-handle repository containment

Commit `5e60d7e` opens each reference once, resolves its final Windows path with `GetFinalPathNameByHandleW`, proves the final target remains within the repository boundary, and hashes from the same accepted handle. Real junction, symbolic-link, and path-swap/handle-stability regressions pass and reject external targets.

### Closure identities and gates

- Ceremony procedure: `01-32/independent-security-review/v1`, review interval `2026-08-25T10:51:45.4958996Z`–`2026-08-25T10:51:46.2670017Z`.
- Current manifest digest: `fcadc1d8609afc0357083b843715f6a1db15e2878978d97759ee8d44e75815c3`.
- Reviewer-policy identity: `edfa1018ee5c9fbb5073af0a16b71bf82e83f144a48568164b8a691fdff960fd`.
- Direct signed-off verifier: `valid`, zero diagnostics.
- Canonical FinalGate: passed 34/34 checks; 30/30 requirements; 7/7 success criteria; 50/50 decisions; 9/9 privilege manifests; identical manifest and policy identities.

**Resolution status:** CR-05, CR-06, and CR-07 closed. A fresh D-48 verifier distinct from the archival-envelope signer must still review and sign the final frozen evidence digest before Phase 1 completion.

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

## Plan 01-40/01-41 Advisory Code Review — 2026-08-26

This interval reviews `scripts/add-independent-review.ps1`, `scripts/evidence/Phase1.Security.Tests.ps1`, and `scripts/verify-phase1-security.ps1` after the gap-closure implementation. Earlier findings and their resolution records remain append-only above.

### Critical Issues

#### CR-08: Historical-envelope signer bypasses the required trust contract (BLOCKER)

**File:** `scripts/verify-phase1-security.ps1:63`
**Issue:** `Test-HistoryEnvelope` verifies only CMS cryptographic validity, signer count, and a thumbprint/identity/context match against the policy. Unlike `Test-SignedAttestation`, it never checks the envelope signer certificate's digital-signature key usage, required EKU, custom-root chain, revocation status, certificate validity at `review_utc`, or future-clock bounds. A revoked, wrong-purpose, or otherwise untrusted envelope signer can therefore keep a forged historical envelope `valid` as long as its thumbprint remains listed in policy. Plan 01-41 requires envelope signer checks under the same external trust contract.
**Fix:** Route the envelope certificate through the same key-usage, EKU, custom-root, revocation, validity, and reviewer-context validation used for the current attestation (with a dedicated diagnostic prefix if needed), and validate the envelope review timestamp against policy clock skew.

#### CR-09: Publisher trusts an unvalidated index and permits history truncation/forks (BLOCKER)

**File:** `scripts/add-independent-review.ps1:34-45`
**Issue:** The publisher deserializes `index.json` and takes the last `generation_digest` as `$previous` without validating the index schema, generation paths, stored generation digests, or predecessor continuity. An edited or truncated index can make a new signed generation reference an attacker-selected predecessor (including an empty history); the independent-review verifier consumes only the latest indexed generation and does not detect the lost entries. This breaks the claimed append-only D-48 history and allows rollback/forked publication to be accepted.
**Fix:** Before signing, canonicalize and validate every existing index entry, hash each referenced `generation.json`, require its digest and `previous_generation_digest` chain to match, reject missing/duplicate/out-of-order entries, and bind the index head (or a signed index digest) into the published commitment. Refuse publication on any index drift instead of treating the last JSON element as authoritative.

### Warnings

#### WR-03: Publication writes are not flushed durably before replacement (WARNING)

**File:** `scripts/add-independent-review.ps1:43-45`
**Issue:** `WriteAllBytes` followed by `Move-Item` does not flush the generation or index temporary file with `Flush(true)`. A power loss can leave an incomplete generation, a missing index update, or an orphaned directory despite the script claiming crash-recoverable immutable publication.
**Fix:** Write through opened `FileStream` instances, call `Flush($true)` before each rename, and use the same durable replacement protocol for the index (including a documented directory-metadata durability strategy on Windows).

#### WR-04: Environment-restoration regression is vacuous across a child process (WARNING)

**File:** `scripts/evidence/Phase1.Security.Tests.ps1:81-84`
**Issue:** `Invoke-Verify` launches a separate PowerShell process. Changes to `PHASE1_CHAIN_CERT` and `PHASE1_CHAIN_ROOTS` in that child can never alter the parent process, so the sentinel assertions at lines 83-84 pass even if `Invoke-CustomRootChainValidation` permanently deletes or overwrites its caller's variables. The source-regex check is not behavioral coverage.
**Fix:** Exercise the helper in-process (for example, dot-source an injectable function or add a test-only entry point) and assert sentinel values before/after both success and failure paths; alternatively have the child report its post-call environment and assert that report.

#### WR-05: Pre-sign-off verifier success is not asserted (WARNING)

**File:** `scripts/evidence/Phase1.Security.Tests.ps1:99`
**Issue:** The test only checks the known digest diagnostic when `$base.Exit -ne 0`; if the verifier incorrectly returns exit code 0 for a malformed or incomplete canonical manifest, the test performs no assertion and continues. This leaves a fail-open regression undetected.
**Fix:** Add an explicit `else` assertion that exit 0 is accompanied by `status == 'valid'` and zero diagnostics (or fail unless the expected digest-mismatch exit is observed).

---

_Reviewed: 2026-08-26T11:40:12.7350048Z_  
_Reviewer: the agent (gsd-code-reviewer)_  
_Depth: standard_

## Plan 01-42 Critical-Finding Resolution — 2026-08-27

The CR-08 and CR-09 findings above remain verbatim as the advisory review interval. They are resolved by commit `ffaecf88e19f5eda79b85c15351436b78f4c25e5`; no earlier finding or signed evidence was rewritten.

### CR-08 Resolved — historical-envelope signer trust

Current and superseded historical envelopes now require exactly one signer and apply the complete reviewer trust contract: approved thumbprint and identity/context, digital-signature key usage, required EKU, custom-root anchoring, online revocation, certificate validity at `review_utc`, and future-clock-skew enforcement. Wrong-purpose, untrusted, and revoked/indeterminate envelope signers fail closed with stable diagnostics. The legacy unsigned-first-entry compatibility rule is unchanged.

### CR-09 Resolved — append-only D-48 index validation

The D-48 publisher now validates the existing index before signing: schema, canonical entry identifiers and paths, generation file digests, embedded commitment predecessor linkage, ordering, uniqueness, missing or extra generation directories, truncation, and fork consistency. Any drift is rejected before staging or publication.

### Verification

- `Phase1.Security.Tests.ps1 -Focus Publication` — passed.
- `Phase1.Security.Tests.ps1 -Focus Verifier` — passed.
- `Phase1.Security.Tests.ps1 -Focus All` — passed.
- GitNexus staged change analysis — LOW risk, no affected indexed execution flows.

**Resolution status:** CR-08 and CR-09 closed. WR-03 through WR-05 remain advisory and were not authorized for remediation in this interval.
