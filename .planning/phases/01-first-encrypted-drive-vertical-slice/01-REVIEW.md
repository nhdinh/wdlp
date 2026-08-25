---
phase: 01-first-encrypted-drive-vertical-slice
reviewed: 2026-08-24T08:57:49Z
depth: standard
files_reviewed: 4
files_reviewed_list:
  - scripts/verify-phase1-security.ps1
  - scripts/add-security-closure-review.ps1
  - scripts/evidence/Phase1.Security.Tests.ps1
  - evidence/phase1/security-closure.yaml
findings:
  critical: 3
  warning: 3
  info: 0
  total: 6
resolved_findings:
  critical: 1
status: issues_found
---

# Phase 01: Code Review Report

**Reviewed:** 2026-08-24T04:45:00Z
**Depth:** standard
**Files Reviewed:** 2
**Status:** issues_found

## Summary

The mounted-drive timestamp assertion correctly executes only after a real WinFsp mount and rejects the zero-FILETIME mapping because that value converts to a `SystemTime` before `UNIX_EPOCH`. All changed SHA-256 values in the closure manifest also match the current bytes on disk. However, the reseal makes the signed-off security gate produce a false positive: seven records now bind August 24 artifacts while continuing to claim that the independent reviewer approved them on August 21.

## Narrative Findings (AI reviewer)

## Critical Issues

### CR-01: Resealed artifacts inherit stale independent-review attestations

**Classification:** BLOCKER
**File:** `C:/Users/nhdinh/dev/dleakprevention/evidence/phase1/security-closure.yaml:114-642`
**Issue:** The implementation/artifact hashes for T-01-15-03, T-01-16-02, T-01-16-03, T-01-18-SC, T-01-20-01, T-01-20-02, and T-01-20-05 were changed on 2026-08-24, but each record retains its original `reviewer_identity` and `review_utc: "2026-08-21T07:30:00Z"` (for example, the new credential digest is at line 114 while the inherited independent-verifier timestamp is at lines 132-135). A reviewer cannot have approved artifact bytes that did not exist until three days later. Because the verifier checks current digests and merely accepts the pre-existing sign-off fields, `-RequireSignedOff` can now pass while misrepresenting current artifacts as independently reviewed. This defeats the fail-closed security evidence contract and can incorrectly clear blocking threats.
**Fix:** Do not mutate an already signed record in place. Obtain a new authenticated review of every changed artifact and append/version a new closure attestation containing the current artifact hashes, actual reviewer identity, fresh review timestamp, procedure/environment provenance, and immutable linkage to the prior record. If no new independent review occurred, mark the affected records unsigned/open and make `-RequireSignedOff` reject them. Extend the verifier/tamper suite to reject any digest reseal that lacks a fresh attestation (for example, bind the signed payload or review record cryptographically to the complete record contents and artifact hashes).

---

_Reviewed: 2026-08-24T04:45:00Z_
_Reviewer: the agent (gsd-code-reviewer)_
_Depth: standard_

## CR-01 Resolution — 2026-08-24

The original blocker above is retained verbatim. Plans 01-28 through 01-30
resolved it without rebinding or deleting the invalid Aug 21 review history:

- Plan 01-28 introduced complete-payload SHA-256 digests, append-only v2
  attestations, predecessor-link validation, and mutation regressions that reject
  inherited review, payload reseal, identity/timestamp changes, broken links, and
  attestation deletion.
- Plan 01-29 captured fresh authenticated independent review for exactly the seven
  reopened records from `LAB\Administrator` on `LAB-CLIENT01`, from
  `2026-08-24T08:38:50.3158536Z` through
  `2026-08-24T08:38:57.7099470Z`, using procedure `01-28/v2` and the
  `independent_reviewer` environment role.
- Plan 01-30 reran the 11-check tamper regression and the signed-off verifier.
  Both passed against canonical manifest SHA-256
  `936e185dd3953e1a8d24431b6a81ecc16d989d833b9295b3c43aa9d5e056c4db`;
  all 19 current closure targets are valid and zero blocking threats remain.

The canonical Phase 01 FinalGate then passed using the guarded machine-role
interface (`hungdinh-lt`, `LAB-DC01`, `LAB-SERVER01` evidence,
`LAB-CLIENT01`, and `LAB-DC02`): 34/34 checks, 30/30 requirements, 7/7
success criteria, 50/50 decisions, and 9/9 privilege manifests, with 62
INTEGRATE and 21 OPT-OUT coverage rows. Evidence bundle/hash, sanitization,
and independent review were all valid. CR-01 is resolved.

## Gap-Closure Code Review — 2026-08-24

The original CR-01 finding and its resolution above are retained as append-only
audit history. This review covers the v2 verifier, review-capture command,
security regression suite, and current closure manifest. The 11-check suite
passes on Windows PowerShell 5.1, but the security boundary still has three
blocking defects and three robustness/test defects.

### Critical Issues

#### CR-02: Attestations are forgeable by anyone who can edit the manifest

**Classification:** BLOCKER  
**File:** `C:/Users/nhdinh/dev/dleakprevention/scripts/verify-phase1-security.ps1:13-20`  
**Issue:** An attestation is authenticated only by an unkeyed SHA-256 digest over
fields stored beside that digest. The verifier neither checks a digital
signature nor validates the claimed reviewer name, identity kind, machine,
domain, role, procedure version, or review time against an external trust root.
An editor can therefore invent `LAB\\Administrator`/`LAB-CLIENT01`, recompute the
payload and attestation digests, and obtain `-RequireSignedOff` success. The
predecessor hashes detect accidental edits but provide no tamper resistance
against a party capable of recomputing SHA-256, so the claimed independent
approval is not verifiable.
**Fix:** Have the reviewer sign the canonical payload with a reviewer-controlled
certificate/key whose trust chain and intended identity are validated by the
verifier (or publish the approval into an append-only externally authenticated
system and verify its receipt). Validate the required LAB identity/machine/role,
procedure version, and timestamp policy before accepting the signature. Do not
treat a self-contained hash chain as authentication.

#### CR-03: The capture command can publish approval without reviewer confirmation

**Classification:** BLOCKER  
**File:** `C:/Users/nhdinh/dev/dleakprevention/scripts/add-security-closure-review.ps1:2,13`  
**Issue:** `-ConfirmEach` is optional. Omitting both `-DryRun` and
`-ConfirmEach` silently appends attestations for every requested threat. Even
when confirmation is enabled, the displayed object omits protected fields such
as disposition, severity, evidence attempt IDs, required machine roles,
procedure version, and environment fingerprint, so the prompt's “exact payload”
claim is false. A caller can thus clear human-review gates without an affirmative
per-payload decision, or obtain confirmation without showing the complete
payload being attested.
**Fix:** Make interactive confirmation mandatory for publication unless a
separate, strongly authenticated signed-input mode is used. Render the exact
canonical payload (all fields in `Payload`) and its digest before each prompt,
then require an affirmative response bound to that digest. Reject publication
when neither a valid signed approval nor explicit confirmation is present.

#### CR-04: Drift check has a race that can overwrite concurrent manifest updates

**Classification:** BLOCKER  
**File:** `C:/Users/nhdinh/dev/dleakprevention/scripts/add-security-closure-review.ps1:12-14`  
**Issue:** The command hashes the manifest, builds an in-memory copy, checks the
hash once, then writes a temporary file and performs `Move-Item -Force`. Another
reviewer can publish after the final hash check but before the move; the later
move replaces that newer manifest with the stale in-memory copy, losing the
other review while still reporting success. The check-and-replace sequence is
not a compare-and-swap operation, and the regression suite has no concurrent
writer case.
**Fix:** Serialize writers with an exclusive lock held from the initial read
through replacement, or use a storage/API primitive providing atomic
compare-and-swap on the expected digest. Revalidate while holding the lock and
use a same-volume durable atomic replacement that does not introduce a
delete/replace window. Add a two-writer regression proving neither attestation
is lost.

### Warnings

#### WR-01: “Canonical” digests are runtime-dependent and the scripts do not enforce the runtime

**Classification:** WARNING  
**File:** `C:/Users/nhdinh/dev/dleakprevention/scripts/verify-phase1-security.ps1:8-13`; `C:/Users/nhdinh/dev/dleakprevention/scripts/add-security-closure-review.ps1:4-6`  
**Issue:** Canonicalization delegates to `ConvertTo-Json`, whose serialization
differs between Windows PowerShell 5.1 and PowerShell 7 for these objects. The
review workflow already encountered widespread digest mismatches under `pwsh`,
yet neither script declares or enforces Windows PowerShell 5.1. The same valid
manifest can therefore pass or fail depending on the host executable.
**Fix:** Implement a version-independent canonical JSON serializer (for example,
RFC 8785 with explicit schema/type handling) and test it under both engines. As
an immediate fail-closed guard, reject unsupported `$PSVersionTable` values with
a clear diagnostic.

#### WR-02: Mutation tests do not model an attacker who recomputes digests

**Classification:** WARNING  
**File:** `C:/Users/nhdinh/dev/dleakprevention/scripts/evidence/Phase1.Security.Tests.ps1:10-20`  
**Issue:** The “payload reseal” case changes an assertion but leaves the stored
payload digest stale, and the attestation cases mutate fields without
recomputing their digests or downstream links. These tests prove checksum
consistency, not tamper resistance. The suite also exercises only capture
dry-run/failure, not successful confirmed capture, omitted confirmation,
provenance validation, or concurrent publication. Consequently it passes while
CR-02 through CR-04 remain exploitable.
**Fix:** Add adversarial fixtures that recompute every unkeyed digest/link after
tampering and require rejection by a trusted signature/provenance check. Add
end-to-end success and refusal tests for capture, plus an interleaved two-writer
publication test and cross-PowerShell canonicalization vectors.

#### WR-03: Public command contracts advertise behavior they do not implement

**Classification:** WARNING  
**File:** `C:/Users/nhdinh/dev/dleakprevention/scripts/add-security-closure-review.ps1:1-14`; `C:/Users/nhdinh/dev/dleakprevention/scripts/verify-phase1-security.ps1:2`  
**Issue:** The capture cmdlet declares `SupportsShouldProcess` but never calls
`$PSCmdlet.ShouldProcess`, so `-WhatIf` does not prevent publication. The
verifier accepts `-SecurityPath` but never reads or validates it, although the
test and FinalGate invocation pass the argument as if it were part of the gate.
These misleading interfaces can cause operators and callers to believe a write
was simulated or a security artifact was validated when neither is true.
**Fix:** Guard the replacement with `$PSCmdlet.ShouldProcess` (and test
`-WhatIf`), and either remove `-SecurityPath` or implement and test the intended
binding/validation.

---

_Reviewed: 2026-08-24T08:57:49Z_  
_Reviewer: the agent (gsd-code-reviewer)_  
_Depth: standard_

## Plan 01-33 Resolution of 2026-08-24 Re-verification Findings

This section is append-only. It resolves CR-02 through CR-04 without altering
their original wording or the earlier review history. Plans 01-31 through 01-33
implemented the hardened verifier/publication boundary, obtained fresh
independent signatures, and reconciled the canonical FinalGate.

### CR-02 resolved: authenticated, externally rooted attestations

`recomputed forgery rejected`, `signed-off mode requires external trust
inputs`, `stable missing-root diagnostic`, and `malformed external trust inputs
fail closed` all passed. The verifier accepted 19/19 current detached CMS
signatures from authenticated reviewer `LAB\dlp-reviewer`, certificate
thumbprint `E5AC839BE9C7F8800941B81E73A2AB3EF07C5CF7`, under procedure
`01-32/independent-security-review/v1`. The exact manifest SHA-256 was
`341d42cddafcfa0119924ec5c052051e32627b7b83a8b0efd5abad916fad8bef`;
the mandatory external reviewer-policy identity was
`21b488cdee3e5181f9195c2c0dc7b84d7c6b6c7575636d641ec4ffc679d4a0c6`.

### CR-03 resolved: exact affirmative review and non-mutating simulation

The regressions/source contracts `optional confirmation bypass removed`,
`exact affirmative input required`, `capture protects field <field>`, `dry run
succeeds`, `dry run byte-identical`, and `WhatIf byte-identical` passed. The
capture path displays every protected payload field, requires the literal
affirmative response, signs through reviewer-controlled CMS material, and
cannot publish through `-DryRun` or `-WhatIf`.

### CR-04 resolved: lossless serialized publication

The publication contracts requiring `Mutex`, `Get-PublicationMutexName`,
`WaitOne`, locked re-read, `Flush($true)`, atomic `Replace(`,
`PublicationBarrierPath`, and `CrashBeforeReplace` passed. These cover the
deterministic two-writer interleaving and crash-before-replace preservation
paths established by Plan 01-31, preventing a stale writer from silently
overwriting a newer attestation.

### Canonical FinalGate reconciliation

The Phase 1 security suite passed, followed by the signed-off verifier with
zero diagnostics and the same manifest/policy identities above. The canonical
FinalGate forwarded the exact `TrustedRootPath` and `ReviewerPolicyPath` with
`-RequireSignedOff`, reported those identical identities, and passed: 34/34
checks, 30/30 requirements, 7/7 success criteria, 50/50 decisions, 9/9
privilege manifests, 62 INTEGRATE and 21 OPT-OUT coverage rows, valid evidence
bundle/hash, valid sanitization, and valid independent review. Its regression
contract also requires a nonzero exit when the authenticated security subgate
fails. CR-02, CR-03, and CR-04 are resolved; SEC-01 through SEC-03 remain
complete only while these gates continue to pass.
