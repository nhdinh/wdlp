---
phase: 01-first-encrypted-drive-vertical-slice
plan: 37
subsystem: evidence
tags: [powershell, cms, x509, d48, atomic-publication]
requires:
  - phase: 01-first-encrypted-drive-vertical-slice
    provides: Authenticated archival security closure and frozen Phase 1 evidence set
provides:
  - Observed-context, certificate-backed D-48 publication primitives
  - Detached-CMS attestation history with append-only, mutex-protected atomic publication
  - Fail-closed frozen-set, signer-separation, supersession, drift, and FinalGate wiring
affects: [01-38, 01-39, phase-1-verification]
actuals:
  tokens: 18000
  tasks: 3
  commits: 3
tech-stack:
  added: []
  patterns: [detached CMS signatures, canonical JSON commitments, durable same-volume replacement]
key-files:
  created: []
  modified:
    - scripts/add-independent-review.ps1
    - scripts/evidence/Phase1.Evidence.psm1
    - scripts/evidence/Phase1.Evidence.Tests.ps1
    - scripts/verify-phase1.ps1
    - scripts/add-security-closure-review.ps1
    - scripts/verify-phase1-security.ps1
    - scripts/evidence/Phase1.Security.Tests.ps1
key-decisions:
  - "D-48 publication derives identity, station, and certificate from observed Windows context and an explicit reviewer policy; free-form identity is not accepted."
  - "The signed generation and append-only history are authoritative; derived post-ceremony notes cannot change review meaning."
  - "When hardened implementation digests supersede the archival closure, the prior signed payload and history are preserved additively and a new authenticated ceremony is required."
patterns-established:
  - "Canonical commitment: hash the complete frozen payload and sign the exact UTF-8 canonical bytes with detached CMS."
  - "Atomic publication: serialize writers with a named mutex, flush same-volume staging, and replace the manifest only at the commit point."
  - "Fail closed: reject stale digests, signer reuse, policy mismatch, malformed history, drift, and missing external trust inputs without mutation."
requirements-completed: [CRY-04, TST-08]
coverage:
  - id: D1
    description: "Authenticated D-48 publisher observes Windows identity/machine and publishes detached-CMS generations atomically."
    requirement: CRY-04
    verification:
      - kind: unit
        ref: "scripts/evidence/Phase1.Security.Tests.ps1 -Focus Publication"
        status: pass
    human_judgment: false
  - id: D2
    description: "Security verifier enforces trust, frozen-set binding, history integrity, and FinalGate propagation."
    requirement: TST-08
    verification:
      - kind: unit
        ref: "scripts/evidence/Phase1.Security.Tests.ps1 -Focus FinalGate"
        status: pass
    human_judgment: false
  - id: D3
    description: "Canonical archival closure is re-signed after implementation-digest supersession by a distinct authorized D-48 reviewer."
    requirement: TST-08
    verification: []
    human_judgment: true
    rationale: "The separate reviewer certificate ceremony and public trust-root setup are intentionally deferred to Plan 01-38."
duration: 2h
completed: 2026-08-26
status: complete
---

# Phase 01: First Encrypted-Drive Vertical Slice, Plan 37 Summary

**D-48 review publication and verification are now observed-context, certificate-backed, canonical, append-only, crash-recoverable, and mandatory at FinalGate.**

## Accomplishments

- Replaced self-asserted reviewer input with observed Windows identity, machine, CurrentUser certificate, explicit policy authorization, and archival-signer separation.
- Added canonical detached-CMS commitments over the frozen evidence payload, durable append-only history, mutex serialization, same-volume flushes, atomic replacement, crash cleanup, and predecessor rechecks.
- Added fail-closed verifier and FinalGate checks for trust, key usage/EKU, policy/context, history order, supersession, digest drift, and mandatory independent-review presence/validity.
- Added behavioral coverage for spoofing, policy mismatch, signer reuse, drift, concurrent publishers, injected crash, malformed signatures, history tampering, and FinalGate failure propagation.

## Task Commits

1. **Authenticated D-48 publication, verification, and adversarial coverage** - `8f64e33`
2. **Approved supersession follow-up preserving prior payload/history** - `5182c37`
3. **Repository-root anchoring regression fix** - `3317849`

## Decisions Made

- The current signed generation is the sole authoritative D-48 closure; operational notes are derived and non-authoritative.
- A changed implementation digest cannot reuse an earlier signature. Supersession preserves the old signed payload and requires a new authenticated signer ceremony.
- FinalGate remains fail-closed until the separate D-48 reviewer policy/root and signed generation are available.

## Deviations from Plan

The approved execution revision added authenticated additive supersession because Plan 01-37 changed a script digest protected by the Plan 01-36 closure. The prior protected payload, attestations, CMS bytes, and history remain preserved; no evidence was erased or overwritten.

## Verification

- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/evidence/Phase1.Security.Tests.ps1 -Focus Publication` passed.
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/evidence/Phase1.Security.Tests.ps1 -Focus FinalGate` passed.
- The full verifier correctly remains blocked in this checkout until external D-48 public root/policy setup and re-signing; the available archival fixture reports the stale implementation digest instead of passing.

## Next Phase Readiness

Plan 01-37 implementation is complete. Plan 01-38 must obtain explicit D-48 reviewer authorization, public trust inputs, and one signed immutable generation. Plan 01-39 can then perform final re-verification, the visual checklist, and independent review. No production code should be weakened to bypass that ceremony.

---
*Phase: 01-first-encrypted-drive-vertical-slice*
*Completed: 2026-08-26*
