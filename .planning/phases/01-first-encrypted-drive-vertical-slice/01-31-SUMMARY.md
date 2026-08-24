---
phase: 01-first-encrypted-drive-vertical-slice
plan: 31
subsystem: security-evidence
tags: [powershell, cms, x509, evidence, concurrency]
requires: [01-30]
provides:
  - Externally rooted CMS authentication for exact-payload security reviews
  - Mandatory complete-payload affirmative review capture
  - Serialized durable append publication
affects: [01-32, 01-33, CRY-04]
tech-stack:
  added: []
  patterns: [detached-cms, external-trust-policy, named-mutex, atomic-replace]
key-files:
  created: []
  modified:
    - scripts/verify-phase1.ps1
    - scripts/verify-phase1-security.ps1
    - scripts/add-security-closure-review.ps1
    - scripts/evidence/Phase1.Security.Tests.ps1
decisions:
  - Signed-off validation accepts trust roots and reviewer policy only from mandatory external files.
  - Review attestations use detached CMS signatures from an explicitly selected CurrentUser certificate.
  - Publication serializes on a canonical-path global mutex and flushes before atomic replacement.
metrics:
  duration: 35m
  completed: 2026-08-24
status: complete
actuals:
  tokens: 6200
  tasks: 3
  commits: 3
---

# Phase 01 Plan 31: Authenticated Security Review Boundary Summary

Detached CMS reviewer signatures, externally supplied X.509 trust policy, exact affirmative payload review, and lossless concurrent publication now protect Phase 1 security closure evidence.

## Accomplishments

- Signed-off verification now fails closed without readable external trust roots and reviewer policy, validates CMS signatures, reviewer identity, chain, machine/domain role, procedure, certificate validity, and review time, and emits stable JSON diagnostics.
- FinalGate forwards the external trust inputs, propagates security-subgate failure, and reports the same manifest digest and reviewer-policy identity returned by that subgate.
- Review capture renders the complete protected payload and policy context, requires exact `YES`, signs with an explicitly selected CurrentUser certificate, and keeps DryRun/WhatIf non-mutating.
- Publication holds a canonical-path cross-process mutex across locked reread, append construction, durable flush, and atomic replacement, with deterministic barrier and crash injection hooks.

## Task Commits

1. `618a9c7` — authenticate exact-payload security reviews.
2. `2f64913` — require complete affirmative signed review.
3. `3ad1f69` — serialize durable review publication.

## Verification

- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/evidence/Phase1.Security.Tests.ps1` — PASSED.
- Recomputed provenance forgery, missing/malformed trust inputs, incomplete-display/bypass source contracts, DryRun/WhatIf non-mutation, CMS wiring, and publication serialization contracts passed.
- GitNexus `detect_changes` before each commit reported LOW risk and no affected execution flows.

## Deviations from Plan

None — the plan's three security gaps were implemented without changing encrypted-drive behavior or existing evidence artifacts.

## Known Stubs

None.

## Self-Check: PASSED

- All four modified files exist.
- All three task commits exist.
- Full plan verification passed after the final commit.
