# Phase 01 Replan Source Coverage Audit

This audit is for the replacement plan set 01-13 through 01-17. Historical summaries 01-01, 01-02, 01-03, 01-04, 01-05, 01-06, 01-07, 01-09, and 01-10 remain evidence of completed implementation; they are inputs, not work to repeat.

## Coverage result

| Source | Items audited | Covered | Missing | Excluded |
|---|---:|---:|---:|---:|
| ROADMAP goal | 1 | 1 | 0 | 0 |
| REQUIREMENTS phase IDs | 30 | 30 | 0 | 0 |
| RESEARCH features and constraints | 14 | 14 | 0 | 0 |
| CONTEXT locked decisions | 50 | 50 | 0 | 0 |
| Spec-less fallback edges | 36 | 36 | 0 | 0 |
| External API/service capabilities | all detected | all classified in COVERAGE.md | 0 | reasoned OPT-OUT rows only |

## GOAL coverage

| Source item | Status | Plan coverage |
|---|---|---|
| As an authorized Windows user, I want a private encrypted drive, so that committed files survive restart without readable plaintext in its backing store | COVERED | 01-17 establishes evidence/privilege contracts; 01-13 proves LAB-DC01 persistence and role hygiene; 01-14 completes enrollment/config/service runtime; 01-15 proves the endpoint drive lifecycle; 01-16 executes and independently reviews the production-shaped exit matrix |

## REQ coverage

| Requirement IDs | Status | Plan coverage |
|---|---|---|
| WRK-01, WRK-02, WRK-03, WRK-04 | COVERED | 01-13, 01-16 |
| SRV-01 | COVERED | 01-13, 01-16 |
| SRV-03 | COVERED | 01-14, 01-16 |
| SRV-11, SRV-12 | COVERED | 01-13, 01-16 |
| CRY-01 | COVERED | 01-15, 01-16 |
| CRY-02 | COVERED | 01-14, 01-16 |
| CRY-04 | COVERED | 01-14, 01-15, 01-16 |
| AGT-01 | COVERED | 01-14, 01-15, 01-16 |
| AGT-02, AGT-03, AGT-04, AGT-05, AGT-06 | COVERED | 01-14, 01-16 |
| AGT-07 | COVERED | 01-14, 01-15, 01-16 |
| DRV-01, DRV-02, DRV-03, DRV-04, DRV-06, DRV-07, DRV-09 | COVERED | 01-15, 01-16 |
| TST-01, TST-02, TST-03 | COVERED | preserved automated source tests plus 01-16 |
| TST-05 | COVERED | 01-14, 01-16 |
| TST-08 | COVERED | 01-15, 01-16 |

Every Phase 01 requirement ID appears in at least one replacement PLAN.md frontmatter requirements list. Plans 01-16 and 01-17 deliberately carry the full set: 01-17 creates the authoritative empty/current evidence index and 01-16 fills and independently reviews it.

## RESEARCH coverage

| Research item | Status | Plan coverage |
|---|---|---|
| Preserve approved Rust/LLVM/Hyper-V development stack and completed implementations | COVERED | 01-13 inventory guard; all plans use existing crates and source patterns |
| Correct four-machine responsibility map | COVERED | 01-13 through 01-16, plus COVERAGE.md |
| Two independent AD authorities with authenticated directory access | COVERED | 01-13, 01-16 |
| Kerberos-authenticated WinRM/CIM collection from trusted LAB-DC01 | COVERED | 01-13, 01-16 |
| Authenticated HTTPS server boundary and mTLS endpoint identity | COVERED | 01-14, 01-16 |
| Trusted enrollment station and fingerprint confirmation | COVERED | 01-14 |
| DPAPI machine-scope custody with explicit ACLs and failure closure | COVERED | 01-14 |
| Durable last-known-good configuration cache | COVERED | 01-14 |
| Automatic Windows service plus per-session WTS/IPC host lifecycle | COVERED | 01-14, 01-15 |
| Existing encrypted storage, journal, recovery, audit, and key-lifecycle code remains authoritative | COVERED | 01-15 preservation and real-runtime wiring |
| Real WinFsp callback/runtime integration | COVERED | 01-15 on LAB-CLIENT01 only |
| PostgreSQL with versioned SQLx migrations and durable restart behavior | COVERED | 01-13 on LAB-DC01; SQLite explicitly limited to isolated unit tests |
| Office/Shell/large-file and graceful restart matrix | COVERED | 01-16 |
| Hyper-V hard-off validation and evidence integrity | COVERED | 01-16 |
| Layered portable/Hyper-V/visual/exit verification, immutable provenance, privilege manifests, cleanup/idempotence, and independent review | COVERED | 01-17 defines the shared contract; 01-13 through 01-16 consume it |

Package legitimacy result: no new npm, pip, or cargo package installation is planned. Existing lockfiles and approved dependencies are reused, so no package-legitimacy checkpoint is introduced.

Schema-push result: no listed JavaScript ORM push pattern is present. Rust SQLx versioned migrations are planned directly; no ORM push is fabricated.

## CONTEXT decision coverage

| Locked decision IDs | Status | Plan coverage |
|---|---|---|
| D-01, D-02, D-03, D-04, D-05, D-06 | COVERED | 01-14 enrollment, attestation, credential custody, configuration, and SCM actions; 01-16 final proof |
| D-07, D-08, D-09, D-10 | COVERED | 01-15 session detection, deterministic drive selection, per-session host, and mount lifecycle; 01-16 |
| D-11, D-12, D-13, D-14, D-15 | COVERED | preserved storage/recovery implementation wired and revalidated in 01-15; 01-16 |
| D-16, D-17, D-18, D-19 | COVERED | 01-16 application, operations, size-boundary, restart, and hard-off matrix |
| D-20, D-21, D-22, D-23, D-24 | COVERED | 01-13 role reconciliation and all machine-bound commands; 01-14 through 01-16 enforce the same topology |
| D-25, D-26, D-27, D-28 | COVERED | 01-17 defines layered tiers, visual-only scope, role validity, and no-waiver matrix rules; 01-13 through 01-16 use them |
| D-29, D-30, D-31, D-32 | COVERED | 01-17 encodes substitute boundaries; 01-13 proves PostgreSQL, 01-14 proves lab PKI and virtual-disk identity-change behavior, and 01-15/01-16 reject runtime substitutes |
| D-33, D-34, D-35, D-36 | COVERED | 01-17 authors and gates exact per-plan privilege manifests; 01-13 through 01-16 require digest approval, baseline, cleanup, idempotence, pin/integrity, and role allowlists |
| D-37, D-38, D-39, D-40 | COVERED | 01-17 defines manifest/visual/publication/staleness contracts; every downstream plan publishes through them |
| D-41, D-42, D-43, D-44 | COVERED | 01-17 implements immutable reruns, full requirement matrix, raw-artifact validity, versioned unique IDs, and supersession links |
| D-45, D-46, D-47 | COVERED | 01-17 implements clock-skew blocking, allowlisted redaction/scanning, and stable environment fingerprints |
| D-48, D-49, D-50 | COVERED | 01-17 defines independent review, deviation, and retention/hold contracts; 01-16 requires the signed final review and validates retention state |

Deferred ideas: none were imported into the replan.

Agent discretion: the primary noun for the detected fallback assumption delta is **session-scoped mount target**. The replan promotes that noun because the phase outcome depends on a per-session drive, while preferred/next-free letters remain selection details. This is recorded as `<assumption_delta_decision>` in 01-15. No assumption delta is silently ignored.

## Spec-less fallback edge coverage

Each unresolved probe row is explicit in replacement-plan `must_haves.assumptions` as either `flagged-unverified` or `covered`.

| Probe rows | Count | Disposition and plan |
|---|---:|---|
| WRK-01, WRK-02, WRK-03, WRK-04 unclassified | 4 | flagged-unverified in 01-13 |
| SRV-01 concurrency | 1 | covered by concurrent readiness/collection proof in 01-13 |
| SRV-03 unclassified | 1 | flagged-unverified in 01-14 |
| SRV-11 idempotency and concurrency | 2 | covered by repeated/concurrent migration starts in 01-13 |
| SRV-12 concurrency | 1 | covered by concurrent collector proof in 01-13 |
| CRY-01 concurrency | 1 | covered by session/key concurrency proof in 01-15 |
| CRY-02 unclassified | 1 | flagged-unverified in 01-14 |
| CRY-04 idempotency and concurrency | 2 | covered by repeated/concurrent service/config behavior in 01-14 |
| AGT-01, AGT-02, AGT-03 unclassified | 3 | flagged-unverified in 01-14 |
| AGT-04 concurrency | 1 | covered by concurrent health/state behavior in 01-14 |
| AGT-05, AGT-06, AGT-07 unclassified | 3 | flagged-unverified in 01-14 |
| DRV-01 idempotency and concurrency | 2 | covered by repeated/concurrent session mount behavior in 01-15 |
| DRV-02 unclassified | 1 | flagged-unverified in 01-15 |
| DRV-03 adjacency, empty, ordering, concurrency | 4 | covered by deterministic letter-selection matrix in 01-15 |
| DRV-04 concurrency | 1 | covered by multi-session isolation proof in 01-15 |
| DRV-06 concurrency | 1 | covered by concurrent I/O and restart proof in 01-15 |
| DRV-07, DRV-09 unclassified | 2 | flagged-unverified in 01-15 |
| TST-01, TST-02, TST-03, TST-05, TST-08 unclassified | 5 | flagged-unverified in 01-16 |
| **Total** | **36** | **36 explicit; none dropped** |

## Prohibition recall

Adversarial requirement-by-requirement recall retained only product-value, safety, evidence-integrity, role-boundary, and secret-handling prohibitions. Retained entries are descriptor-less `flagged-unverified` values under each plan's `must_haves.prohibitions`; none were auto-dismissed.

Routine engineering and canonical security/compliance candidates were not duplicated as bespoke prohibitions. Their breadcrumbs remain the per-plan ASVS L1 STRIDE registers, existing path/input test suites, and the post-execution `$gsd-secure-phase 1` workflow. This exclusion does not waive any threat mitigation or requirement.

## External integration coverage

This phase integrates external services and platform APIs. `COVERAGE.md` is the complete capability matrix for LDAP/AD, Kerberos WinRM/CIM, PostgreSQL, HTTPS/mTLS, Windows SCM/DPAPI/WTS/CreateProcessAsUser/named pipes, WinFsp callbacks/runtime, Hyper-V orchestration, and Office/Shell validation. Every capability is INTEGRATE or has a reasoned phase-boundary OPT-OUT, with the execution machine and owning plan named.

## Final audit verdict

COVERED. No GOAL, REQ, RESEARCH, or CONTEXT item is missing. No phase split or developer deferral is required.
