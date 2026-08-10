# Phase 01 Replan Source Coverage Audit

This audit is for the eleven replacement plans executed in wave order: 01-17, 01-22, 01-23, 01-13, 01-14, 01-18, 01-19, 01-15, 01-20, 01-16, and 01-21. Historical summaries 01-01, 01-02, 01-03, 01-04, 01-05, 01-06, 01-07, 01-09, and 01-10 remain evidence of completed implementation; they are inputs, not work to repeat.

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
| As an authorized Windows user, I want a private encrypted drive, so that committed files survive restart without readable plaintext in its backing store | COVERED | 01-17 establishes evidence/privilege contracts; 01-22/01-23 complete PostgreSQL enrollment authority, production TLS/routes/providers, and trusted-provisioning interfaces; 01-13 deploys them and executes approved dual-DC/Kerberos provisioning; 01-14/01-18/01-19 complete endpoint enrollment, signed configuration, and service runtime; 01-15/01-20 prove session lifecycle and integrity/recovery; 01-16 executes the production/application matrix; 01-21 completes D-19 and independently reviews the sealed exit matrix |

## REQ coverage

| Requirement IDs | Status | Plan coverage |
|---|---|---|
| WRK-01, WRK-02, WRK-03, WRK-04 | COVERED | 01-22, 01-13, 01-16, 01-17, 01-21 |
| SRV-01 | COVERED | 01-23, 01-13, 01-16, 01-17, 01-21 |
| SRV-03 | COVERED | 01-22, 01-23, 01-13, 01-14, 01-16, 01-17, 01-21 |
| SRV-11, SRV-12 | COVERED | 01-13, 01-16, 01-17, 01-21 |
| CRY-01 | COVERED | 01-15, 01-20, 01-16, 01-17, 01-21 |
| CRY-02 | COVERED | 01-18, 01-16, 01-17, 01-21 |
| CRY-04 | COVERED | 01-14, 01-15, 01-20, 01-16, 01-17, 01-21 |
| AGT-01 | COVERED | 01-19, 01-15, 01-20, 01-16, 01-17, 01-21 |
| AGT-02, AGT-03 | COVERED | 01-14, 01-19, 01-16, 01-17, 01-21 |
| AGT-04, AGT-05, AGT-06 | COVERED | 01-18, 01-16, 01-17, 01-21 |
| AGT-07 | COVERED | 01-18, 01-19, 01-15, 01-20, 01-16, 01-17, 01-21 |
| DRV-01, DRV-03 | COVERED | 01-15, 01-16, 01-17, 01-21 |
| DRV-02, DRV-04, DRV-06, DRV-09 | COVERED | 01-15, 01-20, 01-16, 01-17, 01-21 |
| DRV-07 | COVERED | 01-20, 01-16, 01-17, 01-21 |
| TST-01 | COVERED | preserved automated source tests plus 01-16, 01-17, and 01-21 |
| TST-02 | COVERED | 01-18, 01-16, 01-17, 01-21 |
| TST-03 | COVERED | 01-15, 01-20, 01-16, 01-17, 01-21 |
| TST-05 | COVERED | 01-22, 01-23, 01-13, 01-14, 01-16, 01-17, 01-21 |
| TST-08 | COVERED | 01-15, 01-20, 01-16, 01-17, 01-21 |

Every Phase 01 requirement ID appears in at least one replacement PLAN.md frontmatter requirements list. Plans 01-16, 01-17, and 01-21 deliberately carry the full set: 01-17 creates the authoritative evidence index, 01-16 fills the production/application rows, and 01-21 validates the complete matrix and independent review.

## RESEARCH coverage

| Research item | Status | Plan coverage |
|---|---|---|
| Preserve approved Rust/LLVM/Hyper-V development stack and completed implementations | COVERED | 01-13 inventory guard; all plans use existing crates and source patterns |
| Correct four-machine responsibility map | COVERED | all eleven replacement plans, plus COVERAGE.md |
| Two independent AD authorities with authenticated directory access | COVERED | 01-23 source contract; 01-13 real execution; 01-14, 01-16, and 01-21 verification |
| Kerberos-authenticated WinRM/CIM collection from trusted LAB-DC01 | COVERED | 01-23 source contract; 01-13 real execution; 01-16 final matrix |
| Authenticated HTTPS server boundary and mTLS endpoint identity | COVERED | 01-22/01-23 server implementation; 01-14, 01-19, and 01-16 endpoint/runtime proof |
| Trusted enrollment station and fingerprint confirmation | COVERED | 01-23 procedure/CLI and 01-13 approved LAB-DC01 execution before 01-14 |
| DPAPI machine-scope custody with explicit ACLs and failure closure | COVERED | 01-14 |
| Durable last-known-good configuration cache | COVERED | 01-18 |
| Automatic Windows service plus per-session WTS/IPC host lifecycle | COVERED | 01-19, 01-15 |
| Existing encrypted storage, journal, recovery, audit, and key-lifecycle code remains authoritative | COVERED | 01-15 wiring and 01-20 integrity/recovery proof |
| Real WinFsp callback/runtime integration | COVERED | 01-15 session tracer and 01-20 fault/restart proof on LAB-CLIENT01 only |
| PostgreSQL with versioned SQLx migrations and durable restart behavior | COVERED | 01-22 PostgreSQL-native authority/repository source; 01-13 real LAB-DC01 execution; SQLite explicitly limited to isolated unit tests |
| Office/Shell/large-file and graceful restart matrix | COVERED | 01-16 |
| Hyper-V hard-off validation and evidence integrity | COVERED | 01-21 |
| Layered portable/Hyper-V/visual/exit verification, immutable provenance, privilege manifests, cleanup/idempotence, and independent review | COVERED | 01-17 defines the shared contract; Plans 01-22/01-23 are source-only, the eight lab-mutating plans consume exact privilege manifests, and 01-21 seals/reviews the exit matrix |

Package legitimacy result: Plan 01-23 adds the exact `reqwest@0.13.4` direct dependency already reviewed and human-approved in `01-03-SUMMARY.md`; Plan 01-14 reuses that locked graph. No unaudited npm, pip, or cargo package is introduced, so no new package-legitimacy checkpoint is required.

Schema-push result: no listed JavaScript ORM push pattern is present. Rust SQLx versioned migrations are planned directly; no ORM push is fabricated.

## CONTEXT decision coverage

| Locked decision IDs | Status | Plan coverage |
|---|---|---|
| D-01, D-02, D-03, D-04, D-05, D-06 | COVERED | 01-22 PostgreSQL/PKI transactions; 01-23 production routes/providers and trusted procedure; 01-13 approved pre-enrollment provisioning; 01-14 endpoint credential custody/replacement; 01-19 startup; 01-16 production proof |
| D-07, D-08, D-09, D-10 | COVERED | 01-15 session detection, deterministic drive selection, per-session host, and mount lifecycle; 01-16 |
| D-11, D-12, D-13, D-14, D-15 | COVERED | 01-15 session/commit wiring, 01-20 integrity/recovery proof, and 01-16 production matrix |
| D-16, D-17, D-18 | COVERED | 01-16 application, operation, and size-boundary matrix |
| D-19 | COVERED | 01-20 restart/reboot validation and 01-21 forced-termination/hard-off exit matrix |
| D-20, D-21, D-22, D-23, D-24 | COVERED | 01-23 machine-guarded trusted procedure; 01-13 role reconciliation and real provisioning; every downstream machine-bound command |
| D-25, D-26, D-27, D-28 | COVERED | 01-17 defines layered tiers, visual-only scope, role validity, and no-waiver rules; every other replacement plan consumes them |
| D-29, D-30, D-31, D-32 | COVERED | 01-17 encodes substitute boundaries; 01-22 removes production in-memory authority; 01-13 proves PostgreSQL; 01-14 proves lab PKI and virtual-disk identity change; 01-18 through 01-21 reject runtime substitutes |
| D-33, D-34, D-35, D-36 | COVERED | 01-17 authors and gates eight exact per-plan privilege manifests; each consuming plan requires its separate digest, baseline, cleanup, idempotence, integrity, and role allowlist |
| D-37, D-38, D-39, D-40 | COVERED | 01-17 defines manifest/visual/publication/staleness contracts; every downstream plan publishes through them |
| D-41, D-42, D-43, D-44 | COVERED | 01-17 implements immutable reruns, full requirement matrix, raw-artifact validity, versioned unique IDs, and supersession links |
| D-45, D-46, D-47 | COVERED | 01-17 implements clock-skew blocking, allowlisted redaction/scanning, and stable environment fingerprints |
| D-48, D-49, D-50 | COVERED | 01-17 defines independent review, deviation, and retention/hold contracts; 01-21 requires the signed final review and validates retention state |

Deferred ideas: none were imported into the replan.

Agent discretion: the primary noun for the detected fallback assumption delta is **session-scoped mount target**. The replan promotes that noun because the phase outcome depends on a per-session drive, while preferred/next-free letters remain selection details. This is recorded as `<assumption_delta_decision>` in 01-15. No assumption delta is silently ignored.

## Spec-less fallback edge coverage

Each unresolved probe row is explicit in replacement-plan `must_haves.assumptions` as either `flagged-unverified` or `covered`.

| Probe rows | Count | Disposition and plan |
|---|---:|---|
| WRK-01, WRK-02, WRK-03, WRK-04 unclassified | 4 | flagged-unverified in 01-13 |
| SRV-01 concurrency | 1 | covered by concurrent readiness/collection proof in 01-13 |
| SRV-03 unclassified | 1 | flagged-unverified across 01-22/01-23/01-13/01-14 and final-gated by 01-21 |
| SRV-11 idempotency and concurrency | 2 | covered by repeated/concurrent migration starts in 01-13 |
| SRV-12 concurrency | 1 | covered by concurrent collector proof in 01-13 |
| CRY-01 concurrency | 1 | covered by session/key concurrency proof in 01-15 |
| CRY-02 unclassified | 1 | flagged-unverified in 01-18 |
| CRY-04 idempotency and concurrency | 2 | covered by DPAPI behavior in 01-14 and session/store behavior in 01-15/01-20 |
| AGT-01, AGT-02, AGT-03 unclassified | 3 | flagged-unverified across 01-14, 01-18, and 01-19 |
| AGT-04 concurrency | 1 | covered by concurrent configuration activation in 01-18 |
| AGT-05, AGT-06, AGT-07 unclassified | 3 | flagged-unverified across 01-18 and 01-19 |
| DRV-01 idempotency and concurrency | 2 | covered by repeated/concurrent session mount behavior in 01-15 |
| DRV-02 unclassified | 1 | flagged-unverified in 01-20 |
| DRV-03 adjacency, empty, ordering, concurrency | 4 | covered by deterministic letter-selection matrix in 01-15 |
| DRV-04 concurrency | 1 | covered by multi-session isolation proof in 01-15 |
| DRV-06 concurrency | 1 | covered by concurrent I/O and restart proof in 01-15 |
| DRV-07, DRV-09 unclassified | 2 | flagged-unverified in 01-20 |
| TST-01, TST-02, TST-03, TST-05, TST-08 unclassified | 5 | flagged-unverified in 01-16 and final-gated by 01-21 |
| **Total** | **36** | **36 explicit; none dropped** |

## Prohibition recall

Adversarial requirement-by-requirement recall retained only product-value, safety, evidence-integrity, role-boundary, and secret-handling prohibitions. Retained entries are descriptor-less `flagged-unverified` values under each plan's `must_haves.prohibitions`; none were auto-dismissed.

Routine engineering and canonical security/compliance candidates were not duplicated as bespoke prohibitions. Their breadcrumbs remain the per-plan ASVS L1 STRIDE registers, existing path/input test suites, and the post-execution `$gsd-secure-phase 1` workflow. This exclusion does not waive any threat mitigation or requirement.

## External integration coverage

This phase integrates external services and platform APIs. `COVERAGE.md` is the complete capability matrix for LDAP/AD, Kerberos WinRM/CIM, PostgreSQL, HTTPS/mTLS, Windows SCM/DPAPI/WTS/CreateProcessAsUser/named pipes, WinFsp callbacks/runtime, Hyper-V orchestration, and Office/Shell validation. Every capability is INTEGRATE or has a reasoned phase-boundary OPT-OUT, with the execution machine and owning plan named.

## Final audit verdict

COVERED. No GOAL, REQ, RESEARCH, or CONTEXT item is missing. The added 01-22/01-23 slices make previously implicit server authority and trusted-provisioning work executable without deferral or scope reduction.
