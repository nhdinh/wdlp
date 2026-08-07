# Phase 1 Multi-Source Coverage Audit

The revised 12-plan set was audited against the ROADMAP goal, all 30 Phase 1 requirements, every CONTEXT decision D-01 through D-19, RESEARCH.md features/constraints, all 36 deterministic spec-less edge-probe dispositions, the eight descriptor-less prohibitions, and the complete API coverage matrix. `COVERED` means a named plan task plus verification/acceptance criteria implement or prove the item. Deferred/out-of-phase research remains excluded, not missing.

## Goal, Requirements, and Context Decisions

| Source | ID | Feature / requirement | Plan | Status | Notes |
|---|---|---|---|---|
| GOAL | — | One server, one Windows endpoint, one user completes enroll → signed config → mount → encrypted write/read → restart recovery | 01-05, 01-12 | COVERED | Format-gated portable tracer, then production Windows proof. |
| REQ | WRK-01 | Exact ten-crate Cargo workspace | 01-01, 01-02 | COVERED | Portable members first; exact closed list completes before tracer. |
| REQ | WRK-02 | Shared IDs, policy types, decisions, errors | 01-01 | COVERED | `dlp-domain` contracts/tests. |
| REQ | WRK-03 | Versioned protocol DTOs/wire schemas | 01-01 | COVERED | `/api/v1`, signed envelope, unknown-version behavior. |
| REQ | WRK-04 | Deny portable unsafe; isolate Windows FFI | 01-01, 01-02, 01-10 | COVERED | Portable lints, two Windows boundaries, WinFsp audit. |
| REQ | SRV-01 | Authenticated HTTP JSON APIs | 01-05, 01-06, 01-07 | COVERED | Tracer routes, authority, distinct admin/device mTLS. |
| REQ | SRV-03 | Single-use/short-lived enrollment token | 01-05, 01-06 | COVERED | Hashed, expiring, transactionally consumed. |
| REQ | SRV-11 | PostgreSQL and versioned migrations | 01-02, 01-05, 01-06, 01-07 | COVERED | Real migration ledger, authority migration, readiness gate. |
| REQ | SRV-12 | Liveness/readiness | 01-07 | COVERED | Process-only liveness; dependency/migration readiness. |
| REQ | CRY-01 | AEAD content and sensitive metadata | 01-03, 01-04, 01-05 | COVERED | Human-approved AES-GCM format before first record. |
| REQ | CRY-02 | Ed25519 signing/pre-activation verification | 01-01, 01-05, 01-07, 01-08 | COVERED | Canonical strict verification, server selection, agent cache. |
| REQ | CRY-04 | No plaintext long-lived endpoint secret | 01-04, 01-08, 01-11 | COVERED | Secret interfaces, DPAPI credential and per-SID key wrappers. |
| REQ | AGT-01 | Automatic noninteractive Windows service | 01-02, 01-08, 01-11 | COVERED | Boundary, SCM runtime, session mount lifecycle. |
| REQ | AGT-02 | Enrollment and protected credentials | 01-08 | COVERED | Automatic enrollment plus DPAPI/service ACL. |
| REQ | AGT-03 | Periodic TLS contact/server identity | 01-08 | COVERED | Pinned bootstrap trust and device mTLS polling. |
| REQ | AGT-04 | Download, verify, cache, atomically activate | 01-05, 01-08 | COVERED | Tracer/current-LKG plus Windows cache. |
| REQ | AGT-05 | Current and LKG configurations | 01-05, 01-08 | COVERED | Two immutable selected generations across restart. |
| REQ | AGT-06 | Invalid/partial bundle preserves active | 01-05, 01-08 | COVERED | Signature/schema/hash/replay/partial negative suite. |
| REQ | AGT-07 | Version/health/drive/policy/errors | 01-07, 01-08, 01-11 | COVERED | Device-bound server persistence and local/session health. |
| REQ | DRV-01 | One isolated store per authenticated user | 01-04, 01-11 | COVERED | SID-bound portable store and session actor. |
| REQ | DRV-02 | WinFsp configurable mount | 01-10, 01-11 | COVERED | Real host plus preferred/next-free letter. |
| REQ | DRV-03 | Correct Windows user for every request | 01-04, 01-10, 01-11 | COVERED | Captured SID/store, no request selector. |
| REQ | DRV-04 | Encrypted content and metadata | 01-04, 01-05, 01-10 | COVERED | Store owns AEAD; tracer/WinFsp prove no plaintext backing. |
| REQ | DRV-06 | Crash-consistent updates | 01-04, 01-09, 01-10, 01-12 | COVERED | Staged generation, authenticated publication, fault matrix. |
| REQ | DRV-07 | Corruption denial/no unauthenticated plaintext | 01-09, 01-10, 01-12 | COVERED | Stable status, zero-byte release, evidence retention. |
| REQ | DRV-09 | Restart survival | 01-09, 01-11, 01-12 | COVERED | Recovery, service remount, reboot/kill/hard-off evidence. |
| REQ | TST-01 | Policy matching/priority/conflict/default tests | 01-01 | COVERED | Complete deterministic Phase 1 evaluator tests. |
| REQ | TST-02 | Bundle validation/signature tests | 01-01, 01-05, 01-08 | COVERED | Positive/negative/replay/cache cases. |
| REQ | TST-03 | Storage crypto/integrity/key tests | 01-04, 01-05, 01-09 | COVERED | Boundary, nonce/AAD, recovery, evidence, marker scans. |
| REQ | TST-05 | Enrollment through first activation integration | 01-05, 01-06, 01-07, 01-08, 01-12 | COVERED | Fixture-trust tracer followed by production providers/agent. |
| REQ | TST-08 | Representative real WinFsp validation | 01-10, 01-11, 01-12 | COVERED | Runtime smoke, session lifecycle, complete Office matrix. |
| CONTEXT | D-01 | Agent auto-registers to configured server | 01-08 | COVERED | Service startup state machine. |
| CONTEXT | D-02 | Exact allowlisted fingerprint incl. system disk | 01-06, 01-08 | COVERED | Three-source digest; MAC excluded. |
| CONTEXT | D-03 | Fingerprinted component change blocks enrollment | 01-06, 01-08 | COVERED | Exact digest mismatch denial. |
| CONTEXT | D-04 | Query primary and secondary AD DC | 01-06 | COVERED | Direct trusted LDAPS results must agree. |
| CONTEXT | D-05 | Device mTLS credential in DPAPI service file | 01-06, 01-08 | COVERED | Device CA + protected local custody. |
| CONTEXT | D-06 | Missing/undecryptable credential re-enrolls/revokes prior | 01-06, 01-08 | COVERED | Complete rechecks and atomic replacement. |
| CONTEXT | D-07 | Auto-mount isolated store per eligible user | 01-11 | COVERED | Session actor from token SID. |
| CONTEXT | D-08 | Preferred letter then next available | 01-11 | COVERED | Deterministic collision-safe scan. |
| CONTEXT | D-09 | Reject opens, grace, unmount at sign-out | 01-11 | COVERED | 30-second drain then cancel/unmount. |
| CONTEXT | D-10 | Failed mount absent/retried/diagnosed | 01-11 | COVERED | No placeholder; capped exponential retry. |
| CONTEXT | D-11 | Normal Windows filesystem semantics | 01-04, 01-10, 01-12 | COVERED | Portable model, callbacks, real applications. |
| CONTEXT | D-12 | Flush/close waits for durability | 01-04, 01-10 | COVERED | Ordered durable commit before callback success. |
| CONTEXT | D-13 | Interrupted replacement preserves last commit | 01-09, 01-12 | COVERED | Authenticated old/new-complete recovery. |
| CONTEXT | D-14 | Integrity denial/evidence/redaction/no plaintext | 01-09, 01-10, 01-12 | COVERED | Per-record fixtures and stable Windows mapping. |
| CONTEXT | D-15 | Disk-full error preserves prior version | 01-04, 01-09, 01-10, 01-12 | COVERED | Fault injection through real status/evidence. |
| CONTEXT | D-16 | Explorer/PowerShell/Notepad/Word/Excel | 01-12 | COVERED | Named versioned real-drive evidence. |
| CONTEXT | D-17 | Complete operation list | 01-12 | COVERED | Machine-readable application/operation matrix. |
| CONTEXT | D-18 | Empty through ≥1 GiB and chunk boundaries | 01-04, 01-12 | COVERED | Approved 4 MiB boundaries plus 1 GiB. |
| CONTEXT | D-19 | Restart/reboot/forced kill/abrupt loss | 01-09, 01-12 | COVERED | Fault hooks plus host-controlled hard-off. |

## Research Features and Constraints

| Source | ID | Feature / constraint | Plan | Status | Notes |
|---|---|---|---|---|
| RESEARCH | R-01 | WinFsp and every SUS/ASSUMED package gate before install | 01-03, 01-10 | COVERED | Human exact-package approval precedes manifests. |
| RESEARCH | R-02 | PostgreSQL migrations before readiness/traffic | 01-02, 01-05, 01-06, 01-07 | COVERED | Migration-before-listen and exact ledger probe. |
| RESEARCH | R-03 | Fingerprint is not remote attestation | 01-06, 01-08 | COVERED | Admin digest + residual privileged-local risk. |
| RESEARCH | R-04 | Development private CA contract | 01-06, 01-07 | COVERED | Mounted CA, constrained certificate, active lookup. |
| RESEARCH | R-05 | Canonical signed bytes/current-LKG | 01-01, 01-05, 01-07, 01-08 | COVERED | Strict hash/version/audience/replay gates. |
| RESEARCH | R-06 | 4 MiB AEAD chunk/boundary corpus | 01-03, 01-04, 01-12 | COVERED | Approved before bytes; matrix matches format. |
| RESEARCH | R-07 | 30-second drain/5-minute retry cap | 01-11 | COVERED | Explicit discretion choice and tests. |
| RESEARCH | R-08 | One actor per session ID/captured SID | 01-11 | COVERED | Immutable actor authority. |
| RESEARCH | R-09 | Delay-load helper/no manual WinFsp DLL loading | 01-10 | COVERED | Exact documented build helper. |
| RESEARCH | R-10 | Path normalization/untrusted input bounds | 01-04, 01-10 | COVERED | Portable parser and callback validation. |
| RESEARCH | R-11 | Real Windows validation/no Linux substitute | 01-10, 01-12 | COVERED | Real runtime, Office, session/fault evidence. |
| RESEARCH | R-12 | WinFsp/Docker/PostgreSQL initially absent | 01-02, 01-06, 01-10, 01-12 | COVERED | Explicit setup/preconditions and hard stops. |
| RESEARCH | R-13 | Complete AD, WinFsp, HTTP capability surface | COVERAGE.md; 01-06, 01-07, 01-10 | COVERED | Every row integrated or reasoned OPT-OUT. |
| RESEARCH | R-14 | Redact secrets/raw serials/plaintext/protected paths | 01-05 through 01-12 | COVERED | Stable codes/digests and marker scans. |

## Spec-less Probe and Prohibition Accounting

| Probe class | Surfaced | Authored | Status |
|---|---:|---:|---|
| Deterministic edge probes | 36 | 16 classified truths plus 20 `flagged_assumptions` across the revised plans | COVERED |
| Descriptor-less prohibition recall | 8 | `PROH-01` through `PROH-08`, each `status: unverified`, `flagged: true` | COVERED |

The 20 unclassified deterministic probes remain explicitly unresolved exactly as required by the spec-less fallback protocol; the 16 classified concurrency/idempotency/adjacency/empty/ordering probes remain observable automated truths. None was dismissed, silently converted to a backstop, or lost during renumbering. Generic security candidates are handled by each plan's STRIDE plus executable ASVS L1 map. There are no deferred CONTEXT ideas and no missing source item.
