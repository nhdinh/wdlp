# Phase 1 Multi-Source Coverage Audit

The plan set was audited against the ROADMAP goal, every phase requirement ID, RESEARCH.md constraints/features, CONTEXT.md decisions, the 36 deterministic spec-less edge probes, and the descriptor-less prohibition recall. `COVERED` means at least one named plan task and its acceptance criteria implement or verify the item.

## Goal, Requirements, and Context Decisions

| Source | ID | Feature / requirement | Plan | Status | Notes |
|---|---|---|---|---|
| GOAL | — | One server, one Windows endpoint, one user completes enroll → signed config → mount → encrypted write/read → restart recovery | 01-01, 01-08 | COVERED | Portable tracer proves the trust/data path; final plan proves it on Windows. |
| REQ | WRK-01 | Ten-crate Cargo workspace | 01-01 | COVERED | Exact crate list is created. |
| REQ | WRK-02 | Shared identifiers, policy types, decisions, errors | 01-01 | COVERED | `dlp-domain` owns portable contracts. |
| REQ | WRK-03 | Versioned protocol DTOs and wire schemas | 01-01 | COVERED | `/api/v1` and signed-envelope contracts. |
| REQ | WRK-04 | Deny portable unsafe; isolate Windows FFI | 01-01, 01-06 | COVERED | Workspace lints plus Windows boundary audit. |
| REQ | SRV-01 | Authenticated HTTP JSON APIs | 01-01, 01-02 | COVERED | Admin bearer bootstrap and agent mTLS. |
| REQ | SRV-03 | Single-use/short-lived enrollment token | 01-01, 01-02 | COVERED | Hashed, expiring, transactionally consumed token. |
| REQ | SRV-11 | PostgreSQL with versioned migrations | 01-01, 01-02 | COVERED | Real migration application and verification. |
| REQ | SRV-12 | Health and readiness endpoints | 01-02 | COVERED | Liveness is process-only; readiness checks dependencies. |
| REQ | CRY-01 | AEAD contents and sensitive metadata | 01-01, 01-04 | COVERED | AES-256-GCM records with identity-bound AAD. |
| REQ | CRY-02 | Ed25519 signing and pre-activation verification | 01-01, 01-02, 01-03 | COVERED | Deterministic bytes, strict verification, schema gate. |
| REQ | CRY-04 | No plaintext endpoint long-lived secret | 01-03, 01-04 | COVERED | DPAPI/ACL credential and wrapped per-user store key. |
| REQ | AGT-01 | Automatic noninteractive Windows service | 01-03, 01-07 | COVERED | SCM registration, start, and control handling. |
| REQ | AGT-02 | Enrollment and protected credentials | 01-03 | COVERED | Automatic bootstrap plus DPAPI service-only file. |
| REQ | AGT-03 | Periodic TLS contact and server identity | 01-03 | COVERED | Pinned trust anchor, timeout, polling. |
| REQ | AGT-04 | Download, verify, cache, atomically activate | 01-01, 01-03 | COVERED | Immutable cache and pointer switch. |
| REQ | AGT-05 | Current and LKG configurations | 01-01, 01-03 | COVERED | Two retained verified generations. |
| REQ | AGT-06 | Invalid/partial bundle cannot replace active | 01-01, 01-03 | COVERED | Negative signature/schema/hash/partial tests. |
| REQ | AGT-07 | Version, health, drive, policy, errors | 01-02, 01-03, 01-07 | COVERED | Typed report and redacted diagnostics. |
| REQ | DRV-01 | One isolated store per authenticated user | 01-04, 01-07 | COVERED | Store registry keyed by captured normalized SID. |
| REQ | DRV-02 | WinFsp configurable mount | 01-06, 01-07 | COVERED | Preferred letter and next-free fallback. |
| REQ | DRV-03 | Correct Windows user for every request | 01-06, 01-07 | COVERED | Mount-captured SID, not request/path input. |
| REQ | DRV-04 | Encrypted contents and metadata | 01-01, 01-04, 01-06 | COVERED | Storage owns AEAD; WinFsp never persists plaintext. |
| REQ | DRV-06 | Crash-consistent file and metadata updates | 01-04, 01-05, 01-06, 01-08 | COVERED | Staged generation + durable authenticated commit. |
| REQ | DRV-07 | Corruption denial without unauthenticated plaintext | 01-05, 01-06, 01-08 | COVERED | Stable integrity mapping and preserved evidence. |
| REQ | DRV-09 | Restart survival without committed corruption | 01-05, 01-07, 01-08 | COVERED | Recovery scan and restart/loss matrix. |
| REQ | TST-01 | Policy matching, priority, conflicts, defaults | 01-01 | COVERED | Portable evaluator contract is tested without drive enforcement. |
| REQ | TST-02 | Bundle validation/signature tests | 01-01, 01-03 | COVERED | Valid, tampered, wrong-key, schema, replay, partial cases. |
| REQ | TST-03 | Storage crypto/integrity/key tests | 01-01, 01-04 | COVERED | Roundtrip, nonce, AAD, corruption, recovery, secret handling. |
| REQ | TST-05 | Enrollment through first activation integration | 01-02, 01-03, 01-08 | COVERED | PostgreSQL-backed and final deployed flow. |
| REQ | TST-08 | Representative WinFsp validation | 01-06, 01-07, 01-08 | COVERED | Real runtime plus specified app/operation/fault corpus. |
| CONTEXT | D-01 | Agent auto-registers to configured server | 01-03 | COVERED | Service startup enrollment state machine. |
| CONTEXT | D-02 | Exact allowlisted composite fingerprint including system disk | 01-02, 01-03 | COVERED | SMBIOS UUID + BIOS serial + physical system-disk serial digest; MAC excluded. |
| CONTEXT | D-03 | Fingerprinted component change blocks enrollment | 01-02, 01-03 | COVERED | Exact digest mismatch is a stable denial. |
| CONTEXT | D-04 | Server queries primary and secondary AD DC | 01-02 | COVERED | Direct LDAPS queries must agree. |
| CONTEXT | D-05 | Device-bound mTLS credential in DPAPI service file | 01-02, 01-03 | COVERED | CA issuance, cert binding, DPAPI, ACL. |
| CONTEXT | D-06 | Missing/undecryptable credential re-enrolls and revokes prior | 01-02, 01-03 | COVERED | Replacement transaction revokes old serial. |
| CONTEXT | D-07 | Auto-mount one isolated store per eligible signed-in user | 01-07 | COVERED | Session-change mount actor. |
| CONTEXT | D-08 | Preferred drive letter then next available | 01-07 | COVERED | Deterministic scan with occupied-volume preservation. |
| CONTEXT | D-09 | Reject opens, grace, unmount at sign-out | 01-07 | COVERED | 30-second grace then cancellation/unmount. |
| CONTEXT | D-10 | Failed mount leaves no placeholder, retries, diagnoses | 01-07 | COVERED | Exponential retry capped at five minutes. |
| CONTEXT | D-11 | Normal Windows filesystem semantics | 01-06, 01-08 | COVERED | Open/share/cache/flush/close plus full operation matrix. |
| CONTEXT | D-12 | Flush/close success waits for durability | 01-04, 01-06 | COVERED | Callback completion follows durable commit. |
| CONTEXT | D-13 | Interrupted replacement preserves last commit | 01-05, 01-08 | COVERED | Staging is unreferenced until commit; recovery discards it. |
| CONTEXT | D-14 | Integrity failure denies, preserves evidence, redacts, returns no plaintext | 01-05, 01-06, 01-08 | COVERED | Stable error and evidence quarantine. |
| CONTEXT | D-15 | Disk-full returns Windows error and keeps prior version | 01-04, 01-05, 01-06, 01-08 | COVERED | Fault injection verifies callback/error mapping. |
| CONTEXT | D-16 | Explorer, PowerShell, Notepad, Word, Excel | 01-08 | COVERED | Named validation cases and evidence. |
| CONTEXT | D-17 | Create/copy/open/edit/save/Save As/rename/move/delete/directories | 01-08 | COVERED | Every operation is matrixed by application. |
| CONTEXT | D-18 | Empty through ≥1 GiB and chunk boundaries | 01-04, 01-08 | COVERED | 4 MiB - 1, 4 MiB, 4 MiB + 1 plus empty and 1 GiB. |
| CONTEXT | D-19 | Restart, reboot, forced kill during write, abrupt loss | 01-05, 01-08 | COVERED | Scripted fault points and human-backed reboot/loss evidence. |

## Research Features and Constraints

| Source | ID | Feature / constraint | Plan | Status | Notes |
|---|---|---|---|---|
| RESEARCH | R-01 | WinFsp package legitimacy SUS gate before dependency | 01-01, 01-06 | COVERED | Approval checkpoint precedes manifest change. |
| RESEARCH | R-02 | PostgreSQL migrations run before readiness/server traffic | 01-01, 01-02 | COVERED | Migration ledger is asserted in readiness. |
| RESEARCH | R-03 | Exact fingerprint provenance is not remote attestation | 01-02, 01-03 | COVERED | Admin-preloaded digest + dual-DC identity + residual-risk documentation. |
| RESEARCH | R-04 | Development private CA contract for mTLS | 01-02 | COVERED | Mounted CA secrets, constrained SAN/serial, revocation lookup. |
| RESEARCH | R-05 | Canonical signed bytes; current/LKG atomic selection | 01-01, 01-03 | COVERED | Hash/version replay gates and strict verification. |
| RESEARCH | R-06 | 4 MiB AEAD chunk and boundary corpus | 01-04, 01-08 | COVERED | Versioned format and exact boundary sizes. |
| RESEARCH | R-07 | 30-second sign-out drain and five-minute retry cap | 01-07 | COVERED | Planner-discretion values adopted and tested. |
| RESEARCH | R-08 | One actor per session ID/captured SID | 01-07 | COVERED | Handles, cancellation, mount ownership. |
| RESEARCH | R-09 | WinFsp delay-load helper, no manual DLL loading | 01-06 | COVERED | `build.rs` calls the crate helper. |
| RESEARCH | R-10 | Path normalization and untrusted filesystem input bounds | 01-04, 01-06 | COVERED | Portable `VirtualPath` plus callback translation. |
| RESEARCH | R-11 | Real Windows validation; no Linux substitute | 01-06, 01-08 | COVERED | Runtime, Office, session, restart, fault evidence. |
| RESEARCH | R-12 | WinFsp, Docker, PostgreSQL absent locally | 01-02, 01-06, 01-08 | COVERED | Preconditions and setup commands make external state explicit. |
| RESEARCH | R-13 | Complete AD, WinFsp, and HTTP capability surface | COVERAGE.md | COVERED | Every row is INTEGRATE or reasoned OPT-OUT. |
| RESEARCH | R-14 | Diagnostics redact secrets, raw serials, plaintext, protected paths | 01-02 through 01-08 | COVERED | Stable codes/digests only; log-capture tests. |

## Spec-less Probe and Prohibition Accounting

| Probe class | Surfaced | Authored | Status |
|---|---:|---:|---|
| Deterministic edge probes | 36 | 16 explicit truths + 20 flagged assumptions across 01-01 through 01-08 | COVERED |
| Descriptor-less prohibition recall | 8 | 8 `status: unverified`, `flagged: true` items across 01-01 through 01-08 | COVERED |

The 20 `unclassified` deterministic probes remain explicitly unresolved as required by the spec-less fallback protocol. The 16 classified concurrency/idempotency/adjacency/empty/ordering probes are resolved into automated acceptance truths. No edge probe was dismissed or silently converted to backstop. Canon security candidates (path traversal, injection, generic secret storage, and generic transport security) are handled by each plan's STRIDE threat model and `$gsd-secure-phase` rather than duplicated as bespoke prohibitions.
