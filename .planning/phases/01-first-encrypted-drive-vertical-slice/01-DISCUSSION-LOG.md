# Phase 1: First Encrypted-Drive Vertical Slice - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-08-07
**Phase:** 1-First Encrypted-Drive Vertical Slice
**Areas discussed:** Enrollment bootstrap, Drive mounting lifecycle, File commit and recovery behavior, Vertical-slice validation

---

## Enrollment Bootstrap

| Decision point | Alternatives considered | Selected |
|----------------|-------------------------|----------|
| Initial registration | Admin token, enrollment file, interactive prompt, automatic registration | Automatic first-run registration using configured server address |
| Enrollment authorization | Open enrollment, admin approval, preauthorization, domain and device checks | Domain membership plus server-side hardware whitelist |
| Device identity | Adapter MACs, TPM-weighted match, tolerant composite, exact composite | Exact composite hardware serial fingerprint including system disk |
| Domain proof | Agent claim, deployment-channel trust, Kerberos/AD verification | Server queries primary and secondary AD domain controllers |
| Ongoing credential | Bearer token, access/refresh tokens, Kerberos each call, client certificate | Device-bound mTLS certificate |
| Local protection | Plain configuration, Credential Manager, certificate store, DPAPI file | DPAPI machine-protected credential file |
| Lost credential | Manual reset, admin approval, refuse duplicate, automatic replacement | Repeat all checks, replace credential, revoke prior credential |

**User's choice:** Automatic but tightly preauthorized enrollment tied to the exact domain computer and physical hardware.
**Notes:** The original MAC-address idea was refined into an exact composite hardware fingerprint because the user wants assurance that the endpoint and system disk are the authorized device.

---

## Drive Mounting Lifecycle

| Decision point | Alternatives considered | Selected |
|----------------|-------------------------|----------|
| Mount trigger | Service startup, manual command, eligible-user sign-in | Eligible domain-user sign-in |
| Mount location | Fixed letter, folder path, preferred letter with fallback | Centrally preferred drive letter with next-free fallback |
| Sign-out | Immediate unmount, remain mounted, graceful timeout | Reject new opens, grace existing handles, then unmount |
| Mount failure | Broken visible drive, block sign-in, absent with retry | Keep absent, retry, and record diagnostics |

**User's choice:** Automatic per-user lifecycle that integrates with normal Windows sign-in without blocking it.
**Notes:** User-facing toast notifications remain a Phase 2 capability.

---

## File Commit and Recovery Behavior

| Decision point | Alternatives considered | Selected |
|----------------|-------------------------|----------|
| Filesystem behavior | Per-write durability, periodic flush, explicit custom save, Windows semantics | Normal Windows caching, sharing, flush, and close semantics |
| Interrupted update | Partial recovery, remove file, preserve prior commit | Preserve last committed version and discard incomplete replacement |
| Corruption | Hide, delete, or fail while preserving evidence | Stable integrity error, preserve ciphertext, log diagnostics |
| Disk/write failure | Partial replacement, indefinite buffering, error with rollback | Return Windows error and preserve prior commit |

**User's choice:** Real-time behavior matching a normal Windows filesystem, backed by transactional recovery guarantees.
**Notes:** Unauthenticated plaintext must never be returned.

---

## Vertical-Slice Validation

| Decision point | Alternatives considered | Selected |
|----------------|-------------------------|----------|
| Applications | Basic tools only, harness only, include Office | Explorer, PowerShell, Notepad, Word, and Excel |
| Operations | Minimal read/write, basic copy/edit, common full set | Create, copy, open, edit, save, Save As, rename, move, delete, directories |
| File sizes | 25 MB, 100 MB, 1 GB with boundaries | Empty through at least 1 GB plus encryption-chunk boundaries |
| Recovery matrix | Normal restart only, termination subset, complete matrix | Service restart, reboot, forced mid-write termination, abrupt machine loss |

**User's choice:** A broad early compatibility and recovery proof rather than a narrow happy-path demonstration.
**Notes:** Phase 4 still owns expanded hardening, stress, packaging, and release validation.

---

## the agent's Discretion

- Exact hardware identifiers in the composite fingerprint.
- Sign-out grace duration, mount retry backoff, test corpus, and encryption-boundary values.

## Deferred Ideas

None.

---

# Update: Build and Verification Environment Roles

**Date:** 2026-08-10

| Decision point | Alternatives considered | Selected |
|----------------|-------------------------|----------|
| Endpoint runtime | CLIENT01 only, split between host/client, mixed host runtime | `LAB-CLIENT01` only |
| Test server/database | Dedicated server VM, DC01, physical host | `LAB-DC01` |
| Trusted provisioning station | DC01, DC02, CLIENT01 self-collection | `LAB-DC01` |
| Physical developer host | Developer tools only, developer tools plus WinFsp, no system changes | Developer tools only |

**User's choice:** Keep `hungdinh-lt` as a build/orchestration host. Run the server, database, and trusted provisioning on `LAB-DC01`; retain `LAB-DC02` as the secondary directory authority; run every real endpoint behavior on `LAB-CLIENT01`.

**Notes:** The user initially selected developer tools plus WinFsp for `hungdinh-lt`, then explicitly revised that choice to developer tools only. Existing host-based WinFsp or endpoint evidence must not be used to satisfy replanned endpoint-runtime acceptance criteria.

---

# Update: Verification, Infrastructure, Privilege, and Evidence Policy

**Date:** 2026-08-10

## Verification Tiers

| Decision point | Alternatives considered | Selected |
|----------------|-------------------------|----------|
| Gating model | Layered release gate, everything blocks, automation-only gate | Layered release gate |
| Visual boundary | User-visible behavior, full walkthrough, minimal smoke | User-visible behavior only |
| Hyper-V cadence | Integration boundaries plus final matrix, phase end only, every change | Integration boundaries plus final matrix |
| Deferrals | Later-phase scope only, documented edge waivers, no deferrals | Later-phase scope only |

**User's choice:** Portable automation runs continuously, focused lab checks gate relevant plans, and the full matrix gates Phase 1. No Phase 1 requirement may be waived.

## Infrastructure Substitutes

| Decision point | Alternatives considered | Selected |
|----------------|-------------------------|----------|
| SQLite boundary | Unit/component only, all development checks, behavior-based substitution | Unit/component only |
| Development PKI | Production-shaped lab PKI, simple self-signed certificates, production CA | Production-shaped lab PKI |
| VM disk identity | Stable fixture with mismatch proof, any VM ID, physical endpoint required | Stable fixture with mismatch proof |
| General fixture rule | Contract-preserving only, realism at final matrix only, case-by-case | Contract-preserving only |

**User's choice:** Fixtures may isolate portable logic but cannot replace the external boundary a Phase 1 criterion exists to prove.

## Privileged Changes

| Decision point | Alternatives considered | Selected |
|----------------|-------------------------|----------|
| Approval | Plan-scoped manifest, per-command approval, phase-wide approval | Plan-scoped manifest |
| Cleanup | Restore temporary/retain declared, restore everything, keep successful state | Restore temporary/retain declared |
| Repeatability | Idempotent apply/verify/remove, clean-snapshot only, manual recovery | Idempotent apply/verify/remove |
| Machine boundaries | Strict role allowlist, host fallback, any reversible target | Strict role allowlist |

**User's choice:** Elevated changes are predeclared, machine-specific, reversible, repeatable, and restricted to each machine's established role.

## Evidence and Provenance

| Decision point | Alternatives considered | Selected |
|----------------|-------------------------|----------|
| Blocking evidence | Structured manifest, raw test output, human report | Structured manifest |
| Visual evidence | Checklist with screenshots, recording, signed checklist only | Signed checklist only |
| Storage | Sanitized Git manifest plus controlled raw storage, everything in Git, everything external | Sanitized Git manifest plus controlled raw storage |
| Staleness | Impact-based, every commit, manual judgment | Impact-based |
| Attestation | Authenticated identity record, cryptographic signature, typed name | Authenticated identity record |
| Failed attempts | Preserve audit trail, final only, summaries only | Preserve audit trail |
| Traceability | Requirement-indexed matrix, plan-indexed, narrative | Requirement-indexed matrix |
| Missing raw artifact | Invalidate result, manifest authoritative, verifier judgment | Invalidate result |
| Manifest format | Versioned machine-readable schema, Markdown, native formats | Versioned machine-readable schema |
| Time integrity | Synchronized UTC with skew, UTC only, sequence IDs | Synchronized UTC with skew |
| Sanitization | Mandatory gate, manual review, encrypted sensitive evidence | Mandatory gate |
| Environment fingerprint | Reproducibility-focused, full inventory, minimal versions | Reproducibility-focused |
| Final approval | Independent phase review, executing operator, automation only | Independent phase review |
| Procedure deviations | Non-passing by default, operator judgment, always rerun | Non-passing by default |
| Attempt identity | Immutable ID per attempt, stable ID per check, file path | Immutable ID per attempt |
| Raw retention | Policy-based expiration, indefinite, immediate deletion after audit | Policy-based expiration |

**User's choice:** Evidence must be reproducible, immutable per attempt, requirement-indexed, sanitized, independently reviewed, and auditable without silently losing failures or deviations.

## the agent's Discretion

- Select the concrete JSON or YAML schema and the clock-skew threshold during planning, while preserving the locked evidence contract.
- Select the controlled raw-artifact storage implementation and retention duration, subject to project security constraints and explicit documentation.

## Deferred Ideas

None. Packaging, broad compatibility, stress/load/fuzz testing, credential rotation, and cross-user hardening remain in their already assigned later phases.
