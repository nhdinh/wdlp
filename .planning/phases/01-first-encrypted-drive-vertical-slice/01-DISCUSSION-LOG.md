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
