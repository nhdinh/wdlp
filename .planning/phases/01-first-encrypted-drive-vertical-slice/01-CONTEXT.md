# Phase 1: First Encrypted-Drive Vertical Slice - Context

**Gathered:** 2026-08-07
**Status:** Ready for planning

<domain>
## Phase Boundary

Deliver one complete architectural proof with one management server, one domain-joined Windows endpoint, and one user: enroll the endpoint, receive and verify signed configuration, mount a per-user WinFsp drive, perform normal file operations against authenticated encrypted storage, read committed data back, and recover safely across failures and restarts. Policy enforcement, user notifications, fleet operations, and production hardening remain in later phases.

</domain>

<decisions>
## Implementation Decisions

### Enrollment Bootstrap and Device Trust
- **D-01:** The installed agent is configured with the management-server address and initiates registration automatically on first run.
- **D-02:** Enrollment is permitted only for a domain-joined computer whose exact composite hardware fingerprint is already whitelisted on the server. The fingerprint uses important hardware serial numbers, including system-disk identity; MAC addresses are not authoritative. — **Reversibility:** costly — changing fingerprint composition affects existing whitelist records and device identity matching.
- **D-03:** Any change to a fingerprinted hardware component, including system-disk replacement, blocks enrollment until an administrator updates the whitelist.
- **D-04:** The management server validates the computer account and obtains authoritative device information by querying the organization's two AD domain controllers (one primary and one secondary) on the same network.
- **D-05:** Successful enrollment issues a device-bound client certificate for mutual TLS. The private key and associated credential material are stored in a DPAPI machine-protected file accessible to the Windows service. — **Reversibility:** costly — changing the device-authentication scheme requires credential migration and coordinated server/agent protocol changes.
- **D-06:** If the local credential is missing or cannot be decrypted, the agent automatically repeats the complete domain and hardware checks, receives replacement credentials, and causes the server to revoke the previous credential.

### Drive Mounting Lifecycle
- **D-07:** Mount the protected drive automatically when an eligible domain user signs in; each signed-in user receives that user's isolated store.
- **D-08:** Use the centrally configured preferred drive letter. If it is occupied, select the next available drive letter.
- **D-09:** At sign-out, reject new opens, allow existing handles a short grace period, then unmount and clean up. The exact grace-period duration is left to planning.
- **D-10:** If automatic mounting fails, leave the drive absent, retry automatically, and record a clear diagnostic event. Phase 1 does not block Windows sign-in or expose a broken placeholder drive.

### File Commit and Recovery Behavior
- **D-11:** Present normal Windows filesystem behavior, including expected visibility, caching, sharing, explicit-flush, and handle-close semantics. There is no product-specific save operation.
- **D-12:** A successful Windows flush or close must not be acknowledged until encrypted content and its metadata meet the corresponding durability expectations.
- **D-13:** After an interruption, retain the last fully committed version and discard an incomplete replacement; never expose a partial mixture of old and new data.
- **D-14:** If ciphertext or sensitive metadata fails authenticated verification, deny access with a stable integrity error, preserve the encrypted evidence for diagnosis or recovery, record diagnostics, and never return unauthenticated plaintext.
- **D-15:** On disk-full or backing-store write failure, return the appropriate Windows error and preserve the last committed file version.

### Vertical-Slice Validation
- **D-16:** The Phase 1 end-to-end matrix must include Explorer, PowerShell, Notepad, Microsoft Word, and Microsoft Excel.
- **D-17:** Validate create, copy into the drive, copy out, open, edit, save, Save As, rename, move, delete, and directory operations.
- **D-18:** Validate file sizes from empty through at least 1 GB, including sizes immediately below, at, and above encrypted-storage chunk boundaries.
- **D-19:** Validate normal service restart, Windows reboot, forced service termination during an active write, and simulated abrupt machine loss.

### the agent's Discretion
- Select the exact hardware serial sources used in the composite fingerprint while preserving exact-match behavior, system-disk binding, and resistance to agent-supplied spoofing.
- Select the sign-out handle grace-period duration and retry backoff for failed mounts.
- Define the precise test corpus and encryption-chunk boundary sizes consistent with the selected storage format.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Project Scope and Phase Contract
- `.planning/PROJECT.md` — Product boundary, core value, deployment constraints, security posture, and previously locked architectural decisions.
- `.planning/REQUIREMENTS.md` — Phase 1 requirement IDs, system-wide constraints, traceability, and definition of done.
- `.planning/ROADMAP.md` — Fixed Phase 1 goal, requirements, success criteria, and later-phase boundaries.

### Architecture Decisions
- `.planning/docs/adrs/ADR-001-winfsp-framework.md` — WinFsp selection, replaceable filesystem abstraction, and initial compatibility validation scenarios.
- `.planning/docs/adrs/ADR-002-api-transport.md` — REST/JSON transport, `/api/v1` versioning, and agent-polling model.
- `.planning/docs/adrs/ADR-003-database-migrations.md` — PostgreSQL, SQLx, and forward migration rules.
- `.planning/docs/adrs/ADR-005-policy-signing.md` — Ed25519 bundle signing, verification scope, and signing-key identifiers.
- `.planning/docs/adrs/ADR-006-key-hierarchy.md` — Per-user DEK/KEK structure, DPAPI-NG protection, encrypted metadata, and recovery direction.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- No implementation code exists yet; Phase 1 begins from planning artifacts and ADRs.
- The ADR set provides directly reusable contracts for WinFsp, REST/JSON, SQLx migrations, Ed25519 signing, and per-user encrypted storage.

### Established Patterns
- Portable Rust crates deny unsafe code; Windows-specific FFI must remain isolated and documented.
- Filesystem integration must sit behind a replaceable Rust abstraction.
- Persisted formats and agent/server DTOs are versioned; invalid signed bundles never replace active configuration.
- Security failures fail closed without revealing plaintext or secrets in diagnostics.

### Integration Points
- New Cargo workspace crates and their boundaries are defined by `WRK-01` in `.planning/REQUIREMENTS.md`.
- The server connects to PostgreSQL, both AD domain controllers, and enrolled agents over authenticated HTTP APIs.
- The Windows service connects enrollment/configuration, DPAPI-protected device credentials, per-user session detection, WinFsp mounting, and encrypted backing storage.

</code_context>

<specifics>
## Specific Ideas

- Enrollment should require the exact authorized physical endpoint and its system disk, not merely possession of a token or a matching network adapter.
- The protected drive should feel like a normal Windows filesystem to users and applications.
- The validation bar explicitly includes Word and Excel rather than postponing all Office behavior to final hardening.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 1-First Encrypted-Drive Vertical Slice*
*Context gathered: 2026-08-07*
