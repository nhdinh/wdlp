# Phase 1: First Encrypted-Drive Vertical Slice - Context

**Gathered:** 2026-08-10 (updated during execution and verification-policy discussion)
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

### Build and Verification Environment Roles
- **D-20:** `hungdinh-lt` is the physical developer host and is limited to source builds, developer tooling such as Rust and LLVM, and Hyper-V orchestration. It must not host the DLP endpoint service, DPAPI endpoint credentials, development PKI trust entries, hosts-file mappings, domain/network changes, WinFsp runtime, DLP mounts, or endpoint-runtime verification.
- **D-21:** `LAB-CLIENT01` is the only Phase 1 endpoint-runtime target. Agent installation, Windows service execution, DPAPI credential custody, enrollment, device mTLS, WinFsp installation and mounting, restart/recovery, user-session behavior, and user-visible verification run there.
- **D-22:** `LAB-DC01` hosts the Phase 1 management server and development database and acts as the trusted provisioning station. Provisioning runs in its domain context and queries `LAB-CLIENT01` through Kerberos WinRM-over-HTTPS.
- **D-23:** `LAB-DC02` remains the independent secondary Active Directory authority used for dual-DC corroboration; it does not host the endpoint runtime or provisioning workflow.
- **D-24:** Build/test plans and verification commands must name their execution machine explicitly. A test run on `hungdinh-lt` cannot be accepted as evidence for Windows endpoint service, DPAPI, enrollment, mount, restart, or user-session requirements.

### Verification Tiers and Phase Gates
- **D-25:** Use layered verification gates. Portable automated checks run continuously; focused Hyper-V checks block completion of every plan that changes server, service, enrollment, DPAPI, WinFsp, or recovery behavior; the complete four-machine Office/restart/recovery matrix blocks Phase 1 completion.
- **D-26:** Human visual confirmation is required only for user-visible behavior on `LAB-CLIENT01`: drive presence or absence, Explorer operations, Word and Excel open/save behavior, and drive recovery after mount failures or restarts. Machine-verifiable facts use automated captured evidence.
- **D-27:** A Hyper-V integration result is acceptable only when it runs on the machine role named by D-20 through D-23. Portable or host-side substitutes cannot satisfy a Windows or infrastructure boundary check.
- **D-28:** Only capabilities already assigned to later phases may remain deferred without blocking Phase 1. No Phase 1 success criterion or mapped Phase 1 requirement may be waived as an edge case.

### Infrastructure Substitutes
- **D-29:** SQLite, in-memory repositories, mocks, and fakes may support unit or component tests, but they cannot prove PostgreSQL migrations, SQL compatibility, readiness, enrollment integration, or Phase 1 server acceptance. Those checks require real PostgreSQL on `LAB-DC01`.
- **D-30:** A lab-scoped development CA may replace production PKI for Phase 1 only when it preserves production-shaped server/device certificate roles, identity binding, EKUs, validation, replacement/renewal, and revocation behavior. Development trust is installed only on designated lab VMs and never on `hungdinh-lt`.
- **D-31:** `LAB-CLIENT01` may use a deterministic virtual-system-disk identifier as its Phase 1 fingerprint fixture. Verification must prove exact matching and rejection after virtual-disk replacement or identity change. This validates the workflow, not the robustness of production physical-hardware serial sources.
- **D-32:** Other fixtures are acceptable only when they preserve the contract under test or inject deterministic failures into portable logic. They cannot satisfy criteria intended to prove dual-DC AD corroboration, Kerberos WinRM, Windows service identity, DPAPI, mTLS, WinFsp, PostgreSQL, user sessions, or restart/crash recovery.

### Privileged Changes
- **D-33:** Before execution, every plan containing UAC/elevated work must present a machine-specific privilege manifest naming the exact change, reason, expected state, rollback/cleanup, and possible reboot. One explicit approval covers only the listed manifest; any new privileged change requires fresh approval.
- **D-34:** Capture the relevant baseline before mutation. Temporary certificates, hosts entries, test services, firewall rules, mounts, files, and environment changes must be removed after success or failure. Intended lab dependencies may remain only when the manifest declares them persistent and verifies their final state.
- **D-35:** Privileged automation must implement idempotent apply, verify, and remove behavior. Rerunning after success or partial failure must be safe; installers and build tools must be version-pinned and integrity-checked; existing state must be handled explicitly rather than hidden by ignored errors.
- **D-36:** Enforce a strict machine-role allowlist. `hungdinh-lt` may receive explicitly approved developer build tools only. Trust entries, hosts mappings, services, WinFsp/runtime drivers, DLP credentials, mounts, and domain/network changes stay on their designated lab VMs. Phase 1 introduces no kernel driver beyond the chosen WinFsp dependency.

### Verification Evidence and Provenance
- **D-37:** Every blocking result has a structured manifest containing requirement/check ID, pass/fail/blocked status, UTC time, commit/build ID, target machine and role, procedure version, operator or automation identity, environment fingerprint, and stable references plus hashes for raw artifacts.
- **D-38:** Visual confirmation produces an explicit signed checklist using the operator's authenticated domain identity, UTC timestamp, target machine, build ID, expected behavior, and pass/fail result. Screenshots are optional, not mandatory.
- **D-39:** Commit sanitized manifests and visual checklists to Git. Keep bulky or sensitive raw artifacts in controlled storage, referenced by immutable evidence ID and content hash.
- **D-40:** Evidence becomes stale when its binary, relevant source, configuration, infrastructure dependency, procedure, or target-machine baseline changes. Unaffected evidence remains valid.
- **D-41:** Preserve blocking failures and later successful reruns. Mark earlier attempts superseded and link them to remediation commits; never overwrite the audit trail.
- **D-42:** Maintain a requirement-indexed evidence matrix mapping every Phase 1 requirement and success criterion to automated checks, Hyper-V checks, visual checklist entries, current evidence IDs, and status.
- **D-43:** Missing, inaccessible, or hash-mismatched raw artifacts invalidate the affected passing result unless its committed manifest was explicitly designated self-contained and contains everything required to audit it.
- **D-44:** Use a versioned, machine-validated JSON or YAML manifest schema with immutable globally unique evidence IDs. Every rerun gets a new ID and links to the prior attempt, procedure version, remediation commit, and superseded matrix entry.
- **D-45:** Lab machines use the domain time hierarchy. Manifests record UTC and observed clock offset; excessive skew blocks evidence publication until corrected.
- **D-46:** Evidence publication uses allowlisted fields, source redaction, and automated scanning. Credentials, private keys, tokens, protected plaintext, or unnecessary personal data block commit or archive until the evidence is regenerated or sanitized.
- **D-47:** The environment fingerprint records VM identity/role, OS build and relevant patches, dependency versions, service versions/config digests, test-tool versions, domain/network identity, VM baseline/checkpoint ID, and deployed binary hashes, excluding secrets and unrelated volatile state.
- **D-48:** The executing operator may attest individual visual runs, but an independent verifier must review the complete requirement matrix, provenance, deviations, and artifact integrity before Phase 1 is declared complete.
- **D-49:** Any deviation from an approved verification procedure is recorded and non-passing by default. Only the independent verifier may determine that it was immaterial; otherwise the check must be rerun.
- **D-50:** Retain committed manifests and checklists with repository history. Retain raw artifacts through the milestone audit plus a documented retention window, then securely delete them unless a failure, security investigation, or explicit hold requires longer preservation.

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
- The workspace now contains the portable domain/protocol/crypto/storage crates, authenticated server routes, Windows service boundaries, and a real WinFsp adapter.
- Completed Phase 1 summaries through `01-10-SUMMARY.md` provide reusable build, storage, enrollment, TLS, recovery, and mount evidence that replanning must preserve.
- Hyper-V PowerShell Direct provides orchestration from `hungdinh-lt` into the domain context without changing the physical host's DNS, trust store, hosts file, or domain membership.

### Established Patterns
- Portable Rust crates deny unsafe code; Windows-specific FFI must remain isolated and documented.
- Filesystem integration must sit behind a replaceable Rust abstraction.
- Persisted formats and agent/server DTOs are versioned; invalid signed bundles never replace active configuration.
- Security failures fail closed without revealing plaintext or secrets in diagnostics.
- Verification evidence is requirement-indexed, immutable per attempt, sanitized before publication, and invalidated by relevant implementation or environment changes.

### Integration Points
- New Cargo workspace crates and their boundaries are defined by `WRK-01` in `.planning/REQUIREMENTS.md`.
- The server connects to PostgreSQL, both AD domain controllers, and enrolled agents over authenticated HTTP APIs.
- The Windows service connects enrollment/configuration, DPAPI-protected device credentials, per-user session detection, WinFsp mounting, and encrypted backing storage.
- Replanned Windows integration and verification must deploy artifacts to `LAB-CLIENT01`; server/database and trusted provisioning commands execute on `LAB-DC01`; dual-directory checks use both `LAB-DC01` and `LAB-DC02`.
- Phase verification connects plan-level checks to a versioned evidence-manifest schema, a requirement-indexed matrix, controlled raw-artifact storage, and an independent phase-exit review.

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
*Context gathered: 2026-08-07; environment roles and verification policy updated: 2026-08-10*
