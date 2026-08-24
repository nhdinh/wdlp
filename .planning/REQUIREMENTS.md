# Requirements: Windows Data Leakage Prevention (DLP) Solution

**Defined:** 2026-08-07
**Core Value:** An authorized Windows user can mount a private protected drive, store files in it, and read them back through the drive, while the backing store does not contain directly readable plaintext.

## v1 Requirements

### Workspace and Domain (WRK)

- [ ] **WRK-01**: Establish a Cargo workspace with `dlp-domain`, `dlp-policy`, `dlp-protocol`, `dlp-crypto`, `dlp-storage`, `dlp-server`, `dlp-agent-core`, `dlp-windows-service`, `dlp-windows-drive`, and `dlpctl` crates.
- [ ] **WRK-02**: Define shared identifiers, policy types, enforcement decisions, and structured errors in `dlp-domain`.
- [ ] **WRK-03**: Define versioned protocol DTOs and wire-format schemas in `dlp-protocol`.
- [ ] **WRK-04**: Deny unsafe code in portable domain crates; isolate and document unavoidable unsafe Windows FFI.

### Server (SRV)

- [ ] **SRV-01**: Provide authenticated HTTP JSON APIs for administrators and endpoint agents.
- [ ] **SRV-02**: Support administrator authentication with basic admin and auditor roles; auditors cannot change policies or configuration.
- [ ] **SRV-03**: Enroll Windows devices using single-use or short-lived enrollment tokens.
- [ ] **SRV-04**: Maintain device lifecycle states: pending, active, locked, revoked, and retired.
- [ ] **SRV-05**: Support creation, validation, versioning, signing, and assignment of policies.
- [ ] **SRV-06**: Produce immutable, signed configuration bundles containing policy versions, schema version, agent settings, effective time, and offline allowance.
- [ ] **SRV-07**: Distribute configuration bundles to agents and report deployment status.
- [ ] **SRV-08**: Accept idempotent, batched event uploads from agents.
- [ ] **SRV-09**: Record all administrative mutations with actor, timestamp, old value, and new value.
- [ ] **SRV-10**: Provide audit search and export by time, device, user, action, rule, and severity.
- [ ] **SRV-11**: Persist data in PostgreSQL with versioned migrations.
- [ ] **SRV-12**: Provide health and readiness endpoints.

### Policy Engine (POL)

- [ ] **POL-01**: Evaluate policies deterministically for the same policy version and input.
- [ ] **POL-02**: Support conditions on file properties: name, extension, MIME/type, path, owner, and size.
- [ ] **POL-03**: Support bounded content detectors: regular expressions, dictionaries, hashes, and structured identifiers.
- [ ] **POL-04**: Support operation context: read, write, import, export, copy, and delete.
- [ ] **POL-05**: Support destination context when observable at the drive boundary.
- [ ] **POL-06**: Support actions: `allow`, `block`, `allow_and_audit`, and `warn`.
- [ ] **POL-07**: Reject policies that activate `require_justification` until the workflow is implemented.
- [ ] **POL-08**: Define explicit rule priority and conflict-resolution behavior.
- [ ] **POL-09**: Record a reason code for every enforcement decision.
- [ ] **POL-10**: Be unit-testable independent of Windows APIs.

### Cryptography (CRY)

- [ ] **CRY-01**: Use authenticated encryption for file contents and sensitive metadata at rest.
- [ ] **CRY-02**: Sign configuration bundles with Ed25519; agents verify signature and schema version before activation.
- [ ] **CRY-03**: Implement per-user encryption key hierarchy with a DEK wrapped by a DPAPI-NG-protected KEK and server-escrowed recovery key.
- [ ] **CRY-04**: Store no long-lived secret in plaintext on the endpoint.
- [ ] **CRY-05**: Support server key rotation with a key identifier in each bundle.

### Endpoint Agent (AGT)

- [ ] **AGT-01**: Run as a Windows service with automatic startup and no interactive user session requirement.
- [ ] **AGT-02**: Enroll the device and protect credentials using Windows-protected storage.
- [ ] **AGT-03**: Periodically contact the server over TLS; verify server identity.
- [ ] **AGT-04**: Download, verify, cache, and atomically activate signed configuration bundles.
- [ ] **AGT-05**: Retain the current and last-known-good configurations.
- [ ] **AGT-06**: Reject invalid, unsigned, corrupted, or partially downloaded bundles without replacing the active policy.
- [ ] **AGT-07**: Report version, health, drive state, active policy version, and errors.
- [ ] **AGT-08**: Queue audit events locally when offline; upload in order on reconnection.
- [ ] **AGT-09**: Bound event queue, retries, CPU, memory, and disk usage with configurable limits.
- [ ] **AGT-10**: Recover cleanly from service, process, and machine restarts.
- [ ] **AGT-11**: Lock the protected drive when the device is revoked or the offline allowance expires.

### Protected Drive (DRV)

- [ ] **DRV-01**: Provide one isolated store per authenticated Windows user.
- [ ] **DRV-02**: Mount the drive through WinFsp with a configurable drive letter or mount path.
- [ ] **DRV-03**: Map every request to the correct Windows user identity.
- [ ] **DRV-04**: Encrypt file contents and sensitive metadata at rest.
- [ ] **DRV-05**: Prevent one user from mounting or accessing another user's store through supported interfaces.
- [ ] **DRV-06**: Use crash-consistent metadata and file updates.
- [ ] **DRV-07**: Detect corrupted encrypted data and fail without returning unauthenticated plaintext.
- [ ] **DRV-08**: Return appropriate access-denied errors and clear messages for policy-denied operations.
- [ ] **DRV-09**: Survive service and machine restarts without corrupting committed data.

### User Interaction (UI)

- [ ] **UI-01**: Provide a small per-user companion process for Windows session interaction.
- [ ] **UI-02**: Authenticate companion process requests to the service using the caller's Windows identity.
- [ ] **UI-03**: Show a Windows toast when an operation is blocked, including file name, rule reason, and remediation guidance without exposing sensitive content.

### Administration (ADM)

- [ ] **ADM-01**: Allow administrators to view fleet status: last-seen time, agent version, active policy version, and health state.
- [ ] **ADM-02**: Allow administrators to lock or revoke a device.
- [ ] **ADM-03**: Allow administrators to search enforcement events and export audit results in a structured format.
- [ ] **ADM-04**: Provide basic web UI or CLI for fleet, policy, and event management.

### Testing (TST)

- [ ] **TST-01**: Write unit tests for policy matching, priority, conflict resolution, and default actions.
- [ ] **TST-02**: Write unit tests for bundle validation and signature verification.
- [ ] **TST-03**: Write unit tests for storage encryption, integrity failures, and key handling.
- [ ] **TST-04**: Write unit tests for event queue limits, retry logic, and idempotency.
- [ ] **TST-05**: Write integration tests for server enrollment through first policy activation.
- [ ] **TST-06**: Write integration tests for offline enforcement followed by event synchronization.
- [ ] **TST-07**: Write integration tests for per-user drive isolation and device revocation.
- [ ] **TST-08**: Validate WinFsp with representative Windows applications in an early spike.

## v2 Requirements

### Administration

- **ADM-V2-01**: Staged policy rollout to test device groups before broad deployment.
- **ADM-V2-02**: Policy preview against supplied test metadata or sample content.
- **ADM-V2-03**: Full administrative web interface with role-based dashboards.

### Policy Engine

- **POL-V2-01**: `require_justification` action with user-provided business justification and approval workflow.
- **POL-V2-02**: Additional content detectors (e.g., file-type magic, entropy analysis).
- **POL-V2-03**: Machine-learning classification models.

### Agent

- **AGT-V2-01**: Automatic agent updates with signed MSI packages.
- **AGT-V2-02**: Detailed local diagnostics support bundle generation.

### Scale and Operations

- **OPS-V2-01**: Multi-tenancy in a single server deployment.
- **OPS-V2-02**: Kubernetes deployment manifests and managed PostgreSQL support.
- **OPS-V2-03**: High-availability server configuration.

## Out of Scope

| Feature | Reason |
|---------|--------|
| Kernel-mode file-system filtering | Requires an expensive code-signing certificate; user-mode WinFsp is the chosen boundary |
| OS-wide monitoring of clipboard, print, USB, screen capture | Cannot be reliably enforced from a user-space drive boundary; would require kernel components |
| Full EDR functionality | Out of product scope; focus is DLP policy enforcement at the drive boundary |
| Deep inspection of arbitrary encrypted archives | High complexity and unbounded parsing risk; defer to v2+ |
| OCR for images and scanned documents | High compute cost and complexity; not required for MVP |
| Content inspection of all network traffic | Requires network/kernel components beyond the drive boundary |
| Operating systems other than Windows | MVP targets Windows endpoints only |
| DRM after authorized plaintext export | Once plaintext leaves the drive, product cannot control it |
| Multi-tenancy | One organization per server in MVP; can be added later without architecture changes |
| `require_justification` action | Complete user workflow not implemented; server must reject activating policies that use it |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| WRK-01 | Phase 1 | Gaps Found |
| WRK-02 | Phase 1 | Gaps Found |
| WRK-03 | Phase 1 | Gaps Found |
| WRK-04 | Phase 1 | Gaps Found |
| SRV-01 | Phase 1 | Gaps Found |
| SRV-02 | Phase 2 | Pending |
| SRV-03 | Phase 1 | Gaps Found |
| SRV-04 | Phase 3 | Pending |
| SRV-05 | Phase 2 | Pending |
| SRV-06 | Phase 2 | Pending |
| SRV-07 | Phase 2 | Pending |
| SRV-08 | Phase 3 | Pending |
| SRV-09 | Phase 3 | Pending |
| SRV-10 | Phase 3 | Pending |
| SRV-11 | Phase 1 | Gaps Found |
| SRV-12 | Phase 1 | Gaps Found |
| POL-01 | Phase 2 | Pending |
| POL-02 | Phase 2 | Pending |
| POL-03 | Phase 2 | Pending |
| POL-04 | Phase 2 | Pending |
| POL-05 | Phase 2 | Pending |
| POL-06 | Phase 2 | Pending |
| POL-07 | Phase 2 | Pending |
| POL-08 | Phase 2 | Pending |
| POL-09 | Phase 2 | Pending |
| POL-10 | Phase 2 | Pending |
| CRY-01 | Phase 1 | Gaps Found |
| CRY-02 | Phase 1 | Gaps Found |
| CRY-03 | Phase 3 | Pending |
| CRY-04 | Phase 1 | Gaps Found |
| CRY-05 | Phase 2 | Pending |
| AGT-01 | Phase 1 | Gaps Found |
| AGT-02 | Phase 1 | Gaps Found |
| AGT-03 | Phase 1 | Gaps Found |
| AGT-04 | Phase 1 | Gaps Found |
| AGT-05 | Phase 1 | Gaps Found |
| AGT-06 | Phase 1 | Gaps Found |
| AGT-07 | Phase 1 | Gaps Found |
| AGT-08 | Phase 3 | Pending |
| AGT-09 | Phase 3 | Pending |
| AGT-10 | Phase 1/4 | Pending |
| AGT-11 | Phase 3 | Pending |
| DRV-01 | Phase 1 | Gaps Found |
| DRV-02 | Phase 1 | Gaps Found |
| DRV-03 | Phase 1 | Gaps Found |
| DRV-04 | Phase 1 | Gaps Found |
| DRV-05 | Phase 2/4 | Pending |
| DRV-06 | Phase 1 | Gaps Found |
| DRV-07 | Phase 1 | Gaps Found |
| DRV-08 | Phase 2 | Pending |
| DRV-09 | Phase 1 | Gaps Found |
| UI-01 | Phase 2 | Pending |
| UI-02 | Phase 2 | Pending |
| UI-03 | Phase 2 | Pending |
| ADM-01 | Phase 3 | Pending |
| ADM-02 | Phase 3 | Pending |
| ADM-03 | Phase 3 | Pending |
| ADM-04 | Phase 3 | Pending |
| TST-01 | Phase 2 | Gaps Found |
| TST-02 | Phase 1 | Gaps Found |
| TST-03 | Phase 1 | Gaps Found |
| TST-04 | Phase 3 | Pending |
| TST-05 | Phase 1 | Gaps Found |
| TST-06 | Phase 3 | Pending |
| TST-07 | Phase 2 | Pending |
| TST-08 | Phase 1 | Gaps Found |

**Coverage:**

- v1 requirements: 63 total
- Mapped to phases: 63
- Unmapped: 0 ✓

## Definition of Done

A feature is done only when:

- Its security and failure behavior is documented.
- Unit and relevant integration tests pass.
- Windows-specific behavior is tested on supported Windows versions where applicable.
- Logs, metrics, and stable errors make failures diagnosable.
- No secrets or protected content appear in logs or test artifacts.
- User-facing denial messages are actionable.
- API and persisted-format changes are versioned or migrated.
- Operational and administrator documentation is updated.

---
*Requirements defined: 2026-08-07*
*Last updated: 2026-08-07 after roadmap restructuring*
