# Threat Model: Windows DLP Solution

## Scope

This threat model covers the MVP boundaries of the centrally managed Windows DLP solution:
- Central management server and its APIs
- Windows endpoint agent and Windows service lifecycle
- Local inter-process communication (service ↔ companion process)
- User-space protected drive (WinFsp)
- Encrypted backing store
- Agent update and rollback
- Offline operation and policy expiration

Out of scope for the MVP: kernel-mode enforcement, OS-wide volume monitoring, network traffic inspection, DRM after authorized export, multi-tenancy.

## Trust Boundaries

| Boundary | Trusted Side | Untrusted Side | Notes |
|----------|--------------|----------------|-------|
| Server ↔ Agent | Server control plane; enrolled agent with valid device credential | Public network; attacker with network access | TLS required; mutual TLS for enrolled agents where practical |
| Agent service ↔ OS | Agent service running as dedicated service identity | Endpoint OS; local administrator; kernel-level attacker | User-mode agent cannot fully resist admin/kernel compromise |
| Service ↔ Companion | Privileged service | Per-user companion process in user session | All IPC requests must authenticate caller and check authorization |
| Companion ↔ User | Authenticated Windows user | Other users on same machine | Drive mount is per-user; companion runs in user's session |
| Drive boundary | Files accessed through the virtual drive | Applications after plaintext is released | Product cannot control data once allowed export occurs |
| Backing store | Encrypted store read by the agent service | Direct disk access; offline disk image | Authenticated encryption prevents reading without keys |
| Cached policy / event queue | Files read by the agent service | Same as backing store | Treat as untrusted input when read |

## Threats and Mitigations

### 1. Server Compromise or Impersonation

**Threat:** An attacker compromises the server or impersonates it to push malicious policy or revoke legitimate devices.

**Mitigations:**
- Sign every agent-consumable configuration bundle; agent verifies signature before activation.
- Use TLS for all connections; verify server certificate.
- Separate admin API and agent API authentication.
- Record all administrative mutations in an append-only audit log.
- Use replay protection (nonces/timestamps) for enrollment and commands.

### 2. Malicious or Revoked Endpoint

**Threat:** A revoked or attacker-controlled endpoint connects to the server or receives policy intended for another device.

**Mitigations:**
- Per-device identity with independently revocable credentials.
- Device lifecycle states: pending, active, locked, revoked, retired.
- Agent certificate/key stored in Windows-protected storage.
- Server rejects revoked devices at TLS/auth layer.

### 3. Tampering with Cached Policy or Backing Store

**Threat:** An attacker modifies local policy cache, event queue, or encrypted backing-store files.

**Mitigations:**
- Authenticated encryption (AES-GCM or ChaCha20-Poly1305) for backing store and local queue.
- Cryptographic signatures over policy bundles including schema version.
- Atomic activation: write new config to staging, verify, then swap; retain last-known-good.
- Treat all local persisted files as untrusted input when read; verify signatures and MACs before use.

### 4. Unauthorized Mount or Cross-User Access

**Threat:** One Windows user mounts or reads another user's protected store.

**Mitigations:**
- Per-user encrypted backing store.
- Key hierarchy tied to Windows user identity (DPAPI-NG or user-specific keys).
- Mount authorization checks the calling user's Windows SID.
- Service refuses mount requests for stores owned by a different SID.

### 5. Local Administrator or Kernel Attacker

**Threat:** A local admin or kernel-level attacker bypasses the user-mode agent.

**Mitigations:**
- Document explicit limitation: user-mode enforcement cannot provide absolute protection against admin/kernel attackers.
- Detect and report observable tampering (service stopped, files modified, unexpected processes).
- Run agent as dedicated service identity with least privilege.
- Protect long-lived secrets using Windows security facilities.

**Accepted risk:** Full resistance requires a later kernel-mode component and enterprise Windows controls.

### 6. Offline Policy Circumvention

**Threat:** Endpoint remains offline longer than allowed and continues enforcing an expired or stale policy, or an attacker rolls back the clock.

**Mitigations:**
- Signed policy includes effective time and offline allowance.
- Agent uses trusted time source where possible; detect clock rollback.
- After offline allowance expires, lock protected drive and deny new access.
- Recovery requires a valid signed policy or signed time-limited admin authorization.

### 7. Denial of Service on Endpoint

**Threat:** Large files, many operations, or malformed content exhaust CPU, memory, disk, or event queue.

**Mitigations:**
- Bounded content scanners with size and timeout limits.
- Configurable disk, CPU, memory, and event-queue limits.
- Short file-system callbacks; move expensive scanning to bounded workers.
- Event queue bounded to prevent disk exhaustion.

### 8. Information Leakage via Logs and Audit Events

**Threat:** Protected file contents, encryption keys, tokens, or credentials appear in logs or telemetry.

**Mitigations:**
- Redact secrets and protected content from all logs.
- Audit events contain only minimum metadata needed for investigation.
- Never upload file contents to the server by default.
- Review test artifacts for leaked secrets.

### 9. Agent Update or Rollback Attack

**Threat:** An attacker pushes a malicious agent update or forces rollback to a vulnerable version.

**Mitigations:**
- Sign release artifacts; agent verifies signature before installing.
- Atomic update with rollback protection for security configuration.
- Server controls update rollout and version requirements.

### 10. IPC Spoofing or Elevation

**Threat:** A process other than the authorized companion impersonates the user and sends requests to the service.

**Mitigations:**
- Authenticate every local service request using the caller's Windows identity.
- Validate authorization against the caller's SID and requested operation.
- Use a secure local transport (named pipe with proper ACLs or ALPC with authentication).

## Attack Scenarios

### Scenario A: Copy sensitive file out of protected drive
1. User or app copies file from protected drive to local disk.
2. Agent evaluates file metadata, content detectors (if configured), operation, user, device, and destination.
3. Policy decision recorded with version, rule, action, and reason.
4. If blocked, operation returns access-denied and companion shows toast.
5. If allowed, plaintext leaves the drive boundary — product no longer controls it.

### Scenario B: Revoked device reconnects
1. Device is revoked by administrator.
2. On next heartbeat, agent receives revocation command or TLS/auth fails.
3. Agent locks the protected drive and stops enforcing policy.
4. Backing store remains encrypted and inaccessible through product interfaces.

### Scenario C: Backing-store files copied to another machine
1. Attacker obtains disk image or copies backing-store files.
2. Without the user-specific key protected by Windows credentials, files are unreadable.
3. Tampered files fail MAC verification when read by agent.

## Assumptions

- The management server is operated by the organization and kept patched and secured.
- Endpoints run supported Windows versions with standard enterprise hardening.
- Users are not local administrators by default.
- WinFsp and Windows service APIs behave as documented.
- The organization accepts the explicit user-mode limitation documented in this model.

## Open Risks

- A local admin or kernel attacker can bypass user-mode enforcement.
- Clock rollback may require additional hardening beyond simple policy timestamps.
- WinFsp compatibility with all target applications must be validated by the early spike.
- Recovery from lost user keys requires a documented key-escrow or recovery procedure.

## References

- PROJECT.md for scope and decisions
- ADR-001: User-space Windows file-system framework selection
- ADR-006: Per-user encryption key hierarchy and recovery behavior
- ADR-007: Offline expiration and fail-safe behavior
