# Research: Architecture — Windows DLP Solution

## Domain

Centrally managed endpoint Data Loss Prevention (DLP) for Windows using a user-space virtual drive as the enforcement boundary, with a self-hosted Linux management server and lightweight agents installed as Windows services.

## Key Findings

- Every centrally managed endpoint DLP product follows the same three-layer pattern: a management server that authors and signs policy, a local agent that caches and enforces policy, and a secure channel between them (typically TLS, often with certificate-based mutual authentication).
- Enforcement can be kernel-mode (file-system minifilter, system-wide, tamper-resistant) or user-space (virtual drive, bounded, no signed driver). This project deliberately chooses user-space with WinFsp to avoid kernel development and driver signing costs.
- The virtual drive is the policy enforcement boundary: files inside the drive are encrypted at rest and decrypted only through the drive; once data is copied out through an allowed export, the product no longer controls it.
- Agents must work offline. Standard practice is to cache signed policies locally, enforce them for a bounded time, queue audit events, and upload events on reconnect. New policies cannot be delivered while offline, but the last valid policy remains active.
- Agent-server communication is pull-based with a periodic heartbeat/refresh (e.g., 90 minutes) plus a thin persistent channel for real-time requests. Out-of-sync status is surfaced in the console when a device misses updates.
- The Windows service/agent should be separate from the per-user virtual drive instance and separate again from the per-user toast/notification companion process. This separation matches Windows session architecture and least-privilege principles.

## Major Components

### 1. Central Management Server

- **Responsibility**: Administrator authentication, device enrollment, policy/rule authoring, signing of configuration bundles, aggregation of audit events, and health monitoring.
- **Interfaces**: Web admin console (browser), agent API (HTTPS + mTLS where practical), PostgreSQL database, optional SIEM/AD/LDAP integrations.
- **Trust boundary**: The server is the organizational root of trust for policy. It holds the signing key used to authenticate config bundles and offline policy. Deployed as a Docker Compose stack on a single Linux host inside the customer's network.
- **Build priority**: Build first. Nothing else can enroll, receive policy, or report audit without it.

### 2. Web Admin Console

- **Responsibility**: Create and deploy DLP policies, manage devices and users, search audit logs by time/device/user/action/rule/severity, and view out-of-sync/offline status.
- **Interfaces**: Talks to the management server's REST/GraphQL API only.
- **Trust boundary**: Admin-facing boundary; requires strong authentication and role-based access. It does not communicate directly with endpoints.
- **Build priority**: Build early, immediately after the server skeleton, so administrators can drive enrollment and policy.

### 3. Enrollment and Identity Service

- **Responsibility**: Onboard new endpoints, issue device identity (key pair/certificate), bind the device to a Windows user identity, and authorize the agent to receive signed configuration bundles.
- **Interfaces**: Admin console (initiates enrollment), agent service (submits enrollment request and receives credentials), server database.
- **Trust boundary**: This is the first trust decision. Compromise here allows an attacker to enroll a rogue device. Enrollment should require an admin-issued token or approval.
- **Build priority**: Build early, before agent deployment, because the agent cannot authenticate to the server without it.

### 4. Signed Configuration / Policy Bundle

- **Responsibility**: A portable, versioned, signed artifact containing policy rules, classification definitions, allowed actions, offline expiry timestamp, and rollback metadata. Signed by the server; verified by the agent.
- **Interfaces**: Produced by the server, consumed by the agent service, passed to the virtual drive and enforcement engine.
- **Trust boundary**: The bundle signature is the root of offline trust. The agent must reject any bundle that fails signature/expiration/version checks and fall back to the last valid bundle.
- **Build priority**: Build early, before policy enforcement, because the drive cannot safely act on unsigned rules.

### 5. Agent Windows Service

- **Responsibility**: Runs as LocalSystem, manages the device's enrolled identity, downloads and verifies signed bundles, spawns per-user virtual drive instances on session logon, reports health, and coordinates audit upload.
- **Interfaces**: Management server (HTTPS), WinFsp drive instances (mount/unmount/config), companion process (IPC for notifications), encrypted backing store (key provisioning), local audit queue.
- **Trust boundary**: Highest privilege component on the endpoint. It must protect enrollment keys, signing trust anchors, and the audit queue. Crash or compromise here affects the whole endpoint.
- **Build priority**: Build immediately after the server skeleton; it is the endpoint orchestrator.

### 6. Virtual Drive (WinFsp + Rust bindings)

- **Responsibility**: Presents a per-user protected drive letter. Intercepts file operations (create, read, write, rename, delete, copy from drive) and applies policy at the drive boundary.
- **Interfaces**: Agent service (lifecycle and config), Windows Explorer/applications (file I/O), encrypted backing store (ciphertext read/write).
- **Trust boundary**: User-mode, per-logon-session. Enforcement is limited to the virtual drive; it cannot prevent a privileged process from reading the raw backing-store ciphertext or bypassing the drive entirely. This is an accepted trade-off per PROJECT.md.
- **Build priority**: Build after the agent skeleton and enrollment; this is the core vertical slice (mount, copy, encrypted backing store, read back).

### 7. Encrypted Backing Store

- **Responsibility**: Stores per-user ciphertext files, directory metadata, and wrapped keys on local disk (e.g., `%ProgramData%` or user-protected location). Uses authenticated encryption; keys are wrapped via DPAPI or similar Windows key protection.
- **Interfaces**: Virtual drive reads and writes ciphertext; agent service provisions per-user keys.
- **Trust boundary**: Data at rest must be unreadable outside the product. Each user's store is isolated by Windows identity.
- **Build priority**: Build together with the virtual drive; they are inseparable for the first vertical slice.

### 8. Policy Enforcement Engine

- **Responsibility**: Evaluates file/metadata/content against the active signed policy and decides allow, block, allow-and-audit, or warn. Rejects `require_justification` policies at activation time (per PROJECT.md).
- **Interfaces**: Called by the virtual drive for each relevant I/O operation; reads rules from the signed bundle.
- **Trust boundary**: Runs inside the agent/service context. It must operate only on signed, verified policy and must not expose debug bypasses.
- **Build priority**: Build after virtual drive read/write works but before toast notifications and audit queue.

### 9. Audit and Event Queue

- **Responsibility**: Records enforcement events locally in a tamper-evident, encrypted store and uploads them to the server when reachable. Supports offline buffering and replay on reconnect.
- **Interfaces**: Virtual drive and enforcement engine produce events; agent service uploads to server.
- **Trust boundary**: Must resist local tampering and deletion. Cryptographic chaining or append-only semantics are recommended.
- **Build priority**: Build after core enforcement works; required for compliance and operator visibility.

### 10. Per-User Companion Process (Toast Notifications)

- **Responsibility**: Lightweight user-space process that shows Windows toast notifications when the drive blocks or warns about an operation.
- **Interfaces**: Receives notification messages from the agent service via a secure IPC channel (named pipe or local socket).
- **Trust boundary**: Not authoritative; purely informational. If it crashes or is killed, enforcement continues.
- **Build priority**: Build after blocking/warning enforcement works.

## Data Flow

### 1. Enrollment

1. Administrator creates an enrollment token in the web console.
2. Admin installs the agent Windows service on the endpoint (manual install or deployment tool).
3. Agent service starts, generates a device key pair, and sends an enrollment request + token to the management server.
4. Server validates the token, records the device and Windows identity, and returns a signed device credential/certificate.
5. Agent stores the credential in a protected Windows location (e.g., DPAPI-protected or certificate store).

### 2. Policy Distribution and Activation

1. Administrator authors a policy in the web console and assigns it to users/devices/groups.
2. Server builds a signed configuration bundle containing rules, actions, offline expiry, and version metadata.
3. Agent service, during its periodic sync or on demand, downloads the bundle over HTTPS/mTLS.
4. Agent verifies the bundle signature, version, and expiry. If valid, it atomically activates the new policy and may roll back to the previous bundle on failure.
5. Agent passes the active policy to the per-user virtual drive instances.

### 3. File Access and Enforcement

1. User logs on to Windows; agent service detects the session and spawns/attaches a per-user virtual drive instance, mounting a drive letter.
2. User opens or copies a file into the protected drive.
3. Virtual drive translates the file operation, reads/writes ciphertext from the encrypted backing store, and decrypts/encrypts data as needed.
4. For write/copy/export operations, the virtual drive asks the enforcement engine to evaluate the operation against the active signed policy.
5. Enforcement engine returns allow, block, allow-and-audit, or warn.
6. On block or warn, the virtual drive denies the operation and notifies the companion process, which shows a toast to the user.
7. On allow, the operation completes, and the audit queue records the event.

### 4. Offline Enforcement

1. Agent loses connectivity to the management server.
2. Agent continues using the last valid signed policy bundle.
3. Enforcement engine keeps evaluating operations; events are appended to the local encrypted audit queue.
4. On day five (configurable), the agent warns the user that offline grace is expiring.
5. After seven days with no new valid bundle, the agent locks the protected drive (read-only or unmounted) until a new signed policy or signed recovery authorization is received.

### 5. Audit Upload

1. Enforcement events are written to the local audit queue with timestamps, user SID, device ID, file metadata, rule matched, and action taken.
2. When the agent detects server reachability, it uploads queued events over HTTPS/mTLS.
3. Server validates the device identity, persists events to PostgreSQL, and updates dashboards and alerts.
4. Agent removes or marks uploaded events after server acknowledgment.

## Suggested Build Order

1. **Cargo workspace and crate boundaries** — portable domain crates with `#![deny(unsafe_code)]`, Windows-specific integration crates, shared crypto/protocol types.
2. **Management server skeleton** — Axum/Tokio service, PostgreSQL schema, Docker Compose deployment, admin authentication.
3. **Enrollment and device identity** — token-based enrollment, device key generation, server-side device records.
4. **Signed configuration bundle format** — canonical JSON/serialization, Ed25519/ECDSA signing, version and offline-expiry fields, agent-side verification.
5. **Agent Windows service skeleton** — service lifecycle, periodic sync loop, health reporting, secure local config store.
6. **Encrypted backing store** — per-user ciphertext layout, AEAD encryption, DPAPI key wrapping, directory/file metadata.
7. **WinFsp virtual drive** — mount/unmount, read/write, directory enumeration, rename/delete, concurrent access, Explorer compatibility.
8. **Policy enforcement engine** — rule evaluation, action mapping, rejection of `require_justification`, allow/block/warn/audit paths.
9. **Companion process + toast notifications** — IPC from service, Windows toast APIs, user-facing block/warn messages.
10. **Audit queue and upload** — local encrypted append-only event store, server upload endpoint, idempotency/ack handling.
11. **Offline grace and lock logic** — timestamp tracking, day-five warning, day-seven drive lock, signed recovery path.
12. **Admin console polish and audit search** — policy authoring UI, device list with sync status, audit search by time/device/user/action/rule/severity.

## Sources

- Microsoft Purview Endpoint DLP overview and offline behavior — https://learn.microsoft.com/en-us/purview/endpoint-dlp-learn-about
- ManageEngine Endpoint DLP Plus LAN Architecture — https://www.manageengine.com/endpoint-dlp/help/architectures/endpoint-dlp-plus-lan-architecture.html
- ManageEngine Endpoint DLP Plus WAN Architecture — https://www.manageengine.com/endpoint-dlp/help/architectures/endpoint-dlp-plus-wan-architecture.html
- Symantec DLP secure agent-server communications — https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/26-1/managing-the-enforce-server/secure-comm-dlp-agents-and-endpoint-servers.html
- Proofpoint DLP/ITM architecture whitepaper — https://www.proofpoint.com/sites/default/files/white-papers/pfpt-uk-ms-solutions-architecture.pdf
- WinFsp vs Dokany comparison discussion — https://github.com/winfsp/winfsp/issues/19
- Cryptomator WinFsp usage guide and compatibility notes — https://community.cryptomator.org/t/winfsp-how-to-use-it/7980
- Microsoft Q&A: per-user encrypted drive architecture — https://learn.microsoft.com/en-us/answers/questions/5549164/is-there-a-way-to-create-a-new-encrypted-drive-or
- Strac: DLP endpoint agent capabilities — https://www.strac.io/blog/what-is-dlp-endpoint-agent
- Palo Alto Networks: How Does Endpoint DLP Work? — https://docs.paloaltonetworks.com/enterprise-dlp/administration/configure-enterprise-dlp/endpoint-dlp/how-does-endpoint-dlp-work
- Nightfall: Top Endpoint DLP Solutions 2025 — https://www.nightfall.ai/blog/the-top-10-endpoint-dlp-solutions-of-2025-and-30-faqs-every-security-team-should-know
