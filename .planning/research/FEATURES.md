# Research: Features — Windows DLP Solution

## Domain

A centrally managed Windows endpoint Data Loss Prevention solution that exposes protected data through a per-user, user-space virtual drive backed by encrypted local storage, enforcing policy at the drive boundary without kernel-mode drivers.

## Table Stakes

Features users and evaluators expect from any endpoint DLP product. Missing these makes the product feel incomplete or unsafe.

- **Central policy management** — Administrators create, version, and deploy policies from a web console; policies define what data is protected, which users/devices are in scope, and what actions to take. — Complexity: Medium — Depends on: Admin authentication, device enrollment
- **Device enrollment and identity binding** — Windows endpoints are onboarded to a specific organization and tied to a Windows user/device identity so policy and keys can be delivered securely. — Complexity: Medium — Depends on: Admin authentication, certificate/secret provisioning
- **Windows endpoint agent as a service** — A persistent, tamper-resistant agent runs on the endpoint to receive policy, enforce rules, and report health. — Complexity: Medium — Depends on: Device enrollment, signed configuration
- **Virtual protected drive accessible in Explorer** — Users see a regular drive letter or mount point in Windows Explorer and can work with files through standard applications. — Complexity: High — Depends on: WinFsp integration, per-user encrypted backing store
- **Transparent encryption at rest** — Files stored in the backing store are encrypted and unreadable outside the product; authorized users read plaintext through the drive. — Complexity: High — Depends on: Per-user backing store, key protection
- **Per-user isolated backing store** — Each Windows user has a separate encrypted storage container tied to their identity so data does not leak across accounts on shared machines. — Complexity: Medium — Depends on: Encryption at rest, Windows identity binding
- **Content-aware policy rules** — Rules match files by metadata (path, extension, size) and bounded content detectors (regex, keywords, fingerprints) so enforcement is not limited to file names. — Complexity: Medium — Depends on: Virtual drive enforcement boundary, policy engine
- **Policy actions: allow, block, allow-and-audit, warn** — Graduated enforcement lets administrators tune severity without rewrites; blocked operations surface a clear user-facing message. — Complexity: Low — Depends on: Policy engine, virtual drive hooks, toast notifications
- **Offline policy enforcement with last-known-good** — Cached signed policies continue to protect data when the endpoint is disconnected from the server, preserving availability and safety. — Complexity: Medium — Depends on: Signed configuration bundles, local policy cache
- **User notifications for blocked actions** — A lightweight per-user companion process shows Windows toast notifications explaining why an operation was blocked or warned. — Complexity: Low — Depends on: Policy enforcement events, Windows service-to-user IPC
- **Audit logging of file activities** — Reads, writes, copies, renames, deletes, and policy decisions are recorded with timestamp, user, device, file, rule, and action for compliance review. — Complexity: Medium — Depends on: Policy engine, virtual drive hooks, event queue
- **Server-side audit search and filtering** — Administrators can search enforcement events by time, device, user, action, rule, and severity. — Complexity: Medium — Depends on: Audit logging, server persistence
- **Agent health and status reporting** — The agent periodically reports version, policy sync state, connection status, and errors so administrators know endpoints are protected. — Complexity: Low — Depends on: Agent service, server API

## Differentiators

Features that are not universally expected but create competitive advantage for this specific architecture and constraints.

- **User-space virtual drive enforcement boundary** — No kernel driver or code-signing certificate is required because WinFsp hosts the protected drive in user space; this lowers deployment cost and avoids kernel stability risk. — Complexity: High — Depends on: WinFsp integration, virtual drive implementation
- **Signed configuration bundles with rollback** — Policies and settings are delivered as signed, versioned bundles; the agent verifies signatures and can fall back to the last valid bundle if a new one is corrupt or rejected. — Complexity: Medium — Depends on: Central policy management, agent crypto
- **Bounded content detectors** — File parsers and detectors operate with strict size limits, recursion caps, and timeout budgets to prevent unbounded parsing of malicious or malformed content. — Complexity: Medium — Depends on: Content-aware policy rules
- **Safety-first Rust implementation** — Core domain logic is written in safe Rust with unsafe code isolated to Windows FFI; this reduces memory-safety vulnerabilities in a security-critical product. — Complexity: Medium — Depends on: Cargo workspace structure
- **Seven-day offline allowance with graded warnings** — The product warns on day five and locks the drive after seven days offline, balancing business continuity with security. — Complexity: Medium — Depends on: Offline policy enforcement, local policy cache
- **Single-tenant Docker Compose server deployment** — One organization per self-hosted Linux server keeps the MVP simple and predictable while leaving horizontal scaling as a future option. — Complexity: Low — Depends on: Central management server
- **Per-user companion process for toast notifications** — A minimal user-mode notifier keeps the service authoritative while still giving users immediate, actionable feedback. — Complexity: Low — Depends on: User notifications, Windows service-to-user IPC

## Anti-Features (deliberately avoid in MVP)

Features that are technically possible but explicitly deferred or excluded because they add disproportionate complexity or conflict with the chosen architecture.

- **Kernel-mode file-system filtering or signed drivers** — Avoided because affordable kernel driver code-signing is out of budget and WinFsp provides a sufficient user-mode boundary. Enforcement happens only at the protected drive, not across the whole OS.
- **Multi-tenancy in a single server deployment** — One organization per server is sufficient for the target customer; multi-tenant hosting can be added later without architecture changes.
- **OCR for images and screenshots** — Text extraction from images requires heavy dependencies, high CPU use, and large model/data management; deferred to reduce MVP complexity and unbounded parsing risk.
- **Inspection of arbitrary encrypted or password-protected archives** — Detecting content inside encrypted archives without keys is generally impossible; attempting to crack or prompt for passwords is out of scope and creates abuse risk.
- **Network traffic inspection / network DLP** — Monitoring all outbound network traffic requires proxies, certificates, or kernel components; the MVP enforces only at the protected drive boundary.
- **Full endpoint detection and response (EDR)** — Threat hunting, behavioral analytics, and incident response are separate product categories; the focus is policy enforcement on protected data.
- **DRM-style protection after authorized export** — Once a user is allowed to copy plaintext out of the drive, the product cannot control what happens next; attempts to do so would require pervasive OS hooks or external rights management.
- **Cross-platform endpoint support** — macOS and Linux agents are not built for the MVP; the product targets Windows 10/11 endpoints only.
- **Machine-learning / AI classifiers** — Trainable classifiers add data-science overhead, labeling effort, and false-positive tuning; the MVP uses deterministic metadata and bounded detectors only.
- **`require_justification` action** — The complete user-justification workflow is deferred post-MVP; the server rejects activating policies that use this action.
- **Native clipboard, print, USB, or screen-capture channel controls** — Because the enforcement boundary is the virtual drive rather than the whole OS, the MVP cannot intercept system-wide copy/paste, print jobs, USB copies, or screenshots of decrypted content. User education and policy rules at the drive boundary substitute for channel-level blocking.

## Sources

- Microsoft Purview Endpoint DLP documentation: https://learn.microsoft.com/en-us/purview/endpoint-dlp-learn-about
- Microsoft Purview DLP policy reference: https://learn.microsoft.com/en-us/purview/dlp-policy-reference
- Forcepoint DLP endpoint actions overview: https://help.forcepoint.com/dlp/10.4.0/deployctr/047FFC45-21D7-4885-85BB-D69F2353E5BE.html
- ManageEngine Endpoint DLP Plus architecture: https://www.manageengine.com/endpoint-dlp/help/architectures/endpoint-dlp-plus-wan-architecture.html
- Strac endpoint DLP guide: https://www.strac.io/blog/endpoint-data-loss-prevention
- Forcepoint DLP best practices (audit-before-block rollout): https://www.forcepoint.com/blog/insights/data-loss-prevention-best-practices
- Cyberhaven DLP false-positive analysis: https://www.cyberhaven.com/blog/dlp-false-positives
- Microsoft Purview DLP alert investigation: https://learn.microsoft.com/en-us/purview/dlp-alert-investigation-learn
- Project context: C:/Users/nhdinh/dev/dleakprevention/.planning/PROJECT.md
