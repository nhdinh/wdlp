# Windows Data Leakage Prevention (DLP) Solution

## What This Is

A centrally managed Data Leakage Prevention solution for Windows, written primarily in Rust. A central management server configures lightweight endpoint agents installed as Windows services; each enrolled user gets a per-user, user-space virtual drive backed by encrypted local storage. The agent enforces centrally defined rules whenever protected data is accessed, written, copied, exported, or synchronized, and it continues enforcing the last valid policy while offline.

## Core Value

An authorized Windows user can mount a private protected drive, store files in it, and read them back through the drive, while the backing store does not contain directly readable plaintext.

## Business Context

- **Customer**: A single organization that needs to reduce accidental and intentional data leakage on Windows endpoints without kernel-mode development or signed drivers.
- **Deployment model**: Self-hosted Docker Compose stack on one Linux host per organization.
- **Scale target**: 1,000 enrolled endpoints, 500 concurrently online, up to 5 administrators or auditors.
- **Success metric**: A complete vertical slice — enroll → signed config → mount → copy → encrypted storage — works reliably within the first few phases.

## Requirements

### Validated

(None yet — ship to validate)

### Active

- [ ] Build a Rust Cargo workspace separating portable domain logic from Windows-specific integration.
- [ ] Implement the central management server with administrator authentication, device enrollment, and signed configuration bundles.
- [ ] Implement a Windows service agent that enrolls, downloads and verifies signed bundles, and reports health.
- [ ] Use WinFsp with safe Rust bindings for the per-user protected drive; validate Office files, concurrent access, renames, large files, Explorer, and crash recovery.
- [ ] Provide one isolated encrypted backing store per Windows user, tied to Windows identity and protected keys.
- [ ] Enforce policy at the drive boundary using metadata and bounded content detectors.
- [ ] Support allow, block, allow-and-audit, and warn actions; reserve `require_justification` and reject policies that activate it.
- [ ] Queue enforcement events locally and upload them when the server is reachable.
- [ ] Continue enforcing the last valid signed policy for up to seven days offline, then lock the protected drive.
- [ ] Add a small per-user companion process that shows toast notifications for blocked operations.
- [ ] Record administrative audit events and support searching by time, device, user, action, rule, and severity.
- [ ] Deliver automated tests for policy, crypto, storage, protocol, and critical Windows paths.

### Out of Scope

- Kernel-mode file-system filtering or signed drivers — excluded because driver signing certificates are not affordable for this project, and user-mode WinFsp is sufficient for the MVP boundary.
- Multi-tenancy in a single server deployment — one organization per server; multi-tenant hosting can be added later without architecture changes.
- Content inspection of arbitrary encrypted archives, OCR for images, or network traffic inspection — deferred to reduce MVP complexity and avoid unbounded parsing risk.
- Full endpoint detection and response functionality — out of product scope; the focus is policy enforcement at the protected drive boundary.
- DRM-style protection after authorized plaintext export — the product cannot control data once it leaves the drive through an allowed export.
- Operating systems other than Windows — the MVP targets Windows endpoints only.

## Context

The project originates from a detailed product brief that emphasized:
- Safe, maintainable Rust for security-sensitive components.
- A user-space virtual drive as the enforcement boundary.
- Atomic policy activation and last-known-good rollback.
- Tamper-evident audit logs and bounded scanners on untrusted content.

The user clarified five authoritative decisions:
1. **Virtual drive framework**: WinFsp with safe Rust bindings; Dokany is a fallback if compatibility issues appear.
2. **User interaction**: Small per-user companion process with Windows toast notifications; no tray UI required for MVP.
3. **Scale**: 1,000 endpoints, 500 concurrent, 5 admins, one organization per server.
4. **Server deployment**: Docker Compose on a single Linux host; horizontal scaling kept possible but not required.
5. **Offline tolerance**: Seven days of enforcement after losing server contact; warn on day five; lock the drive after seven days; restore via new policy or signed recovery authorization.

The first vertical slice is: **enroll → receive signed config → mount drive → copy file → encrypted backing store → readable through drive → survive restart**. Policy blocking and toast notifications follow immediately.

## Constraints

- **Tech stack**: Rust for endpoint agent and core domain; PostgreSQL for server persistence; Docker Compose for server deployment; WinFsp for the user-mode filesystem.
- **Security**: No long-lived plaintext secrets on endpoints; authenticated encryption at rest; signed policy bundles; TLS with mutual authentication for enrolled agents where practical.
- **Platform**: Windows 10/11 endpoints; Linux server.
- **Budget**: No paid code-signing certificate for a kernel driver; user-mode only.
- **Safety**: Prefer safe Rust; isolate and document unavoidable `unsafe` Windows FFI; deny unsafe code in portable domain crates.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| WinFsp for virtual drive | Mature, open-source, NTFS-like semantics, safe Rust bindings, runs in a Windows service. Dokany remains fallback. | — Pending (validate with early spike) |
| User-space enforcement boundary only | Cannot afford signed kernel driver; WinFsp keeps enforcement at the drive boundary. | — Pending |
| Docker Compose on single Linux host | Matches one-org deployment; horizontal scale possible later. | — Pending |
| 7-day offline allowance then lock | Balances availability and security; readable export is still leakage. | — Pending |
| Companion process for toast notifications | Minimal user interaction for MVP; service stays authoritative. | — Pending |
| `require_justification` deferred post-MVP | Complete workflow not implemented; server must reject activating policies with this action. | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-08-07 after project initialization*
