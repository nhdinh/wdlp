# Walking Skeleton — Windows Data Leakage Prevention

**Phase:** 1
**Generated:** 2026-08-07

## Capability Proven End-to-End

> A domain-authenticated Windows user can use an automatically mounted protected drive to write and read a committed file while the server authorizes the endpoint, the agent activates only a valid signed configuration, and the backing store contains authenticated ciphertext across restarts.

## Phase Goal

**As a** domain-authenticated Windows user, **I want to** enroll my endpoint and use a mounted protected drive, **so that** I can store and recover files while the backing store remains authenticated and encrypted across restarts.

## Architectural Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Language and workspace | Rust 1.97 Cargo workspace with the ten crates required by WRK-01 | Keeps portable domain, protocol, crypto, storage, and agent logic separate from Windows service and WinFsp integration. |
| Server framework | Axum 0.8 on Tokio with REST/JSON under `/api/v1` | Implements ADR-002 and keeps agent/admin contracts versioned and testable. |
| Data layer | PostgreSQL 18.4 with SQLx 0.9 forward-only migrations | Implements ADR-003 and supplies a real read/write persistence path in the skeleton. |
| Device trust | Short-lived single-use bootstrap token, exact pre-provisioned fingerprint, agreement from two explicitly configured AD domain controllers, then device mTLS | Implements D-02 through D-06 without treating client-reported hardware as remote attestation. |
| Certificate lifecycle | Development private CA loaded from mounted secrets; device certificate identity mapped to the enrolled device and checked against the revocation record on every agent request | Makes issuance and revocation explicit while keeping the CA replaceable behind a `DeviceCertificateIssuer` trait. |
| Configuration trust | Deterministic versioned bytes signed with Ed25519 and verified strictly before atomic current/LKG activation | Implements ADR-005, CRY-02, AGT-04, AGT-05, and AGT-06. |
| Encrypted storage | Proposed AES-256-GCM, 4 MiB chunks, random persisted 96-bit nonce per record, identity-bound AAD, staged generations, authenticated commit record; decision-gated by 01-03 Task 2 and implemented only afterward in 01-04 | Satisfies D-12 through D-15 while ensuring no governed persisted byte exists before the one-way format approval. |
| Endpoint secret protection | Machine-scope DPAPI with noninteractive operation plus service-SID-only directory and file ACLs | Implements D-05, D-06, CRY-04, and AGT-02. |
| Virtual drive | WinFsp 2.1 through the `winfsp` Rust crate, isolated behind `ProtectedFileSystem` and `MountHost` traits | Implements ADR-001 while preserving a replaceable filesystem transport. |
| Session lifecycle | One mount actor per eligible session and captured SID; preferred-letter scan, 30-second sign-out drain, exponential retry capped at five minutes | Implements D-07 through D-10 and the planner-discretion choices recorded by research. |
| Deployment target | Docker Compose on one Linux host for PostgreSQL and the server; real Windows 10/11 validation station for the service and drive | Matches the project deployment boundary and does not substitute Linux tests for WinFsp behavior. |
| Directory layout | `crates/`, `migrations/`, `deploy/`, `config/`, `tests/e2e/`, and `tests/windows/` | Establishes stable ownership for later slices and keeps environment-specific validation separate. |

## Stack Touched in Phase 1

- [ ] Project scaffold — Cargo workspace, formatting, linting, portable unsafe-code denial, and test runner.
- [ ] Routing — authenticated admin and agent routes under `/api/v1`, plus liveness/readiness.
- [ ] Database — migration-backed allowlist, token, device, credential, bundle, and health persistence with real reads and writes.
- [ ] User interaction — normal Windows filesystem operations through a mounted WinFsp drive.
- [ ] Deployment — Docker Compose server/PostgreSQL run command and a documented Windows validation command.

## Revised Walking-Skeleton Execution Spine

1. `01-01` and `01-02` establish portable/executable contracts without persisted encrypted data.
2. `01-03` blocks on exact package legitimacy and persisted-format approval.
3. `01-04` implements the approved encrypted store; `01-05` then proves the real PostgreSQL → HTTP → signed activation → encrypted write/read tracer.
4. `01-06` through `01-11` replace external fixtures and add authenticated server, Windows agent, recovery, WinFsp, and session lifecycle.
5. `01-12` proves the full production-provider Windows/Office/restart matrix.

## Out of Scope (Deferred to Later Slices)

- Phase 2 owns policy enforcement actions at the drive boundary and companion toast notifications; Phase 1 only establishes deterministic shared policy contracts and tests required by TST-01.
- Phase 3 owns offline expiry/drive locking, event queue upload, fleet lifecycle controls, audit search/export, and server-escrowed recovery workflows.
- Phase 4 owns signed MSI packaging, broadened compatibility/load/fuzz validation, and production operations runbooks.
- Kernel-mode interception, OS-wide monitoring, DRM after authorized export, non-Windows endpoints, and multi-tenancy remain outside the milestone boundary.

## Subsequent Slice Plan

- Phase 2: Add deterministic metadata/content policy enforcement and authenticated user feedback on top of the protected drive.
- Phase 3: Add offline resilience, ordered audit synchronization, and fleet administration.
- Phase 4: Harden storage, packaging, compatibility, security, scale, and operations for the MVP release.
