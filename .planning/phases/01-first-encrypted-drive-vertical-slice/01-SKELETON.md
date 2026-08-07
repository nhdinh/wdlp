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
| Device trust | A designated domain-admin Windows provisioning station runs `dlpctl provision-device --computer <FQDN>`, requires matching identity from both configured DCs, captures SMBIOS UUID + BIOS serial + physical OS-disk serial through Kerberos WinRM-over-HTTPS remote CIM, and stores only the version-1 digest plus an expiry-bound one-time token; the first-run agent repeats the tuple and dual-DC checks before device mTLS | Implements D-02 through D-06 while explicitly treating exact-match detection as administrator provisioning, not TPM-backed remote attestation. |
| Certificate lifecycle | Offline ECDSA P-256 `DLP Phase 1 Root CA` whose public certificate is embedded/installed with the agent; online ECDSA P-256 device issuing CA mounted outside the server image; server certificate chained to the same root with the management DNS SAN; endpoint-generated ECDSA P-256 CSR/private key; 30-day `CA:FALSE`/digitalSignature/clientAuth device leaf with device URI SAN; per-request SAN+serial active-status lookup and transactional old-serial revocation on replacement | Resolves D-05/D-06 without exposing the root private key or endpoint private key to the server, while keeping issuance behind the CSR-based `DeviceCertificateIssuer` trait. |
| Configuration trust | Deterministic versioned bytes signed with Ed25519 and verified strictly before atomic current/LKG activation | Implements ADR-005, CRY-02, AGT-04, AGT-05, and AGT-06. |
| Encrypted storage | Proposed AES-256-GCM, 4 MiB chunks, random persisted 96-bit nonce per record, identity-bound AAD, staged generations, authenticated commit record; decision-gated by 01-03 Task 2 and implemented only afterward in 01-04 | Satisfies D-12 through D-15 while ensuring no governed persisted byte exists before the one-way format approval. |
| Endpoint secret protection | Machine-scope DPAPI with noninteractive operation plus service-SID-only directory and file ACLs | Implements D-05, D-06, CRY-04, and AGT-02. |
| Virtual drive | WinFsp 2.1 through the `winfsp` Rust crate, isolated behind `ProtectedFileSystem` and `MountHost` traits | Implements ADR-001 while preserving a replaceable filesystem transport. |
| Session lifecycle | LocalSystem is lifecycle controller only: one actor per eligible WTS session/captured SID uses `WTSQueryUserToken` + `CreateProcessAsUser` to launch a non-UI `dlp-drive-host` in the user's logon session; that host owns WinFsp/letter selection and accesses service-owned storage through a SID/session/PID/generation-authenticated named pipe; 30-second sign-out drain and retry capped at five minutes | Implements D-07 through D-10 while proving the mapping is user-visible, absent from LocalSystem, and isolated across simultaneous sessions. |
| Deployment target | Docker Compose on one Linux host for PostgreSQL and the server; real Windows 10/11 validation station for the service and drive | Matches the project deployment boundary and does not substitute Linux tests for WinFsp behavior. |
| Directory layout | `crates/`, `migrations/`, `deploy/`, `config/`, `tests/e2e/`, and `tests/windows/` | Establishes stable ownership for later slices and keeps environment-specific validation separate. |

## Stack Touched in Phase 1

- [ ] Project scaffold — Cargo workspace, formatting, linting, portable unsafe-code denial, and test runner.
- [ ] Routing — authenticated admin and agent routes under `/api/v1`, plus liveness/readiness.
- [ ] Database — migration-backed allowlist, token, device, credential, bundle, and health persistence with real reads and writes.
- [ ] User interaction — normal Windows filesystem operations through a mounted WinFsp drive.
- [ ] Deployment — Docker Compose server/PostgreSQL run command and a documented Windows validation command.

## Revised Walking-Skeleton Execution Spine

1. Wave 1 runs blocking `01-03` package-legitimacy and persisted-format approval before any Cargo manifest or lockfile is created.
2. Wave 2 runs `01-01` to establish the portable workspace and contracts using only the approved dependency set.
3. Wave 3 runs `01-02` and `01-04` in parallel to complete executable boundaries/migration-before-bind behavior and implement the approved encrypted store.
4. Wave 4 runs `01-05` and `01-09` in parallel to prove the PostgreSQL → HTTP → signed activation → encrypted write/read tracer and storage recovery/integrity behavior.
5. Waves 5 through 8 run `01-06`, then `01-07` with `01-10`, then `01-08`, then `01-11` to add production authority, authenticated APIs, WinFsp, endpoint custody, and the LocalSystem-to-user-session host lifecycle.
6. Wave 9 runs `01-12` to prove the full production-provider Windows/Office/restart matrix.

## Out of Scope (Deferred to Later Slices)

- Phase 2 owns policy enforcement actions at the drive boundary and companion toast notifications; Phase 1 only establishes deterministic shared policy contracts and tests required by TST-01.
- Phase 3 owns offline expiry/drive locking, event queue upload, fleet lifecycle controls, audit search/export, and server-escrowed recovery workflows.
- Phase 4 owns signed MSI packaging, broadened compatibility/load/fuzz validation, and production operations runbooks.
- Kernel-mode interception, OS-wide monitoring, DRM after authorized export, non-Windows endpoints, and multi-tenancy remain outside the milestone boundary.

## Subsequent Slice Plan

- Phase 2: Add deterministic metadata/content policy enforcement and authenticated user feedback on top of the protected drive.
- Phase 3: Add offline resilience, ordered audit synchronization, and fleet administration.
- Phase 4: Harden storage, packaging, compatibility, security, scale, and operations for the MVP release.
