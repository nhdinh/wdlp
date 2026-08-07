# Phase 1: First Encrypted-Drive Vertical Slice - Pattern Map

**Mapped:** 2026-08-07  
**Files analyzed:** 29 expected workspace, implementation, deployment, and validation artifacts  
**Analogs found:** 0 / 29 source-code analogs

## Repository Finding

This repository intentionally contains planning artifacts only: `rg --files` found no Rust workspace, source, test, deployment, or migration files. Consequently, there is **no existing implementation code to copy** and no established code-level import, error, validation, logging, or test convention.

The planner must create the workspace deliberately from the Phase 1 contracts below. The architectural contracts are not code analogs; they are the authoritative sources for responsibilities and invariants.

## File Classification

The research specifies crate/directory boundaries, but not every internal Rust filename. The entries marked **scaffold** are the minimal conventional files required to establish those named crates; planners may split internal modules only where the stated responsibility needs it.

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `Cargo.toml` | config | transform | Workspace contract in `01-RESEARCH.md:196-212` | architectural-contract |
| `crates/dlp-domain/{Cargo.toml,src/lib.rs}` | model | transform | `REQUIREMENTS.md:10-13` | architectural-contract |
| `crates/dlp-protocol/{Cargo.toml,src/lib.rs}` | model | request-response | `ADR-002-api-transport.md:31-36` | architectural-contract |
| `crates/dlp-crypto/{Cargo.toml,src/lib.rs}` | service | transform | `ADR-005-policy-signing.md:24-35` | architectural-contract |
| `crates/dlp-storage/{Cargo.toml,src/lib.rs}` | service | file-I/O | `01-RESEARCH.md:229-233` | architectural-contract |
| `crates/dlp-server/{Cargo.toml,src/main.rs}` | controller | request-response | `ADR-002-api-transport.md:24-36` | architectural-contract |
| `crates/dlp-server/src/{routes,enrollment,repository,health}.rs` | route/service | request-response / CRUD | `01-RESEARCH.md:96-106` | architectural-contract |
| `crates/dlp-agent-core/{Cargo.toml,src/lib.rs}` | service | request-response / event-driven | `01-RESEARCH.md:214-227` | architectural-contract |
| `crates/dlp-windows-service/{Cargo.toml,src/main.rs}` | controller | event-driven | `01-RESEARCH.md:235-239` | architectural-contract |
| `crates/dlp-windows-service/src/{credential,session,mount_manager}.rs` | service | event-driven / file-I/O | `01-RESEARCH.md:235-239` | architectural-contract |
| `crates/dlp-windows-drive/{Cargo.toml,src/lib.rs,build.rs}` | component | file-I/O / event-driven | `ADR-001-winfsp-framework.md:22-35` | architectural-contract |
| `crates/dlp-windows-drive/src/filesystem.rs` | component | file-I/O | `01-RESEARCH.md:241-243` | architectural-contract |
| `crates/dlpctl/{Cargo.toml,src/main.rs}` | controller | request-response | `01-RESEARCH.md:196-212` | architectural-contract |
| `migrations/<forward-only enrollment schema>.sql` | migration | CRUD | `ADR-003-database-migrations.md:28-35` | architectural-contract |
| `deploy/compose.yaml` | config | request-response | `PROJECT.md:21-23` | architectural-contract |
| `tests/windows/<WinFsp validation scripts and capture>` | test | file-I/O / event-driven | `ADR-001-winfsp-framework.md:37-45` | architectural-contract |
| crate-local unit and integration tests | test | transform / request-response / file-I/O | `REQUIREMENTS.md:90-99` | architectural-contract |

`dlp-policy` is a required workspace crate under WRK-01, but its substantive policy behavior is Phase 2. Phase 1 should contain only the minimal pass-through/shared policy types required by WRK-02 and TST-01, as constrained by `01-RESEARCH.md:50-83`.

## Pattern Assignments

### `Cargo.toml` and all crate manifests (config, transform)

**Code analog:** None.

**Contract to follow:** `01-RESEARCH.md:196-212` establishes a Cargo workspace with portable crates (`dlp-domain`, `dlp-protocol`, `dlp-crypto`, `dlp-storage`, `dlp-agent-core`) separated from Windows integration (`dlp-windows-service`, `dlp-windows-drive`) and server/CLI crates.

**Required boundary:** Portable crates deny unsafe code; Windows FFI is isolated and documented (`REQUIREMENTS.md:10-13`, `PROJECT.md:73-79`). Do not place Win32/WinFsp calls in portable crates.

### `crates/dlp-domain/src/lib.rs` and `crates/dlp-protocol/src/lib.rs` (model, transform/request-response)

**Code analog:** None.

**Contract to follow:** `REQUIREMENTS.md:10-13` assigns shared identifiers, policy types, enforcement decisions, structured errors, and versioned DTOs to these crates. `ADR-002-api-transport.md:31-36` fixes REST/JSON versioning:

```text
API version in URL path: /api/v1/...
Bundle schema version embedded in signed payloads.
Agents reject unsupported schema versions after signature verification.
```

**Planner direction:** Define DTOs and persisted-format types as versioned data, and keep domain errors structured/redacted. No server route or Windows type may become part of these portable contracts.

### `crates/dlp-crypto/src/lib.rs` and `crates/dlp-storage/src/lib.rs` (service, transform/file-I/O)

**Code analog:** None.

**Contracts to follow:**

- `ADR-005-policy-signing.md:24-35`: sign bundle scope with Ed25519, include a key identifier, and verify before activation.
- `ADR-006-key-hierarchy.md:24-40`: each user store has its own DEK; sensitive metadata is encrypted and authenticated.
- `01-RESEARCH.md:229-233`: write a replacement under an unreferenced generation, flush chunks and encrypted manifest, then atomically publish one authenticated commit record. Recovery trusts only the last valid commit.

**Concrete verification gate** from `01-RESEARCH.md:308-314`:

```rust
key.verify_strict(bytes, signature).is_ok()
```

**Failure behavior:** authentication must succeed before plaintext is decoded or returned; preserve the prior fully committed generation on failure (`01-CONTEXT.md: D-12 through D-15`).

### `crates/dlp-server/src/{routes,enrollment,repository,health}.rs` and `migrations/*.sql` (route/service/migration, request-response/CRUD)

**Code analog:** None.

**Contracts to follow:**

- `ADR-002-api-transport.md:24-36`: REST-style JSON over HTTP/1.1 and HTTP/2, namespaced under `/api/v1`, with agent polling/heartbeat initially.
- `ADR-003-database-migrations.md:24-35`: PostgreSQL + SQLx, forward-only migrations under `migrations/`, applied before server startup; development seed data belongs in `config/`, not automatic production seeding.
- `01-CONTEXT.md: D-02 through D-06` plus resolved research: a designated domain-admin Windows station pre-provisions the version-1 fingerprint digest by querying both configured DCs and collecting the exact SMBIOS/BIOS/physical OS-disk tuple over Kerberos WinRM-over-HTTPS remote CIM. The server repeats dual-DC agreement and digest comparison during enrollment, signs only an endpoint-generated CSR through the online device issuing CA, and revokes replaced serials transactionally.

**Error/validation pattern:** Enrollment disagreement, missing/changed fingerprinted hardware, invalid computer account, and invalid device state fail closed. Responses/logs must not disclose credentials or protected values (`01-RESEARCH.md:245-251`, `REQUIREMENTS.md:217-227`).

### `crates/dlp-agent-core/src/lib.rs` and Windows-service credential/session modules (service/controller, request-response/event-driven/file-I/O)

**Code analog:** None.

**Contracts to follow:**

- `01-RESEARCH.md:214-227`: verify canonical signed bytes and schema before replacing the active configuration; retain current and last-known-good immutable caches; activate through an atomic current-pointer change only after verification.
- `01-CONTEXT.md: D-05 through D-06`: generate the ECDSA P-256 device key on the endpoint, send only its signed CSR, validate the constrained returned leaf/chain, and store private key/certificate/token-until-consumed/metadata in one machine-DPAPI-protected file with service-only ACL; a missing or undecryptable credential triggers a fresh key/CSR, complete re-enrollment, and server-side revocation of the prior serial.
- `01-RESEARCH.md:235-246`: model each mount as a LocalSystem lifecycle actor keyed by Windows session ID and captured user SID. Use `WTSQueryUserToken` plus `CreateProcessAsUser` to launch one non-UI `dlp-drive-host` in that user's logon session; the host owns WinFsp/drive-letter enumeration and accesses service-owned storage through a named pipe that validates connecting SID, session ID, PID, and actor generation. Reject new opens at sign-out, wait 30 seconds, then force cancellation/unmount; retry mounts with exponential backoff capped at five minutes.

**Error/diagnostic pattern:** Mount failure leaves no placeholder drive, retries automatically, and writes a clear structured diagnostic (`01-CONTEXT.md: D-09 through D-10`). Redact DPAPI/TLS/credential failure details.

### `crates/dlp-windows-drive/{build.rs,src/filesystem.rs}` (component, file-I/O/event-driven)

**Code analog:** None.

**Contracts to follow:**

- `ADR-001-winfsp-framework.md:22-35`: use safe WinFsp Rust bindings; keep callbacks behind a replaceable Rust abstraction so storage/policy remain portable; validate Office, Explorer, concurrent access, rename/delete, large files, and crash recovery.
- `01-RESEARCH.md:241-243`: implement the WinFsp filesystem context; create/start/mount in the host start closure, unmount/drop in stop, and use the delay-load build helper rather than manual DLL loading.
- `01-CONTEXT.md: D-11 through D-15`: map normal Windows open/share/cache/flush/close semantics to durable storage commits. Flush/close success is returned only after the generation is durable; disk-full returns the Windows error and leaves the prior version intact.

**Identity pattern:** Determine store selection from the SID captured at mount/session creation, never a caller-provided user identifier or path (`REQUIREMENTS.md:67-75`).

### `deploy/compose.yaml`, `dlpctl`, and validation artifacts (config/controller/test, request-response/file-I/O)

**Code analog:** None.

**Contracts to follow:** PostgreSQL/server deployment is Compose-based (`PROJECT.md:21-23`, `ADR-003-database-migrations.md:28-35`). The validation suite must exercise enrollment through signed activation, storage crypto/integrity/recovery, and a real Windows WinFsp matrix—not a Linux-only substitute (`REQUIREMENTS.md:92-99`, `01-CONTEXT.md: D-16 through D-19`).

## Shared Patterns

### Trust boundary and authentication

**Sources:** `01-CONTEXT.md: D-02 through D-06`; `ADR-002-api-transport.md:24-36`  
**Apply to:** server enrollment routes, agent enrollment/client, credential persistence.

- Enrollment is server-authoritative: trusted-station remote-CIM version-1 digest + corroborated computer account from both configured DCs, repeated again on endpoint enrollment.
- The Phase 1 public offline root is installed with the agent; its private key never reaches runtime. The agent keeps its generated device private key local, and the online issuing CA returns only a constrained 30-day certificate chain.
- After enrollment, agent APIs require device mTLS plus per-request SAN URI/serial lookup with `credential_status=active`; replacement enrollment revokes the prior serial in the same transaction that activates the new one.
- REST DTOs are versioned at `/api/v1`; bundle schema version is inside the signed payload.

### Signed configuration activation

**Sources:** `ADR-005-policy-signing.md:24-35`; `01-RESEARCH.md:214-227`  
**Apply to:** protocol, server bundle output, agent cache/state machine, tests.

- Sign deterministic canonical bytes, including schema and bundle versions plus agent settings.
- Verify strictly before any activation; unsupported schema, bad signature/hash, or partial download never replaces current/LKG configuration.
- Use staged immutable cache plus atomic pointer swap, rather than mutating active configuration in place.

### Encryption, durability, and integrity failure

**Sources:** `ADR-006-key-hierarchy.md:24-40`; `01-RESEARCH.md:229-233`; `01-CONTEXT.md: D-12 through D-15`  
**Apply to:** crypto, storage, filesystem callbacks, fault-injection tests.

- Encrypt content and sensitive metadata with authenticated encryption; authentication precedes plaintext decoding.
- Stage a whole generation, flush its records/manifest, then atomically publish one commit record.
- A failed authentication denies access with a stable integrity error, preserves encrypted evidence, emits redacted diagnostics, and never returns unauthenticated plaintext.

### Windows isolation and lifecycle

**Sources:** `ADR-001-winfsp-framework.md:22-45`; `01-RESEARCH.md:235-243`  
**Apply to:** Windows service, mount manager, WinFsp adapter, Windows-only validation.

- Isolate unavoidable Windows integration in the two Windows crates and document any unsafe boundary.
- LocalSystem launches one `dlp-drive-host` per eligible Windows session/user SID with the WTS primary token; the host owns the preferred/next-letter mapping in the user namespace, while the service owns authenticated storage/key IPC.
- At sign-out, reject new opens then boundedly drain/cancel existing handles before unmount.

### Database and migrations

**Source:** `ADR-003-database-migrations.md:24-35`  
**Apply to:** server repository and deployment.

- PostgreSQL with SQLx; migrations are version-controlled, forward-only, and run before server startup.
- Do not ship automatic production seed data.

## No Code Analog Found

All Phase 1 implementation artifacts have no code analog because the repository has no implementation. The listed ADRs/research are the only available patterns. The planner should not state that a new module "follows" a source file; it should cite the governing contract and create the first project convention intentionally.

## Metadata

**Analog search scope:** repository root excluding no directories; searched all files via `rg --files`  
**Files scanned:** 21 planning artifacts; 0 source-code artifacts  
**Pattern extraction date:** 2026-08-07
