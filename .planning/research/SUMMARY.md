# Project Research Summary

## Project

A centrally managed Windows Data Leakage Prevention solution written in Rust, where each enrolled user gets a per-user, user-space virtual drive (WinFsp) backed by encrypted local storage, enforced by centrally signed policies, and managed by a self-hosted Linux server deployed via Docker Compose.

## Key Findings

### Stack

- **Rust async runtime**: `tokio` `1.53.1` is the de-facto standard and the integration target for Axum, SQLx, tokio-rustls, and reqwest; use `rt-multi-thread`, `net`, `fs`, `time`, `macros`, and `sync` features.
- **Web framework**: `axum` `0.8.9` is the recommended Tokio-native framework for the management server REST API.
- **Database**: `sqlx` `0.9.0` + `sqlx-cli` `0.9.0` for compile-time checked SQL, PostgreSQL pooling, and plain-SQL migrations; prepare `sqlx-data.json` for CI builds without a live DB.
- **TLS / mTLS**: `rustls` `0.23.43` + `tokio-rustls` `0.26.4`; pin the `ring` crypto provider on Windows to avoid C-toolchain bindings.
- **Authenticated encryption**: `chacha20poly1305` `0.11.0` as the primary AEAD; `aes-gcm` `0.11.0` only if an AES/FIPS requirement exists.
- **Key derivation / password hashing**: `argon2` `0.5.3` for passwords, `hkdf` `0.13.0` for deterministic key derivation, `sha2` `0.11.0` as needed.
- **Secret handling**: `zeroize` `1.9.0` + `secrecy` `0.10.3` to clear and wrap keys.
- **Policy bundle signatures**: `ed25519-dalek` `3.0.0` for compact, pure-Rust Ed25519 signing.
- **Windows service lifecycle**: `windows-service` `0.8.1` for SCM integration and Tokio spawning.
- **Virtual drive**: `winfsp` `0.13.0+winfsp-2.1` bindings over the separately installed WinFsp 2.1 runtime.
- **Windows API**: `windows` `0.62.2`, feature-gated to keep compile times reasonable.
- **Toast notifications**: `notify-rust` `4.18.0` (medium confidence) for cross-platform notifications; fall back to the `windows` crate if needed.
- **Serialization**: `serde` `1.0.229` + `serde_json` `1.0` for REST API and signed policy bundles.
- **JWT**: `jsonwebtoken` `11.0.0` for short-lived admin/enrollment tokens only; do not use JWT for agent authentication.
- **HTTP client**: `reqwest` `0.13.4` with `rustls-tls` feature for agent-to-server mTLS.
- **Middleware**: `tower` `0.5.3` for shared auth, logging, rate-limit, and timeout layers.
- **Error handling**: `thiserror` `2.0.19` in library crates, `anyhow` `1.0.104` in binaries.
- **CLI / config**: `clap` `4.6.6`, `config` `0.15.25`, `dotenvy` `0.15.7`.
- **Identifiers / time**: `uuid` `1.24.0` (prefer v7), `chrono` `0.4.45` for PostgreSQL `TIMESTAMPTZ`.
- **Observability**: `tracing` `0.1.44` + `tracing-subscriber` `0.3.23`; optional `tracing-appender` for non-blocking agent logs.
- **Testing**: `tokio-test`, `wiremock`, `tempfile`, `insta`.
- **Deployment**: Docker Compose with `postgres:18.4` and `rust:1.97-bookworm` multi-stage build; target Rust `1.97`.

### Table Stakes

Features that must be present in v1 for the product to feel complete:

- Central policy management web console.
- Device enrollment and identity binding.
- Windows endpoint agent installed as a service.
- Per-user virtual protected drive visible in Explorer.
- Transparent authenticated encryption at rest.
- Per-user isolated encrypted backing store.
- Content-aware policy rules (metadata + bounded detectors).
- Policy actions: `allow`, `block`, `allow-and-audit`, `warn`; reject `require_justification`.
- Offline enforcement using the last valid signed policy.
- User toast notifications for blocked/warned actions.
- Audit logging of file activities.
- Server-side audit search and filtering.
- Agent health and status reporting.

### Architecture

- The design follows the standard three-layer endpoint DLP pattern: **management server**, **endpoint agent**, and a **secure agent-server channel** (TLS, mTLS where practical).
- Enforcement is deliberately **user-space only** via a WinFsp virtual drive; no kernel-mode filtering or signed driver is required.
- The **virtual drive is the policy boundary**: files inside are encrypted at rest and decrypted only through the drive; once data is allowed to leave the drive, control is lost.
- The **server is the root of trust**: it authors and signs configuration bundles; the agent verifies signatures, enforces offline expiry, and can roll back to the previous valid bundle.
- Agent-server communication is **pull-based** with periodic heartbeats/sync plus a thin persistent channel for real-time requests.
- The Windows service, per-user virtual drive instance, and per-user companion notification process should be **separate** to match Windows session architecture and least-privilege principles.
- Suggested build order:
  1. Cargo workspace and crate boundaries.
  2. Management server skeleton (Axum, PostgreSQL, Docker Compose, admin auth).
  3. Enrollment and device identity.
  4. Signed configuration bundle format and activation/rollback.
  5. Agent Windows service skeleton (lifecycle, sync, health).
  6. Encrypted backing store.
  7. WinFsp virtual drive (mount, read/write, directory, rename, delete, concurrency).
  8. Policy enforcement engine.
  9. Companion process + toast notifications.
  10. Audit queue and upload.
  11. Offline grace and lock logic.
  12. Admin console polish and audit search.

### Pitfalls

Top critical pitfalls to watch, with prevention and the phase that should address them:

1. **Treating WinFsp as a generic block device instead of an NTFS-like file system**
   - *Risk*: Explorer/Office/AV hang or fail because reparse points, streams, case handling, oplocks, or `DeviceIoControl` are wrong.
   - *Prevention*: Use `ntptfs-winfsp-rs` as a conformance target, implement realistic `GetVolumeInfo`, handle `Cleanup`/`Close` reference counts, and test real Office workflows before adding policy logic.
   - *Phase*: WinFsp drive spike / vertical-slice validation.

2. **IRP cancellation and shutdown deadlocks in WinFsp**
   - *Risk*: Holding a file-node lock while notifying the kernel can deadlock during termination, leaving the drive unmountable and Explorer hanging.
   - *Prevention*: Keep lock scopes small, never call `FspFileSystemNotify` while holding a file-node lock, implement explicit stop-dispatcher handling, and test unclean termination under load.
   - *Phase*: WinFsp drive robustness / crash recovery.

3. **Session and UAC isolation making the drive invisible**
   - *Risk*: A drive mounted from Session 0 or an elevated token is not visible in a normal user Explorer session.
   - *Prevention*: Mount the volume from a process in the target user's session with a linked token, or mount to a directory junction inside the user's profile; validate from a non-elevated interactive session.
   - *Phase*: Per-user agent / companion process.

4. **Blocking the async runtime or using the wrong mutex types in the Windows service**
   - *Risk*: Synchronous WinFsp I/O, encryption, or policy evaluation inside async tasks can deadlock the runtime or make the service ignore SCM stop requests.
   - *Prevention*: Move synchronous work to `tokio::task::spawn_blocking`, use `tokio::sync::Mutex` across await points, keep the SCM control handler non-blocking, and integrate `tokio::select!` with the stop event.
   - *Phase*: Agent service skeleton / SCM integration.

5. **Storing encryption keys alongside the encrypted backing store**
   - *Risk*: Keys in the same directory or registry path as ciphertext allow an attacker with disk access to decrypt everything.
   - *Prevention*: Bind store keys to the Windows user via DPAPI/TPM; keep an offline recovery key only on the server; never log plaintext key material; rotate keys on re-enrollment.
   - *Phase*: Encrypted backing store / crypto foundation.

Additional high-impact concerns to track:

- **Clock tampering in offline enforcement**: include signed `not-before`/`not-after` in bundles, use monotonic time locally, and consider a tamper-evident "last seen online" counter signed by the server.
- **Unclean policy activation**: validate bundle signature/schema before activation, stage-and-rename the new policy, and keep `policy.prev` as a fallback.
- **False positives in policy rules**: start in audit-only mode, require bounded context (regex + proximity + file type), and measure false-positive rates before enabling block actions.
- **Unbounded content parsing**: cap file sizes, set cancellable timeouts, whitelist safe extensions, and refuse encrypted archives as declared out of scope.
- **Session 0 cannot show toasts**: run a per-user companion process in the interactive session and send notifications over a named pipe.
- **Audit event loss**: append events to a hash-chained, encrypted local log with acknowledged sequence numbers, and protect the store with ACLs.

## Implications for Roadmap

The first vertical slice should prove the core value chain: **enroll → receive signed config → mount drive → copy file → encrypted backing store → read back through drive → survive restart**. This means the server skeleton, enrollment, signed bundles, agent service, encrypted backing store, and WinFsp drive must come before policy blocking and notifications.

Suggested phase grouping:

1. **Foundation & Server Skeleton** — Cargo workspace, Axum server, PostgreSQL schema, Docker Compose, admin authentication, health endpoints.
   - *Rationale*: Everything else depends on the server and the database.
   - *Avoids*: SQLx compile-time checks without a DB or offline data; production use of `postgres:latest`.

2. **Enrollment & Identity** — Token-based enrollment, device key generation, server-side device/user records, TLS/mTLS bootstrap.
   - *Rationale*: The agent cannot authenticate or receive policy without enrollment.
   - *Avoids*: Binding the store key to a local SID that changes after domain migration; storing enrollment secrets in plain files.

3. **Signed Configuration Bundles** — Canonical JSON bundle format, Ed25519 signing, version/expiry fields, agent-side verification, atomic activation, and rollback.
   - *Rationale*: Enforcement cannot safely act on unsigned rules; offline behavior depends on signed expiry.
   - *Avoids*: Clock-tampering extension of offline grace; half-applied policies after a failed update.

4. **Agent Service Skeleton** — Windows service lifecycle, periodic sync loop, health reporting, secure local config store, DPAPI key wrapping for per-user keys.
   - *Rationale*: The service orchestrates the endpoint and must integrate cleanly with SCM before adding drive logic.
   - *Avoids*: SCM timeout kills during slow startup; async-runtime deadlocks.

5. **Encrypted Backing Store + Virtual Drive Vertical Slice** — Per-user ciphertext layout, AEAD encryption, WinFsp mount/unmount, read/write, directory enumeration, rename/delete, Explorer compatibility, large-file streaming.
   - *Rationale*: This is the core product differentiator and the riskiest integration.
   - *Avoids*: NTFS semantic failures, IRP shutdown deadlocks, invisible drives due to session isolation, keys stored with ciphertext.

6. **Policy Enforcement Engine** — Rule evaluation, metadata and bounded content detectors, action mapping, rejection of `require_justification`, audit-only rollout mode.
   - *Rationale*: Once the drive works, protection logic can be layered on top.
   - *Avoids*: False positives that drive users to bypass the drive; unbounded parsing hangs.

7. **Companion Process & Toast Notifications** — Named-pipe IPC from service to a per-user interactive process, Windows toast APIs, block/warn messaging.
   - *Rationale*: Pure UX layer; enforcement must work without it.
   - *Avoids*: Trying to show notifications directly from Session 0.

8. **Audit Queue, Offline Grace & Operations** — Encrypted append-only local event store, hash chaining, server upload endpoint with idempotency, seven-day offline warning/lock, signed recovery authorization, AV/EDR exclusion guidance.
   - *Rationale*: Compliance and production readiness depend on reliable audit delivery and offline resilience.
   - *Avoids*: Audit loss on crash/uninstall; locked devices with no recovery path.

**Research flags**: Phases 5 and 6 (WinFsp drive and policy engine) likely need a `/gsd-plan-phase --research-phase` pass to validate real Office/Explorer behavior, concurrency, and detector budgets. Phase 2 (enrollment/identity) may need a spike on DPAPI/TPM key wrapping on the target Windows builds. Phases 1, 3, 4, 7, and 8 follow well-documented patterns and can skip dedicated research unless new constraints emerge.

## Confidence

| Area | Level | Notes |
|------|-------|-------|
| Stack | High | Recommendations are mature, actively maintained crates with verified versions; the Tokio/Axum/SQLx/rustls combination is the mainstream Rust server stack. |
| Features | High | Table stakes are derived from Microsoft Purview, Forcepoint, ManageEngine, and Strac documentation and align with PROJECT.md constraints. |
| Architecture | Medium-High | The three-layer DLP pattern is well documented, but the exact WinFsp NTFS conformance boundary and per-user session mechanics need validation through spikes. |
| Pitfalls | Medium | Issues are drawn from WinFsp GitHub discussions, DLP practitioner guides, and crypto/storage best practices; severity and prevalence are plausible but need empirical validation on target Windows builds. |

**Overall confidence**: Medium-High.

**Key gaps to address during planning**:

- Exact WinFsp NTFS conformance test suite and Office/Explorer validation scenarios.
- Real-world AV/EDR compatibility and exclusion recommendations.
- DPAPI vs TPM key-wrapping decision for per-user store keys on Windows 10/11.
- Performance budget for content detectors (regex, keyword, fingerprint) on large and malformed files.
- mTLS certificate issuance, renewal, and revocation lifecycle for enrolled agents.

## Sources

### Stack sources

- Tokio: https://crates.io/crates/tokio / https://docs.rs/tokio/1.53.1/tokio/
- Axum: https://crates.io/crates/axum / https://docs.rs/axum/0.8.9/axum/
- SQLx: https://crates.io/crates/sqlx / https://docs.rs/sqlx/0.9.0/sqlx/
- sqlx-cli: https://crates.io/crates/sqlx-cli
- rustls: https://crates.io/crates/rustls / https://docs.rs/rustls/0.23.43/rustls/
- tokio-rustls: https://crates.io/crates/tokio-rustls / https://docs.rs/tokio-rustls/0.26.4/tokio_rustls/
- chacha20poly1305: https://crates.io/crates/chacha20poly1305
- aes-gcm: https://crates.io/crates/aes-gcm
- argon2: https://crates.io/crates/argon2
- hkdf: https://crates.io/crates/hkdf
- sha2: https://crates.io/crates/sha2
- ed25519-dalek: https://crates.io/crates/ed25519-dalek
- zeroize: https://crates.io/crates/zeroize
- secrecy: https://crates.io/crates/secrecy
- windows-service: https://crates.io/crates/windows-service / https://docs.rs/windows-service/0.8.1/windows_service/
- winfsp: https://crates.io/crates/winfsp / https://docs.rs/winfsp/0.13.0+winfsp-2.1/winfsp/
- WinFsp installer: https://winfsp.dev/rel/
- windows crate: https://crates.io/crates/windows
- notify-rust: https://crates.io/crates/notify-rust
- serde: https://crates.io/crates/serde
- jsonwebtoken: https://crates.io/crates/jsonwebtoken
- reqwest: https://crates.io/crates/reqwest
- tower: https://crates.io/crates/tower
- thiserror: https://crates.io/crates/thiserror
- anyhow: https://crates.io/crates/anyhow
- clap: https://crates.io/crates/clap
- config: https://crates.io/crates/config
- dotenvy: https://crates.io/crates/dotenvy
- uuid: https://crates.io/crates/uuid
- chrono: https://crates.io/crates/chrono
- tracing: https://crates.io/crates/tracing / https://docs.rs/tracing/0.1.44/tracing/
- tracing-subscriber: https://crates.io/crates/tracing-subscriber
- PostgreSQL Docker image: https://hub.docker.com/_/postgres

### Feature & architecture sources

- Microsoft Purview Endpoint DLP: https://learn.microsoft.com/en-us/purview/endpoint-dlp-learn-about
- Microsoft Purview DLP policy reference: https://learn.microsoft.com/en-us/purview/dlp-policy-reference
- Forcepoint DLP endpoint actions: https://help.forcepoint.com/dlp/10.4.0/deployctr/047FFC45-21D7-4885-85BB-D69F2353E5BE.html
- ManageEngine Endpoint DLP Plus architecture: https://www.manageengine.com/endpoint-dlp/help/architectures/endpoint-dlp-plus-wan-architecture.html
- ManageEngine LAN Architecture: https://www.manageengine.com/endpoint-dlp/help/architectures/endpoint-dlp-plus-lan-architecture.html
- Strac endpoint DLP guide: https://www.strac.io/blog/endpoint-data-loss-prevention
- Forcepoint DLP best practices: https://www.forcepoint.com/blog/insights/data-loss-prevention-best-practices
- Cyberhaven DLP false positives: https://www.cyberhaven.com/blog/dlp-false-positives
- Microsoft DLP alert investigation: https://learn.microsoft.com/en-us/purview/dlp-alert-investigation-learn
- Symantec DLP secure agent-server communications: https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/26-1/managing-the-enforce-server/secure-comm-dlp-agents-and-endpoint-servers.html
- Proofpoint DLP architecture whitepaper: https://www.proofpoint.com/sites/default/files/white-papers/pfpt-uk-ms-solutions-architecture.pdf
- Palo Alto Endpoint DLP: https://docs.paloaltonetworks.com/enterprise-dlp/administration/configure-enterprise-dlp/endpoint-dlp/how-does-endpoint-dlp-work
- WinFsp vs Dokany discussion: https://github.com/winfsp/winfsp/issues/19
- Cryptomator WinFsp usage: https://community.cryptomator.org/t/winfsp-how-to-use-it/7980

### Pitfall sources

- WinFsp deadlock on volume shutdown: https://github.com/winfsp/winfsp/issues/682
- WinFsp user-mode locking and kernel caching: https://github.com/winfsp/winfsp/issues/116
- WinFsp mount point not showing in Explorer: https://github.com/winfsp/winfsp/issues/416
- WinFsp disk file system creation on 32-bit Windows: https://github.com/winfsp/winfsp/issues/88
- WinFsp Rust bindings: https://github.com/SnowflakePowered/winfsp-rs
- Writing a Windows Service in Rust: https://davidhamann.de/2026/02/28/writing-a-windows-service-in-rust/
- Common async Rust pitfalls: https://reintech.io/blog/avoid-common-async-rust-pitfalls-deadlocks
- Microsoft Purview DLP deployment mistakes: https://www.welkasworld.com/post/common-mistakes-you-may-be-making-with-data-loss-prevention
- Endpoint DLP deployment guide: https://dlptest.com/endpoint-dlp-deployment-guide/
- Hidden costs of DLP false positives: https://www.cyberhaven.com/blog/5-reasons-you-cant-afford-to-ignore-false-positives
- Tuning DLP false positives: https://www.cybersierra.co/blog/tune-dlp-false-positives
- Encrypted file storage best practices: https://phalanx.io/encrypted-file-storage-best-practices/
- Tray icons and toast notifications Session 0 IPC pattern: https://comcomponent.com/en/blog/windows-tray-icon-toast-notification-guide
- Flowtriq tamper-evident audit log: https://flowtriq.com/features/audit
- Common DLP implementation failures: https://www.kickidler.com/info/common-dlp-implementation-failures-and-how-to-avoid-them
- Broadcom DLP known issues: https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/26-1/new-and-changed/release-notes/dlp-known-issues.html

### Project context

- `C:/Users/nhdinh/dev/dleakprevention/.planning/PROJECT.md`
