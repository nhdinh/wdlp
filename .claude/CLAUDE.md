<!-- GSD:project-start source:PROJECT.md -->

## Project

**Windows Data Leakage Prevention (DLP) Solution**

A centrally managed Data Leakage Prevention solution for Windows, written primarily in Rust. A central management server configures lightweight endpoint agents installed as Windows services; each enrolled user gets a per-user, user-space virtual drive backed by encrypted local storage. The agent enforces centrally defined rules whenever protected data is accessed, written, copied, exported, or synchronized, and it continues enforcing the last valid policy while offline.

**Core Value:** An authorized Windows user can mount a private protected drive, store files in it, and read them back through the drive, while the backing store does not contain directly readable plaintext.

### Constraints

- **Tech stack**: Rust for endpoint agent and core domain; PostgreSQL for server persistence; Docker Compose for server deployment; WinFsp for the user-mode filesystem.
- **Security**: No long-lived plaintext secrets on endpoints; authenticated encryption at rest; signed policy bundles; TLS with mutual authentication for enrolled agents where practical.
- **Platform**: Windows 10/11 endpoints; Linux server.
- **Budget**: No paid code-signing certificate for a kernel driver; user-mode only.
- **Safety**: Prefer safe Rust; isolate and document unavoidable `unsafe` Windows FFI; deny unsafe code in portable domain crates.

<!-- GSD:project-end -->

<!-- GSD:stack-start source:research/STACK.md -->

## Technology Stack

## Domain

## Key Findings

- **Rust async runtime**: Tokio is the de-facto standard and is explicitly supported by every other crate in the stack (Axum, SQLx, tokio-rustls, reqwest).
- **Web framework**: Axum is the recommended Tokio-native framework for the management server, with deep `tower` middleware integration.
- **Database access**: SQLx provides compile-time checked queries without a DSL, direct async PostgreSQL support, and a built-in migration CLI (`sqlx-cli`).
- **Cryptography**: Use RustCrypto crates (`aes-gcm`, `chacha20poly1305`, `argon2`, `hkdf`, `sha2`) for pure-Rust, auditable cryptography; use `ed25519-dalek` for policy-bundle signing; use `rustls` + `tokio-rustls` for TLS.
- **Windows service lifecycle**: The `windows-service` crate is the mature, maintained choice for registering and running a Windows service in Rust.
- **Virtual drive**: `winfsp` 0.13.0 provides safe Rust bindings over WinFsp 2.1; the runtime must be installed separately on endpoints.
- **Serialization**: `serde` + `serde_json` is the universal choice; avoid bespoke binary protocols for the MVP.
- **Testing**: Combine `tokio-test`, `wiremock` for HTTP mocking, `tempfile` for FS tests, and `insta` for snapshot assertions.
- **Deployment**: Docker Compose with official `postgres:18.4` and a multi-stage Rust build image.
- **Observability**: `tracing` + `tracing-subscriber` is the Rust standard; add `tracing-opentelemetry` only when centralized observability is needed.

## Recommended Stack

### Rust Async Runtime

- **Choice**: `tokio`
- **Version**: `1.53.1`
- **Rationale**: Tokio is the dominant async runtime in the Rust ecosystem and is the integration target for Axum, SQLx, tokio-rustls, reqwest, and tracing. It supports Windows IOCP-based networking and timers and has first-class support for spawning tasks from synchronous Windows service callbacks. Use the `full` or `rt-multi-thread`, `net`, `fs`, `time`, `macros`, and `sync` features.
- **Confidence**: High
- **Avoid**: `async-std` (maintenance mode, effectively superseded by Tokio) and `smol` (smaller ecosystem; only consider if you need an embeddable runtime, which you do not).

### Web Framework (Management Server)

- **Choice**: `axum`
- **Version**: `0.8.9`
- **Rationale**: Axum is built directly on `hyper` and `tokio`, uses `tower` for middleware, and has a macro-free, type-safe extractor API. It is maintained by the Tokio team, has excellent async ergonomics, and integrates cleanly with `tokio-rustls` and `tower-http` middleware for auth, compression, and CORS. Its request/response model maps naturally to a JSON REST API for enrollment, policy, and audit endpoints.
- **Confidence**: High
- **Avoid**: `Rocket` ( heavier compile times, synchronous legacy, less active async-first evolution) and `actix-web` (good performance but a separate actor runtime that adds conceptual friction with the rest of the Tokio stack). Do not build on raw `hyper` for the full server; the routing/boilerplate savings of Axum are worth it.

### Database Access & Migrations

- **Choice**: `sqlx` + `sqlx-cli`
- **Version**: `sqlx = "0.9.0"`, `sqlx-cli = "0.9.0"`
- **Rationale**: SQLx gives compile-time checked SQL queries via `query_as!` without an ORM DSL, direct async PostgreSQL support through `sqlx::postgres`, connection pooling via `PgPool`, and migrations through `sqlx migrate`. This matches the project’s preference for explicit SQL and safe Rust while avoiding the runtime overhead and learning curve of an ORM. The offline query metadata (`sqlx-data.json`) enables CI builds without a live database.
- **Confidence**: High
- **Avoid**: `Diesel` (sync-first; async support is less mature and requires additional adapters) and `SeaORM` (full ORM that adds DSL complexity and runtime overhead; useful later if you need complex relational mapping, but overkill for the MVP). Do not use raw `tokio-postgres` without a pool/connection manager; you will re-implement SQLx features.

### TLS / mTLS

- **Choice**: `rustls` + `tokio-rustls`
- **Version**: `rustls = "0.23.43"`, `tokio-rustls = "0.26.4"`
- **Rationale**: `rustls` is a modern, memory-safe TLS library written in Rust that supports TLS 1.2/1.3, post-quantum key exchange by default, and pluggable crypto providers. `tokio-rustls` provides the Tokio-compatible async stream wrapper. For agent-to-server mutual authentication, configure `ClientConfig`/`ServerConfig` with custom root CAs and client certificate verifiers. Use the `ring` crypto provider (`rustls::crypto::ring::default_provider()`) for a pure-Rust build on Windows; avoid the default `aws-lc-rs` provider unless you want to manage C-toolchain bindings during cross-compilation.
- **Confidence**: High
- **Avoid**: `native-tls` (wraps OpenSSL/SChannel/Secure Transport and introduces platform-specific C dependencies) and `openssl`/`openssl-sys` on Windows (build pain, unsafe FFI, unnecessary for this project). Do not use unencrypted HTTP or self-signed certificates without pinning for agent traffic.

### Authenticated Encryption at Rest

- **Choice**: `chacha20poly1305` (primary), `aes-gcm` (alternative for FIPS-aligned needs)
- **Version**: `chacha20poly1305 = "0.11.0"`, `aes-gcm = "0.11.0"`
- **Rationale**: Both crates are from the audited RustCrypto ecosystem and provide authenticated encryption with associated data (AEAD), which prevents tampering and provides confidentiality. `chacha20poly1305` is preferred for a pure-Rust, constant-time implementation with no AES-NI dependency, making it safer across endpoint hardware. Use a fresh 96-bit nonce per file/chunk and store it alongside the ciphertext; never reuse a (key, nonce) pair. Use `aes-gcm` only if you have a specific organizational requirement for AES.
- **Confidence**: High
- **Avoid**: `sodiumoxide` (deprecated; use `libsodium-sys-stable` only if you specifically need libsodium) and any crate that is not an AEAD construction (e.g., raw AES-CBC without HMAC). Never roll your own encryption or use ECB mode.

### Key Derivation & Password Hashing

- **Choice**: `argon2` for password/passphrase hashing, `hkdf` for deterministic key derivation
- **Version**: `argon2 = "0.5.3"` (stable; ignore `0.6.0-rc.x`), `hkdf = "0.13.0"`
- **Rationale**: `argon2` (Argon2id) is the current winner of the Password Hashing Competition and is suitable for deriving keys from admin/user passwords with memory-hard resistance. `hkdf` extracts high-entropy keying material from shared secrets (e.g., a TLS master secret or an enrollment token) and is ideal for deriving per-file or per-user keys from a high-entropy root. Use `sha2` (`0.11.0`) as the underlying hash for HKDF when needed.
- **Confidence**: High
- **Avoid**: `pbkdf2` for new password hashing (it is not memory-hard and weaker than Argon2id against GPU attacks; only use if you must interop with legacy systems). Do not use simple SHA-256 of a password as a key.

### Secret Handling

- **Choice**: `zeroize` + `secrecy`
- **Version**: `zeroize = "1.9.0"`, `secrecy = "0.10.3"`
- **Rationale**: `zeroize` provides a portable, no-std-compatible trait for securely clearing secrets from memory. `secrecy` wraps secret types so they are not accidentally logged, copied, or displayed. Use `SecretString`/`SecretBox` for keys loaded from configuration or derived during enrollment, and call `.zeroize()` explicitly when rotating or discarding keys.
- **Confidence**: High
- **Avoid**: Storing keys in plain `String`/`Vec<u8>` without zeroization, and printing secrets in `tracing` events (use `secrecy` wrappers or `%`/`?` only after redaction).

### Digital Signatures (Policy Bundles)

- **Choice**: `ed25519-dalek`
- **Version**: `3.0.0`
- **Rationale**: `ed25519-dalek` provides a pure-Rust, fast, and compact Ed25519 signature implementation. Ed25519 produces small 64-byte signatures and 32-byte public keys, which keeps signed policy bundles small for distribution to endpoints. It is suitable for offline bundle verification where the agent only needs the server’s public key.
- **Confidence**: High
- **Avoid**: `rsa` for signing policy bundles unless you specifically need X.509/PKCS#7 interop (the `rsa` crate is currently at `0.9.10` stable; `0.10.x` is still RC). Avoid ECDSA crates with unclear constant-time guarantees.

### Windows Service Lifecycle

- **Choice**: `windows-service`
- **Version**: `0.8.1`
- **Rationale**: This crate provides the standard, maintained abstraction for registering, dispatching, and handling service control events (start, stop, pause, continue) in Rust. It handles the low-level FFI boilerplate and integrates with Tokio by spawning the async runtime inside the service entry point. It correctly manages `ServiceStatusHandle` transitions and `wait_hint`/`checkpoint` semantics, which are critical to prevent the SCM from killing a slow-starting service.
- **Confidence**: High
- **Avoid**: Writing raw `windows-sys` service FFI by hand (easy to get SCM state transitions wrong) and using `winservice` (unmaintained). Do not run the agent as a scheduled task; a Windows service gives the required lifecycle and restart semantics.

### Virtual Drive (WinFsp)

- **Choice**: `winfsp`
- **Version**: `0.13.0+winfsp-2.1`
- **Rationale**: `winfsp` provides safe Rust bindings to WinFsp 2.1, a mature user-mode file-system framework. You implement `FileSystemContext` and host it with `FileSystemHost`; the crate handles delayload linking via `winfsp_link_delayload` in `build.rs`. This satisfies the project constraint of avoiding kernel-mode drivers while still presenting an NTFS-like volume to Windows Explorer and Office.
- **Confidence**: High
- **Avoid**: `dokan-rs` / `dokany` unless WinFsp proves incompatible (Dokany is the documented fallback but has a smaller ecosystem and less active Rust binding maintenance). Do not use `winfsp-sys` directly unless you need raw FFI; prefer the safe `winfsp` crate.

### Windows API Bindings

- **Choice**: `windows`
- **Version**: `0.62.2`
- **Rationale**: The official Microsoft `windows` crate provides safe, idiomatic bindings to the Windows API. Use it for user identity lookups (SID/TOKEN), toast-notification helpers, and any WinFsp-adjacent operations that need native handles. Enable only the features you need (e.g., `Win32_Security`, `Win32_System_Threading`, `Win32_UI_Shell`) to keep compile times reasonable.
- **Confidence**: High
- **Avoid**: `winapi` (maintenance mode; the `windows` crate is its modern replacement) and pulling in the entire `windows` feature set (compile times explode).

### Toast Notifications

- **Choice**: `notify-rust` (cross-platform abstraction), with `windows` crate as fallback for Windows-specific UX
- **Version**: `notify-rust = "4.18.0"`
- **Rationale**: `notify-rust` implements the D-Bus/Desktop Notifications specification on Linux and uses the Windows native notification APIs on Windows, giving the companion process a simple API to show blocked-operation toasts without a tray UI. If the abstraction is too limited, use the `windows` crate to call `Windows.UI.Notifications` directly.
- **Confidence**: Medium
- **Avoid**: Building a full tray/Win32 GUI for the MVP (out of scope) and relying on `msgbox` or console popups (poor UX and accessibility).

### JSON / Protocol Serialization

- **Choice**: `serde` + `serde_json`
- **Version**: `serde = "1.0.229"`, `serde_json = "1.0"`
- **Rationale**: `serde` is the universal Rust serialization framework. Use `serde_json` for the REST API and for signed policy bundles (sign the canonical byte representation, e.g., `serde_json::to_vec`, and verify before deserialization). Add `serde_with` if you need custom serialization for timestamps or base64-encoded key material.
- **Confidence**: High
- **Avoid**: Hand-rolled JSON parsing and bespoke binary wire protocols for the MVP. Do not use `bincode` for signed policy bundles unless you pin an exact version, because `bincode` is not self-describing and can change encoding across versions.

### JWT / Token Handling

- **Choice**: `jsonwebtoken`
- **Version**: `11.0.0`
- **Rationale**: Use JWT only for short-lived admin session tokens or enrollment-token payloads that are verified by the server. The crate supports RS256/ES256/EdDSA and integrates with `serde`. Keep token lifetimes short and validate `exp`, `nbf`, `iss`, and `aud` strictly.
- **Confidence**: High
- **Avoid**: Using JWT for agent-to-server authentication; prefer mTLS with client certificates for the agent. Do not accept the `none` algorithm or ignore signature verification.

### HTTP Client (Agent)

- **Choice**: `reqwest`
- **Version**: `0.13.4`
- **Rationale**: `reqwest` is the standard high-level HTTP client for Rust, built on `hyper` and `tokio`. Configure it with the `rustls-tls` feature (not `native-tls`) to keep the agent pure-Rust and to enable mTLS via `reqwest::ClientBuilder::add_root_certificate` and `identity`. It supports connection pooling, timeouts, and retry middleware through `reqwest-middleware`/`reqwest-retry`.
- **Confidence**: High
- **Avoid**: `hyper` client directly (too low-level for the agent) and `ureq` (synchronous, blocks the async runtime).

### Middleware & Service Composition

- **Choice**: `tower`
- **Version**: `0.5.3`
- **Rationale**: `tower` provides reusable `Service` middleware that Axum uses internally. Use it for request logging, rate limiting, timeout, and auth layers that can be shared between server routes and tested independently. `tower-http` adds ready-made HTTP middleware.
- **Confidence**: High
- **Avoid**: Writing ad-hoc middleware in every Axum handler; centralize cross-cutting concerns in `tower` layers.

### Error Handling

- **Choice**: `thiserror` (library/errors) + `anyhow` (application/binaries)
- **Version**: `thiserror = "2.0.19"`, `anyhow = "1.0.104"`
- **Rationale**: `thiserror` derives `std::error::Error` for domain errors in shared crates, preserving typed error variants for programmatic handling. `anyhow` provides ergonomic error propagation in binary entry points and Windows service wrappers. Use `thiserror` in the domain/library crates and `anyhow` at the application boundary.
- **Confidence**: High
- **Avoid**: Using `Box<dyn Error>` everywhere and mixing `failure` (deprecated) into the codebase.

### CLI / Configuration Parsing

- **Choice**: `clap` + `config` + `dotenvy`
- **Version**: `clap = "4.6.6"`, `config = "0.15.25"`, `dotenvy = "0.15.7"`
- **Rationale**: `clap` is the standard derive-based CLI parser for server utilities and diagnostic tools. `config` supports layered configuration (defaults, file, env) for the server. `dotenvy` loads `.env` files during local development; keep it out of production container images.
- **Confidence**: High
- **Avoid**: `structopt` (merged into `clap` v3/v4) and manual environment-variable parsing in every module.

### Identifiers & Time

- **Choice**: `uuid` + `chrono`
- **Version**: `uuid = "1.24.0"`, `chrono = "0.4.45"`
- **Rationale**: `uuid` v7 is time-sortable and ideal for audit/event IDs and device enrollment tokens. `chrono` remains the most ergonomic date/time library for PostgreSQL `TIMESTAMPTZ` round-tripping via SQLx. Use `chrono::Utc` for all server timestamps and store as `timestamptz`.
- **Confidence**: High
- **Avoid**: Using `std::time::SystemTime` directly in serializable models (poor ergonomics) and `uuid` v4 for high-insert tables where v7 gives better locality.

### Logging / Observability

- **Choice**: `tracing` + `tracing-subscriber`
- **Version**: `tracing = "0.1.44"`, `tracing-subscriber = "0.3.23"`
- **Rationale**: `tracing` is the standard structured logging framework in Rust. Use spans to correlate requests/events, and events for log lines. `tracing-subscriber` provides `FmtSubscriber` for local development and JSON formatting for production log aggregation. Add `tracing-appender` for non-blocking file logging on the agent.
- **Confidence**: High
- **Avoid**: `log` crate alone (use it only via `tracing`’s `log` compatibility feature for third-party integrations) and ad-hoc `println!`/`eprintln!` in production code.

### Testing

- **Choice**: `tokio-test`, `wiremock`, `tempfile`, `insta`, `rstest` (optional)
- **Version**: `tokio-test = "0.4.5"`, `wiremock = "0.6.5"`, `tempfile = "3.27.0"`, `insta = "1.48.0"`
- **Rationale**: `tokio-test` provides async test helpers and a test runtime. `wiremock` stubs the server side when testing the agent’s HTTP client. `tempfile` creates isolated directories for encrypted-storage and WinFsp tests. `insta` snapshot-tests policy decisions, audit log output, and serialized bundles. Use `rstest` if you want parametrized test cases for policy actions.
- **Confidence**: High
- **Avoid**: Spinning up real services in unit tests and writing large hand-maintained assertion blocks for JSON/policy output.

### Server Deployment

- **Choice**: Docker Compose + official `postgres:18.4` + Rust official image (`rust:1.97-bookworm`) for build
- **Version**: PostgreSQL 18.4, Docker Compose v2 syntax, Rust 1.97
- **Rationale**: PostgreSQL 18.4 is the current `latest` tag and matches the project’s one-org-per-server deployment. Use a multi-stage Dockerfile (`rust:1.97-bookworm` builder → `debian:bookworm-slim` or `distroless/cc-debian12` runtime) to keep the management-server image small. Docker Compose is explicitly required by the project brief and is sufficient for 1,000 endpoints / 500 concurrent agents.
- **Confidence**: High
- **Avoid**: Kubernetes for the MVP (operational overkill for a single-host deployment) and `postgres:latest` in production Compose files (pin the major version).

### Migration Tooling

- **Choice**: `sqlx-cli`
- **Version**: `0.9.0`
- **Rationale**: `sqlx-cli` manages migrations in plain `.sql` files, runs them against PostgreSQL, and can prepare offline query data for CI. It integrates cleanly with SQLx and avoids adding a separate migration DSL.
- **Confidence**: High
- **Avoid**: Manual schema versioning scripts and ORM-managed migrations (e.g., SeaORM/Diesel DSL migrations) unless the team is already committed to that ORM.

## Watch Out For

## Sources

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
- tokio-test: https://crates.io/crates/tokio-test
- wiremock: https://crates.io/crates/wiremock
- tempfile: https://crates.io/crates/tempfile
- insta: https://crates.io/crates/insta
- PostgreSQL Docker image: https://hub.docker.com/_/postgres
- Cargo registry API (used to verify all versions): https://crates.io/api/v1/crates/{crate}

<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->

## Conventions

Conventions not yet established. Will populate as patterns emerge during development.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->

## Architecture

Architecture not yet mapped. Follow existing patterns found in the codebase.
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->

## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, or `.codex/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->

## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:

- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->

<!-- GSD:profile-start -->

## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
