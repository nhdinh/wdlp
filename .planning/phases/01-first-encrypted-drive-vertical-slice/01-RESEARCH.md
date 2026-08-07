# Phase 1: First Encrypted-Drive Vertical Slice - Research

**Researched:** 2026-08-07  
**Domain:** Rust control plane, Windows service/WinFsp virtual filesystem, authenticated encrypted local storage  
**Confidence:** MEDIUM

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

<!-- DATA_Q7M4V2KP_START -->
- **D-01:** The installed agent is configured with the management-server address and initiates registration automatically on first run.
- **D-02:** Enrollment is permitted only for a domain-joined computer whose exact composite hardware fingerprint is already whitelisted on the server. The fingerprint uses important hardware serial numbers, including system-disk identity; MAC addresses are not authoritative. — **Reversibility:** costly — changing fingerprint composition affects existing whitelist records and device identity matching.
- **D-03:** Any change to a fingerprinted hardware component, including system-disk replacement, blocks enrollment until an administrator updates the whitelist.
- **D-04:** The management server validates the computer account and obtains authoritative device information by querying the organization's two AD domain controllers (one primary and one secondary) on the same network.
- **D-05:** Successful enrollment issues a device-bound client certificate for mutual TLS. The private key and associated credential material are stored in a DPAPI machine-protected file accessible to the Windows service. — **Reversibility:** costly — changing the device-authentication scheme requires credential migration and coordinated server/agent protocol changes.
- **D-06:** If the local credential is missing or cannot be decrypted, the agent automatically repeats the complete domain and hardware checks, receives replacement credentials, and causes the server to revoke the previous credential.
- **D-07:** Mount the protected drive automatically when an eligible domain user signs in; each signed-in user receives that user's isolated store.
- **D-08:** Use the centrally configured preferred drive letter. If it is occupied, select the next available drive letter.
- **D-09:** At sign-out, reject new opens, allow existing handles a short grace period, then unmount and clean up. The exact grace-period duration is left to planning.
- **D-10:** If automatic mounting fails, leave the drive absent, retry automatically, and record a clear diagnostic event. Phase 1 does not block Windows sign-in or expose a broken placeholder drive.
- **D-11:** Present normal Windows filesystem behavior, including expected visibility, caching, sharing, explicit-flush, and handle-close semantics. There is no product-specific save operation.
- **D-12:** A successful Windows flush or close must not be acknowledged until encrypted content and its metadata meet the corresponding durability expectations.
- **D-13:** After an interruption, retain the last fully committed version and discard an incomplete replacement; never expose a partial mixture of old and new data.
- **D-14:** If ciphertext or sensitive metadata fails authenticated verification, deny access with a stable integrity error, preserve the encrypted evidence for diagnosis or recovery, record diagnostics, and never return unauthenticated plaintext.
- **D-15:** On disk-full or backing-store write failure, return the appropriate Windows error and preserve the last committed file version.
- **D-16:** The Phase 1 end-to-end matrix must include Explorer, PowerShell, Notepad, Microsoft Word, and Microsoft Excel.
- **D-17:** Validate create, copy into the drive, copy out, open, edit, save, Save As, rename, move, delete, and directory operations.
- **D-18:** Validate file sizes from empty through at least 1 GB, including sizes immediately below, at, and above encrypted-storage chunk boundaries.
- **D-19:** Validate normal service restart, Windows reboot, forced service termination during an active write, and simulated abrupt machine loss.
<!-- DATA_Q7M4V2KP_END -->

### the agent's Discretion

<!-- DATA_N3X8L1RD_START -->
- Select the exact hardware serial sources used in the composite fingerprint while preserving exact-match behavior, system-disk binding, and resistance to agent-supplied spoofing.
- Select the sign-out handle grace-period duration and retry backoff for failed mounts.
- Define the precise test corpus and encryption-chunk boundary sizes consistent with the selected storage format.
<!-- DATA_N3X8L1RD_END -->

### Deferred Ideas (OUT OF SCOPE)

<!-- DATA_B5T9W6HC_START -->
None — discussion stayed within phase scope.
<!-- DATA_B5T9W6HC_END -->
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|---|---|---|
| WRK-01 | Cargo workspace and specified crates | Workspace boundary and dependency plan below |
| WRK-02 | Shared IDs, policy types, decisions, errors | Portable `dlp-domain` ownership map |
| WRK-03 | Versioned protocol DTOs | Canonical signed-envelope and API DTO pattern |
| WRK-04 | Deny portable unsafe; isolate Windows FFI | Windows-host-only FFI and crate lint policy |
| SRV-01 | Authenticated HTTP JSON APIs | Axum + rustls API boundary and endpoint map |
| SRV-03 | Enroll devices with short-lived token | Bootstrap then mTLS enrollment state machine |
| SRV-11 | PostgreSQL and migrations | SQLx migration discipline and Compose validation |
| SRV-12 | Health and readiness | Liveness/readiness semantics and tests |
| CRY-01 | Authenticated encryption at rest | Chunk-record AEAD format and AAD rules |
| CRY-02 | Ed25519 signed configurations | Canonical bytes + `verify_strict` activation gate |
| CRY-04 | No long-lived plaintext endpoint secret | DPAPI file ACL and key zeroization rules |
| AGT-01 | Automatic Windows service | `windows-service` lifecycle pattern |
| AGT-02 | Enroll and protect credentials | DPAPI machine scope plus service-only ACL |
| AGT-03 | TLS and server identity validation | rustls trust-anchor and client-cert plan |
| AGT-04 | Download, verify, cache, atomically activate bundle | staged download, verification, atomic pointer flip |
| AGT-05 | Keep current and last-known-good configs | two-version immutable cache |
| AGT-06 | Reject invalid bundles without activation | signature/schema/hash failure tests |
| AGT-07 | Report health and drive state | typed diagnostic events and health endpoint contract |
| DRV-01 | One store per authenticated user | SID-indexed store registry and session ownership |
| DRV-02 | WinFsp configurable drive mount | host lifecycle and preferred-letter fallback |
| DRV-03 | Map every request to Windows identity | session token/SID captured at mount, never path/user input |
| DRV-04 | Encrypt contents and metadata | chunk records and encrypted metadata database |
| DRV-06 | Crash-consistent updates | write-to-staging + atomic commit journal |
| DRV-07 | Detect corruption; no unauthenticated plaintext | AEAD authentication before decode and stable error |
| DRV-09 | Survive restarts without committed corruption | recovery scan and fault-injection matrix |
| TST-01 | Policy unit tests | Keep a minimal pass-through policy type only; full policy behavior is Phase 2 |
| TST-02 | Bundle signature validation tests | tamper, wrong key, unsupported schema, partial-cache cases |
| TST-03 | Storage/crypto/key unit tests | nonce, AAD, corruption, recovery, no-plaintext checks |
| TST-05 | Enrollment through activation integration test | PostgreSQL-backed server/agent flow |
| TST-08 | Early WinFsp representative-app spike | Windows-only manual and scripted test matrix |
</phase_requirements>

## Summary

Build Phase 1 as a narrow but complete trust chain: an administrator preloads an exact allowlisted endpoint record; the server corroborates its AD computer identity against both configured DCs, issues a bootstrap response, then all subsequent agent APIs require the device mTLS certificate. The agent verifies a canonical, versioned signed configuration before atomically selecting it, then a session-aware Windows host mounts one user's WinFsp filesystem over an encrypted, crash-consistent store. [CITED: https://docs.rs/winfsp/0.13.0%2Bwinfsp-2.1/winfsp/] [CITED: https://docs.rs/rustls/latest/rustls/struct.ConfigBuilder.html]

The hard boundary is not encryption alone. Each write must be staged separately from the committed generation; the file's encrypted chunks, encrypted metadata, generation number, and commit record must become visible together only after the data is durable. AES-GCM needs a nonce unique under a key for every encrypted record, and decryption must authenticate the record and associated metadata before any plaintext is returned. [CITED: https://docs.rs/crate/aes-gcm/latest/source/src/lib.rs]

The phase must run its real WinFsp spike on Windows 10/11 with a WinFsp runtime installed. It cannot be accepted from Linux CI or pure unit tests: Explorer, PowerShell, Notepad, Word, Excel, drive-letter collisions, service/session controls, disk-full behavior, and abrupt loss are all operating-system interactions. The present workstation has Windows 10 Pro 64-bit and Word/Excel, but WinFsp, Docker, and PostgreSQL CLIs are absent. [VERIFIED: local environment probe 2026-08-07]

**Primary recommendation:** Plan the vertical slice in dependency order—workspace/protocol/crypto first, server enrollment and signed configuration second, storage recovery third, then WinFsp session mounting—while treating the Windows validation matrix as a release gate for the phase.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|---|---|---|---|
| Enrollment allowlist and dual-DC computer validation | API / Backend | Windows service | Server is authoritative for enrollment; agent supplies an attestation and receives credentials only after validation. |
| Device mTLS credential | Windows service | API / Backend | The service owns its private credential and presents it; server validates chain and device state. |
| Signed configuration lifecycle | Windows service | API / Backend | Server creates immutable signed bytes; agent verifies, caches, and activates locally. |
| User-session drive lifecycle | Windows service | Windows filesystem host | SCM session changes decide eligibility; the WinFsp host owns the mounted volume. |
| Request-to-user association | Windows filesystem host | Windows service | File callbacks enforce the mount's captured user SID and session scope. |
| Encryption, metadata, commit/recovery | Database / Storage | Windows filesystem host | Portable storage owns the durable encrypted format; filesystem translates Windows operations. |
| Enrollment, health and readiness HTTP | API / Backend | Database / Storage | Server exposes versioned JSON and persists authoritative device/enrollment records. |

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---|---:|---|---|
| `winfsp` [WARNING: flagged as suspicious — verify before using.] | `0.13.0+winfsp-2.1` | Safe Rust WinFsp host and filesystem traits | Its official docs prescribe `FileSystemContext`, `FileSystemHost`, and service builder lifecycle. [CITED: https://docs.rs/winfsp/0.13.0%2Bwinfsp-2.1/winfsp/] |
| `windows-service` | `0.8.1` | SCM dispatcher and control handler | Exposes the service dispatcher and a `SessionChange` service control variant. [CITED: https://docs.rs/windows-service/latest/windows_service/service_dispatcher/fn.start.html] |
| `aes-gcm` | `0.11.0` | AES-256-GCM file-record AEAD | Official usage documents unique per-key nonces and authenticated encryption. [CITED: https://docs.rs/crate/aes-gcm/latest/source/src/lib.rs] |
| `ed25519-dalek` | `3.0.0` | Bundle signing and strict verification | It supports `VerifyingKey::verify_strict`; the docs explain why normal verification accepts weak-key cases. [CITED: https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.VerifyingKey.html] |
| `axum` | `0.8.9` | Versioned JSON control-plane API | Tokio/Hyper-native router with extractors and Tower middleware. [CITED: https://docs.rs/axum/0.8.9/axum/] |
| `sqlx` | `0.9.0` | PostgreSQL pool and migrations | SQLx migrations are versioned SQL files and can be embedded/run at startup. [CITED: https://docs.rs/sqlx/latest/sqlx/macro.migrate.html] |
| `rustls` + `tokio-rustls` | `0.23.42` + `0.26.4` | Server TLS and required client certificates | rustls supports client-certificate verification through `WebPkiClientVerifier` / `with_client_cert_verifier`. [CITED: https://docs.rs/rustls/latest/rustls/server/struct.WebPkiClientVerifier.html] |

### Supporting

| Library | Version | Purpose | When to Use |
|---|---:|---|---|
| `tokio` | `1.53.1` | Async runtime | Server, agent network loop, background recovery. [CITED: https://docs.rs/axum/0.8.9/axum/] |
| `serde` + `serde_json` | `1.0.229` + `1.0.151` | Versioned DTO serialization | All REST DTOs and signed bundle payloads; never sign an arbitrary map serialization. [VERIFIED: crates.io registry search 2026-08-07] |
| `reqwest` | `0.13.4` | Agent HTTPS client | Configure it with the server CA and device client identity after enrollment. [ASSUMED] |
| `uuid` | `1.24.0` | Opaque typed IDs | Device, enrollment, configuration, and commit IDs. [ASSUMED] |
| `thiserror` | `2.0.19` | Structured portable errors | Domain error enums without Windows-status leakage. [ASSUMED] |
| `tracing` + `tracing-subscriber` | `0.1.44` + `0.3.23` | Structured diagnostics | Correlation IDs and stable codes; redact secrets, keys, plaintext, and raw hardware serials. [ASSUMED] |
| `tempfile` + `wiremock` | `3.27.0` + `0.6.5` | Unit and HTTP integration tests | Portable storage fault tests and mock bootstrap/mTLS-negative tests. [ASSUMED] |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|---|---|---|
| WinFsp | Dokany | Dokany is the ADR fallback only if the WinFsp spike proves incompatible; do not implement both in Phase 1. [CITED: .planning/docs/adrs/ADR-001-winfsp-framework.md] |
| AES-GCM record encryption | A whole-file encrypted blob | Whole-file rewrites cannot satisfy normal random Windows write/flush behavior without excessive complexity. [ASSUMED] |
| Explicit staged commit journal | In-place ciphertext overwrite | In-place mutation cannot guarantee D-13 after interruption. [ASSUMED] |

**Installation:**

```bash
cargo add winfsp windows-service aes-gcm ed25519-dalek axum sqlx rustls tokio-rustls tokio serde serde_json
```

Pin exact compatible versions in the workspace lockfile after the `winfsp` human-verification checkpoint; use `cargo update -p <crate> --precise <version>` only intentionally. [ASSUMED]

## Package Legitimacy Audit

| Package | Registry | Age | Downloads | Source Repo | Verdict | Disposition |
|---|---|---:|---:|---|---|---|
| `winfsp` | crates.io | 3y 10m | 737/wk | SnowflakePowered/winfsp-rs | SUS | Flagged — human checkpoint before install |
| `windows-service` | crates.io | 8y 2m | 123,087/wk | mullvad/windows-service-rs | OK | Approved |
| `aes-gcm` | crates.io | 6y 11m | 2,522,246/wk | RustCrypto/AEADs | OK | Approved |
| `ed25519-dalek` | crates.io | 9y 8m | 4,057,352/wk | dalek-cryptography/curve25519-dalek | OK | Approved |
| `axum` | crates.io | 5y 1m | 8,183,411/wk | tokio-rs/axum | OK | Approved |
| `sqlx` | crates.io | 7y 2m | 2,510,612/wk | launchbadge/sqlx | OK | Approved |
| `tokio` | crates.io | 10y 1m | 15,711,067/wk | tokio-rs/tokio | OK | Approved |
| `serde` / `serde_json` | crates.io | 11y / 11y | 20M+/wk each | serde-rs | OK | Approved |
| `rustls` / `tokio-rustls` | crates.io | 9y / 9y | 11M+/wk each | rustls | OK | Approved |
| `reqwest`, `uuid`, `thiserror`, `tracing`, `tempfile`, `wiremock` | crates.io | established | 1M+/wk each | published source repos | OK | Approved, but planner gates the assumed recommendations |

**Packages removed due to [SLOP] verdict:** none.  
**Packages flagged as suspicious [SUS]:** `winfsp` — planner must insert `checkpoint:human-verify` before adding it. [VERIFIED: package-legitimacy seam 2026-08-07]

## Architecture Patterns

### System Architecture Diagram

```text
Admin preloads exact allowlist + short-lived token
                 |
                 v
Windows service -- bootstrap HTTPS --> Server enrollment endpoint
   | local WMI/SMBIOS + disk identity          |-- query DC-1 and DC-2
   |                                          |-- compare allowlist + AD identity
   |                                          '-- issue device certificate + signed config
   v
DPAPI machine-protected credential file (service-only ACL)
   |
   '-- mTLS --> /api/v1/agent/config --> verify signature + schema --> cache current/LKG
                                                                  |
Windows session change --> eligible user SID --> WinFsp FileSystemHost
                                                   |
Windows file API --> filesystem callbacks --> portable encrypted storage
                                                   |
                          stage chunks + encrypted metadata --> fsync --> commit record
                                                   |
                                               atomic generation switch
```

The server must make both AD DC responses agree on the configured computer object identity (`objectGUID`, `objectSid`, enabled account, expected domain); failure or disagreement fails enrollment closed. AD stores replicated object attributes, while platform and disk serials are local WMI/SMBIOS observations—not directory facts—so record their normalized digest in the allowlist and document the residual privileged-local-spoofing risk. [CITED: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adcomputer?view=windowsserver2025-ps] [CITED: https://learn.microsoft.com/en-us/windows/win32/ad/attributes] [CITED: https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystemproduct]

### Recommended Project Structure

```text
crates/
├── dlp-domain/           # IDs, errors, invariants; forbid unsafe
├── dlp-protocol/         # versioned DTOs and canonical signed envelopes
├── dlp-crypto/           # AEAD record and Ed25519 operations; forbid unsafe
├── dlp-storage/          # portable encrypted store, journal, recovery; forbid unsafe
├── dlp-server/           # Axum routes, SQLx repositories, CA/signing integration
├── dlp-agent-core/       # enrollment/config cache/state machine; no Win32 FFI
├── dlp-windows-service/  # SCM, DPAPI, WTS, Windows identity; documented unsafe boundary
├── dlp-windows-drive/    # WinFsp adapter from callbacks to storage
└── dlpctl/               # development/admin bootstrap CLI
migrations/               # forward-only SQLx migrations
deploy/compose.yaml        # PostgreSQL + server development deployment
tests/windows/             # manual scripts and result capture, no sensitive files checked in
```

### Pattern 1: Canonical signed configuration envelope

**What:** Serialize one fully specified envelope type to deterministic bytes, sign those exact bytes, persist a content hash beside them, and only then activate by replacing an atomic `current` pointer after verify+schema checks.

**When to use:** Every server-to-agent configuration response; never sign reconstructed JSON or a post-deserialization object.

**Example:**

```rust
// Source: https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.VerifyingKey.html
fn verify_bundle(bytes: &[u8], signature: &Signature, key: &VerifyingKey) -> Result<(), BundleError> {
    key.verify_strict(bytes, signature).map_err(|_| BundleError::InvalidSignature)
}
```

### Pattern 2: Generation-based encrypted file commit

**What:** Write replacement chunks and metadata beneath an unreferenced generation ID. Encrypt each chunk using a fresh nonce; authenticate `{format_version, store_id, file_id, generation, chunk_index, plaintext_length}` as AAD. Flush staged records, write and flush the encrypted manifest, then atomically publish one authenticated commit record. Recovery trusts only the last valid commit record and deletes unreferenced staging data later.

**When to use:** Create, overwrite, truncate, rename, delete, `FlushFileBuffers`, and final close. A close or flush success is returned only after the corresponding commit boundary is durable. [ASSUMED]

### Pattern 3: Session-owned mount actor

**What:** Treat every mount as a stateful actor keyed by Windows session ID and captured user SID. It owns the WinFsp host, open-handle count, reject-new-opens flag, cancellation token, and retry schedule. At sign-out, set reject-new-opens, wait **30 seconds** for handles, force cancellation/unmount, and emit one structured result. Mount retry uses exponential delay capped at **5 minutes**. [ASSUMED]

**When to use:** `SERVICE_CONTROL_SESSIONCHANGE`; Windows services receive session changes via a HandlerEx control callback, and the service-control enum is non-exhaustive, so retain a wildcard arm. [CITED: https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsregistersessionnotification] [CITED: https://docs.rs/windows-service/latest/windows_service/service/enum.ServiceControl.html]

### Pattern 4: WinFsp service-managed host

**What:** Implement `FileSystemContext` in `dlp-windows-drive`; create/start/mount the host in WinFsp's start closure and unmount/drop it in the stop closure. `build.rs` must call `winfsp_link_delayload`; do not dynamically load the WinFsp DLL by hand. [CITED: https://docs.rs/winfsp/0.13.0%2Bwinfsp-2.1/winfsp/]

### Anti-Patterns to Avoid

- **Mounting one global drive from the LocalSystem service:** loses per-user identity and violates D-07/DRV-03; mount one host per eligible session. [ASSUMED]
- **Using `CRYPTPROTECT_LOCAL_MACHINE` as an ACL:** that flag allows any local user to decrypt; the credential file directory and object ACL must restrict access to the service identity. [CITED: https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata]
- **Trusting a single client-reported serial as authoritative:** AD identity and local hardware observations have different trust properties; log only a digest and require the pre-provisioned exact digest. [CITED: https://learn.microsoft.com/en-us/windows/win32/ad/attributes]
- **Returning success after buffering plaintext or ciphertext:** breaks D-12/D-13; couple Windows flush/close acknowledgement to the storage commit protocol. [ASSUMED]
- **Decrypting before tag verification or logging failed buffers:** returns or exposes unauthenticated protected data. [CITED: https://docs.rs/crate/aes-gcm/latest/source/src/lib.rs]

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---|---|---|---|
| User-mode Windows filesystem transport | Custom Windows driver/IRP bridge | WinFsp + `winfsp` | WinFsp supplies the Windows filesystem dispatch and mount integration. [CITED: https://winfsp.dev/doc/WinFsp-API-winfsp.h/] |
| AEAD primitive | AES/GCM, nonce arithmetic, tag comparison | `aes-gcm` | Nonce uniqueness and authentication failure semantics are security-critical. [CITED: https://docs.rs/crate/aes-gcm/latest/source/src/lib.rs] |
| Ed25519 | Custom signing/verification | `ed25519-dalek::verify_strict` | The library documents strict handling of weak-key cases. [CITED: https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.VerifyingKey.html] |
| Windows service dispatcher | Custom SCM FFI loop | `windows-service` | Dispatcher blocks correctly and exposes typed control events. [CITED: https://docs.rs/windows-service/latest/windows_service/service_dispatcher/fn.start.html] |
| TLS/mTLS | Certificate parser/handshake | rustls | rustls provides TLS 1.2/1.3 and client-certificate verifier integration. [CITED: https://docs.rs/rustls/latest/rustls/] |
| SQL migration ledger | Ad-hoc startup DDL | SQLx migrations | Versioned migration scripts and migration tracking are built in. [CITED: https://docs.rs/sqlx/latest/sqlx/migrate/index.html] |

**Key insight:** The project should implement its own encrypted-store *format and commit semantics*, but delegate cryptographic primitives, Windows FS dispatch, SCM, TLS, and migrations to vetted components.

## Common Pitfalls

### Pitfall 1: Hardware allowlist mistaken for remote hardware proof

**What goes wrong:** A forged/elevated agent reports expected serials, or the server accepts a value that AD never corroborates.  
**How to avoid:** Require Kerberos/LDAPS-authenticated lookup of the machine account on both explicitly configured DCs, exact matching of preloaded normalized fingerprint digest, and an enrollment audit record. Treat admin-local tampering as residual risk; Phase 1 has no TPM remote-attestation decision. [CITED: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adcomputer?view=windowsserver2025-ps]  
**Warning signs:** Missing/zero serials, DC disagreement, fingerprint mismatch, or a replacement system disk.

### Pitfall 2: DPAPI machine scope grants broader decryption than intended

**What goes wrong:** Credential bytes are machine-protected but readable/decryptable by another local account.  
**How to avoid:** `CRYPTPROTECT_UI_FORBIDDEN`; create the credential directory/file with a service-SID-only ACL; redact all DPAPI errors; re-enroll and revoke prior credential as D-06 requires. [CITED: https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata]  
**Warning signs:** User-readable service data directory or a credential copied to another process.

### Pitfall 3: Reused AEAD nonces or mutable unauthenticated metadata

**What goes wrong:** Two chunks under one DEK reuse a nonce, or file/generation/chunk metadata is changed independently of ciphertext.  
**How to avoid:** Persist each nonce with its record; allocate from a CSPRNG and reject duplicate nonce in the active generation; bind immutable record identity into AAD; perform tag verification before decoding. [CITED: https://docs.rs/crate/aes-gcm/latest/source/src/lib.rs]  
**Warning signs:** Counter reset after restart, tests that re-encrypt with a fixed nonce, or metadata edits without re-encryption.

### Pitfall 4: Save/rename semantics treated as a simple overwrite

**What goes wrong:** Office commonly uses temp files, sharing, flush, rename, and replace behavior; an in-place store yields partial files after a service kill.  
**How to avoid:** Implement create/open/share flags, flush, close, rename, delete, directory enumeration, and generation commit before declaring the spike passed. Test Word and Excel's actual Save and Save As flows. WinFsp can dispatch asynchronous read/write/directory requests, but Phase 1 should keep its own durable operation sequencing explicit. [CITED: https://winfsp.dev/doc/WinFsp-API-winfsp.h/]  
**Warning signs:** Explorer works but Word Save As fails, open handles block cleanup forever, or crash recovery exposes a new name with old chunks.

### Pitfall 5: Premature runtime dependence assumptions

**What goes wrong:** A plan claims tests are runnable, but WinFsp/Docker/PostgreSQL are unavailable.  
**How to avoid:** Split portable CI tests from a named Windows validation station; install/pin the WinFsp runtime before host tests, and provision Compose/PostgreSQL before server integration. [VERIFIED: local environment probe 2026-08-07]

## Code Examples

### WinFsp build integration

```rust
// Source: https://docs.rs/winfsp/0.13.0%2Bwinfsp-2.1/winfsp/
fn main() {
    winfsp::build::winfsp_link_delayload();
}
```

### Strict signed-bundle check before activation

```rust
// Source: https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.VerifyingKey.html
fn validate_signed_bytes(bytes: &[u8], signature: &Signature, key: &VerifyingKey) -> bool {
    key.verify_strict(bytes, signature).is_ok()
}
```

### AES-GCM record operation

```rust
// Source: https://docs.rs/crate/aes-gcm/latest/source/src/lib.rs
// `nonce` must be unique for every record encrypted under `cipher`'s key.
let tag = cipher.encrypt_in_place_detached(&nonce, associated_data, &mut staged_ciphertext)?;
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|---|---|---|---|
| `ed25519-dalek` 2.x | 3.x | Current major release | Version 3 has MSRV 1.85 and explicit strict-verification guidance; the available Rust 1.97 toolchain satisfies it. [CITED: https://docs.rs/crate/ed25519-dalek/latest] [VERIFIED: local environment probe 2026-08-07] |
| In-process DLL linking assumptions | WinFsp delay-load build helper | Current `winfsp` docs | Add `build.rs` helper at workspace implementation time. [CITED: https://docs.rs/winfsp/0.13.0%2Bwinfsp-2.1/winfsp/] |

**Deprecated/outdated:** Do not use normal `VerifyingKey::verify` for a server trust key: `verify_strict` is specifically documented to deny weak keys. [CITED: https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.VerifyingKey.html]

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|---|---|---|
| A1 | A 4 MiB encrypted chunk with boundary tests at 4 MiB - 1, 4 MiB, and 4 MiB + 1 is a practical Phase 1 choice. | Architecture Patterns | Changes stored format and test corpus; keep format versioned. |
| A2 | A 30-second sign-out grace and 5-minute capped retry balance UX and cleanup. | Architecture Patterns | May be too short for Office or too slow to recover mounts. |
| A3 | `reqwest`, `uuid`, `thiserror`, tracing, tempfile, and wiremock are appropriate supporting crates. | Standard Stack | Planner must human-verify their official docs before install. |
| A4 | A local privileged attacker can spoof local WMI/SMBIOS serial reporting absent an attestation mechanism. | Common Pitfalls | The exact-match allowlist must not be represented as hardware-rooted remote attestation. |

## Open Questions

1. **How are system-disk identity and platform UUID administratively captured before first enrollment?**
   - What we know: D-02 requires exact pre-existing allowlisting and D-04 requires both DC checks.
   - What's unclear: AD does not inherently make local disk serials authoritative.
   - Recommendation: add an administrator-only provisioning command/process that captures and normalizes `SMBIOS UUID + BIOS serial + physical system-disk serial`, stores only a digest, and identifies which values must be manually supplied in the environment. Do not relax exact match.

2. **What CA issues the device certificate and what trust anchor is installed on the agent?**
   - What we know: D-05 locks device-bound mTLS after enrollment.
   - What's unclear: private CA ownership, certificate profile/SAN, renewal period, revocation enforcement, and bootstrap server-auth trust.
   - Recommendation: make a Phase 1 design task choose a development private CA and document certificate fields/validity; server must map certificate serial/SAN to enrolled device and reject revocation.

3. **Which WinFsp mounting mode exposes a per-session letter with the required visibility?**
   - What we know: D-07 requires user sign-in mounting and D-08 requires letter fallback.
   - What's unclear: service/session isolation behavior for the selected `winfsp` API configuration.
   - Recommendation: make this the first Windows spike checkpoint; do not build the full store before proving drive visibility to the signed-in user.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|---|---|---|---|---|
| Rust/Cargo | workspace and portable tests | ✓ | 1.97.1 | — |
| Windows 10 Pro 64-bit | Windows service/WinFsp tests | ✓ | Build 26200 | — |
| Microsoft Word/Excel | D-16 Office validation | ✓ | Office16 paths found | — |
| WinFsp runtime | actual mounted-drive spike | ✗ | — | Install supported x64 runtime; no substitute for selected framework |
| Docker Compose | server/PostgreSQL integration | ✗ | — | Provision Docker Desktop/Compose or an equivalent dedicated PostgreSQL test host |
| PostgreSQL CLI/service | migration and integration diagnostics | ✗ | — | Compose-provisioned PostgreSQL after Docker is available |

**Missing dependencies with no fallback:** WinFsp runtime for DRV-02 and TST-08.  
**Missing dependencies with fallback:** Docker/PostgreSQL may be supplied by a remote development database, but Docker Compose remains the project deployment target.

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---|---|---|
| V2 Authentication | yes | Bootstrap allowlist/token only at enrollment; mTLS device certificate thereafter. |
| V3 Session Management | yes | Device cert revocation record, certificate expiry, user session mount actor. |
| V4 Access Control | yes | Captured Windows SID/session controls store selection and mount lifecycle. |
| V5 Input Validation | yes | Bounded/typed DTOs; schema/version checks before bundle activation; canonical size limits. |
| V6 Cryptography | yes | `aes-gcm`, `ed25519-dalek`, DPAPI, rustls; never custom primitives. |
| V8 Data Protection | yes | AEAD contents/metadata, service-only ACL, redacted diagnostics, no plaintext backing-store fixtures. |
| V9 Communications | yes | TLS server identity validation and required client certificates for agent APIs. |
| V12 File and Resources | yes | Normalized virtual paths; no host-path traversal; staging/commit recovery; disk-full propagation. |

### Known Threat Patterns for this Stack

| Pattern | STRIDE | Standard Mitigation |
|---|---|---|
| Enrollment replay or unauthorized endpoint | Spoofing | Single-use/short-lived token plus exact fingerprint allowlist, two-DC identity confirmation, then mTLS. |
| Stolen machine-scope credential file | Elevation / Information disclosure | Service SID ACL, noninteractive DPAPI, certificate revocation/re-enrollment, no secret logging. |
| Bundle downgrade/tamper | Tampering | Versioned canonical bytes, strict Ed25519 verification, hash, atomic current/LKG selection. |
| Ciphertext/metadata modification | Tampering | AEAD tag + AAD for record identity, stable integrity failure, evidence retention. |
| Crash during write | Availability / Tampering | Staged generation, durable manifest, atomic commit record, recovery scan. |
| Path traversal or cross-store path confusion | Elevation | Virtual path parser; store selected from captured SID, never a caller-provided path/user ID. |
| Resource exhaustion by file I/O | Denial of service | Max path/component/chunk sizes, bounded directories/handles, backpressure; schedule fuzzing in Phase 4. [ASSUMED] |

## Sources

### Primary (HIGH confidence)

- None. The research-plan seam classified available sources at MEDIUM confidence; no Context7 MCP was available.

### Secondary (MEDIUM confidence)

- [WinFsp Rust crate docs](https://docs.rs/winfsp/0.13.0%2Bwinfsp-2.1/winfsp/) - host/service lifecycle and required delay-load build helper.
- [WinFsp API](https://winfsp.dev/doc/WinFsp-API-winfsp.h/) - user-mode filesystem interface, mount points, async callbacks.
- [aes-gcm docs](https://docs.rs/crate/aes-gcm/latest/source/src/lib.rs) - unique nonce and AEAD behavior.
- [ed25519-dalek docs](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.VerifyingKey.html) - strict verification and weak-key behavior.
- [windows-service docs](https://docs.rs/windows-service/latest/windows_service/service_dispatcher/fn.start.html) - dispatcher contract.
- [Rustls config docs](https://docs.rs/rustls/latest/rustls/struct.ConfigBuilder.html) - client certificate configuration.
- [Microsoft DPAPI docs](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata) - machine-scope semantics.
- [Microsoft WTS session notifications](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsregistersessionnotification) - service session-change handler behavior.
- [Microsoft AD computer lookup](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adcomputer?view=windowsserver2025-ps) - computer identity lookup.

### Tertiary (LOW confidence)

- No web-only findings used as authoritative. Assumptions are listed above for planner confirmation.

## Metadata

**Confidence breakdown:**
- Standard stack: MEDIUM — current registry values and official crate docs checked; supporting-crate recommendations remain assumed.
- Architecture: MEDIUM — locked context plus official WinFsp/Windows/crypto docs; exact WinFsp session mounting needs a physical spike.
- Pitfalls: MEDIUM — critical crypto, DPAPI, session-control, and filesystem facts are official-source-backed.

**Research date:** 2026-08-07  
**Valid until:** 2026-09-06 for stable Windows/Rust APIs; re-check crate releases at execution time.
