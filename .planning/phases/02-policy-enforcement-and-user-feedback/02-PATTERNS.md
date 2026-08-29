# Phase 2: Policy Enforcement and User Feedback - Pattern Map

**Mapped:** 2026-08-29
**Files analyzed:** 35 new or modified files
**Analogs found:** 34 / 35

## Scope Notes

- The eight Wave 0 test paths below are explicit in `02-RESEARCH.md`.
- Production file names come from existing architectural seams named by the research. `grants.rs`, `notification.rs`, and `src/bin/dlp-companion.rs` are inferred planner-discretion placements; the planner may keep those responsibilities in `service.rs`, `session.rs`, or `pipe.rs` if that produces a smaller coherent change.
- The research path `crates/dlp-storage/src/manifest.rs` does not exist. The manifest codec is `EncryptedManifestV1` in `crates/dlp-storage/src/format.rs` lines 141-193.
- Migrations are stored in root `migrations/`, not `crates/dlp-server/migrations/`. The next lifecycle migration should follow the root migration sequence.
- `Cargo.lock` will be regenerated if dependencies change, but it is intentionally omitted from the implementation classification because it contains no hand-authored pattern.
- The root `Cargo.toml` has no `[workspace.dependencies]`; live manifests use crate-local paths for internal crates and exact `=version` pins for versioned dependencies. Phase 2 follows that current convention: add `dlp-policy = { path = "../dlp-policy", version = "=0.1.0" }` directly to each consuming crate and do not introduce workspace dependency centralization.

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `crates/dlp-domain/src/lib.rs` | model | transform | Existing `PolicyInput`, `EnforcementAction`, `PolicyDecision` in same file | exact |
| `crates/dlp-policy/src/lib.rs` | service | transform | Existing `PolicyEvaluator::evaluate` in same file | exact |
| `crates/dlp-policy/Cargo.toml` | config | batch | Existing crate manifest and root workspace manifest | exact |
| `crates/dlp-windows-drive/Cargo.toml` | config | batch | Existing crate-local internal paths and exact external pins | exact |
| `crates/dlp-server/Cargo.toml` | config | batch | Existing crate-local internal paths and exact external pins | exact |
| `crates/dlpctl/Cargo.toml` | config | batch | Existing crate-local internal paths and exact external pins | exact |
| `crates/dlp-agent-core/Cargo.toml` | config | batch | Existing crate-local internal paths and exact external pins | exact |
| `crates/dlp-protocol/src/lib.rs` | model | request-response | `ConfigurationEnvelopeV1` / `SignedConfigurationV1` in same file | exact |
| `migrations/<next>_policy_lifecycle.sql` | migration | CRUD | `migrations/202608070001_walking_skeleton.sql` and `202608070003_authenticated_routes.sql` | role-match |
| `crates/dlp-server/src/routes.rs` | controller | request-response | Existing authenticated configuration and enrollment handlers | exact |
| `crates/dlp-server/src/repository.rs` | service | CRUD | Existing transactional configuration persistence and token consumption | exact |
| `crates/dlp-server/src/tls.rs` | middleware | request-response | Existing TLS-derived administrator/device identity | exact |
| `crates/dlpctl/src/lib.rs` | service | request-response | Existing mTLS provisioning client | exact |
| `crates/dlpctl/src/main.rs` | controller | request-response | Existing strict command parser and dispatch | exact |
| `crates/dlp-agent-core/src/config_cache.rs` | service | file-I/O | Existing stage-verify-activate current/LKG cache | exact |
| `crates/dlp-storage/src/format.rs` | model | file-I/O | Existing bounded `EncryptedManifestV1` codec | exact |
| `crates/dlp-storage/src/store.rs` | service | file-I/O | Existing staged writes and durable `flush_file` publication | exact |
| `crates/dlp-windows-drive/src/filesystem.rs` | controller | request-response | Existing Dokan read/write/flush/rename/delete callbacks | exact |
| `crates/dlp-windows-drive/src/status.rs` | utility | transform | Existing storage error to NTSTATUS mapping | exact |
| `crates/dlp-windows-service/src/pipe.rs` | middleware | request-response | Existing authenticated, length-prefixed actor pipe | exact |
| `crates/dlp-windows-service/src/session.rs` | service | event-driven | Existing per-session actor lifecycle | exact |
| `crates/dlp-windows-service/src/service.rs` | service | event-driven | Existing fail-closed Windows service event loop | exact |
| `crates/dlp-windows-service/src/grants.rs` (inferred) | service | event-driven | `pipe.rs` request validation plus `session.rs` generation-bound identity | partial |
| `crates/dlp-windows-service/src/notification.rs` (inferred) | provider | event-driven | No Windows notification provider exists | none |
| `crates/dlp-windows-service/src/bin/dlp-companion.rs` (inferred) | component | event-driven | `crates/dlp-windows-drive/src/bin/dlp-drive-host.rs` | role-match |
| `crates/dlp-windows-service/src/lib.rs` | config | batch | Existing module/re-export declarations | exact |
| `crates/dlp-windows-service/Cargo.toml` | config | batch | Existing Windows API feature declaration | exact |
| `crates/dlp-policy/tests/policy_v2.rs` | test | transform | Inline policy tests in `crates/dlp-policy/src/lib.rs` | exact |
| `crates/dlp-server/tests/policy_lifecycle.rs` | test | CRUD | `tests/e2e/server_enrollment.rs` and route/repository inline tests | role-match |
| `crates/dlp-agent-core/tests/policy_activation.rs` | test | file-I/O | `crates/dlp-agent-core/tests/enrollment_activation.rs` | exact |
| `crates/dlp-storage/tests/policy_staging.rs` | test | file-I/O | `crates/dlp-storage/tests/operations.rs` | exact |
| `crates/dlp-windows-drive/tests/policy_enforcement.rs` | test | request-response | `crates/dlp-windows-drive/tests/callback_contract.rs` | exact |
| `crates/dlp-windows-service/tests/companion_grants.rs` | test | event-driven | `crates/dlp-windows-service/tests/session_lifecycle.rs` | role-match |
| `crates/dlp-server/tests/policy_distribution.rs` | test | request-response | `tests/e2e/server_enrollment.rs` | exact behavior; crate-local placement for Cargo auto-discovery |
| `tests/windows/Invoke-Phase2PolicySmoke.ps1` | test | batch | `tests/windows/Invoke-Phase1Matrix.ps1` | exact |

## Pattern Assignments

### `crates/dlp-domain/src/lib.rs` (model, transform)

**Analog:** Existing policy contract types in the same file.

**Portable model and redacted error pattern** (`crates/dlp-domain/src/lib.rs` lines 1-4, 27-43):

```rust
#![forbid(unsafe_code)]

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomainError {
    #[error("invalid domain value")]
    InvalidValue,
    #[error("invalid identifier")]
    InvalidIdentifier,
}
```

**Decision vocabulary pattern** (`crates/dlp-domain/src/lib.rs` lines 146-213):

```rust
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementAction {
    Allow,
    AllowAndAudit,
    Warn,
    Block,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyDecision {
    pub action: EnforcementAction,
    pub reason: DecisionReason,
}
```

Copy these conventions for Phase 2 rule predicates, operation direction, unavailable-input observations, warn challenge identity, and decision evidence: portable serde types, snake-case wire values, explicit enums, and non-sensitive display messages. Keep OS handles, regex engine objects, UI strings, and timestamps used only for runtime bookkeeping out of `dlp-domain`.

---

### `crates/dlp-policy/src/lib.rs` and `crates/dlp-policy/Cargo.toml` (service/config, transform)

**Analog:** Existing deterministic `PolicyEvaluator`.

**Core deterministic evaluation pattern** (`crates/dlp-policy/src/lib.rs` lines 36-89):

```rust
pub fn evaluate(&self, input: &PolicyInput) -> PolicyDecision {
    let mut candidates = self
        .rules
        .iter()
        .filter(|rule| rule.matches(input))
        .collect::<Vec<_>>();

    if candidates.is_empty() {
        return PolicyDecision {
            action: self.default_action,
            reason: DecisionReason::Default,
        };
    }

    candidates.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| right.action.restrictiveness().cmp(&left.action.restrictiveness()))
            .then_with(|| left.id.cmp(&right.id))
    });

    let winner = candidates[0];
    PolicyDecision {
        action: winner.action,
        reason: DecisionReason::RuleMatch {
            rule_id: winner.id.clone(),
        },
    }
}
```

Preserve the ordering contract exactly: priority descending, then `block > warn > allow_and_audit > allow`, then stable ascending rule ID. Add v2 predicate evaluation inside `matches`/an equivalent pure layer; do not let filesystem enumeration order, hash-map iteration, current time, or UI state influence selection. Model `all` as conjunction and `any_of` as an explicit nested disjunction. An unavailable attribute must produce a non-match plus a bounded observation, not an implicit match or evaluator error.

**Test table pattern** (`crates/dlp-policy/src/lib.rs` lines 93-156):

```rust
#[test]
fn higher_priority_rule_wins() {
    let evaluator = PolicyEvaluator::new(...);
    let decision = evaluator.evaluate(&input());
    assert_eq!(decision.action, EnforcementAction::Block);
}
```

For `Cargo.toml`, follow the live crate-local pin style. Add `regex = "=1.13.1"` and `aho-corasick = "=1.1.5"` directly to `crates/dlp-policy/Cargo.toml`. Add exact internal `dlp-policy = { path = "../dlp-policy", version = "=0.1.0" }` entries directly to `dlp-windows-drive`, `dlp-server`, `dlpctl`, and `dlp-agent-core`; refresh `Cargo.lock`. Do not add root `[workspace.dependencies]`. Configure explicit size/complexity limits in code; dependency choice alone does not bound content inspection.

---

### `crates/dlp-policy/tests/policy_v2.rs` (test, transform)

**Analog:** Inline evaluator tests in `crates/dlp-policy/src/lib.rs` lines 93-156.

Use table-driven inputs that assert the complete decision, winning rule ID, and bounded observations. Minimum matrices should cover stable tie-breaking, `all` plus nested `any_of`, unavailable fields, direction mapping, explicit default, regex/dictionary/hash/structured identifier matches, all scanner limits, and every inspection-failure fail-closed branch. Repeat identical evaluations to prove determinism.

---

### `crates/dlp-protocol/src/lib.rs` (model, request-response)

**Analog:** `ConfigurationEnvelopeV1` and `SignedConfigurationV1`.

**Versioned bounded contract pattern** (`crates/dlp-protocol/src/lib.rs` lines 1-14, 317-388):

```rust
#![forbid(unsafe_code)]

pub const PROTOCOL_VERSION_V1: u16 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfigurationEnvelopeV1 {
    pub protocol_version: u16,
    pub configuration_version: u64,
    pub device_id: DeviceId,
    pub payload: Vec<u8>,
}

impl ConfigurationEnvelopeV1 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Fixed field order and explicit length prefixes.
    }
}
```

**Signed audience-bound pattern** (`crates/dlp-protocol/src/lib.rs` lines 433-490):

```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedConfigurationV1 {
    pub envelope: ConfigurationEnvelopeV1,
    pub content_digest: [u8; 32],
    pub signature: Vec<u8>,
}
```

Extend the payload with a versioned policy document and limits without changing canonical field order for existing v1 messages. Any new companion IPC message should carry a protocol version, bounded strings/bytes, an opaque operation/challenge ID, and no plaintext content or filename. Reject unknown versions, trailing bytes, oversized counts, and audience mismatches with stable non-sensitive errors.

---

### `crates/dlp-agent-core/src/config_cache.rs` (service, file-I/O)

**Analog:** Existing `stage_verify_activate` flow.

**Verify-before-publication pattern** (`crates/dlp-agent-core/src/config_cache.rs` lines 105-184):

```rust
pub fn stage_verify_activate(
    &self,
    signed_bytes: &[u8],
    expected_device_id: &DeviceId,
) -> Result<ActivationOutcome, ConfigurationCacheError> {
    let _guard = self.activation_lock.lock().map_err(|_| ...)?;
    let signed = deserialize_signed_configuration(signed_bytes)?;
    verify_digest(&signed)?;
    verify_signature(&signed, &self.trust_anchor)?;
    verify_audience(&signed, expected_device_id)?;
    self.verify_monotonic_version(&signed)?;
    let staged = self.write_content_addressed(&signed)?;
    self.swap_pointer(&self.current_pointer, &staged)?;
    Ok(ActivationOutcome { ... })
}
```

**Atomic file pattern** (`crates/dlp-agent-core/src/config_cache.rs` lines 307-313):

```rust
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), ConfigurationCacheError> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes).map_err(|_| ConfigurationCacheError::Io)?;
    fs::rename(&temporary, path).map_err(|_| ConfigurationCacheError::Io)
}
```

Compile and validate the policy, dictionaries, regexes, and scanner limits before swapping `current`. Preserve last-known-good on every parse, signature, audience, rollback, or compilation failure. Treat compiled runtime state as derived cache data; the signed canonical document remains the source of truth.

---

### `crates/dlp-agent-core/tests/policy_activation.rs` (test, file-I/O)

**Analog:** `crates/dlp-agent-core/tests/enrollment_activation.rs` lines 109-139, 153-305, 369-477.

Copy its real temporary-directory fixture and signed-bundle helpers. Assert that a higher valid version activates, invalid/unsupported policy data leaves both current and LKG pointers unchanged, concurrent activations serialize correctly, restart reloads the same compiled semantics, rollback is rejected, and two device audiences cannot consume the same bundle.

---

### `migrations/<next>_policy_lifecycle.sql` (migration, CRUD)

**Analogs:** Root migrations `202608070001_walking_skeleton.sql` lines 1-36 and `202608070003_authenticated_routes.sql` lines 1-19.

**Constraint-first schema pattern:**

```sql
CREATE TABLE signed_configurations (
    device_id UUID NOT NULL REFERENCES devices(id),
    version BIGINT NOT NULL CHECK (version > 0),
    signed_payload BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, version)
);

CREATE UNIQUE INDEX one_active_credential_per_device
    ON device_credentials (device_id)
    WHERE revoked_at IS NULL;
```

Use immutable published policy-version rows and separate assignment rows. Put lifecycle invariants in PostgreSQL (`CHECK`, foreign keys, uniqueness, and partial unique indexes) so two concurrent publishers/assigners cannot create two versions with the same policy/version or an invalid default. Do not overwrite published content; assignments point at a published version.

---

### `crates/dlp-server/src/repository.rs` (service, CRUD)

**Analog:** Existing transactional repository operations.

**Locked transaction pattern** (`crates/dlp-server/src/repository.rs` lines 31-123):

```rust
let mut transaction = self.pool.begin().await.map_err(|_| RouteRepositoryError::Unavailable)?;
let row = sqlx::query(... "FOR UPDATE")
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| RouteRepositoryError::Unavailable)?;

// Validate current state, then insert/update within the same transaction.
transaction
    .commit()
    .await
    .map_err(|_| RouteRepositoryError::Unavailable)?;
```

**Atomic single-use transition pattern** (`crates/dlp-server/src/repository.rs` lines 126-173):

```rust
let result = sqlx::query(
    "UPDATE enrollment_tokens
     SET consumed_at = NOW()
     WHERE token_digest = $1 AND consumed_at IS NULL AND expires_at > NOW()"
)
.execute(&mut *transaction)
.await?;

if result.rows_affected() != 1 {
    return Err(RouteRepositoryError::Conflict);
}
```

Implement draft edits, publish, set-default, and device assignment as narrow repository methods with transactions around state transitions. Publication should insert immutable canonical content and fail on duplicate version/state conflicts. Assignment and default selection should reference already-published versions. Keep authorization out of repository SQL except where the repository is resolving a certificate identity to a stored role.

---

### `crates/dlp-server/src/tls.rs` (middleware, request-response)

**Analog:** Existing TLS-derived identities.

**Authenticated identity pattern** (`crates/dlp-server/src/tls.rs` lines 297-353):

```rust
#[derive(Clone, Debug)]
pub struct AuthenticatedAdmin {
    pub administrator_id: AdministratorId,
}

#[derive(Clone, Debug)]
pub struct AuthenticatedDevice {
    pub device_id: DeviceId,
}
```

The listener authenticates the peer certificate before HTTP handling (`tls.rs` lines 214-295), and forwarded identity headers are rejected (`tls.rs` lines 316-319). Reuse these request extensions for policy APIs. Do not add bearer/header fallbacks. Resolve administrator vs auditor authority from the authenticated administrator record; device assignment fetches must use the authenticated `DeviceId`, never a device ID supplied solely in a path/body.

---

### `crates/dlp-server/src/routes.rs` (controller, request-response)

**Analog:** Existing authenticated route partitions and configuration handler.

**Router and guard pattern** (`crates/dlp-server/src/routes.rs` lines 163-232):

```rust
pub fn api_v1_router(state: RouteState) -> Router {
    Router::new()
        .route("/configuration", get(fetch_configuration))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_active_device,
        ))
        .with_state(state)
}

async fn require_administrator(
    Extension(identity): Extension<AuthenticatedAdmin>,
    State(state): State<RouteState>,
    request: Request,
    next: Next,
) -> Result<Response, RouteError> {
    state.repository.require_administrator(&identity).await?;
    Ok(next.run(request).await)
}
```

**Stable response/error pattern** (`crates/dlp-server/src/routes.rs` lines 147-161, 315-353):

```rust
impl IntoResponse for RouteError {
    fn into_response(self) -> Response {
        let (status, code) = match self { ... };
        (status, Json(json!({ "error": code }))).into_response()
    }
}
```

Create separate administrator mutation routes, administrator/auditor inspection routes, and device assignment retrieval. Validate path/body version, count, and size bounds before repository calls. Publish should canonicalize and sign only after validation succeeds. Inspection responses may expose policy metadata and validation findings, but never private key material, plaintext samples, or unbounded internal errors.

---

### `crates/dlpctl/src/main.rs` and `crates/dlpctl/src/lib.rs` (controller/service, request-response)

**Analogs:** Strict CLI parser (`main.rs` lines 136-247) and mTLS client (`lib.rs` lines 107-218).

**Command grammar pattern:**

```rust
enum Command {
    Provision(ProvisionArgs),
    Enroll(EnrollArgs),
}

fn parse_command(arguments: impl Iterator<Item = String>) -> Result<Command, CliError> {
    // Exact subcommand/options, required values, and rejection of trailing input.
}
```

**Stable CLI failure pattern** (`crates/dlpctl/src/main.rs` lines 221-247):

```rust
impl CliError {
    fn code(&self) -> &'static str {
        match self {
            Self::Usage => "usage_error",
            Self::Transport => "transport_error",
            Self::Server => "server_error",
        }
    }
}
```

Add exact subcommands for draft create/edit, local validate, inspect, publish, set-default, and assign-device. Keep parse/validate separate from network dispatch. The library should own typed API request/response serialization and reuse the existing HTTPS/mTLS client builder; `main.rs` should format human output and stable machine-readable failure codes. Local validate and server publish must use the same canonical policy schema and validation rules.

---

### `crates/dlp-server/tests/policy_lifecycle.rs` (test, CRUD)

**Analogs:** Repository contract tests in `tests/e2e/server_enrollment.rs` lines 84-163 and route request helpers beginning around line 378.

Test draft mutation, validation failure, immutable publish, duplicate-version conflict, set-default, explicit device assignment, auditor read-only access, administrator mutation access, and TLS-derived identity rejection. Include concurrent publication/assignment cases against PostgreSQL when the database test harness is available.

---

### `crates/dlp-server/tests/policy_distribution.rs` (test, request-response)

**Analog:** Signed configuration distribution in `tests/e2e/server_enrollment.rs` lines 200-269. The new test is placed under `crates/dlp-server/tests/` so `cargo test -p dlp-server --test policy_distribution` discovers it without an additional `[[test]]` registration.

Exercise the real path: administrator publishes and assigns; authenticated device fetches only its assignment; server reconstructs canonical signed bytes; agent verifies/activates; the evaluator produces the expected decision; an invalid or older assignment leaves LKG active. Assert device audience, monotonic version, content digest, signature, and exact canonical round-trip.

---

### `crates/dlp-storage/src/format.rs` (model, file-I/O)

**Analog:** `EncryptedManifestV1` in the same file (`format.rs` lines 141-193).

**Bounded explicit codec pattern:**

```rust
pub struct EncryptedManifestV1 {
    pub generation: u64,
    pub plaintext_len: u64,
    pub chunks: Vec<ChunkReferenceV1>,
}

impl EncryptedManifestV1 {
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> { ... }
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        // Validate version, exact lengths, maximum count, and trailing bytes.
    }
}
```

If Phase 2 needs staging metadata, extend/version the explicit codec rather than using an unbounded general-purpose serializer. Persist only opaque operation IDs, hashes, lengths, staged chunk references, and generation state; never persist plaintext inspection buffers or warn-notification text.

---

### `crates/dlp-storage/src/store.rs` (service, file-I/O)

**Analog:** Existing write staging and durable publication (`store.rs` lines 206-345).

**Current publication boundary:**

```rust
pub fn write_file(&self, handle: &FileHandle, offset: u64, bytes: &[u8]) -> Result<usize, StoreError> {
    // Update per-handle staged plaintext/chunks only.
}

pub fn flush_file(&self, handle: &FileHandle) -> Result<(), StoreError> {
    // Encrypt staged data, publish a new manifest generation, then select it.
}
```

Split the boundary into explicit prepare/inspect and commit/abort semantics while preserving current generation isolation. Reads must continue authenticating/decrypting the selected generation before returning data (`store.rs` lines 346-452). A block, warn, scanner error, timeout, service outage, or crash must discard/ignore staged data and leave the previously selected generation authoritative. Avoid placing policy semantics in storage; storage should expose bounded staged content to the enforcement layer and apply an explicit commit token/result.

---

### `crates/dlp-storage/tests/policy_staging.rs` (test, file-I/O)

**Analog:** `crates/dlp-storage/tests/operations.rs` lines 1-16 and 51-147.

Reuse its deterministic store fixture. Prove that allow commits a new generation; block/warn/inspection failure never changes selected generation; abort is idempotent; crash/reopen ignores incomplete staging; concurrent handles remain isolated; committed ciphertext authenticates; and no inspection plaintext is present in durable files.

---

### `crates/dlp-windows-drive/src/filesystem.rs` (controller, request-response)

**Analog:** Existing Dokan callback implementation.

**Read/export enforcement insertion point** (`filesystem.rs` lines 536-552):

```rust
fn read_file(...) -> OperationResult<u32> {
    let bytes = self
        .store
        .read_file(&handle, offset, buffer.len())
        .map_err(map_storage_error)?;
    buffer[..bytes.len()].copy_from_slice(&bytes);
    Ok(bytes.len() as u32)
}
```

Evaluate export after authenticated store read/inspection has produced the bounded facts, but before `copy_from_slice` exposes plaintext to the caller. A deny returns `STATUS_ACCESS_DENIED` and copies zero bytes.

**Write/import enforcement insertion point** (`filesystem.rs` lines 554-599):

```rust
fn write_file(...) -> OperationResult<u32> {
    let written = self
        .store
        .write_file(&handle, offset, data)
        .map_err(map_storage_error)?;
    self.store.flush_file(&handle).map_err(map_storage_error)?;
    Ok(written as u32)
}
```

Replace the immediate publish with stage -> inspect -> evaluate -> commit/abort. Evaluate before the current flush/publication line. Apply the same pre-mutation rule to create, overwrite/truncate, rename, delete, and cleanup paths (`filesystem.rs` lines 246-302, 331-460). Derive `read = export` and `create/write = import` in one shared conversion function so callbacks cannot drift.

---

### `crates/dlp-windows-drive/src/status.rs` (utility, transform)

**Analog:** Existing centralized NTSTATUS mapping (`status.rs` lines 5-15, 38-56).

```rust
pub const STATUS_SUCCESS: NTSTATUS = 0;
pub const STATUS_INVALID_PARAMETER: NTSTATUS = 0xC000_000D_u32 as i32;

pub fn map_storage_error(error: StoreError) -> NTSTATUS {
    match error {
        StoreError::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        _ => STATUS_UNSUCCESSFUL,
    }
}
```

Add `STATUS_ACCESS_DENIED` (`0xC0000022`) and map all authoritative block/warn/no-grant/inspection-failure results to it. Do not expose rule text or scanner detail through NTSTATUS.

---

### `crates/dlp-windows-drive/tests/policy_enforcement.rs` (test, request-response)

**Analog:** `crates/dlp-windows-drive/tests/callback_contract.rs` lines 1-100.

Use the existing callback contract style to assert stable NTSTATUS values and source/runtime boundaries. Cover read-before-copy, write-before-publish, create/overwrite/rename/delete, deny with zero partial plaintext, warn without grant, warn with an exact valid grant, mismatched/expired/replayed grants, service unavailable, scanner failure, and prior-generation preservation.

---

### `crates/dlp-windows-service/src/pipe.rs` (middleware, request-response)

**Analog:** Existing actor pipe protocol and kernel identity verification.

**Bounded versioned message pattern** (`pipe.rs` lines 15-59, 120-141):

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct ActorPipeRequest {
    pub version: u16,
    pub session_id: u32,
    pub store_id: String,
    pub generation: u64,
}

fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, PipeAuthError> {
    let payload = serde_json::to_vec(value).map_err(|_| PipeAuthError::Malformed)?;
    // Prefix a bounded length before payload.
}
```

**Identity-before-request pattern** (`pipe.rs` lines 394-445):

```rust
let client_identity = verify_named_pipe_client_identity(pipe_handle)?;
if client_identity.session_id != expected.session_id
    || client_identity.sid != expected.sid
{
    return Err(PipeAuthError::IdentityMismatch);
}
let request = read_bounded_frame(pipe_handle)?;
validate_request(&request, expected)?;
```

Use a separate versioned companion channel or extend this framing without weakening it. The service must verify the companion process token SID/session through the kernel pipe endpoint before accepting `Proceed once`. The message should contain only an opaque challenge ID and action; bind server-side state to SID, session, store, generation, operation, file identity, content/policy fingerprint, expiry, and one-use status.

---

### `crates/dlp-windows-service/src/session.rs` (service, event-driven)

**Analog:** Existing per-user actor lifecycle.

**Generation-bound session identity pattern** (`session.rs` lines 63-114):

```rust
pub struct EligibleSession {
    pub session_id: u32,
    pub user_sid: String,
    pub store_id: StoreId,
    pub generation: u64,
}
```

**Injected launcher seam** (`session.rs` lines 744-757):

```rust
pub trait ActorLauncher: Send + Sync {
    fn launch(&self, session: &EligibleSession, pipe_name: &str) -> Result<LaunchedActor, SessionError>;
}
```

**Lifecycle pattern** (`session.rs` lines 988-1076): discover logon -> create unpredictable authenticated pipe -> load per-user key/material -> launch with `CreateProcessAsUserW` -> authenticate actor -> mark running. Companion lifecycle should use the same SID/session ownership and stop/restart cleanup (`session.rs` lines 1078-1187). Do not make the interactive companion authoritative for grants or policy decisions.

---

### `crates/dlp-windows-service/src/service.rs` (service, event-driven)

**Analog:** Existing fail-closed service startup and poll/event loop.

**Fail-closed startup pattern** (`service.rs` lines 130-216):

```rust
pub fn run_service(context: ServiceContext) -> Result<(), ServiceError> {
    context.validate()?;
    let runtime = context.initialize_runtime()?;
    runtime.run()
}
```

**Redacted diagnostic pattern** (`service.rs` lines 226-247): project only safe drive/session state into logs/status. Add the authoritative in-memory grant registry and notification dispatch beside this service-owned lifecycle. On service restart, session end, policy/config change, content change, or expiry, invalidate outstanding challenges/grants. Use a monotonic clock for TTL evaluation and a bounded registry with deterministic eviction. If the companion is absent or IPC fails, warn remains denied.

---

### `crates/dlp-windows-service/src/grants.rs` (inferred service, event-driven)

**Partial analogs:** `pipe.rs` identity/request validation and `session.rs` generation binding.

Use a single mutex-protected or actor-owned registry with typed keys rather than distributing grant state across callbacks. Follow the atomic transition shape of `repository.rs::consume_token` lines 126-173: lookup exact binding, verify not expired/consumed, mark consumed, and return success in one critical section. Store fingerprints/opaque identifiers only. Tests must control the clock and prove exact-match, TTL, one-use, replay rejection, and invalidation behavior.

---

### `crates/dlp-windows-service/src/notification.rs` and `src/bin/dlp-companion.rs` (provider/component, event-driven)

**Closest process analog:** `crates/dlp-windows-drive/src/bin/dlp-drive-host.rs` lines 1-17, 19-44, 73-196, 198-306.

```rust
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", error.code());
            ExitCode::from(error.exit_code())
        }
    }
}
```

Copy the exact argument grammar, stable fail-closed exit codes, service pipe handshake, and non-sensitive errors from `dlp-drive-host`. The companion should render a privacy-safe toast containing a generic operation label and policy/rule display label, never content, filename, or path. `Proceed once` sends only the opaque challenge ID back through authenticated IPC. Toast deduplication by Tag+Group is presentation-only; each operation still requires a distinct service-owned challenge/grant.

There is no in-repo Windows App SDK/WinRT notification provider analog. Follow official platform API patterns selected during implementation for activation registration, per-user execution, Tag+Group replacement, and cleanup; keep all platform-specific FFI inside the Windows service crate and expose a small safe trait for tests.

---

### `crates/dlp-windows-service/src/lib.rs` and `Cargo.toml` (config, batch)

**Analog:** Existing module exports and Windows feature declarations.

Add only the modules selected by the planner and expose narrow safe types to tests. Follow the current `windows` crate feature-list style in `Cargo.toml`; enable only namespaces required by notification and token/process APIs. Keep `unsafe` in minimal Windows adapter functions because workspace code forbids unsafe by default elsewhere.

---

### `crates/dlp-windows-service/tests/companion_grants.rs` (test, event-driven)

**Analog:** `crates/dlp-windows-service/tests/session_lifecycle.rs` lines 7-153 and 258-403.

Reuse injected fakes for session discovery, launcher, pipe, clock, and notifier. Prove multi-session/SID isolation, companion launch/restart, authenticated reply, exact grant binding, one-use consumption, expiry, stale policy/content invalidation, dedupe without shared authorization, redacted payloads, and fail-closed behavior when launch/notification/IPC fails.

---

### `tests/windows/Invoke-Phase2PolicySmoke.ps1` (test, batch)

**Analog:** `tests/windows/Invoke-Phase1Matrix.ps1` lines 1-249.

Copy its strict parameter block, repository/fixture resolution, named assertions, remoting helpers, scenario switch, and timestamped JSON/evidence bundle. Add allow, allow-and-audit, block, warn, proceed-once, replay, expiry, wrong-session, service-restart, and scanner-failure scenarios. Evidence must contain IDs, decisions, status codes, hashes, timestamps, and redacted event fields—not sampled plaintext or user paths.

## Shared Patterns

### Authentication and Authorization

**Sources:** `crates/dlp-server/src/tls.rs` lines 214-353; `crates/dlp-server/src/routes.rs` lines 163-232; `crates/dlp-windows-service/src/pipe.rs` lines 394-445.

Apply TLS-derived identities to all server policy routes and kernel-verified SID/session identity to companion IPC. Never trust forwarded identity headers, body-supplied device identity, or the companion UI as an authority.

### Stable, Redacted Errors

**Sources:** `crates/dlp-domain/src/lib.rs` lines 27-43; `crates/dlp-server/src/routes.rs` lines 147-161; `crates/dlpctl/src/main.rs` lines 221-247; `crates/dlp-windows-service/src/pipe.rs` lines 90-118.

Use typed internal errors mapped to stable codes/statuses. Logs, HTTP bodies, CLI output, pipe errors, and toasts must not contain plaintext content, filenames, paths, keys, signatures, or raw parser/regex errors.

### Canonicalization, Bounds, and Validation

**Sources:** `crates/dlp-protocol/src/lib.rs` lines 317-490; `crates/dlp-storage/src/format.rs` lines 1-193.

Every persisted/signed/IPC document has an explicit version, fixed canonical field order, explicit length/count limits, exact decode with trailing-input rejection, and validation before activation or mutation. Regex/dictionary/content scans also need time/byte/match/depth limits.

### Verify/Inspect Before Publish

**Sources:** `crates/dlp-agent-core/src/config_cache.rs` lines 105-184; `crates/dlp-storage/src/store.rs` lines 206-345; `crates/dlp-windows-drive/src/filesystem.rs` lines 536-599.

Use the common state transition `stage -> validate/inspect -> decide -> atomic publish`, with failure preserving the prior authoritative state. For reads, evaluate before plaintext copy; for writes and metadata mutations, evaluate before durable publication/mutation.

### Determinism and Single-Use Transitions

**Sources:** `crates/dlp-policy/src/lib.rs` lines 36-89; `crates/dlp-server/src/repository.rs` lines 126-173.

Make ordering explicit and consume grants atomically. A UI dedupe key must never serve as an authorization key. Time is an input only to grant expiry and operational limits, not policy rule ordering.

### Testability Through Narrow Ports

**Sources:** `crates/dlp-server/src/repository.rs` lines 539-718; `crates/dlp-windows-service/src/session.rs` lines 744-757; `crates/dlp-windows-service/tests/session_lifecycle.rs` lines 7-153.

Hide databases, clocks, process launch, notifications, and pipes behind narrow traits. Unit tests use deterministic in-memory/fake implementations; integration tests retain at least one real PostgreSQL, filesystem, named-pipe, and Windows smoke path.

## No Analog Found

| File | Role | Data Flow | Reason / Planner Guidance |
|---|---|---|---|
| `crates/dlp-windows-service/src/notification.rs` | provider | event-driven | No notification/App SDK/WinRT provider exists in the repository. Use the process, redaction, and trait-injection patterns above plus official platform API guidance. |
| `crates/dlp-windows-service/src/bin/dlp-companion.rs` (notification UI portion) | component | event-driven | `dlp-drive-host` is a strong lifecycle/IPC analog, but it has no interactive notification activation or Tag+Group behavior. Keep UI thin and service authority explicit. |

## Metadata

**Analog search scope:** `crates/dlp-domain`, `dlp-policy`, `dlp-protocol`, `dlp-agent-core`, `dlp-server`, `dlpctl`, `dlp-storage`, `dlp-windows-drive`, `dlp-windows-service`, root `migrations`, `tests/e2e`, and `tests/windows`.

**Files scanned:** 29 source, manifest, migration, and test files, plus phase context/research.

**GitNexus use:** The repository index was refreshed before concept and symbol queries. GitNexus still reported a two-commit freshness lag after refresh, and `DlpFileSystemContext::read` had unresolved receiver call sites, so graph results for that callback were treated as a lower bound and confirmed against source. No source files were edited.

**Pattern extraction date:** 2026-08-29
