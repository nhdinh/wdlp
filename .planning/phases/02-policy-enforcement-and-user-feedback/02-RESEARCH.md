# Phase 2: Policy Enforcement and User Feedback - Research

**Researched:** 2026-08-29  
**Domain:** Deterministic DLP policy lifecycle, endpoint enforcement, and authenticated Windows feedback  
**Confidence:** HIGH for in-repo seams and locked behavior; MEDIUM for Windows notification integration; LOW for discretionary numeric ceilings

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

### Policy Authoring and Publication
- **D-01:** `dlpctl` is the Phase 2 policy-authoring surface. It must support creating and editing drafts, validation, inspection, immutable publication, default assignment, and per-device assignment. A policy-management web UI is not part of Phase 2.
- **D-02:** Drafts remain mutable until validation and publication. Publishing creates a new immutable policy version; published versions are never edited in place. — **Reversibility:** costly — changing this later would require policy-history migration and new server/CLI mutation semantics.
- **D-03:** Published policies use an organization-wide default assignment with optional per-device overrides. Device-group assignment and staged group rollout remain v2 capabilities.
- **D-04:** Publication has no endpoint effect by itself. Separate `set-default` and `assign-device` operations change distribution; the selected signed configuration becomes effective on the endpoint's next successful poll and activation.

### Rule Matching and Conflict Resolution
- **D-05:** When multiple rules match, the highest numeric priority wins. Equal priorities choose the most restrictive action in this order: `block`, `warn`, `allow_and_audit`, `allow`; a stable rule ID resolves any remaining tie. — **Reversibility:** costly — published policy behavior, tests, reason codes, and enforcement evidence depend on this precedence contract.
- **D-06:** Conditions inside one rule use flat AND semantics. An individual condition may contain a bounded `any_of` value list; administrators express broader OR logic with separate rules.
- **D-07:** Every policy must explicitly declare its no-match default action. New-policy templates start with `allow`; decisions produced through this fallback use the stable `default_action` reason.
- **D-08:** If a rule requires context the drive cannot observe, that rule does not match. Evaluation continues through the remaining rules and records `input_unavailable`; the policy default applies only if no other rule matches.
- **D-09:** `require_justification` remains invalid for activation and must be rejected during server-side validation and compilation.

### Enforcement Timing and Detector Limits
- **D-10:** Runtime operation mapping is deliberately simple and deterministic: every read is classified as `export`, and every create/write is classified as `import`. Process identity and ETW signals may enrich enforcement-event metadata but do not alter this classification.
- **D-11:** Read/export policy approval occurs before the first plaintext byte is returned. Write/import content is staged and evaluated before durable publication. Rename and delete are evaluated before mutation. — **Reversibility:** costly — this timing changes WinFsp callback behavior, encrypted-store commit semantics, and application-visible errors.
- **D-12:** Content inspection is deterministic and bounded. Detectors scan a configured prefix under agent-enforced hard maxima; administrator regexes have pattern-length, nesting, compiled-size, and memory limits. Full-file hash rules may use an authenticated stored content digest without rereading the complete file.
- **D-13:** Reaching the configured prefix boundary is a successful bounded scan, not an error. The detector's semantics explicitly cover only that configured prefix.
- **D-14:** If a required detector cannot complete because of corruption, decoding failure, a missing authenticated digest, or an internal resource error, the operation fails closed with stable reason `inspection_failed`. The result identifies the affected rule, creates an enforcement event, and supplies safe remediation guidance.

### Warn, Block, and User Feedback
- **D-15:** `block` always denies. `warn` denies the current operation and offers an authenticated **Proceed once** action; no business justification is collected in Phase 2.
- **D-16:** Proceed once creates a short-lived, single-use grant bound to the exact user SID, file identity/path, operation, matched rule, and policy version. The service atomically consumes the grant on the next matching attempt. — **Reversibility:** costly — this becomes a security-sensitive service/companion IPC and enforcement contract.
- **D-17:** Toasts show only the base file name, operation, administrator-authored safe rule display name, stable reason, and concise remediation. They never expose file content, detector matches, full paths, SIDs, secrets, or internal identifiers.
- **D-18:** Always display the first toast for a decision key. During a short window, group repeats for the same user, file, operation, rule, action, and policy version and update a count. Notification deduplication never suppresses enforcement-event creation.
- **D-19:** The companion remains a per-user process and authenticates every request to the service with the caller's Windows identity. The Windows service remains authoritative and never displays interactive UI itself.

### the agent's Discretion
- Choose exact `dlpctl` command names and JSON field names while preserving the lifecycle and assignment model above.
- Choose conservative numeric maxima for scan prefixes, regex pattern/compiled sizes, dictionary sizes, and detector resource use; all limits must be configurable within hard agent ceilings.
- Choose the brief Proceed-once expiry and toast-deduplication window; neither may broaden the exact binding or single-use semantics.
- Choose safe operator-facing wording and stable error-code names where a decision above does not prescribe one.

### Deferred Ideas (OUT OF SCOPE)
- Device-group assignment and staged group rollout remain v2 (`ADM-V2-01`).
- A full policy administration web interface remains v2 (`ADM-V2-03`).
- Kernel minifilter enforcement and OS-wide destination interception remain outside the MVP and the project's user-space-only boundary.
- `require_justification` and collection of business justification remain post-MVP (`POL-V2-01`).
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| SRV-02 | Support administrator authentication with basic admin and auditor roles; auditors cannot change policies or configuration. | Repository-backed administrator/auditor roles and route matrix. [VERIFIED: .planning/REQUIREMENTS.md:18] |
| SRV-05 | Support creation, validation, versioning, signing, and assignment of policies. | Draft/publish/assign API lifecycle, compiler boundary, and signing seam. [VERIFIED: .planning/REQUIREMENTS.md:21] |
| SRV-06 | Produce immutable, signed configuration bundles containing policy versions, schema version, agent settings, effective time, and offline allowance. | Bundle V2 payload and insert-only policy/configuration version storage. [VERIFIED: .planning/REQUIREMENTS.md:22] |
| SRV-07 | Distribute configuration bundles to agents and report deployment status. | Desired-assignment materialization, device polling, and health reporting. [VERIFIED: .planning/REQUIREMENTS.md:23] |
| POL-01 | Evaluate policies deterministically for the same policy version and input. | Canonical IR and priority/restrictiveness/stable-ID selection. [VERIFIED: .planning/REQUIREMENTS.md:36] |
| POL-02 | Support conditions on file properties: name, extension, MIME/type, path, owner, and size. | Explicit metadata condition algebra and unavailable-input semantics. [VERIFIED: .planning/REQUIREMENTS.md:37] |
| POL-03 | Support bounded content detectors: regular expressions, dictionaries, hashes, and structured identifiers. | Regex, dictionary, prefix, digest, and structured-identifier detector limits. [VERIFIED: .planning/REQUIREMENTS.md:38] |
| POL-04 | Support operation context: read, write, import, export, copy, and delete. | Operation vocabulary plus deterministic callback mapping. [VERIFIED: .planning/REQUIREMENTS.md:39] |
| POL-05 | Support destination context when observable at the drive boundary. | Tri-state observable/unavailable destination input. [VERIFIED: .planning/REQUIREMENTS.md:40] |
| POL-06 | Support actions: `allow`, `block`, `allow_and_audit`, and `warn`. | Runtime-only action type and callback result mapping. [VERIFIED: .planning/REQUIREMENTS.md:41] |
| POL-07 | Reject policies that activate `require_justification` until the workflow is implemented. | Server compiler and agent activation defense in depth. [VERIFIED: .planning/REQUIREMENTS.md:42] |
| POL-08 | Define explicit rule priority and conflict-resolution behavior. | Priority, restrictiveness, and stable rule-ID ordering. [VERIFIED: .planning/REQUIREMENTS.md:43] |
| POL-09 | Record a reason code for every enforcement decision. | Primary reason, observations, and safe remediation model. [VERIFIED: .planning/REQUIREMENTS.md:44] |
| POL-10 | Be unit-testable independent of Windows APIs. | Portable domain/policy crates and table/property tests. [VERIFIED: .planning/REQUIREMENTS.md:45] |
| CRY-05 | Support server key rotation with a key identifier in each bundle. | Old-key-authorized bounded verification keyring transition. [VERIFIED: .planning/REQUIREMENTS.md:53] |
| AGT-10 | Recover cleanly from service, process, and machine restarts. | Current/LKG preservation, grant restart behavior, and recovery tests. [VERIFIED: .planning/REQUIREMENTS.md:66] |
| DRV-05 | Prevent one user from mounting or accessing another user's store through supported interfaces. | SID-bound drive/service routing and multi-user tests. [VERIFIED: .planning/REQUIREMENTS.md:75] |
| DRV-08 | Return appropriate access-denied errors and clear messages for policy-denied operations. | Stable NTSTATUS mapping and service-to-companion feedback. [VERIFIED: .planning/REQUIREMENTS.md:78] |
| UI-01 | Provide a small per-user companion process for Windows session interaction. | Session-managed companion with purpose-limited IPC. [VERIFIED: .planning/REQUIREMENTS.md:83] |
| UI-02 | Authenticate companion process requests to the service using the caller's Windows identity. | Named-pipe DACL, PID, impersonation token SID/session. [VERIFIED: .planning/REQUIREMENTS.md:84] |
| UI-03 | Show a Windows toast when an operation is blocked, including file name, rule reason, and remediation guidance without exposing sensitive content. | Minimal toast projection, grouping, and action activation. [VERIFIED: .planning/REQUIREMENTS.md:85] |
| TST-07 | Write integration tests for per-user drive isolation and device revocation. | Windows lab matrix covering SID isolation, grants, and revoked credentials. [VERIFIED: .planning/REQUIREMENTS.md:102] |
</phase_requirements>

## Summary

Phase 2 should extend the existing portable policy and signed-configuration seams rather than introduce a parallel policy runtime. The current evaluator already establishes deterministic ordering, the agent cache already verifies and atomically activates content-addressed signed configurations, and the encrypted store already stages writes before `flush_handle`. [VERIFIED: crates/dlp-policy/src/lib.rs:36-91; crates/dlp-agent-core/src/config_cache.rs:93-241; crates/dlp-storage/src/store.rs:329-446] The critical implementation change is to make policy evaluation part of the filesystem transaction boundary: authorize a read before copying plaintext, evaluate a complete staged import before `flush_handle`, and authorize rename/delete before namespace mutation. [VERIFIED: crates/dlp-windows-drive/src/filesystem.rs:411-599]

The server should own mutable authoring and canonical compilation; endpoints should consume immutable compiled policy snapshots only after signed-bundle verification and bounded detector materialization. [VERIFIED: .planning/docs/adrs/ADR-004-policy-expression.md:1-185; .planning/docs/adrs/ADR-005-policy-signing.md:1-177] Publication and assignment must remain separate. A transactionally selected desired policy can be materialized into the existing monotonically versioned, per-device signed configuration on poll, allowing default and device overrides without mutating a published policy. [VERIFIED: crates/dlp-server/src/routes.rs:79-152; crates/dlp-server/src/repository.rs:475-592]

User feedback is a separate trust boundary. The service should create every enforcement event synchronously, deny `warn` on the current attempt, and send a privacy-minimized notification to a per-user companion over purpose-limited authenticated IPC. The companion returns only an opaque notification identifier; the service resolves it and owns an exact, expiring, atomically consumed grant. Existing SID/session/PID/generation authentication is the right reusable pattern. [VERIFIED: crates/dlp-windows-service/src/pipe.rs:50-174; crates/dlp-windows-service/src/session.rs:1-320]

**Primary recommendation:** Plan Phase 2 as six ordered contracts—policy schema/compiler, immutable server lifecycle, signed activation/key rotation, decision-time drive enforcement, service event/grant authority, and per-user toast UI—with storage and Windows-registration migrations explicitly scheduled before end-to-end tests.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Draft/edit/validate/publish/assign | API / Backend | Database / Storage | Server owns authorization and canonical compilation; PostgreSQL owns immutability and assignment state. [VERIFIED: crates/dlp-server/src/routes.rs:16-152; crates/dlp-server/src/repository.rs:41-592] |
| CLI policy authoring | Browser / Client | API / Backend | `dlpctl` is a trusted client of authenticated server operations; it must not become an alternate compiler. [VERIFIED: crates/dlpctl/src/lib.rs:1-327] |
| Signed bundle selection/activation | API / Backend | Database / Storage | Server signs the effective assignment; agent verifies, stages, materializes, and atomically swaps. [VERIFIED: crates/dlp-protocol/src/lib.rs:317-488; crates/dlp-agent-core/src/config_cache.rs:93-241] |
| Metadata/content evaluation | API / Backend | Database / Storage | Portable endpoint policy engine owns deterministic decisions; encrypted store supplies staged bytes and authenticated digest. [VERIFIED: crates/dlp-policy/src/lib.rs:1-155; crates/dlp-storage/src/store.rs:329-446] |
| Read/write/rename/delete enforcement | API / Backend | Database / Storage | WinFsp callback adapter is the DLP boundary and must decide before externally visible release/mutation. [VERIFIED: crates/dlp-windows-drive/src/filesystem.rs:411-599] |
| Event creation and Proceed-once grants | API / Backend | Browser / Client | Windows service is authoritative; companion only renders and relays an opaque action. [VERIFIED: crates/dlp-windows-service/src/pipe.rs:50-174] |
| Windows toast display | Browser / Client | API / Backend | Interactive per-user process owns notification APIs; session-0 service must not display UI. [VERIFIED: .planning/docs/THREAT-MODEL.md:106-129] |

## Project Constraints (from AGENTS.md)

- Run GitNexus impact analysis before editing any function, class, or method; report callers, processes, and risk. [VERIFIED: AGENTS.md:8-14]
- Warn before edits if impact is HIGH or CRITICAL; treat UNKNOWN as unresolved and confirm it with text search. [VERIFIED: AGENTS.md:11-19]
- Use GitNexus semantic query/context for unfamiliar code and never substitute grep for graph impact analysis. [VERIFIED: AGENTS.md:13-17]
- Use graph-aware rename rather than find-and-replace. [VERIFIED: AGENTS.md:21-25]
- Run complete, non-partial GitNexus change detection before committing. [VERIFIED: AGENTS.md:9-12]
- Prefix every shell command with `rtk`; use `rtk passthrough <command>` only when exact output is required, and use `rtk powershell -Command` for PowerShell built-ins. [VERIFIED: C:/Users/nhdinh/.codex/RTK.md:1-30]
- Portable Rust crates forbid unsafe code; Windows FFI is isolated in Windows adapter crates. [VERIFIED: Cargo.toml:1-23; crates/dlp-windows-drive/Cargo.toml:5-21; crates/dlp-windows-service/Cargo.toml:5-28]

## Standard Stack

### Core

| Library / component | Version | Purpose | Why Standard |
|---------------------|---------|---------|--------------|
| Rust workspace | edition `2024`, MSRV `1.97` | Portable policy, protocol, service, and adapters | Existing project contract. [VERIFIED: Cargo.toml:17-23] |
| `serde` / `serde_json` | `1.0.229` / `1.0` | Versioned authoring schema, canonical IR, event and IPC messages | Already used across the policy-adjacent workspace. [VERIFIED: crates/dlp-windows-drive/Cargo.toml:12-13] |
| `sqlx` | `0.9.0` | Draft, immutable version, assignment, principal-role persistence | Existing PostgreSQL repository stack. [VERIFIED: crates/dlp-server/Cargo.toml:20-23] |
| `ed25519-dalek` | `3.0.0` | Configuration and key-transition signatures | Existing ADR-selected signing primitive and verifier. [VERIFIED: crates/dlp-crypto/Cargo.toml:12-15; .planning/docs/adrs/ADR-005-policy-signing.md:28-70] |
| `regex` | `1.13.1` (published 2026-07-15) | Bounded administrator regex detector | Official crate documents syntax-size and haystack bounds and `RegexBuilder` resource limits. [VERIFIED: https://docs.rs/regex/latest/regex/; crates.io registry; package-legitimacy check] |
| `aho-corasick` | `1.1.5` (published August 2026) | Deterministic multi-pattern dictionary detector | Official crate exposes builder/match semantics and heap-usage inspection suitable for activation limits. [VERIFIED: https://docs.rs/aho-corasick/latest/aho_corasick/; crates.io registry; package-legitimacy check] |
| `windows` | `0.62.2` | App notifications, named-pipe identity checks, service/session integration | Existing official Windows binding; add only the required notification/XML features. [VERIFIED: crates/dlp-windows-service/Cargo.toml:18-27; crates/dlp-windows-drive/Cargo.toml:15-20] |

### Supporting

| Library / component | Version | Purpose | When to Use |
|---------------------|---------|---------|-------------|
| `axum` | `0.8.9` | Administrator and device policy HTTP APIs | Extend the current authenticated router; do not add a web UI. [VERIFIED: crates/dlp-server/Cargo.toml:12-18] |
| `tokio` | `1.53.1` | Server, service IPC, and companion delivery concurrency | Preserve existing asynchronous service/server patterns. [VERIFIED: crates/dlp-windows-service/Cargo.toml:13-17] |
| `sha2` | `0.11` | Bundle and authenticated plaintext-content digests | Existing digest dependency; content digest must be authenticated by the encrypted manifest. [VERIFIED: crates/dlp-windows-drive/Cargo.toml:14-15; crates/dlp-protocol/Cargo.toml:9-12] |
| WinFsp | crate `0.13.0`; installed runtime `2.1.25156` | Filesystem enforcement boundary | Existing user-space drive contract. [VERIFIED: crates/dlp-windows-drive/Cargo.toml:14-17; environment probe] |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Declarative JSON + compiled IR | Embedded scripting language | Explicitly rejected by ADR-004 because it weakens bounded validation and deterministic execution. [VERIFIED: .planning/docs/adrs/ADR-004-policy-expression.md:18-45] |
| Direct `windows` bindings | Community toast wrapper | Adds an unnecessary security-sensitive dependency while the workspace already uses official bindings. [VERIFIED: crates/dlp-windows-service/Cargo.toml:18-27] |
| Aho-Corasick dictionary matcher | Repeated regex/string scans | Repeated scans multiply work by dictionary size and complicate a hard memory/time budget. [CITED: https://docs.rs/aho-corasick/latest/aho_corasick/]

**Installation:**

```bash
cargo add -p dlp-policy regex@=1.13.1 aho-corasick@=1.1.5
```

The exact dependency placement is a planning recommendation, not an existing repository value. [ASSUMED]

## Package Legitimacy Audit

| Package | Registry | Age | Downloads | Source Repo | Verdict | Disposition |
|---------|----------|-----|-----------|-------------|---------|-------------|
| `regex` | crates.io | Since 2014-12-13 | 18,057,440 recent weekly downloads | `github.com/rust-lang/regex` | OK | Approved [VERIFIED: crates.io registry; package-legitimacy check] |
| `aho-corasick` | crates.io | Since 2015-06-12 | 17,487,399 recent weekly downloads | `github.com/BurntSushi/aho-corasick` | OK | Approved [VERIFIED: crates.io registry; package-legitimacy check] |

**Packages removed due to [SLOP] verdict:** none. [VERIFIED: package-legitimacy check]  
**Packages flagged as suspicious [SUS]:** none. [VERIFIED: package-legitimacy check]

## Architecture Patterns

### System Architecture Diagram

```text
dlpctl + admin mTLS
        |
        v
draft JSON -> validate/compile -> immutable policy version
                                  |          |
                          set default     assign device
                                  \          /
                                   desired policy
                                         |
device mTLS poll -> per-device bundle version -> canonical sign -> PostgreSQL
                                         |
                                         v
agent verify key/audience/version -> bounded detector materialization
             | valid                         | invalid
             v                               v
    atomic current/LKG pointer          retain current/LKG
             |
             v
immutable evaluator snapshot -> authenticated per-user drive host
             |
      +------+------+----------------+
      |             |                |
 read/export   staged import    rename/delete
 before bytes  before publish   before mutation
      |             |                |
      +-------------+----------------+
                    v
       allow / audit / block / warn / inspection failure
                    |
             synchronous event
                    |
             Windows service authority
                    |
       privacy-safe per-user companion toast
                    |
              Proceed once action
                    |
      authenticated opaque IPC response
                    |
 exact TTL grant -> atomic consume on matching retry
```

### Recommended Project Structure

```text
crates/
├── dlp-domain/           # portable policy input/decision/event vocabulary
├── dlp-policy/           # authoring validation, canonical IR, bounded evaluator
├── dlp-protocol/         # signed bundle payload and service/companion wire contracts
├── dlp-server/           # draft/version/assignment APIs and repository
├── dlpctl/               # CLI commands only; calls server APIs
├── dlp-agent-core/       # verify, compile/materialize, atomic activation, keyring
├── dlp-storage/          # authenticated digest and staged candidate commit/abort
├── dlp-windows-drive/    # callback enforcement and access-denied mapping
└── dlp-windows-service/  # event authority, grants, companion lifecycle/IPC
tests/
├── e2e/                  # server-to-agent policy distribution
└── windows/              # mounted-drive, toast, multi-user, revocation lab smoke
```

This mapping follows current workspace boundaries; proposed new files within them remain planner discretion. [VERIFIED: Cargo.toml:1-17] [ASSUMED]

### Pattern 1: Authoring Schema → Canonical Runtime IR

**What:** Deserialize a versioned authoring document, reject unknown/unsupported constructs, normalize paths/extensions/dictionaries, compile bounded detector resources, and persist an immutable canonical IR. Repeat bounded materialization on the endpoint before activation. [VERIFIED: .planning/docs/adrs/ADR-004-policy-expression.md:46-145]

**When to use:** Every draft validation, publication, and endpoint activation.

The current runtime action values are quoted verbatim below; Phase 2 must keep authoring-only `require_justification` out of the activated action type. [VERIFIED: crates/dlp-domain/src/lib.rs:146-173]

```text
DATA_R7M2K9VX_START
Allow,
Block,
AllowAndAudit,
Warn,
RequireJustification,
DATA_R7M2K9VX_END
```

Recommended compiler shape (illustrative; names and limits are not yet repository contracts): [ASSUMED]

```rust
fn compile(authoring: PolicyDocumentV2, ceilings: DetectorCeilings)
    -> Result<CompiledPolicyV2, ValidationErrors>
{
    validate_required_default(authoring.default_action)?;
    reject_require_justification(&authoring)?;
    normalize_and_sort(authoring, ceilings)?;
    materialize_bounded_detectors(ceilings)
}
```

### Pattern 2: Tri-State Conditions with Separate Observations

**What:** A condition returns `Match`, `NoMatch`, or `InputUnavailable`. An unavailable input makes only that rule non-matching while appending the stable observation `input_unavailable`; it does not replace the eventual primary reason such as `matched_rule` or `default_action`. This avoids losing diagnostic evidence while preserving deterministic selection. [VERIFIED: 02-CONTEXT.md D-08]

**When to use:** Destination, process, owner, content digest, and other inputs that the drive may not be able to observe.

Current primary reasons are quoted verbatim. [VERIFIED: crates/dlp-domain/src/lib.rs:177-193]

```text
DATA_F4Q8N1HZ_START
MatchedRule,
EqualPriorityConflict,
DefaultAction,
EmptyPolicy,
DATA_F4Q8N1HZ_END
```

Adding `inspection_failed` and a separate observation collection is required by the locked context, but the exact Rust representation is planner discretion. [VERIFIED: 02-CONTEXT.md D-08,D-14] [ASSUMED]

### Pattern 3: Evaluate Before the Irreversible Boundary

**What:** Build a candidate view, evaluate, then commit or discard. A read evaluates before copying plaintext into the WinFsp output buffer. A write updates the encrypted store's staged generation, evaluates the complete candidate, and calls `flush_handle` only on success. Rename/delete decide before invoking the store mutation. [VERIFIED: crates/dlp-storage/src/store.rs:329-446; crates/dlp-windows-drive/src/filesystem.rs:411-599]

**When to use:** Every protected filesystem callback, including the first read byte and every durable import publication.

The current adapter calls `flush_handle` in its write callback, so inserting a check after the callback returns would be too late. [VERIFIED: crates/dlp-windows-drive/src/filesystem.rs:554-599]

### Pattern 4: Desired Assignment → Monotonic Signed Bundle

**What:** Keep immutable policy versions and mutable assignment pointers separate. Inside one PostgreSQL transaction, resolve per-device override before default, lock the device distribution cursor, and issue the next signed bundle version only when desired content changes. Unique constraints protect version identity; row locking serializes competing issuers. [CITED: https://www.postgresql.org/docs/current/ddl-constraints.html] [CITED: https://www.postgresql.org/docs/current/sql-select.html]

**When to use:** Default/device assignment changes and device configuration polling.

The existing signed envelope fields are quoted verbatim and must remain in the signing scope. [VERIFIED: crates/dlp-protocol/src/lib.rs:317-373]

```text
DATA_C3W6J8LP_START
pub version: u16,
pub schema_version: u16,
pub device_id: DeviceId,
pub bundle_version: BundleVersion,
pub issued_at_epoch_seconds: i64,
pub payload: Vec<u8>,
DATA_C3W6J8LP_END
```

### Pattern 5: Old-Key-Authorized Rotation

**What:** Replace the endpoint's single verification key with a bounded keyring. The currently trusted old key verifies a signed transition that introduces the new public key; an overlap period accepts both IDs, then new bundles advance under the new key. Never accept a self-introduced key before verification by an already trusted key. [VERIFIED: crates/dlp-crypto/src/lib.rs:230-326; .planning/docs/adrs/ADR-005-policy-signing.md:72-126]

**When to use:** CRY-05 rotation and all configuration verification after the first transition.

### Pattern 6: Opaque Notification Intent and Exact Grant

**What:** Persist an in-memory service intent keyed by an unguessable notification ID. The toast action returns only that ID. After authenticating the pipe caller, the service resolves the intent to the captured SID and creates a grant bound to SID, file identity and normalized path, operation, rule, action, and policy version. Matching retry atomically removes it. [VERIFIED: crates/dlp-windows-service/src/pipe.rs:50-174; 02-CONTEXT.md D-15,D-16,D-19]

**When to use:** Every `warn` decision. Service restart should invalidate outstanding grants to minimize authorization lifetime. [ASSUMED]

### Anti-Patterns to Avoid

- **Compile only on the server:** endpoint versions/resources can differ; activation must independently enforce hard ceilings before pointer swap. [VERIFIED: .planning/docs/adrs/ADR-004-policy-expression.md:112-145]
- **Serialize regex automata as trusted executable state:** sign canonical detector definitions and reconstruct bounded runtime objects locally. [ASSUMED]
- **Enforce after `read`/`flush_handle`:** plaintext or a durable generation has already crossed the boundary. [VERIFIED: crates/dlp-windows-drive/src/filesystem.rs:536-599]
- **Make publication deploy automatically:** contradicts D-04 and makes review unsafe. [VERIFIED: 02-CONTEXT.md D-04]
- **Trust SID or grant fields supplied in JSON:** identity must come from the impersonated named-pipe token and server-owned notification intent. [VERIFIED: crates/dlp-windows-service/src/pipe.rs:332-489]
- **Dedupe events with toasts:** only notification rendering is grouped; every decision still creates evidence. [VERIFIED: 02-CONTEXT.md D-18]
- **Show full path or detector match in UI/logs:** violates the Phase 2 privacy contract. [VERIFIED: 02-CONTEXT.md D-17]

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Regex parser/matcher | Custom expression engine | `regex::RegexBuilder` | Official implementation exposes nesting, compiled-size/DFA, and syntax controls; bound both pattern and haystack because worst case is proportional to both. [CITED: https://docs.rs/regex/latest/regex/] |
| Multi-pattern dictionary scan | One loop/search per term | `aho-corasick::AhoCorasickBuilder` | One deterministic automaton and heap accounting are easier to cap. [CITED: https://docs.rs/aho-corasick/latest/aho_corasick/] |
| Signature or key wrapping | Custom cryptography | Existing Ed25519 and AES-GCM stack | ADR-005 and the current crypto crate already define the trust model. [VERIFIED: crates/dlp-crypto/src/lib.rs:1-326] |
| Atomic configuration selector | Bespoke overwrite protocol | Existing content-addressed staging plus current/LKG pointer | It already rejects invalid/replayed bundles without replacing the selected configuration. [VERIFIED: crates/dlp-agent-core/src/config_cache.rs:93-241] |
| Toast framework | Third-party wrapper | Microsoft app-notification APIs through `windows` | The official model defines registration, activation, Tag/Group replacement, and update sequencing. [CITED: https://learn.microsoft.com/en-us/windows/apps/develop/notifications/app-notifications/app-notifications-quickstart] |
| IPC identity | Caller-supplied SID/token | Named-pipe DACL, kernel client PID, impersonation token SID/session | Existing code already implements and tests this boundary. [VERIFIED: crates/dlp-windows-service/src/pipe.rs:332-489] |
| Policy version immutability | Application convention alone | PostgreSQL constraints plus denied UPDATE/DELETE path | Database enforcement protects history across concurrent or future clients. [CITED: https://www.postgresql.org/docs/current/ddl-constraints.html] |

**Key insight:** Determinism and fail-closed behavior come from bounding and authenticating every transition—not from adding more branches inside the WinFsp callback.

## Runtime State Inventory

This phase is a schema/configuration/storage migration even though it is not a rename. The inventory prevents source-only planning from missing deployed state. [VERIFIED: migrations/202608070001_walking_skeleton.sql:1-92; crates/dlp-storage/src/format.rs:1-193]

| Category | Items Found | Action Required |
|----------|-------------|-----------------|
| Stored data | PostgreSQL currently stores per-device signed configuration schema/version history but has no policy draft/version/assignment tables. [VERIFIED: migrations/202608070001_walking_skeleton.sql:1-92] Encrypted file manifests carry generation, file ID, logical length, and chunk lengths but no authenticated plaintext digest. [VERIFIED: crates/dlp-storage/src/format.rs:141-193] Agent cache stores content-addressed bundles plus current/LKG pointers. [VERIFIED: crates/dlp-agent-core/src/config_cache.rs:93-241] | Add forward-only SQL migrations; preserve old signed rows; version the encrypted manifest and backfill authenticated digests or prevent hash-policy assignment until the affected files have trusted digests; preserve current/LKG across activation failures. |
| Live service config | Endpoint verification currently has one `key_id` and one verifying key, and server TLS treats authenticated administrator-CA peers as one administrator role. [VERIFIED: crates/dlp-crypto/src/lib.rs:230-326; crates/dlp-server/src/tls.rs:1-260] | Migrate to a bounded trust set/transition state and repository-resolved `admin`/`auditor` principals. Define bootstrap mapping for existing administrator certificates before enabling role checks. |
| OS-registered state | Windows service and per-user drive hosts already exist; no companion notification registration is present. [VERIFIED: crates/dlp-windows-service/src/session.rs:1-320; repository file inventory] Unpackaged desktop notifications require application identity/registration and activation wiring. [CITED: https://learn.microsoft.com/en-us/samples/microsoft/windows-classic-samples/desktop-toasts/] | Install/register the companion per user or per machine as selected by installer design, establish AppUserModelID/activation registration, and integrate its start/stop with authenticated user sessions. Verify registration on Windows 10 and 11. |
| Secrets/env vars | Existing configuration verification and signing material must remain valid through rotation; no secret-key rename is required. [VERIFIED: crates/dlp-crypto/src/lib.rs:230-326] | Add old/new public-key overlap state without exposing server signing keys. Preserve existing env/config names during migration. |
| Build artifacts | Service, drive host, CLI, agent, and new companion binaries must agree on versioned protocol and policy schemas. [VERIFIED: Cargo.toml:1-17] | Rebuild/deploy the set atomically enough that old endpoints reject unsupported schemas and retain LKG. No stale renamed package artifact was found. [VERIFIED: repository file inventory] |

## Common Pitfalls

### Pitfall 1: Treating Staged Write as Already Safe

**What goes wrong:** The drive stages encrypted bytes and immediately calls `flush_handle`; evaluating afterward cannot undo the visible committed generation. [VERIFIED: crates/dlp-windows-drive/src/filesystem.rs:554-599]  
**Why it happens:** The current callback was designed for encrypted durability, not a policy transaction.  
**How to avoid:** Split candidate write from publication, evaluate the complete candidate, then commit or explicitly abort.  
**Warning signs:** A deny test observes new content after reopening, or callback code calls `flush_handle` before the policy result.

### Pitfall 2: Losing `input_unavailable`

**What goes wrong:** A single reason enum cannot represent both the winning/default reason and unavailable inputs encountered along the way. [VERIFIED: crates/dlp-domain/src/lib.rs:177-193]  
**Why it happens:** Existing decisions were built for extension-only rules.  
**How to avoid:** Keep one primary reason and a sorted/deduplicated observation list; never make unavailable context a match. [VERIFIED: 02-CONTEXT.md D-08]  
**Warning signs:** Same policy produces different primary reasons based on rule iteration order.

### Pitfall 3: Resource Limits Only in JSON Validation

**What goes wrong:** A valid-looking bundle can cause excessive allocation or compile cost on the endpoint.  
**Why it happens:** Pattern length alone does not bound compiled size, and input length also affects search work. [CITED: https://docs.rs/regex/latest/regex/]  
**How to avoid:** Enforce hard ceilings on server publication and again during endpoint materialization; bound scanned bytes and dictionary automaton heap.  
**Warning signs:** Activation performs unbounded compilation before validation or swaps the pointer before materialization.

### Pitfall 4: Hash Rules on Legacy Files

**What goes wrong:** A full-file hash condition silently does not match or forces a full reread because legacy manifests lack an authenticated digest. [VERIFIED: crates/dlp-storage/src/format.rs:141-193]
**Why it happens:** Adding a field to new writes does not migrate old files.  
**How to avoid:** Specify a manifest-version migration/backfill and assignment readiness gate; until then, a required missing digest is `inspection_failed`. [VERIFIED: 02-CONTEXT.md D-12,D-14]  
**Warning signs:** Tests cover only files created after the upgrade.

### Pitfall 5: Role Name Without a Principal Source

**What goes wrong:** An `auditor` string in a request/header becomes an authorization bypass, or existing admin certificates are locked out.  
**Why it happens:** Current mTLS code proves a CA relationship but does not resolve an administrator/auditor role. [VERIFIED: crates/dlp-server/src/tls.rs:1-260]  
**How to avoid:** Map canonical certificate identity to a persisted role, seed existing administrators explicitly, and authorize every route server-side.  
**Warning signs:** Role is accepted from HTTP JSON/header or publication is reachable by auditor credentials.

### Pitfall 6: Toast Action as Authorization

**What goes wrong:** Replaying or altering toast arguments grants access to another user/file/policy.  
**Why it happens:** UI payload is treated as trusted state.  
**How to avoid:** Return an opaque ID, authenticate caller SID/session, resolve server-owned intent, and atomically consume an exact grant. Microsoft requires checking impersonation success and reverting impersonation afterward. [CITED: https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient]  
**Warning signs:** Companion sends authoritative SID/path/rule fields or grants survive service restart without an explicit secure persistence design.

### Pitfall 7: Notification Dedupe Suppresses Evidence

**What goes wrong:** Repeated denied operations disappear from enforcement history.  
**Why it happens:** One cache is reused for event and presentation throttling.  
**How to avoid:** Create the event first; use Tag+Group plus monotonic update sequence only for the toast. Microsoft documents same Tag/Group replacement and sequence-based stale-update rejection. [CITED: https://learn.microsoft.com/en-us/uwp/api/windows.ui.notifications.toastnotifier.update?view=winrt-26100]  
**Warning signs:** Event count equals toast count after a burst test.

### Pitfall 8: CRY-05 Becomes Trust-on-First-Use

**What goes wrong:** An attacker-supplied bundle introduces its own key and validates itself.  
**Why it happens:** Key material and data are activated in the same untrusted step.  
**How to avoid:** Require the already trusted key to authorize the transition, persist it monotonically, then accept new-key bundles during bounded overlap.  
**Warning signs:** Unknown `key_id` causes key import instead of `WrongKeyId`/transition verification.

## Code Examples

The examples below are architecture sketches, not compile-ready repository APIs; identifiers not quoted from current source are `[ASSUMED]`.

### Deterministic Selection with Availability Evidence

```rust
let mut observations = BTreeSet::new();
let mut matches = Vec::new();

for rule in policy.rules() {
    match rule.matches(input, detectors) {
        MatchOutcome::Match => matches.push(rule),
        MatchOutcome::NoMatch => {}
        MatchOutcome::InputUnavailable(kind) => {
            observations.insert((rule.id(), kind));
        }
        MatchOutcome::InspectionFailed(code) => {
            return Decision::inspection_failed(rule.id(), code, observations);
        }
    }
}

matches.sort_by_key(|rule| (
    Reverse(rule.priority()),
    Reverse(rule.action().restrictiveness()),
    rule.id(),
));
```

Current evaluator ordering is priority descending, action restrictiveness descending, then rule ID ascending. [VERIFIED: crates/dlp-policy/src/lib.rs:51-75]

### Write Candidate Transaction

```rust
store.write_handle(handle, offset, bytes)?;       // staged generation only
let candidate = store.inspect_staged(handle, scan_plan)?;
let decision = evaluator.evaluate(import_input(candidate));
event_sink.record(&decision)?;

match decision.effect() {
    Allow | AllowAndAudit => store.flush_handle(handle),
    Block | Warn => {
        store.abort_staged(handle)?;
        Err(NtStatus::access_denied())
    }
}
```

The existing staged-versus-committed behavior is verified, while `inspect_staged`, `abort_staged`, and the policy wrappers are proposed APIs. [VERIFIED: crates/dlp-storage/src/store.rs:329-446] [ASSUMED]

### Atomic Proceed-Once Consumption

```rust
fn consume_grant(&self, attempt: &Attempt) -> bool {
    let mut grants = self.grants.lock();
    let key = GrantKey::from_attempt(attempt);
    grants.remove_if(&key, |grant| grant.expires_at > now())
}
```

The data structure must implement exact equality over every D-16 binding and remove atomically; concrete locking and clock APIs are planner choices. [VERIFIED: 02-CONTEXT.md D-16] [ASSUMED]

### Safe Toast Projection

```rust
ToastModel {
    file_name: basename(event.normalized_path),
    operation: event.operation,
    rule_display_name: event.safe_rule_display_name,
    reason: event.reason,
    remediation: event.safe_remediation,
    opaque_action_id: intent.id,
}
```

No full path, SID, content, detector match, secret, internal file ID, or rule ID should be projected. [VERIFIED: 02-CONTEXT.md D-17]

## Recommended Discretionary Limits

These values are conservative planning defaults and therefore remain `[ASSUMED]` until accepted in the plan or discussion. The 4 MiB scan ceiling aligns with the current exact chunk size quoted below, but alignment does not itself prove the ceiling is operationally correct. [VERIFIED: crates/dlp-storage/src/lib.rs:15-19] [ASSUMED]

```text
DATA_B5T1Y9DU_START
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;
DATA_B5T1Y9DU_END
```

| Limit | Recommended default | Hard endpoint ceiling | Rationale |
|-------|---------------------|-----------------------|-----------|
| Content prefix | 1 MiB | 4 MiB | One current storage chunk; bounded memory and I/O. [ASSUMED] |
| Regex source | 4 KiB | 16 KiB | Stops pathological author input before compile. [ASSUMED] |
| Regex nesting | 32 | 64 | Conservative parser recursion budget. [ASSUMED] |
| Regex compiled/automaton budget | 1 MiB | 4 MiB per rule | Must be enforced with builder/resource accounting. [ASSUMED] |
| Dictionary entries | 10,000 | 25,000 | Explicit count bound. [ASSUMED] |
| Dictionary source bytes | 1 MiB | 4 MiB | Bound parse and canonical payload size. [ASSUMED] |
| Dictionary automaton heap | 8 MiB | 16 MiB per policy | Endpoint activation rejects over-budget materialization. [ASSUMED] |
| Proceed-once TTL | 120 seconds | 300 seconds | Brief retry window; single use and exact binding still mandatory. [ASSUMED] |
| Toast dedupe window | 30 seconds | 60 seconds | Shows first notification and quickly updates burst count. [ASSUMED] |

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Extension-only rule input | Versioned metadata + bounded content IR | Phase 2 | Compiler and endpoint evaluator gain explicit unavailable/failure semantics. [VERIFIED: crates/dlp-domain/src/lib.rs:98-105; crates/dlp-policy/src/lib.rs:8-34] |
| One verification key | Old-key-authorized bounded keyring transition | Phase 2 / CRY-05 | Rotation does not require trust-on-first-use. [VERIFIED: crates/dlp-crypto/src/lib.rs:230-326] |
| Write then immediate flush | Stage → inspect/evaluate → publish or abort | Phase 2 / D-11 | Denied imports never become durable. [VERIFIED: crates/dlp-windows-drive/src/filesystem.rs:554-599] |
| One administrator trust class | mTLS identity plus persisted admin/auditor role | Phase 2 / SRV-05 | Auditors can inspect but cannot mutate. [VERIFIED: crates/dlp-server/src/tls.rs:1-260] |
| Notification APIs without grouping state | Tag+Group replacement plus sequence-numbered updates | Microsoft current app-notification model | Repeated toasts can update a count without dropping enforcement events. [CITED: https://learn.microsoft.com/en-us/uwp/api/windows.ui.notifications.toastnotifier.update?view=winrt-26100] |

**Deprecated/outdated:**

- Treating `RequireJustification` as an activatable action is invalid for Phase 2 even though the current portable enum contains it. [VERIFIED: crates/dlp-domain/src/lib.rs:146-163; 02-CONTEXT.md D-09]
- The current single-key verifier cannot satisfy CRY-05 rotation. [VERIFIED: crates/dlp-crypto/src/lib.rs:230-326]
- Current immediate write flush cannot satisfy D-11. [VERIFIED: crates/dlp-windows-drive/src/filesystem.rs:554-599]

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Regex and Aho-Corasick dependencies belong directly in `dlp-policy`. | Standard Stack | Compilation might instead be split into another portable crate. |
| A2 | Detector, grant, and dedupe numeric defaults/ceilings in the recommendation table are operationally suitable. | Recommended Discretionary Limits | Resource exhaustion or unusable policies; benchmark/tune before locking. |
| A3 | Outstanding Proceed-once grants should be memory-only and expire on service restart. | Architecture Pattern 6 | Product may require restart continuity, which needs protected persistence and replay design. |
| A4 | Compiled regex machines should not be serialized; endpoint should reconstruct from canonical definitions. | Anti-Patterns | A stable, authenticated portable representation might later be justified, but version coupling is high. |
| A5 | Proposed new test paths and helper API names are appropriate. | Validation / Code Examples | Planner should map them to actual module ownership and avoid unnecessary public APIs. |
| A6 | Every allow decision gets an event, with `allow_and_audit` distinguished by explicit audit semantics. | Resolved Phase 2 contract | Plans 02-04/02-05 make decision-time creation testable while leaving durable transport to the later phase boundary. |
| A7 | Missing local Docker and PostgreSQL readiness can be covered by the existing lab/CI topology. | Environment Availability | Server integration tests may block locally until a database is provided. |

## Open Questions — RESOLVED

All four research questions below are resolved as Phase 2 execution contracts by the locked CONTEXT decisions and the corresponding existing plans. These resolutions record the already-planned contracts; they do not add user decisions.

1. **[RESOLVED] How are existing administrator certificates bootstrapped into the new role model?**
   - What we know: current TLS authentication yields an administrator identity without an `admin`/`auditor` repository lookup. [VERIFIED: crates/dlp-server/src/tls.rs:1-260]
   - Resolved uncertainty: canonical principal key and first-admin bootstrap path.
   - Resolution: Plan 02-02 keys the persisted principal by trusted issuer plus canonical leaf fingerprint, assigns exactly `admin` or `auditor`, seeds the currently configured administrator through a forward migration/operator-safe path, and rejects request-supplied roles. This is the server-side authorization contract supporting D-01/D-02 without changing the locked lifecycle. [RESOLVED: 02-02 Task 1]

2. **[RESOLVED] How are authenticated content digests established for files created before Phase 2?**
   - What we know: the current `EncryptedManifestV1` codec in `format.rs` has no plaintext digest. [VERIFIED: crates/dlp-storage/src/format.rs:141-193]
   - Resolved uncertainty: eager maintenance migration versus lazy recomputation on authenticated full read.
   - Resolution: Plan 02-04 versions the explicit `EncryptedManifestV1` encode/decode contract, authenticates a full-file digest for each newly committed import, lazily backfills only after an authenticated complete legacy read, and applies D-14 `inspection_failed` whenever a required digest is still missing. This directly implements D-12 through D-14. [RESOLVED: 02-04 Task 1]

3. **[RESOLVED] What exact evidence distinction is required between `allow` and `allow_and_audit` in Phase 2?**
   - What we know: success criteria require decision-time enforcement events, while durable offline queuing/upload belongs to Phase 3. [VERIFIED: .planning/ROADMAP.md:35-76; 02-CONTEXT.md Phase Boundary]
   - Resolved uncertainty: whether `allow` emits the same event class/retention as `allow_and_audit`.
   - Resolution: Plans 02-04 and 02-05 create one normalized synchronous event for every decision; `allow_and_audit` sets `mandatory_audit=true`, ordinary `allow` sets it false, and both allow the immediate operation. Phase 2 keeps the event handoff local/in-memory, consistent with the Phase Boundary and D-18; durable offline transport remains outside this phase. [RESOLVED: 02-04 Task 2; 02-05 Task 2]

4. **[RESOLVED] What is the exact rotation overlap/removal policy?**
   - What we know: ADR-005 requires old-key authorization and allows re-enrollment for endpoints that miss the overlap. [VERIFIED: .planning/docs/adrs/ADR-005-policy-signing.md:72-126]
   - Resolved uncertainty: overlap duration and whether old-key retirement is time- or version-based.
   - Resolution: Plan 02-03 requires an already-trusted old key to authorize a transition carrying both a monotonic not-after bundle version and an epoch-seconds not-after bound. Equality at both bounds is accepted; exceeding either rejects old-key use, preserves LKG, and endpoints that miss the overlap follow ADR-005 re-enrollment. This preserves D-04 next-poll activation and introduces no trust-on-first-use path. [RESOLVED: 02-03 Task 2]

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|-------------|-----------|---------|----------|
| Rust toolchain | Workspace build/test | ✓ | `cargo 1.97.1`, `rustc 1.97.1` | — [VERIFIED: environment probe] |
| Node.js | GSD/GitNexus tooling | ✓ | `v26.5.0` | — [VERIFIED: environment probe] |
| PostgreSQL client | Server migration/integration diagnostics | ✓ | `psql 16.2` | CI/lab PostgreSQL [VERIFIED: environment probe] |
| PostgreSQL readiness tool | Local DB probe | ✗ | `pg_isready` not found | Use configured CI/lab DB and SQLx connectivity check. [VERIFIED: environment probe] [ASSUMED] |
| Docker | Containerized PostgreSQL/e2e | ✗ | — | Existing physical/VM lab or install Docker before container tests. [VERIFIED: environment probe] [ASSUMED] |
| Windows | Service/drive/companion tests | ✓ | Windows 11 Pro `10.0.26200` | Windows 10/11 lab matrix for remaining coverage. [VERIFIED: environment probe] |
| WinFsp runtime | Mounted drive enforcement | ✓ | `2.1.25156`, Launcher running Automatic | — [VERIFIED: environment probe] |

**Missing dependencies with no fallback:** none if lab/CI PostgreSQL is reachable; otherwise server integration tests are blocked. [ASSUMED]  
**Missing dependencies with fallback:** local Docker and `pg_isready`; use existing lab/CI infrastructure or install them before the relevant wave. [ASSUMED]

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in test harness through Cargo `1.97.1`; PowerShell for Windows mounted-drive smoke [VERIFIED: environment probe; repository test inventory] |
| Config file | Workspace `Cargo.toml`; no separate Rust test-runner config [VERIFIED: Cargo.toml:1-23] |
| Quick run command | `cargo test -p dlp-policy --quiet` [VERIFIED: current baseline, 3 passing tests] |
| Full suite command | `cargo test --workspace --all-targets` plus Windows lab smoke script [VERIFIED: repository test inventory] |

Current focused baselines passed during research: `dlp-policy` 3 tests, `dlp-agent-core --test enrollment_activation` 15, `dlp-server route_tests` 5, `dlp-windows-drive --test callback_contract` 2, `dlp-windows-service --test session_lifecycle` 22, `dlp-protocol` 4, and `dlp-domain` 3. [VERIFIED: local test execution 2026-08-29]

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SRV-02 | Auditor reads allowed; every policy/config mutation forbidden | integration | `cargo test -p dlp-server policy_roles --quiet` | ❌ Wave 0 [ASSUMED] |
| SRV-05 | Draft CRUD, validation, immutable publish, signing, and assignment | integration | `cargo test -p dlp-server policy_lifecycle --quiet` | ❌ Wave 0 [ASSUMED] |
| SRV-06 | Bundle includes policy/schema/settings/effective/offline fields and is immutable/signed | integration | `cargo test -p dlp-server policy_bundle_contract --quiet` | ❌ Wave 0 [ASSUMED] |
| SRV-07 | Assigned bundle polls, activates, and reports deployed version/status | end-to-end | `cargo test -p dlp-server policy_distribution_status --quiet` | ❌ Wave 0 [ASSUMED] |
| POL-01 | Same policy version and input serialize to identical decision | unit/property | `cargo test -p dlp-policy deterministic_evaluation --quiet` | Existing basic coverage; ❌ expanded Wave 0 [VERIFIED: crates/dlp-policy/src/lib.rs:109-155] [ASSUMED] |
| POL-02 | Name/extension/MIME/path/owner/size plus AND/any_of/unavailable | unit | `cargo test -p dlp-policy metadata_conditions --quiet` | ❌ Wave 0 [ASSUMED] |
| POL-03 | Prefix, regex, dictionary, hash, and structured-ID detectors obey bounds | unit | `cargo test -p dlp-policy bounded_detectors --quiet` | ❌ Wave 0 [ASSUMED] |
| POL-04 | Read/write/import/export/copy/delete context, including callback mapping | unit/integration | `cargo test -p dlp-windows-drive operation_mapping --quiet` | ❌ Wave 0 [ASSUMED] |
| POL-05 | Observable destination matches; unavailable destination is recorded/no-match | unit | `cargo test -p dlp-policy destination_context --quiet` | ❌ Wave 0 [ASSUMED] |
| POL-06 | Allow/block/allow-and-audit/warn runtime effects | unit | `cargo test -p dlp-policy runtime_actions --quiet` | ❌ Wave 0 [ASSUMED] |
| POL-07 | Justification rejected by server and endpoint, preserving LKG | integration | `cargo test -p dlp-agent-core unsupported_action_preserves_lkg --quiet` | ❌ Wave 0 [ASSUMED] |
| POL-08 | Priority/restrictiveness/stable-ID conflict matrix | unit/property | `cargo test -p dlp-policy deterministic_precedence --quiet` | Existing basic coverage; ❌ expanded Wave 0 [VERIFIED: crates/dlp-policy/src/lib.rs:109-155] [ASSUMED] |
| POL-09 | Every outcome, including default/unavailable/failure, has a stable reason | unit | `cargo test -p dlp-domain decision_reason_contract --quiet` | ❌ Wave 0 [ASSUMED] |
| POL-10 | Full policy engine suite runs without Windows dependencies | unit | `cargo test -p dlp-policy --quiet` | ✅ harness; ❌ expanded Wave 0 [VERIFIED: current baseline] [ASSUMED] |
| CRY-05 | Old key authorizes new; unknown/self key rejected; overlap works | unit/integration | `cargo test -p dlp-agent-core signing_key_rotation --quiet` | ❌ Wave 0 [ASSUMED] |
| AGT-10 | Service/process/machine restart retains valid activation/LKG and rejects stale grants | integration | `cargo test -p dlp-agent-core policy_restart_recovery --quiet` | Existing cache coverage; ❌ policy Wave 0 [VERIFIED: crates/dlp-agent-core/tests/enrollment_activation.rs:1-901] [ASSUMED] |
| DRV-05 | User A cannot mount/access user B store or consume user B grant | Windows integration | `powershell -File tests/windows/Invoke-Phase2PolicySmoke.ps1 -Case MultiUserIsolation` | ❌ Wave 0 [ASSUMED] |
| DRV-08 | All policy denials return `STATUS_ACCESS_DENIED` plus clear feedback | integration | `cargo test -p dlp-windows-drive access_denied_feedback --quiet` | ❌ Wave 0 [ASSUMED] |
| UI-01 | Companion is small, per-user, and follows session lifecycle | Windows integration | `powershell -File tests/windows/Invoke-Phase2PolicySmoke.ps1 -Case CompanionLifecycle` | ❌ Wave 0 [ASSUMED] |
| UI-02 | Spoofed SID/PID/session rejected; correct Windows caller accepted | integration | `cargo test -p dlp-windows-service companion_identity --quiet` | Existing pipe patterns; ❌ companion Wave 0 [VERIFIED: crates/dlp-windows-service/src/pipe.rs:332-489] [ASSUMED] |
| UI-03 | Toast shows allowed fields/remediation and never sensitive fields | unit/Windows integration | `cargo test -p dlp-windows-service toast_projection --quiet` | ❌ Wave 0 [ASSUMED] |
| TST-07 | Multi-user isolation and revoked device credential | Windows/e2e | `powershell -File tests/windows/Invoke-Phase2PolicySmoke.ps1 -Case IsolationAndRevocation` | ❌ Wave 0 [ASSUMED] |

The Windows access-denied value is exactly `0xC0000022`; add a named adapter constant and assert it at the callback boundary. [CITED: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/7440cfac-6052-4925-84e4-c32e417de300]

### Sampling Rate

- **Per task commit:** run the changed crate's focused test target; keep it under 30 seconds where feasible. [ASSUMED]
- **Per wave merge:** `cargo test --workspace --all-targets`. [ASSUMED]
- **Phase gate:** full workspace suite plus the Windows 10/11 multi-user, warn-grant, restart, LKG, and revocation smoke matrix before `$gsd-verify-work`. [ASSUMED]

### Wave 0 Gaps

- [ ] `crates/dlp-policy/tests/policy_v2.rs` — table/property cases for POL-01 through POL-10. [ASSUMED]
- [ ] `crates/dlp-server/tests/policy_lifecycle.rs` — repository/API concurrency and role cases for SRV-02/05/06/07. [ASSUMED]
- [ ] `crates/dlp-agent-core/tests/policy_activation.rs` — activation, key rotation, and LKG failures. [ASSUMED]
- [ ] `crates/dlp-storage/tests/policy_staging.rs` — candidate inspect/commit/abort and digest migration. [ASSUMED]
- [ ] `crates/dlp-windows-drive/tests/policy_enforcement.rs` — timing and status contracts. [ASSUMED]
- [ ] `crates/dlp-windows-service/tests/companion_grants.rs` — authenticated routing, grants, expiry, replay, restart. [ASSUMED]
- [ ] `crates/dlp-server/tests/policy_distribution.rs` — publish/assign/poll/activate end-to-end, auto-discovered as the `dlp-server` integration target. [ASSUMED]
- [ ] `tests/windows/Invoke-Phase2PolicySmoke.ps1` — real toast activation, mounted-drive behavior, two-user isolation, revoked device. [ASSUMED]
- [ ] Database fixture availability for SQLx integration tests; Docker is absent locally. [VERIFIED: environment probe] [ASSUMED]

## Security Domain

Security enforcement is enabled at level 1. [VERIFIED: .planning/config.json:1-75]

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|------------------|
| V2 Authentication | yes | Existing mutual TLS for admin/device and Windows token authentication for companion IPC; never accept claimed identity. [VERIFIED: crates/dlp-server/src/tls.rs:1-260; crates/dlp-windows-service/src/pipe.rs:332-489] |
| V3 Session Management | no web session | No browser session in Phase 2; short-lived grant is an authorization capability with exact binding, expiry, and one-time atomic consumption. [VERIFIED: 02-CONTEXT.md D-16] |
| V4 Access Control | yes | Persisted admin/auditor roles, resource-scoped device assignment, SID/session-bound companion routing, deny-by-default mutations. [CITED: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md] |
| V5 Input Validation | yes | `serde` schema deny/validate, canonical compiler, bounded any_of/prefix/regex/dictionary, endpoint defense in depth. [VERIFIED: .planning/docs/adrs/ADR-004-policy-expression.md:46-145] |
| V6 Cryptography | yes | Existing AES-GCM encrypted storage and Ed25519 signed bundle/key transition; never hand-roll primitives. [VERIFIED: crates/dlp-crypto/Cargo.toml:11-15; .planning/docs/adrs/ADR-005-policy-signing.md:28-126] |

OWASP ASVS 5.0.0 is the current stable release and organizes these controls under authentication, authorization, cryptography, and data protection; mappings here are adapted to a native Windows/service system rather than a browser application. [VERIFIED: https://github.com/OWASP/ASVS] [CITED: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x20-V11-Cryptography.md] [CITED: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x23-V14-Data-Protection.md]

### Known Threat Patterns for Rust/Windows/PostgreSQL Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Malicious policy resource exhaustion | Denial of Service | Server + endpoint hard ceilings, bounded input prefix, activation before pointer swap. [CITED: https://docs.rs/regex/latest/regex/] |
| Policy tampering/replay | Tampering | Canonical signed envelope, content digest, audience/key/schema validation, monotonic version, current/LKG retention. [VERIFIED: crates/dlp-agent-core/src/config_cache.rs:93-241] |
| Concurrent duplicate publication/bundle issue | Tampering | SQL transaction, unique constraints, per-device row lock. [CITED: https://www.postgresql.org/docs/current/ddl-constraints.html] [CITED: https://www.postgresql.org/docs/current/sql-select.html] |
| Companion identity spoofing | Spoofing/Elevation | Purpose-limited pipe DACL, kernel client PID, impersonation token SID/session, `RevertToSelf`, no caller-selected identity. [VERIFIED: crates/dlp-windows-service/src/pipe.rs:332-489] |
| Grant replay/cross-user reuse | Elevation | Opaque intent ID, exact tuple, brief TTL, atomic single-use removal, policy-version binding. [VERIFIED: 02-CONTEXT.md D-16] |
| Sensitive notification/log disclosure | Information Disclosure | Base name only, safe display/remediation, structured redaction, no match/path/SID/content. [VERIFIED: 02-CONTEXT.md D-17] |
| Detector corruption/decoder error bypass | Tampering | Fail closed as `inspection_failed`, name affected rule, create event, safe remediation. [VERIFIED: 02-CONTEXT.md D-14] |
| Key-transition substitution | Spoofing/Tampering | Old trusted key signs transition; bounded overlap; reject unknown self-introduced keys. [VERIFIED: .planning/docs/adrs/ADR-005-policy-signing.md:72-126] |

## Sources

### Primary (HIGH confidence)

- `crates/dlp-domain/src/lib.rs` — current policy vocabulary, action ordering, and reasons. [VERIFIED: crates/dlp-domain/src/lib.rs:98-193]
- `crates/dlp-policy/src/lib.rs` — evaluator rule model, deterministic ordering, tests. [VERIFIED: crates/dlp-policy/src/lib.rs:1-155]
- `crates/dlp-agent-core/src/config_cache.rs` — signed verification, replay checks, staging, atomic current/LKG. [VERIFIED: crates/dlp-agent-core/src/config_cache.rs:1-360]
- `crates/dlp-windows-drive/src/filesystem.rs` — enforcement callback order and current immediate write flush. [VERIFIED: crates/dlp-windows-drive/src/filesystem.rs:411-599]
- `crates/dlp-storage/src/store.rs` and `format.rs` — staged generations and persisted manifest codec state. [VERIFIED: crates/dlp-storage/src/store.rs:329-446; crates/dlp-storage/src/format.rs:141-193]
- `crates/dlp-windows-service/src/pipe.rs` and `session.rs` — authenticated IPC and per-user lifecycle. [VERIFIED: crates/dlp-windows-service/src/pipe.rs:50-489; crates/dlp-windows-service/src/session.rs:1-320]
- ADR-004, ADR-005, and threat model — canonical policy/signing/trust decisions. [VERIFIED: .planning/docs/adrs/ADR-004-policy-expression.md:1-185; .planning/docs/adrs/ADR-005-policy-signing.md:1-177; .planning/docs/THREAT-MODEL.md:1-180]
- Official `regex` and `aho-corasick` documentation plus registry/legitimacy checks — APIs, limits, current packages. [VERIFIED: https://docs.rs/regex/latest/regex/] [VERIFIED: https://docs.rs/aho-corasick/latest/aho_corasick/]

### Secondary (MEDIUM confidence)

- Microsoft desktop app notification quickstart and desktop toast sample — registration and activation. [CITED: https://learn.microsoft.com/en-us/windows/apps/develop/notifications/app-notifications/app-notifications-quickstart] [CITED: https://learn.microsoft.com/en-us/samples/microsoft/windows-classic-samples/desktop-toasts/]
- Microsoft `ToastNotifier.Update` — Tag/Group replacement and sequence behavior. [CITED: https://learn.microsoft.com/en-us/uwp/api/windows.ui.notifications.toastnotifier.update?view=winrt-26100]
- Microsoft named-pipe identity APIs — impersonation and kernel client PID. [CITED: https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient] [CITED: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid]
- PostgreSQL constraints and row locking. [CITED: https://www.postgresql.org/docs/current/ddl-constraints.html] [CITED: https://www.postgresql.org/docs/current/sql-select.html]
- OWASP ASVS 5.0.0 categories. [CITED: https://github.com/OWASP/ASVS]

### Tertiary (LOW confidence)

- Project-specific numeric ceilings, TTL, dedupe interval, file placement, and rollout recommendations are listed in the Assumptions Log. [ASSUMED]

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — existing manifests plus official package docs, registry checks, and legitimacy gate.
- Architecture: HIGH — based on opened source-of-truth callbacks, cache, protocol, repository, storage, IPC, and locked ADR/context decisions.
- Windows notification integration: MEDIUM — official Microsoft guidance verified, but no existing companion implementation or Windows 10 validation yet.
- Pitfalls: HIGH for transaction/authentication/activation seams; LOW for the recommended numeric thresholds pending benchmarks.

**Research date:** 2026-08-29  
**Valid until:** 2026-09-28 for stable architecture; recheck current package versions and Windows notification guidance after 2026-09-05.
