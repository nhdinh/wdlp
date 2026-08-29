# Phase 2: Policy Enforcement and User Feedback - Context

**Gathered:** 2026-08-29
**Status:** Ready for planning

<domain>
## Phase Boundary

Turn the existing encrypted WinFsp drive into a deterministic DLP enforcement boundary. Phase 2 delivers CLI-based policy authoring, validation, immutable publication and assignment; signed policy distribution and atomic activation; metadata and bounded content evaluation; allow, block, allow-and-audit, and warn actions; enforcement events; and authenticated per-user Windows notifications. Offline event queuing and upload, fleet control, audit search/export, device-group rollout, and production hardening remain in later phases.

</domain>

<decisions>
## Implementation Decisions

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

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Project Scope and Phase Contract
- `.planning/PROJECT.md` — Product boundary, core value, user-space-only enforcement, action set, companion-process decision, and deployment constraints.
- `.planning/REQUIREMENTS.md` — Phase 2 requirement definitions and traceability for server, policy, crypto, agent, drive, UI, and testing work.
- `.planning/ROADMAP.md` — Fixed Phase 2 goal, dependencies, success criteria, later-phase boundaries, and v2 rollout/UI boundaries.
- `.planning/STATE.md` — Current phase position, accumulated architectural decisions, lab topology, and completed Phase 1 capabilities.
- `.planning/phases/01-first-encrypted-drive-vertical-slice/01-CONTEXT.md` — Prior locked drive, user/session, WinFsp, security, evidence, and verification contracts that Phase 2 must preserve.

### Policy and Security Architecture
- `.planning/docs/adrs/ADR-004-policy-expression.md` — Declarative JSON rule DSL, server-side validation/compilation, supported conditions/actions, deterministic evaluation, and bounded detector requirements.
- `.planning/docs/adrs/ADR-005-policy-signing.md` — Ed25519 bundle signing, key identifiers and rotation, signing scope, and pre-activation verification.
- `.planning/docs/THREAT-MODEL.md` — Drive-boundary limitations, service/companion trust boundary, bounded-scanner requirements, metadata minimization, and authenticated IPC mitigations.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/dlp-domain/src/lib.rs`: Existing `PolicyInput`, `PolicyDecision`, `EnforcementAction`, and `DecisionReason` types provide the stable portable vocabulary to extend with operation, destination, detector, and new reason data.
- `crates/dlp-policy/src/lib.rs`: Existing portable `PolicyEvaluator` already implements deterministic priority, restrictive-action, and stable-rule-ID selection. It currently matches extensions only and is the natural seam for compiled Phase 2 rules.
- `crates/dlp-server/src/routes.rs` and `crates/dlp-server/src/repository.rs`: Existing authenticated administrator/device routes, per-device configuration selection, persistence, and Ed25519 signing can be extended for draft, publish, default, and override workflows.
- `crates/dlpctl/src/lib.rs`: Existing administrator CLI and signed-configuration helpers provide the Phase 2 authoring surface.
- `crates/dlp-agent-core/src/config_cache.rs`: Existing signature verification, replay protection, content-addressed staging, atomic selection, and last-known-good recovery should remain the configuration-activation boundary.
- `crates/dlp-windows-drive/src/filesystem.rs`: Existing WinFsp open/create/read/write/flush/rename/delete callbacks are the enforcement insertion points. The adapter currently accesses encrypted storage directly and emits filesystem notifications only.
- `crates/dlp-windows-service/src/pipe.rs` and `crates/dlp-windows-service/src/session.rs`: Existing SID-, session-, PID-, and generation-bound named-pipe/bootstrap infrastructure and per-user process lifecycle provide patterns for authenticated companion messaging and Proceed-once grants.

### Established Patterns
- Portable Rust crates forbid unsafe code; Windows FFI stays isolated and documented.
- Persisted and wire formats are versioned; invalid or replayed signed configurations never replace the current selection.
- Security failures fail closed with stable codes, redacted diagnostics, and no plaintext or secret leakage.
- The service captures and authorizes Windows identity; callers cannot select another user's store or supply authoritative identity fields.
- Encrypted-store mutations use staged generations and authenticated publication; Phase 2 enforcement must preserve crash consistency and last-committed recovery.

### Integration Points
- Extend the policy schema/compiler in `dlp-policy` and the signed configuration payload in `dlp-protocol` without weakening canonical signing bytes or schema-version rejection.
- Add administrator policy lifecycle and assignment APIs behind the existing mTLS administrator boundary, then expose them through `dlpctl`.
- Load the selected compiled policy through the existing agent configuration cache and pass an immutable evaluator snapshot into each authenticated per-user drive host.
- Insert decisions before plaintext release and before staged import publication in the WinFsp adapter; translate denials to stable access-denied NTSTATUS results.
- Carry enforcement decisions from the drive host to the authoritative service, then to the authenticated per-user companion for local Windows app notifications and Proceed-once authorization.

</code_context>

<specifics>
## Specific Ideas

- Keep policy publication and endpoint activation visibly separate in the CLI so reviewing an immutable version cannot accidentally deploy it.
- Treat read/export and create-or-write/import mappings as explicit product semantics, not heuristics inferred from process or ETW correlation.
- Make warning override grants exact, brief, single-use, and policy-version-bound so stale notifications cannot authorize later operations.
- Notification privacy is stricter than enforcement-event metadata: show a base name and safe explanation, never sensitive match details or a full path.

</specifics>

<deferred>
## Deferred Ideas

- Device-group assignment and staged group rollout remain v2 (`ADM-V2-01`).
- A full policy administration web interface remains v2 (`ADM-V2-03`).
- Kernel minifilter enforcement and OS-wide destination interception remain outside the MVP and the project's user-space-only boundary.
- `require_justification` and collection of business justification remain post-MVP (`POL-V2-01`).

</deferred>

---

*Phase: 2-Policy Enforcement and User Feedback*
*Context gathered: 2026-08-29*
