---
phase: 02-policy-enforcement-and-user-feedback
plan: 02
subsystem: api
tags: [rust, axum, postgresql, mtls, policy-lifecycle, immutable-publication, distribution-cursors]

requires:
  - phase: 02-policy-enforcement-and-user-feedback
    plan: 01
    provides: "Strict policy-v2 compiler, bounded validation, and require_justification rejection"
  - phase: 01-first-encrypted-drive-vertical-slice
    provides: "Verified administrator/device TLS identities, PostgreSQL authority, and signed-configuration routing"

provides:
  - "Persisted administrator/auditor roles keyed by verified issuer+leaf certificate SHA-256 fingerprints"
  - "Fail-closed initial administrator bootstrap before listener bind, with idempotent exact replay and conflict rejection"
  - "Mutable policy drafts, compiler-backed validation, and trigger-protected immutable published versions"
  - "Explicit organization-default and per-device policy assignments with override-before-default selection"
  - "Identity-bound policy bundles with monotonic desired, issued, activated, and error distribution status"

affects:
  - 02-policy-administration-cli
  - 02-signed-policy-bundles
  - 02-agent-policy-activation
  - 02-policy-enforcement-and-user-feedback

actuals:
  tokens: 42500
  tasks: 2
  commits: 4

tech-stack:
  added:
    - "dlp-policy 0.1.0 workspace path dependency in dlp-server"
  patterns:
    - "Verified certificate issuer+leaf digests are the sole administrator principal key"
    - "Migration-before-bootstrap-before-bind production startup ordering"
    - "Immutable publication separated from explicit default/device deployment pointers"
    - "PostgreSQL advisory-lock serialization with monotonic per-device bundle cursors"
    - "AuthenticatedDevice-derived bundle selection and deployment reporting"

key-files:
  created:
    - "migrations/202608290001_policy_lifecycle.sql"
    - "crates/dlp-server/tests/policy_lifecycle.rs"
  modified:
    - "Cargo.lock"
    - "crates/dlp-server/Cargo.toml"
    - "crates/dlp-server/src/lib.rs"
    - "crates/dlp-server/src/repository.rs"
    - "crates/dlp-server/src/routes.rs"
    - "crates/dlp-server/src/tls.rs"

key-decisions:
  - "Form AdministratorPrincipalV1 only from separate SHA-256 digests of the verified issuer DER and canonical verified leaf DER; subjects, serial strings, headers, bodies, and query roles never authorize."
  - "Consume DLP_INITIAL_ADMIN_PRINCIPAL_SHA256 after migrations and before listener bind using the exact lowercase issuer:leaf grammar; exact replay is idempotent and changed replay fails closed."
  - "Keep drafts mutable and published rows insert-only, with PostgreSQL triggers rejecting UPDATE and DELETE independently of route/repository method availability."
  - "Keep publication deployment-neutral; organization default and optional device override point only to immutable published versions, with device override selected first."
  - "Serialize assignment, selection, and status transitions with a dedicated PostgreSQL advisory lock and advance each device's desired bundle version only when its effective immutable policy changes."
  - "Use the authenticated device extension, never caller-supplied device identity, to select bundles and report desired/issued/activated/error status."

patterns-established:
  - "Role boundary: registered auditors may inspect immutable versions, while every mutation re-resolves and requires the persisted administrator role."
  - "Lifecycle boundary: save mutable draft -> compile/validate -> publish immutable version -> assign explicitly -> select for authenticated device."
  - "Distribution boundary: identical desired pointers are idempotent; distinct concurrent assignments serialize and advance one monotonic per-device cursor per transition."
  - "Bundle contract: schema version, immutable policy identity/digest/source, agent settings, effective time, seven-day offline allowance, device audience, bundle version, and signing key ID travel together."

requirements-completed:
  - SRV-02
  - SRV-05
  - SRV-06
  - SRV-07
  - POL-07

coverage:
  - id: D1
    description: "A verified certificate principal resolves to a persisted administrator or auditor role; auditors inspect but cannot mutate, spoofed roles do not authorize, and the last administrator cannot be removed."
    requirement: SRV-02
    verification:
      - kind: integration
        ref: "crates/dlp-server/tests/policy_lifecycle.rs#policy_roles_and_immutable_publish"
        status: pass
    human_judgment: false

  - id: D2
    description: "The server bootstraps exactly one initial administrator before bind, supports mutable drafts, compiles before publication, and preserves published versions as immutable authority."
    requirement: SRV-05
    verification:
      - kind: integration
        ref: "crates/dlp-server/tests/policy_lifecycle.rs#policy_roles_and_immutable_publish"
        status: pass
    human_judgment: false

  - id: D3
    description: "An authenticated device receives the selected immutable policy and all required bundle fields, while publication alone changes no assignment."
    requirement: SRV-06
    verification:
      - kind: integration
        ref: "crates/dlp-server/tests/policy_lifecycle.rs#policy_bundle_contract"
        status: pass
    human_judgment: false

  - id: D4
    description: "Organization default and device override selection, clear-to-default behavior, concurrent assignment serialization, idempotency, and monotonic desired/issued/activated/error status are persisted transactionally."
    requirement: SRV-07
    verification:
      - kind: integration
        ref: "crates/dlp-server/tests/policy_lifecycle.rs#policy_bundle_contract"
        status: pass
    human_judgment: false

  - id: D5
    description: "Unsupported require_justification policy content is rejected before published authority changes."
    requirement: POL-07
    verification:
      - kind: integration
        ref: "crates/dlp-server/tests/policy_lifecycle.rs#policy_roles_and_immutable_publish"
        status: pass
    human_judgment: false

duration: 38min
completed: 2026-08-29
status: complete
---

# Phase 2 Plan 02: Policy Lifecycle and Distribution Authority Summary

**mTLS-authorized PostgreSQL policy publication, explicit default/device assignment, and identity-bound monotonic bundle distribution.**

## Performance

- **Duration:** 38 min
- **Started:** 2026-08-29T12:26:45+07:00
- **Completed:** 2026-08-29T13:04:04+07:00
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments

- Added exact verified issuer+leaf administrator principals, persisted administrator/auditor roles, fail-closed startup bootstrap, replacement-admin rotation, and last-admin protection.
- Added mutable drafts, policy-v2 compiler validation, stable metadata-only audit codes, immutable published versions, and rejection of unsupported `require_justification` content.
- Separated publication from deployment through explicit organization-default and per-device override pointers to immutable versions.
- Added serialized assignment changes, idempotent repeated assignments, override-before-default selection, clear-to-default behavior, and monotonic device distribution cursors/status.
- Added an authenticated-device bundle contract carrying policy identity/version/digest/source, agent settings, effective time, seven-day offline allowance, audience, bundle version, and signing key ID.

## Task Commits

Each TDD boundary was committed atomically:

1. **Task 1 RED: Failing policy role, bootstrap, validation, and immutable-publication contracts** - `04fcd41` (test)
2. **Task 1 GREEN: Authenticated policy lifecycle authority** - `b5de99a` (feat)
3. **Task 2 RED: Failing default/override, distribution, and named bundle contract** - `b66b183` (test)
4. **Task 2 GREEN: Policy assignment and distribution authority** - `925eed9` (feat)

**Plan metadata:** pending final summary commit by the root orchestrator

## Files Created/Modified

- `Cargo.lock` - Locked the server's workspace-local policy compiler dependency.
- `crates/dlp-server/Cargo.toml` - Added exact `dlp-policy` path dependency.
- `migrations/202608290001_policy_lifecycle.sql` - Principal roles, bootstrap marker, metadata-only audit ledger, drafts, immutable versions, explicit assignments, device cursors, and deployment status.
- `crates/dlp-server/src/lib.rs` - Enforced validate -> migrate -> initial-admin bootstrap -> bind startup ordering.
- `crates/dlp-server/src/repository.rs` - PostgreSQL and deterministic fixture implementations for roles, lifecycle, assignments, selection, cursors, and status transitions.
- `crates/dlp-server/src/routes.rs` - Administrator/auditor authorization, lifecycle/assignment endpoints, identity-bound bundle selection, and deployment-status endpoints.
- `crates/dlp-server/src/tls.rs` - Canonical issuer+leaf certificate fingerprint principal and authenticated administrator identity.
- `crates/dlp-server/tests/policy_lifecycle.rs` - PostgreSQL lifecycle tracer and exact top-level `policy_bundle_contract` integration test.

## Decisions Made

- Used separate verified issuer and leaf DER digests instead of certificate subject or serial metadata, preventing equal-subject certificate substitution and issuer/leaf swapping.
- Kept initial administrator recovery operator-controlled and one-time/idempotent, with no unauthenticated recovery route or runtime authorization bypass.
- Added database triggers that reject published-policy UPDATE and DELETE so immutability does not depend solely on application API discipline.
- Used a dedicated policy-distribution advisory lock for coherent organization/device assignment changes and per-device cursor materialization.
- Preserved deployment status across later desired versions while clearing only stale error state; issued and activated cursors remain monotonic.
- Reserved Plan 02-04 for signed-byte assertions while keeping the exact `policy_bundle_contract` test as its extension seam.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Separated the integration-test advisory lock from repository authority locks**

- **Found during:** Task 1 GREEN PostgreSQL validation.
- **Issue:** The test-wide advisory lock key could collide with a repository transaction lock and self-block the lifecycle tracer.
- **Fix:** Changed `POLICY_TEST_LOCK` to `0x0202_00ff`, leaving repository authority/distribution lock keys distinct.
- **Files modified:** `crates/dlp-server/tests/policy_lifecycle.rs`.
- **Verification:** Exact `policy_roles_and_immutable_publish` and the complete lifecycle target passed against PostgreSQL.
- **Committed in:** `b5de99a`.

**2. [Rule 3 - Blocking] Completed assignment/status schema in the unshipped lifecycle migration**

- **Found during:** Task 2 GREEN implementation.
- **Issue:** The declared lifecycle migration contained Task 1 principal/draft/publication objects but not the assignment, cursor, and deployment-status tables required by Task 2.
- **Fix:** Added organization assignment, device override, and device distribution tables with published-version foreign keys and monotonic/status constraints to the same unshipped migration.
- **Files modified:** `migrations/202608290001_policy_lifecycle.sql`.
- **Verification:** The root orchestrator confirmed the dedicated database contained fixture-only rows, reset only that unshipped migration's objects/checksum state, then passed the exact bundle contract and full lifecycle suite.
- **Committed in:** `925eed9`.

---

**Total deviations:** 2 auto-fixed blocking issues
**Impact on plan:** Both fixes were required for deadlock-free PostgreSQL validation and the already-specified assignment/status artifact; no product scope was added.

## Issues Encountered

- The isolated executor sandbox could not reach PostgreSQL or write the shared Git index. RED/GREEN checkpoints therefore supplied exact files, verification output, and commit messages for root-orchestrator database validation, complete GitNexus scans, and normal hook-enabled commits.
- The shared GitNexus CLI runner attempted an unavailable package-registry fallback inside the sandbox. MCP/orchestrator impact results and required text searches supplied the pre-edit gates instead.
- GitNexus reported the expected CRITICAL routing/repository blast radius for `api_v1_router`; the user explicitly authorized that surface before implementation.
- Updating the unshipped migration changed its checksum in the dedicated test database. The root orchestrator verified fixture-only contents before resetting only the affected migration objects/checksum state.

## Verification Evidence

- Task 1 PostgreSQL acceptance: exact `policy_roles_and_immutable_publish` passed.
- Task 2 PostgreSQL acceptance: exact `policy_bundle_contract` passed.
- Complete lifecycle regression: `cargo test --locked -p dlp-server --test policy_lifecycle` passed 2 tests.
- Discovery gate: both `policy_roles_and_immutable_publish: test` and `policy_bundle_contract: test` were present in the integration target's test list.
- Static quality gate: `cargo clippy --locked -p dlp-server --all-targets -- -D warnings` completed cleanly.
- GitNexus Task 1 RED gate (`04fcd41`): 3 files, 8 new test symbols, 0 processes, LOW, complete.
- GitNexus Task 2 RED gate (`b66b183`): complete LOW scan before commit.
- Final Task 2 GREEN gate (`925eed9`): 3 files, 50 symbols, 18 processes, CRITICAL due to the explicitly authorized routes/repository surface; nonpartial and nontruncated.

## User Setup Required

None - production operators must supply the already-documented PostgreSQL/TLS configuration and initial administrator fingerprint; this plan adds no separate external service setup.

## Next Phase Readiness

- Plan 02-03 can add administrator CLI/client workflows over the authenticated lifecycle and assignment endpoints.
- Plan 02-04 can extend the exact `policy_bundle_contract` with canonical signed-byte assertions without changing selection semantics.
- Agent activation can consume one immutable desired policy and report issued, activated, or bounded error status against its authenticated DeviceId.
- No known implementation blocker remains; the final CRITICAL change surface was explicitly authorized and fully scanned.

## Self-Check: PASSED

- All four TDD commits exist: `04fcd41`, `b5de99a`, `b66b183`, and `925eed9`.
- Exact Task 1 and Task 2 PostgreSQL tests pass, and both named tests are discoverable.
- The complete lifecycle target passes 2 tests and strict server clippy is clean.
- Final GitNexus detection was complete, nonpartial, and nontruncated with the authorized CRITICAL result.
- `.planning/STATE.md` and `.planning/ROADMAP.md` remain untouched.

---
*Phase: 02-policy-enforcement-and-user-feedback*
*Completed: 2026-08-29*
