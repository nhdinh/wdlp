# Phase 2: Policy Enforcement and User Feedback - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-08-29
**Phase:** 2-policy-enforcement-and-user-feedback
**Areas discussed:** Policy authoring and publication, Rule matching and conflict resolution, Enforcement timing and detector limits, Warn/block feedback behavior

---

## Policy Authoring and Publication

### Primary authoring surface

| Option | Description | Selected |
|--------|-------------|----------|
| CLI-first | Extend `dlpctl` with create, validate, inspect, assign, and publish commands; reuse existing administrator and signing infrastructure. | ✓ |
| Minimal web UI | Add a browser-based authoring surface and its frontend/authentication requirements. | |
| CLI and web UI | Deliver both surfaces during Phase 2. | |

**User's choice:** CLI-first.
**Notes:** The repository already has `dlpctl` and authenticated administrator routes but no frontend stack.

### Version lifecycle

| Option | Description | Selected |
|--------|-------------|----------|
| Mutable draft → validate → immutable published version | Permit repeated draft edits; publishing creates a new immutable version. | ✓ |
| One-step validate and publish | Every accepted edit immediately creates and activates a version. | |
| Mutable published policy | Edit active versions in place. | |

**User's choice:** Mutable draft followed by validation and immutable publication.
**Notes:** This preserves reviewability, rollback, and deterministic version history.

### Assignment model

| Option | Description | Selected |
|--------|-------------|----------|
| Organization default plus per-device override | Every device inherits a default; one device may receive another published version. | ✓ |
| One organization-wide policy only | Every publication targets all active devices. | |
| Explicit assignment per device | No device receives a policy without an explicit assignment. | |

**User's choice:** Organization default plus per-device overrides.
**Notes:** Device-group rollout remains a v2 feature.

### Publication effect

| Option | Description | Selected |
|--------|-------------|----------|
| Publish without activation | Publishing creates an immutable version; separate default/assignment commands alter distribution. | ✓ |
| Publish with activation flag | Allow a combined publish-and-activate command. | |
| Always activate on publish | Every publication becomes the organization default immediately. | |

**User's choice:** Publication and endpoint activation are separate operations.
**Notes:** Activation takes effect through signed configuration distribution on the next successful endpoint poll.

---

## Rule Matching and Conflict Resolution

### Multiple matching rules

| Option | Description | Selected |
|--------|-------------|----------|
| Priority first, restrictive tie-breaker | Highest priority wins; equal priority uses action restrictiveness and stable rule ID. | ✓ |
| Most restrictive always wins | Any block overrides allows and warnings regardless of priority. | |
| First matching rule wins | Published list order determines the first result. | |

**User's choice:** Priority first with deterministic restrictive and rule-ID tie-breakers.
**Notes:** This preserves the existing evaluator's selection pattern and supports explicit high-priority exceptions.

### Conditions within a rule

| Option | Description | Selected |
|--------|-------------|----------|
| Flat AND with bounded value lists | Every clause matches; a clause may use bounded `any_of`; separate rules express broader OR. | ✓ |
| One-level ALL/ANY groups | Permit explicit non-nested groups. | |
| Fully nested Boolean expressions | Permit bounded arbitrary `all`, `any`, and `not` trees. | |

**User's choice:** Flat AND with bounded `any_of` lists.
**Notes:** This follows the declarative MVP model in ADR-004 and keeps compilation predictable.

### No-match behavior

| Option | Description | Selected |
|--------|-------------|----------|
| Required policy-level default | Every policy declares a supported fallback; templates begin with `allow`. | ✓ |
| Always allow | Fix no-match behavior globally to allow. | |
| Always block | Fix no-match behavior globally to block. | |

**User's choice:** Require an explicit policy-level default action.
**Notes:** The default path records a stable `default_action` reason.

### Unavailable context

| Option | Description | Selected |
|--------|-------------|----------|
| Rule does not match; continue | Record `input_unavailable`, evaluate other rules, then apply the default if needed. | ✓ |
| Immediately use policy default | Stop evaluation when a candidate lacks required context. | |
| Fail closed with block | Treat unavailable context as a denial. | |

**User's choice:** The affected rule does not match and evaluation continues.
**Notes:** This applies to destination or other runtime context the drive cannot observe.

---

## Enforcement Timing and Detector Limits

### Runtime operation classification

| Option | Description | Selected |
|--------|-------------|----------|
| Direct evidence only | Enforce primitive operations; use import/export/copy only with direct destination evidence. | |
| Heuristic process/ETW correlation | Infer import/export/copy by correlating requestor and machine-wide file events. | |
| Primitive mapping | Treat every read as export and every create/write as import. | ✓ |

**User's choice:** Primitive mapping.
**Notes:** The user initially selected primitive mapping, returned to the question to ask whether Windows system signals could be intercepted, reviewed the limits of WinFsp process IDs, ETW correlation, and kernel minifilters, then confirmed primitive mapping. Process and ETW data may enrich audit records but are not authoritative for classification.

### Enforcement point

| Option | Description | Selected |
|--------|-------------|----------|
| Before the protected effect becomes visible | Approve export before plaintext release, stage imports until approval, and approve rename/delete before mutation. | ✓ |
| At open/create only | Decide from metadata before returning handles. | |
| After each I/O chunk | Re-evaluate every read/write chunk. | |

**User's choice:** Enforce before plaintext release or durable mutation.
**Notes:** Imports require staged content because content-dependent rules cannot be decided at create time.

### Inspection extent

| Option | Description | Selected |
|--------|-------------|----------|
| Deterministic bounded scan | Scan a configured prefix under hard agent maxima and compile regexes with resource limits. | ✓ |
| Whole file below a ceiling | Scan all bytes only for files under a configured size. | |
| Stream until budget expires | Scan successive chunks until time or byte budget exhaustion. | |

**User's choice:** Deterministic bounded scanning.
**Notes:** Authenticated stored content digests may satisfy full-file hash detectors without rereading the file.

### Detector failure

| Option | Description | Selected |
|--------|-------------|----------|
| Fail closed | Block with `inspection_failed`, identify the rule, create an event, and show remediation. | ✓ |
| Policy-configured fallback | Let each policy choose block, warn, or default behavior. | |
| Skip affected rule | Record a diagnostic and continue evaluation. | |

**User's choice:** Fail closed for required detector failures.
**Notes:** Reaching the configured prefix boundary normally is a completed prefix scan, not a detector failure.

---

## Warn/Block Feedback Behavior

### Meaning of warn

| Option | Description | Selected |
|--------|-------------|----------|
| Deny once, then authenticated retry | Deny the current attempt and let the companion grant one retry without justification. | ✓ |
| Allow immediately and notify | Complete the operation and display an informational warning. | |
| Deny without override | Enforce like block with different severity and wording. | |

**User's choice:** Deny once, then permit one authenticated retry.
**Notes:** This distinguishes warn from hard block while leaving business-justification collection post-MVP.

### Proceed-once scope

| Option | Description | Selected |
|--------|-------------|----------|
| Single exact retry | Short-lived, single-use grant bound to user, file, operation, rule, and policy version. | ✓ |
| Short retry window | Permit repeated operations on the file for several minutes. | |
| Session-wide exception | Permit the rule/file combination until sign-out or policy change. | |

**User's choice:** Single exact retry.
**Notes:** The service consumes the grant atomically on the next matching attempt.

### Toast information boundary

| Option | Description | Selected |
|--------|-------------|----------|
| File name with safe policy context | Show base name, operation, safe rule display name, stable reason, and remediation. | ✓ |
| Full virtual path | Include the complete protected-drive path. | |
| Generic message only | Do not identify the file. | |

**User's choice:** Base file name with safe policy context.
**Notes:** Never display content, detector matches, full paths, SIDs, secrets, or internal identifiers.

### Repeated notifications

| Option | Description | Selected |
|--------|-------------|----------|
| Deduplicate by decision key | Always show the first toast; group repeats for the exact decision key during a short window. | ✓ |
| Show every toast | Display a notification for each denied or warned attempt. | |
| Global rate limit with summary | Cap all DLP toasts and periodically summarize them. | |

**User's choice:** Deduplicate by decision key.
**Notes:** Deduplication affects only presentation; every enforcement decision still creates its event.

---

## the agent's Discretion

- Exact `dlpctl` command names and policy JSON field names.
- Conservative scan-prefix, regex, dictionary, and detector resource maxima within hard agent ceilings.
- Brief Proceed-once expiry and notification-deduplication window.
- Safe remediation wording and stable error-code names not explicitly prescribed above.

## Deferred Ideas

- Device-group policy assignment and staged rollout (`ADM-V2-01`).
- Full policy administration web interface (`ADM-V2-03`).
- Business-justification collection for overrides (`POL-V2-01`).
- Kernel minifilter and OS-wide destination interception remain outside the project's user-space-only boundary.
