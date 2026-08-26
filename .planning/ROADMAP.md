# Roadmap: Windows Data Leakage Prevention (DLP) Solution

**Project mode:** mvp  
**Granularity:** coarse  
**Phase naming:** sequential

## Phases

- [ ] **Phase 1: First Encrypted-Drive Vertical Slice** - One server, one Windows endpoint, one user: enroll, signed config, WinFsp mount, copy, encrypted backing store, read back, survive restart
- [ ] **Phase 2: Policy Enforcement and User Feedback** - Metadata policy engine, block/warn/audit actions, companion toast notifications, enforcement event creation
- [ ] **Phase 3: Audit, Offline Operation, and Fleet Control** - Local event queue and upload, offline grace/lock, fleet status, device lock/revoke/retire, audit search/export
- [ ] **Phase 4: Hardening and MVP Release** - Per-user isolation tests, crash-consistent storage, key rotation, signed installer, Office/Explorer compatibility, fuzz/load tests, operations docs

## Phase Details

### Phase 1: First Encrypted-Drive Vertical Slice

**Goal**: As an authorized Windows user, I want a private encrypted drive, so that committed files survive restart without readable plaintext in its backing store.
**Mode:** mvp
**Depends on**: Nothing (first phase)
**Requirements**: WRK-01, WRK-02, WRK-03, WRK-04, SRV-01, SRV-03, SRV-11, SRV-12, CRY-01, CRY-02, CRY-04, AGT-01, AGT-02, AGT-03, AGT-04, AGT-05, AGT-06, AGT-07, DRV-01, DRV-02, DRV-03, DRV-04, DRV-06, DRV-07, DRV-09, TST-01, TST-02, TST-03, TST-05, TST-08
**Success Criteria** (what must be TRUE):

  1. The Cargo workspace is established with portable domain crates using safe Rust and Windows-specific integration crates.
  2. A minimal server runs with PostgreSQL and exposes a one-time enrollment token endpoint.
  3. A Windows service agent enrolls, receives a minimal signed configuration, and verifies its signature and schema version.
  4. The agent mounts a per-user WinFsp drive visible to the authenticated Windows user.
  5. The user can copy a file into the drive; the per-user backing store contains authenticated encrypted data with no directly readable plaintext.
  6. The user can read the file back through the drive; corrupted ciphertext fails without returning unauthenticated plaintext.
  7. A fully committed file survives service and machine restarts; an interrupted write is either committed completely or discarded without corrupting prior state.

**Plans**: 30 completed plans; D-48 ceremony and final Phase 1 verification remain pending

Plans:

- [x] 01-40-PLAN.md
- [ ] 01-41-PLAN.md

- [x] 01-35-PLAN.md
- [x] 01-36-PLAN.md
- [x] 01-37-PLAN.md
- [x] 01-38-PLAN.md
- [x] 01-39-PLAN.md

- [x] 01-34-PLAN.md

- [x] 01-31-PLAN.md
- [x] 01-32-PLAN.md
- [x] 01-33-PLAN.md

- [x] 01-27-PLAN.md
- [x] 01-28-PLAN.md
- [x] 01-29-PLAN.md
- [x] 01-30-PLAN.md

**Wave 1**

- [x] 01-17-PLAN.md (Wave 1) — Establish layered evidence/provenance, substitute boundaries, four-machine roles, and exact privilege-manifest approvals

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 01-22-PLAN.md (Wave 2) — Replace partial in-memory enrollment seams with PostgreSQL authority, transactional replacement, and constrained issuance

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 01-23-PLAN.md (Wave 3) — Wire production TLS/routes/providers and build the dual-DC/Kerberos trusted-provisioning procedure

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 01-13-PLAN.md (Wave 4) — Reconcile roles, deploy LAB-SERVER01 PostgreSQL and LAB-DC01 management server, and execute approved trusted LAB-CLIENT01 provisioning before enrollment

**Wave 5** *(blocked on Wave 4 completion)*

- [x] 01-14-PLAN.md (Wave 5) — Complete LAB-CLIENT01 initial/replacement enrollment, DPAPI credential custody, device mTLS, revocation proof, and redacted health

**Wave 6** *(blocked on Wave 5 completion)*

- [x] 01-18-PLAN.md (Wave 6) — Activate signed configuration into a durable concurrency-safe current/LKG cache on LAB-CLIENT01

**Wave 7** *(blocked on Wave 6 completion)*

- [x] 01-19-PLAN.md (Wave 7) — Install and exercise the automatic noninteractive LAB-CLIENT01 endpoint service and Windows-native fingerprint collector

**Wave 8** *(blocked on Wave 7 completion)*

- [x] 01-15-PLAN.md (Wave 8) — Wire the per-session host, authenticated storage IPC, deterministic drive lifecycle, isolation, sign-out drain, and service-restart behavior

**Wave 9** *(blocked on Wave 8 completion)*

- [x] 01-20-PLAN.md (Wave 9) — Revalidate real WinFsp integrity denial, disk-full last-commit preservation, service restart, and Windows reboot on LAB-CLIENT01

**Wave 10** *(blocked on Wave 9 completion)*

- [x] 01-24-PLAN.md (Wave 10) — Close the 01-16 blocker with real same-session host launch, authenticated key/bootstrap IPC, retained WinFsp lifetime, safe letter selection, cleanup, restart, and LAB-CLIENT01 proof

**Wave 11** *(blocked on Wave 10 completion)*

- [x] 01-16-PLAN.md (Wave 11) — Execute the four-machine production vertical slice and complete the D-16 through D-18 Office, operation, and size matrix

**Wave 12** *(blocked on Wave 11 completion)*

- [x] 01-21-PLAN.md (Wave 12) — Execute D-19 failure recovery, seal requirement-indexed evidence, and require independent Phase 1 review

**Wave 13** *(blocked on Wave 12 completion)*

- [x] 01-25-PLAN.md (Wave 13) — Validate the immutable security closure-target set, prove fail-closed tampering behavior, and sign off Phase 1 security

**Wave 14** *(gap closure for SC-04)*

- [x] 01-26-PLAN.md (Wave 14) — Fix WinFsp directory metadata, wildcard patterns, change notifications, and re-verify SC-04 on LAB-CLIENT01

### Phase 01.3: Make a background app that run in devices to collect log and provide the result through a HTTP port for easier debugging (INSERTED)

**Goal:** Developers can manually run an independent development-only Windows service on an endpoint and retrieve a bounded, allowlisted log tail over HTTP from trusted lab clients without affecting DLP runtime components.
**Requirements**: TBD
**Depends on:** Phase 1
**Plans:** 3/3 plans executed

Plans:

**Wave 1**

- [x] 01.3-01-PLAN.md (Wave 1) — Prove the listener-to-file tracer and harden fail-closed config, canonical direct-child authorization, and bounded complete-line tailing

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 01.3-02-PLAN.md (Wave 2) — Complete peer-authorized raw-text HTTP behavior and the isolated gracefully stoppable Windows SCM lifecycle

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 01.3-03-PLAN.md (Wave 3) — Publish the manual ACL/firewall/SCM runbook and verify the reversible LAB-CLIENT01 lifecycle and network boundaries

### Phase 01.2: DLP_AGENT_ENROLLMENT_TOKEN should be obtained automatically when DlpWindowsService installed (INSERTED)

**Goal:** As a lab operator, I want the endpoint deployment script to obtain the enrollment token automatically from trusted provisioning, so that I can install and start DlpWindowsService without manually copying a short-lived secret.
**Requirements**: SRV-13, SRV-14, TST-05, AGT-01
**Depends on:** Phase 1
**Plans:** 1/1 plans executed

Plans:

**Wave 1**

- [x] 01.2-01-PLAN.md (Wave 1) — Orchestrator-chained automatic enrollment token acquisition, validation, cleanup, and doc update (completed 2026-08-13)

### Phase 01.1: Add docs for those env var DLP_DEVICE_ID, DLP_SERVER_URL, DLP_ROOT_CA_PEM, DLP_CONFIGURATION_PUBLIC_KEY_HEX. Add docs to guide how to collect/create all env vars for setting up (INSERTED)

**Goal:** Document every runtime environment variable consumed by the DLP Windows endpoint agent service and provide operator instructions for collecting or creating the four required variables.
**Requirements**: TBD
**Depends on:** Phase 01
**Plans:** 1/1 plans executed

Plans:

**Wave 1**

- [x] 01.1-01-PLAN.md (Wave 1) — Create ENV-VARS.md reference and cross-reference it from the lab startup guide

### Phase 2: Policy Enforcement and User Feedback

**Goal**: Turn the encrypted drive into a working DLP boundary with metadata rules, actions, and user-facing feedback.
**Mode:** mvp
**Depends on**: Phase 1
**Requirements**: SRV-02, SRV-05, SRV-06, SRV-07, POL-01, POL-02, POL-03, POL-04, POL-05, POL-06, POL-07, POL-08, POL-09, POL-10, CRY-05, AGT-10, DRV-05, DRV-08, UI-01, UI-02, UI-03, TST-07
**Success Criteria** (what must be TRUE):

  1. Administrators can author, validate, version, assign, and publish policies through a web UI or CLI.
  2. The server produces immutable signed configuration bundles that the agent activates atomically, with last-known-good rollback on failure.
  3. The policy engine evaluates metadata and bounded content detectors deterministically and rejects policies that activate `require_justification`.
  4. Configured rules can `allow`, `block`, `allow_and_audit`, or `warn` on file operations, and every decision records a reason code.
  5. A blocked or warned operation returns an appropriate access-denied result, and the companion process shows a Windows toast with file name, rule reason, and remediation guidance.
  6. Enforcement events are created at the time of the decision with policy version, matched rule, action, and selected metadata.

**Plans**: TBD
**UI hint**: yes

### Phase 3: Audit, Offline Operation, and Fleet Control

**Goal**: Make enforcement centrally observable and resilient to disconnection.
**Mode:** mvp
**Depends on**: Phase 1, Phase 2
**Requirements**: SRV-04, SRV-08, SRV-09, SRV-10, CRY-03, AGT-08, AGT-09, AGT-11, ADM-01, ADM-02, ADM-03, ADM-04, TST-04, TST-06
**Success Criteria** (what must be TRUE):

  1. The agent queues enforcement events locally in an encrypted, bounded store and uploads them in order when the server is reachable.
  2. The agent continues enforcing the last valid signed policy for up to seven days offline, warns the user around day five, and locks the protected drive after the offline allowance expires.
  3. The agent recovers cleanly from service, process, and machine restarts without losing committed events or corrupting local state.
  4. Device lifecycle states (pending, active, locked, revoked, retired) are maintained and visible in the management console or CLI.
  5. Revocation takes effect locally after the agent receives it; an unreachable endpoint cannot know it has been revoked.
  6. Administrators can view fleet status, lock or revoke devices, and search/export audit events by time, device, user, action, rule, and severity.

**Plans**: TBD
**UI hint**: yes

### Phase 4: Hardening and MVP Release

**Goal**: Establish that the solution is safe and deployable beyond the development environment.
**Mode:** mvp
**Depends on**: Phase 1, Phase 2, Phase 3
**Requirements**: DRV-05 (stress/validation), AGT-10 (additional restart/recovery scenarios), TST-08 validation expansion
**Success Criteria** (what must be TRUE):

  1. Per-user SID isolation is validated: one user cannot mount or read another user's protected store through supported product interfaces.
  2. Storage is crash-consistent and recovers from corruption without returning unauthenticated plaintext.
  3. Credentials and encryption keys support rotation with replay and rollback protection.
  4. The agent ships as a signed MSI supporting install, upgrade, repair, and uninstall, with WinFsp dependency installation/version management documented.
  5. Representative Windows applications (Explorer, Word, Excel) open, save, rename, and delete files on the protected drive under concurrent access.
  6. Fuzz tests exercise policy deserialization, protocol parsing, path handling, and encrypted records.
  7. Load tests validate the target of 1,000 enrolled endpoints and 500 concurrently online endpoints.
  8. Operational, backup, recovery, and incident-response runbooks are complete.

**Plans**: TBD

## Progress

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. First Encrypted-Drive Vertical Slice | 28/29 | In Progress|  |
| 1.1. Add env-var docs | 1/1 | Complete | 2026-08-15 |
| 1.2. Automatic enrollment token acquisition | 1/1 | In Progress|  |
| 2. Policy Enforcement and User Feedback | 0/TBD | Not started | - |
| 3. Audit, Offline Operation, and Fleet Control | 0/TBD | Not started | - |
| 4. Hardening and MVP Release | 0/TBD | Not started | - |

## Coverage

- v1 requirements: 63 total
- Mapped to phases: 63
- Unmapped: 0

## Traceability Notes

- Phase 1 concentrates the riskiest integration first: server, enrollment, agent service, WinFsp drive, and encrypted storage. Policy authoring is deliberately minimal.
- Phase 2 layers policy enforcement and user feedback on top of the working drive.
- Phase 3 adds operational resilience: audit, offline behavior, and fleet control.
- Phase 4 is dedicated to hardening, packaging, compatibility, and release readiness.
- `CRY-03` (per-user key hierarchy with server escrow) is deferred to Phase 3 because Phase 1 can use a simpler per-user key wrapped by DPAPI-NG; the hierarchy and recovery workflow are required for fleet-scale operations.
- Device lifecycle state transitions and administrative audit logging are in Phase 3; Phase 1 only needs to create an enrolled device record.
- `DRV-05` (cross-user isolation) is introduced in Phase 2 for basic enforcement and revalidated under stress in Phase 4.

## Notes

- The central principle: Phase 1 ends with a real encrypted virtual drive working on Windows, not merely with server scaffolding.
- Toast notifications require authenticated service-to-companion IPC (UI-02) as a success criterion in Phase 2.
- Offline revocation behavior is documented: it takes effect only after the agent receives the revocation or its credentials are rejected.
- Waves 5, 6, and 7 are source-complete and merged; their LAB-CLIENT01 runtime smoke tests are blocked by missing lab orchestration artifacts and will be retried when those artifacts are available.
