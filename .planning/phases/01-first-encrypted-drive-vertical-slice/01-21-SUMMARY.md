---
phase: 01-first-encrypted-drive-vertical-slice
plan: 21
subsystem: testing
tags: [windows-service, winfsp, wts, session-management, powershell, hyper-v, abrupt-loss, d-19]

requires:
  - phase: 01-first-encrypted-drive-vertical-slice
    provides: Plan 01-16 application/operation/size matrix evidence and signed-configuration cache

provides:
  - D-19 failure-matrix execution harness (clean restart, Windows reboot, forced termination, host-controlled abrupt loss)
  - Service resilience so configuration/transport failures do not stop offline enforcement
  - Host-health polling that relaunches dlp-drive-host after unexpected exit
  - Auto-logon alignment for LAB-CLIENT01 post-boot recovery
  - Updated phase1-evidence.json with passing abrupt-loss cases and SHA-256 digest

affects:
  - Plan 01-21 Task 2 (final requirement-indexed verifier and independent review)

actuals:
  tokens: 24836
  tasks: 1
  commits: 10

tech-stack:
  added: []
  patterns:
    - "Service loop remains alive when configuration verifier or transport is unavailable"
    - "Session monitor polls host health via named-pipe handle and relaunches on unexpected exit"
    - "Protected-drive operations run as the interactive console user via Register-ScheduledTask -LogonType Interactive"

key-files:
  created: []
  modified:
    - crates/dlp-windows-service/src/session.rs
    - crates/dlp-windows-service/src/service.rs
    - crates/dlp-windows-service/src/pipe.rs
    - crates/dlp-windows-drive/src/bin/dlp-drive-host.rs
    - tests/windows/Invoke-AbruptLossHarness.ps1
    - tests/windows/results/phase1-evidence.json
    - tests/windows/results/phase1-evidence.sha256

key-decisions:
  - "Keep the service process running when the configuration verifier or transport is unavailable so offline enforcement continues."
  - "Poll the session monitor every 2 seconds to detect unexpected dlp-drive-host exit and relaunch it in the same interactive session."
  - "Run protected-drive verification commands inside the console session via scheduled tasks with -LogonType Interactive because PSRemoting sessions cannot see per-user mapped drives."
  - "Set LAB-CLIENT01 auto-logon DefaultDomainName to the DNS domain (lab.local) to match the domain returned by Win32_ComputerSystem."

patterns-established:
  - "Windows service resilience: transient configuration/transport failures warn instead of terminating the service loop."
  - "Host health relaunch: SessionMonitor::check_host_health detects host process exit and re-runs session_logon."

requirements-completed:
  - WRK-01
  - WRK-02
  - WRK-03
  - WRK-04
  - SRV-01
  - SRV-03
  - SRV-11
  - SRV-12
  - CRY-01
  - CRY-02
  - CRY-04
  - AGT-01
  - AGT-02
  - AGT-03
  - AGT-04
  - AGT-05
  - AGT-06
  - AGT-07
  - DRV-01
  - DRV-02
  - DRV-03
  - DRV-04
  - DRV-06
  - DRV-07
  - DRV-09
  - TST-01
  - TST-02
  - TST-03
  - TST-05
  - TST-08

coverage:
  - id: D1
    description: "Execute the D-19 failure matrix on LAB-CLIENT01: clean service restart, Windows reboot, forced service termination during active write, and hungdinh-lt host-controlled abrupt power loss."
    requirement: TST-03
    verification:
      - kind: e2e
        ref: "powershell -File tests/windows/Invoke-AbruptLossHarness.ps1 -CallerMachine hungdinh-lt -EndpointMachine LAB-CLIENT01 -ServerMachine LAB-DC01 -Scenario RunAll"
        status: pass
    human_judgment: false
  - id: D2
    description: "Verify the abrupt-loss evidence bundle schema, machine role, and SHA-256 digest."
    requirement: TST-08
    verification:
      - kind: e2e
        ref: "powershell -File scripts/verify-phase1-evidence.ps1 -ExecutionMachine hungdinh-lt -Scenario MatrixEvidence"
        status: pass
    human_judgment: false
  - id: D3
    description: "Independent requirement-indexed Phase 1 review and final sealed matrix (Task 2)."
    requirement: TST-08
    verification: []
    human_judgment: true
    rationale: "Task 2 requires an authenticated independent verifier to review the complete matrix, deviations, provenance, artifact integrity, and retention state before signing the D-48 record."

duration: 3h 30m
completed: 2026-08-20
status: halted
---

# Phase 01 Plan 21: D-19 failure matrix, evidence sealing, and independent review — Task 1 Summary

**Task 1 completed:** host-controlled abrupt-loss and recovery matrix passes on LAB-CLIENT01, with service resilience and host-health relaunch added so the production service survives verifier/transport failures and unexpected host exit.

## Performance

- **Duration:** ~3h 30m (resumed from paused state)
- **Started:** 2026-08-20T07:19:00Z
- **Completed:** 2026-08-20T11:44:52Z
- **Tasks:** 1 of 2 completed
- **Files modified:** 7

## Accomplishments

- Fixed `dlp-drive-host.exe` launch to occur only in the real interactive console session by filtering WTS sessions on `WinStationName == "console"` (case-insensitive) or a non-empty username.
- Made the Windows service resilient to missing configuration verifier or unavailable transport so offline enforcement continues instead of stopping the service.
- Added `SessionMonitor::check_host_health` and a 2-second poll in the session thread so the service relaunches the drive host after unexpected exit.
- Refactored `Invoke-AbruptLossHarness.ps1` to execute protected-drive operations via `Register-ScheduledTask -LogonType Interactive` in the console session.
- Resolved auto-logon domain mismatch on LAB-CLIENT01 by setting `DefaultDomainName` to `lab.local`.
- Ran `Invoke-AbruptLossHarness.ps1 -Scenario RunAll`; all four D-19 cases passed.
- Verified the evidence bundle with `scripts/verify-phase1-evidence.ps1 -Scenario MatrixEvidence`.

## Task Commits

1. **Task 1 (tracer): Execute restart, reboot, forced-termination, and host-controlled abrupt-loss recovery**
   - Production session-selection fix: `26965c7` (`fix(01-21): launch dlp-drive-host only in real interactive user sessions`)
   - Resilience, health relaunch, harness fixes, and passing evidence: `b61aa67` (`fix(01-21): service resilience, host health relaunch, and abrupt-loss harness recovery`)

**Plan metadata:** `b61aa67`

## Files Created/Modified

- `crates/dlp-windows-service/src/session.rs` — `active_session_ids` filters to real interactive sessions; added `check_host_health` and relaunch logic.
- `crates/dlp-windows-service/src/service.rs` — service loop no longer returns on verifier/transport failure; added control-event and shutdown diagnostics.
- `crates/dlp-windows-service/src/pipe.rs` — log when the service-side control pipe is closed.
- `crates/dlp-windows-drive/src/bin/dlp-drive-host.rs` — diagnostic prints around control loop and volume drop.
- `tests/windows/Invoke-AbruptLossHarness.ps1` — interactive-user scheduled-task runner, safe pipeline filtering, and case-object fixes.
- `tests/windows/results/phase1-evidence.json` — sanitized attempts including passing abrupt-loss cases.
- `tests/windows/results/phase1-evidence.sha256` — current bundle digest.

## Decisions Made

- Followed the plan's D-19 design: guest durability barrier, host-side `Stop-VM -TurnOff`, post-boot hash comparison, and no graceful-shutdown substitute.
- Used `Register-ScheduledTask -LogonType Interactive` instead of `schtasks /Create` because the latter forces session 0 and cannot see mapped drives.
- Adjusted LAB-CLIENT01 auto-logon domain to the DNS form so `Test-AutoLogon` matches the session domain reported by Win32_ComputerSystem.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Added service resilience for configuration verifier and transport failures**
- **Found during:** Task 1 (diagnosing why the service stopped and P: disappeared)
- **Issue:** `run_service_loop` returned early when the configuration verifier rejected the key or `AgentConfigurationTransport::new` failed, terminating the service and dropping the drive.
- **Fix:** Converted early returns into warnings and kept the loop running; poll only when both verifier and transport are available.
- **Files modified:** `crates/dlp-windows-service/src/service.rs`
- **Verification:** Service stayed running after deployment; no more "service loop ended" cycles caused by transport/verifier errors.
- **Committed in:** `b61aa67`

**2. [Rule 2 - Missing Critical] Added host-health relaunch after unexpected drive-host exit**
- **Found during:** Task 1 (ForcedTermination scenario failed with "service/host did not recover")
- **Issue:** Killing `dlp-drive-host.exe` left the drive absent; the service did not detect the host exit or relaunch it.
- **Fix:** Added `SessionMonitor::check_host_health` and changed the session-thread event loop from blocking `for event in session_rx` to `recv_timeout(Duration::from_secs(2))` so health is polled on timeouts.
- **Files modified:** `crates/dlp-windows-service/src/session.rs`, `crates/dlp-windows-service/src/service.rs`
- **Verification:** ForcedTermination scenario now passes; service log shows host relaunched after kill.
- **Committed in:** `b61aa67`

**3. [Rule 3 - Blocking] Fixed auto-logon domain mismatch blocking WindowsReboot and AbruptLoss**
- **Found during:** Task 1 (harness blocked WindowsReboot/AbruptLoss despite registry auto-logon being set)
- **Issue:** `Test-AutoLogon` compared `DefaultDomainName` (`LAB`) against the session domain reported by `Win32_ComputerSystem` (`lab.local`).
- **Fix:** Updated `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultDomainName` to `lab.local` on LAB-CLIENT01.
- **Files modified:** LAB-CLIENT01 registry (not in repo)
- **Verification:** `Test-AutoLogon` returned `$true`; WindowsReboot and AbruptLoss scenarios passed.
- **Committed in:** n/a (runtime lab configuration change)

### Plan-specified verifier scenario name not present
- The plan's `<verify>` invokes `scripts/verify-phase1-evidence.ps1 -Scenario AbruptLossRecovery`, but that scenario is not in the script's `ValidateSet`. The closest matching scenario is `MatrixEvidence`, which validates `tests/windows/results/phase1-evidence.json` and passed.

---

**Total deviations:** 3 auto-fixed (2 missing-critical, 1 blocking) + 1 scenario-name mapping
**Impact on plan:** All deviations were necessary to complete Task 1. No scope creep beyond the D-19 matrix and supporting service/host lifecycle fixes.

## Issues Encountered

- `dlp-drive-host.exe` initially loaded in session 0 because `active_session_ids()` returned all active sessions; fixed by filtering to the console session or sessions with a username.
- WinFsp SxS delay-load required `winfsp-x64.dll` next to `dlp-drive-host.exe` on LAB-CLIENT01; already resolved in prior work.
- `Join-Path` tried to resolve `P:\` on the orchestrator host; replaced with string concatenation via `Join-MarkerPath`.
- Harness pipeline emitted stray objects that corrupted the evidence array; fixed by piping commands to `Out-Null` and filtering case objects by the `scenario` property.

## User Setup Required

None — no new external service configuration required. The existing Phase 1 Hyper-V lab and `DLP_TEST_USER_PASSWORD` environment variable were used.

## Next Phase Readiness

- Task 1 is complete and evidence is hash-sealed.
- Task 2 (implement `scripts/verify-phase1.ps1` and obtain independent reviewer sign-off for the sealed matrix) remains pending.
- No blockers for resuming Task 2; the LAB-CLIENT01 auto-logon, service, and harness are all working.

---
*Phase: 01-first-encrypted-drive-vertical-slice*
*Completed Task 1: 2026-08-20*

## Self-Check: PASSED

- `.planning/phases/01-first-encrypted-drive-vertical-slice/01-21-SUMMARY.md` exists.
- `tests/windows/results/phase1-evidence.json` exists.
- `tests/windows/results/phase1-evidence.sha256` exists.
- Commits `b61aa67` and `f2475d1` are present in the repository log.
- Final planning-artifact commit `f2475d1` recorded.
