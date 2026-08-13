---
gsd_plan_version: 1.0
quick_task: true
date: "2026-08-13"
slug: update-startup-guide
---

# Quick Task: Update HYPERV-DLP-STARTUP-GUIDE.md to utilize Invoke-Client01Runtime.ps1

## Goal

Update `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md` so it uses the new `scripts/lab/Invoke-Client01Runtime.ps1` orchestrator for building, installing, and starting the endpoint agent service on `LAB-CLIENT01`, instead of the older manual `Invoke-Command` snippets.

## Scope

- Update prerequisites section to include endpoint runtime secrets required by `Invoke-Client01Runtime.ps1`.
- Replace section 8 (manual service install/start/stop) with a new section that calls `Invoke-Client01Runtime.ps1` for `ServiceInstall` and `Tracer` scenarios.
- Update section 7 or merge it into the tracer section since `Invoke-Client01Runtime.ps1 -Scenario Tracer` already probes health endpoints from `LAB-CLIENT01`.
- Update troubleshooting table to reference `DlpWindowsService` and `Invoke-Client01Runtime.ps1` error codes.
- Update cheat sheet commands.
- Update related docs list to include `Invoke-Client01Runtime.ps1`.

## Steps

1. Read the current guide and `scripts/lab/Invoke-Client01Runtime.ps1` to identify exact parameters and required environment variables.
2. Edit `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md`:
   - Add endpoint runtime secrets to prerequisites (`DLP_DEVICE_ID`, `DLP_SERVER_URL`, `DLP_ROOT_CA_PEM`, `DLP_CONFIGURATION_PUBLIC_KEY_HEX`, optional `DLP_AGENT_ENROLLMENT_TOKEN`).
   - Replace section 8 with `Invoke-Client01Runtime.ps1` examples for dry-run and `-Apply`.
   - Remove or condense the manual `Invoke-Command` service snippets.
   - Update troubleshooting entries for service name `DlpWindowsService`, paths `C:\dlp\agent\`, and `Invoke-Client01Runtime.ps1`.
   - Update cheat sheet.
   - Update related docs.
3. Run `git diff --check` and a markdown sanity check.
4. Write `SUMMARY.md`, update `.planning/STATE.md`, and commit.

## Verification

- `git diff --check` passes.
- Document references the correct script path, parameters, and environment variables.
- No stale references to `dlp-agent` service name remain in commands.
