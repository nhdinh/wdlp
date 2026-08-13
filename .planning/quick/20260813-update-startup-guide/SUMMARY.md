---
gsd_summary_version: 1.0
quick_task: true
date: "2026-08-13"
slug: update-startup-guide
status: complete
---

# Quick Task Summary: Update HYPERV-DLP-STARTUP-GUIDE.md to utilize Invoke-Client01Runtime.ps1

## Result

Updated `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md` to use `scripts/lab/Invoke-Client01Runtime.ps1` for deploying and starting the endpoint agent service on `LAB-CLIENT01`.

## Changes

- Added endpoint runtime secrets to the prerequisites section (`DLP_DEVICE_ID`, `DLP_SERVER_URL`, `DLP_ROOT_CA_PEM`, `DLP_CONFIGURATION_PUBLIC_KEY_HEX`, optional `DLP_CONFIGURATION_KEY_ID` and `DLP_AGENT_ENROLLMENT_TOKEN`).
- Replaced section 8 (manual service install/start/stop) with `Invoke-Client01Runtime.ps1` usage:
  - Dry-run example.
  - `-Apply` install/start example.
  - Endpoint tracer example that probes health endpoints from `LAB-CLIENT01`.
  - Retained manual check/start/stop/restart snippets for `DlpWindowsService`.
- Updated troubleshooting table entries to reference `Invoke-Client01Runtime.ps1`, `DlpWindowsService`, and `C:\dlp\agent` paths.
- Updated the cheat sheet to deploy/start the endpoint service with the new orchestrator.
- Updated related docs list to include `Invoke-Client01Runtime.ps1`.

## Verification

- `git diff --check` passed.
- No stale references to `dlp-agent` service name remain in commands.

## Artifacts

- `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md`
