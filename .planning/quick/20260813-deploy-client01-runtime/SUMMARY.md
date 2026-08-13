---
gsd_summary_version: 1.0
quick_task: true
date: "2026-08-13"
slug: deploy-client01-runtime
status: complete
---

# Quick Task Summary: Deploy dlp-windows-service runtime to LAB-CLIENT01

## Result

Created `scripts/lab/Invoke-Client01Runtime.ps1`, a fail-closed PowerShell orchestrator modeled on `scripts/lab/Invoke-Dc01Server.ps1`, that builds the `dlp-windows-service` release binary and deploys it to `LAB-CLIENT01`.

## Artifacts

- `scripts/lab/Invoke-Client01Runtime.ps1`

## What the script does

- Validates the orchestrator role (`developer_orchestrator` on `hungdinh-lt`).
- Validates the approved Plan 01-19 privilege manifest digest.
- Resolves VM admin credentials from `-Credential` or `DLP_VM_ADMIN_USER/PASSWORD`.
- Asserts required runtime secrets (`DLP_DEVICE_ID`, `DLP_SERVER_URL`, `DLP_ROOT_CA_PEM`, `DLP_CONFIGURATION_PUBLIC_KEY_HEX`).
- Builds `dlp-windows-service.exe` in release mode if missing.
- Copies the binary to `C:\dlp\agent\dlp-windows-service.exe` on `LAB-CLIENT01` via `Copy-VMFile` with a PowerShell Direct fallback.
- Creates data/cache directories.
- Writes the root CA and an `agent.env` file on the target.
- Installs or reconfigures the `DlpWindowsService` Windows service as automatic, running as `NT AUTHORITY\SYSTEM`.
- Persists the env file contents to the service registry `Environment` value so the SCM loads them into the service process.
- Starts the service and verifies it reaches the `Running` state.
- Supports `Tracer`, `ServiceInstall`, and `All` scenarios, with an `-Apply` switch for dry-run by default.
- Collects Phase 1 evidence/fingerprint artifacts consistent with `Invoke-Dc01Server.ps1`.

## Verification

- PowerShell parse check passed (`[System.Management.Automation.PSParser]::Tokenize` returned 2308 tokens with no parse errors).
- `git diff --check` passed with no whitespace errors.

## Notes

- Live VM execution remains blocked by missing runtime token and VM reachability, per `STATE.md` blockers for Plan 01-19. The script is the source deliverable and is fail-closed when secrets or VM access are unavailable.
- Service environment variables are persisted via the service registry `Environment` value; the service binary reads them with `std::env::var` as implemented in `crates/dlp-windows-service/src/service.rs`.
