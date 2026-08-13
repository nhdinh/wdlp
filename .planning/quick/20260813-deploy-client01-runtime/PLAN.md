---
gsd_plan_version: 1.0
quick_task: true
date: "2026-08-13"
slug: deploy-client01-runtime
---

# Quick Task: Deploy dlp-windows-service runtime to LAB-CLIENT01

## Goal

Create `scripts/lab/Invoke-Client01Runtime.ps1`, modeled on `scripts/lab/Invoke-Dc01Server.ps1`, that builds the `dlp-windows-service` release binary on the developer orchestrator host and deploys it to `LAB-CLIENT01` as an installed Windows service with runtime configuration.

## Scope

- Source-only artifact: the PowerShell deployment/orchestration script.
- No live VM mutation is performed by this quick task; the script is the deliverable.
- Align with Plan 01-19 privilege manifest (`install service`, `configure service identity and fingerprint runtime state`).

## Steps

1. Read `scripts/lab/Invoke-Dc01Server.ps1` and `crates/dlp-windows-service/src/service.rs` to identify shared helpers, parameter style, evidence/fingerprint patterns, and required runtime configuration.
2. Create `scripts/lab/Invoke-Client01Runtime.ps1` with:
   - `[CmdletBinding()]` parameter block matching the DC01 orchestrator conventions (`CallerMachine`, `ExecutionMachine=LAB-CLIENT01`, `ProbeMachine`, `SecretProvider`, `Scenario`, `Apply`, `Credential`).
   - Role manifest guard (`developer_orchestrator` on `hungdinh-lt`).
   - Approved privilege manifest digest check for Plan 01-19.
   - VM credential resolution via `-Credential` or `DLP_VM_ADMIN_USER/PASSWORD`.
   - Runtime-secret presence assertion for endpoint service configuration.
   - Release binary build (`cargo build --release -p dlp-windows-service`).
   - File copy to `LAB-CLIENT01` via `Copy-VMFile` with PowerShell Direct fallback.
   - Directory creation (`C:\dlp\agent`, `C:\dlp\agent\data`, `C:\dlp\agent\cache`).
   - Service installation idempotency using `sc.exe create` / `New-Service` with the service name `DlpWindowsService`.
   - Runtime environment file written to `C:\dlp\agent\agent.env`.
   - Service start and status verification.
   - Evidence/fingerprint helpers mirroring `Invoke-Dc01Server.ps1`.
3. Ensure the script is fail-closed: missing secrets, failed build, missing binary, or failed service status throws a stable error code.
4. Update `.planning/STATE.md` Quick Tasks Completed table.
5. Commit the new script with a `chore` or `feat` prefix and the standard Co-Authored-By trailer.

## Verification

- `pwsh -Command "Get-Command scripts/lab/Invoke-Client01Runtime.ps1"` resolves.
- Script parses without errors: `pwsh -Command "Test-ScriptFileInfo scripts/lab/Invoke-Client01Runtime.ps1"` (or `Get-Command` / AST parse).
- `git diff --check` passes.
