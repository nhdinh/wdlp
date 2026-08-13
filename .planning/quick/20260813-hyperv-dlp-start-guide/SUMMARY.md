---
status: complete
completed_at: 2026-08-13
---

# Quick Task Summary: DLP Server / Services / Endpoint Startup on Hyper-V VMs

## What was done

- Created `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md` with:
  - Phase 1 lab topology recap.
  - Environment-variable prerequisites.
  - VM warm-start and cold-start sequences.
  - Database startup and SQLx migration commands.
  - Management-server startup via `scripts/lab/Invoke-Dc01Server.ps1`.
  - Endpoint agent service install/start/stop/restart commands.
  - Smoke-test invocation via `tests/windows/Invoke-AgentServiceSmoke.ps1`.
  - Environment reconcile / cleanup via `scripts/lab/Invoke-Phase1EnvironmentReconcile.ps1`.
  - Troubleshooting table and cheat sheet.
- Updated `.planning/STATE.md` "Quick Tasks Completed" table.

## Artifacts

- `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md`
- `.planning/STATE.md`

## Verification

- All referenced script paths and parameter names match the current codebase.
- PowerShell commands use valid Hyper-V, service, and WinRM/PSDirect patterns.
- Cross-references to related project docs are correct.
