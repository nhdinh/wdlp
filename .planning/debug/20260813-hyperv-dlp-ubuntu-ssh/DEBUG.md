---
observed: 2026-08-13
file: .planning/docs/HYPERV-DLP-STARTUP-GUIDE.md
symptom: Section 5 uses PowerShell Direct (Invoke-Command -VMName) against LAB-SERVER01, but LAB-SERVER01 is an Ubuntu Server VM. PowerShell Direct only works on Windows guests, so the commands cannot succeed.
expected: The guide should use SSH and bash to manage PostgreSQL on LAB-SERVER01.
actual: The guide tells the reader to use Invoke-Command and Get-Service/Start-Service on a Linux VM.
impact: Operators following the guide will get connection failures or command-not-found errors.
---

# Debug Session: HYPERV-DLP-STARTUP-GUIDE.md Ubuntu SSH Fix

## Root Cause

`LAB-SERVER01` is documented as Ubuntu Server in `.planning/docs/LAB-SERVER01-SETUP.md`. `Invoke-Command -VMName` relies on the Hyper-V PowerShell Direct guest integration component, which is only available on Windows guests. The Ubuntu VM is managed via SSH from `hungdinh-lt`.

## Fix Plan

1. Rewrite Section 5 of `HYPERV-DLP-STARTUP-GUIDE.md` to use SSH/bash commands for PostgreSQL service status, start, restart, and migration verification.
2. Update prerequisites to mention the SSH credential/identity.
3. Update the troubleshooting table to remove the Windows-specific PostgreSQL service note and add SSH/connectivity notes.
4. Update the cheat sheet to use SSH for LAB-SERVER01 PostgreSQL checks.
5. Update the quick-task summary and commit.

## Status

Fix applied. Section 5 now uses `ssh` + `systemctl` + `psql` for LAB-SERVER01. Prerequisites include `DLP_SERVER01_SSH_USER`. Cheat sheet and troubleshooting updated.
