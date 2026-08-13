---
status: complete
completed_at: 2026-08-13
---

# Quick Task Summary: Hyper-V VM Start / Cold-Start PowerShell Guide

## What was done

- Created `.planning/docs/HYPERV-VM-START-GUIDE.md` with:
  - Prerequisite checks for the Hyper-V PowerShell module.
  - Commands to list VMs and inspect their state.
  - Warm-start (`Start-VM`) and cold-start (`Stop-VM -TurnOff -Force` + `Start-VM`) sequences.
  - Remote-host examples using `-ComputerName` and `-Credential`.
  - A reusable `Start-Lab.ps1` batch script for ordered lab boot sequences.
  - Common gotchas and a cheat sheet.
- Updated `.planning/STATE.md` with the "Quick Tasks Completed" table entry.

## Artifacts

- `.planning/docs/HYPERV-VM-START-GUIDE.md`
- `.planning/STATE.md`

## Verification

- Markdown renders without broken frontmatter.
- All PowerShell snippets use valid Hyper-V module cmdlets and parameter names.
- Cheat sheet covers the most common operator actions.
