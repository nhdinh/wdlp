---
generated: 2026-08-14
---

# Quick Task: Comprehensive DLP Lab Setup Guide

Create a single, comprehensive lab setup guide that collects the existing Phase 1 DLP documentation and `scripts/lab/` scripts into a coherent, step-by-step walkthrough for setting up the DLP lab from scratch on Hyper-V VMs.

## Scope

- Exclude Hyper-V VM creation/networking guides (already covered in `.planning/docs/HYPERV-VM-START-GUIDE.md`).
- Include topology, prerequisites, environment setup, PKI generation, PostgreSQL setup, management-server deployment, endpoint enrollment, verification, and troubleshooting.
- Reference specialized docs (`ENV-VARS.md`, `PEM-KEY-GUIDE.md`, `LAB-SERVER01-SETUP.md`, `HYPERV-DLP-STARTUP-GUIDE.md`) rather than duplicating them.
- Provide a scripts inventory so operators know which script to run and when.

## Output

1. Create `.planning/docs/LAB-SETUP-GUIDE.md` as the canonical "start here" lab setup document.
2. Create `scripts/lab/README.md` listing each lab script with purpose, prerequisites, and example invocation.
3. Update `.planning/STATE.md` "Quick Tasks Completed" table.
4. Commit the result.

## Verification

- Guide references only files that exist in the current codebase.
- Script examples use current parameter names and ValidateSet values.
- Cross-links to related docs are correct.
