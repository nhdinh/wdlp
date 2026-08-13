---
status: complete
date: 2026-08-13
---

# Quick Task Summary: PEM/KEY Collection Guide

## What Was Done

- Created `.planning/docs/PEM-KEY-GUIDE.md` with step-by-step instructions for obtaining or generating every PEM/KEY file used by Phase 1 lab environment variables.
- Covered:
  - Phase 1 root CA
  - Server TLS certificate and key
  - Administrator CA and provisioning admin certificate
  - Device-issuing CA certificate and key
  - Active Directory LDAPS CA
  - Trusted-provisioning root CA, admin cert, and admin key
  - Agent runtime root CA
- Added an environment-variable-to-file mapping table.
- Updated `.planning/docs/ENV-VARS.md` to link to the new guide from the `DLP_ROOT_CA_PEM` section and Related Docs.
- Updated `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md` to reference the new guide in the prerequisites and Related Docs.

## Verification

- Markdown renders without syntax errors.
- All referenced files exist.
- Guide maps every PEM/KEY variable in `config/lab.env.example` to an acquisition method.

## Artifacts

- `.planning/docs/PEM-KEY-GUIDE.md`
- `.planning/docs/ENV-VARS.md` (updated)
- `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md` (updated)
