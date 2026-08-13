---
created: 2026-08-13
type: quick-task
status: in_progress
---

# Quick Task: PEM/KEY Collection Guide

Write a guide that explains how to obtain or create every PEM and KEY file referenced by the DLP Phase 1 lab environment variables. The guide should cover server TLS certificates, CA trust anchors, device-issuing CA, Active Directory LDAPS CA, and trusted-provisioning administrator mTLS credentials. It should also map each artifact to the env var that consumes it.

## Scope

- Document `DLP_SERVER_CERT_PEM` / `DLP_SERVER_KEY_PEM`
- Document `DLP_ADMIN_CA_CERT_PEM`
- Document `DLP_PHASE1_ROOT_CA_CERT_PEM`
- Document `DLP_DEVICE_ISSUING_CA_CERT_PEM` / `DLP_DEVICE_ISSUING_CA_KEY_PEM`
- Document `DLP_AD_CA_CERT_PEM`
- Document `DLP_PROVISIONING_ROOT_CA_PATH`
- Document `DLP_PROVISIONING_ADMIN_CERT_PATH` / `DLP_PROVISIONING_ADMIN_KEY_PATH`
- Document `DLP_ROOT_CA_PEM` (agent runtime)
- Link from `ENV-VARS.md` and `HYPERV-DLP-STARTUP-GUIDE.md`

## Acceptance Criteria

- New guide file at `.planning/docs/PEM-KEY-GUIDE.md`
- Each section explains what the file is, how to obtain or generate it, and which env var(s) use it
- Include PowerShell and OpenSSL examples where appropriate
- Update `ENV-VARS.md` and `HYPERV-DLP-STARTUP-GUIDE.md` to reference the new guide
- Commit atomically with a clear message
