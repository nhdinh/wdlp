---
gsd_plan_version: 1.0
quick_task: true
date: "2026-08-13"
slug: provisioning-token-capture
---

# Quick Task: Capture enrollment token from Invoke-TrustedProvisioning.ps1

## Goal

Update `scripts/lab/Invoke-TrustedProvisioning.ps1` so that before invoking `dlpctl provision-device`, it writes the required provisioning material and sets the `DLP_PROVISIONING_*` environment variables that `dlpctl` expects. After `dlpctl` succeeds, capture the enrollment token from the handoff file and return it in the script output so the caller can set `DLP_AGENT_ENROLLMENT_TOKEN` for `Invoke-Client01Runtime.ps1`.

## Background

`dlpctl provision-device` (`crates/dlpctl/src/main.rs:299-350`) requires these environment variables:

- `DLP_PROVISIONING_ENDPOINT` — full URL to `/api/v1/admin/provisioning`
- `DLP_PROVISIONING_ROOT_CA_PATH` — path to root CA PEM file
- `DLP_PROVISIONING_ADMIN_CERT_PATH` — path to admin client cert PEM
- `DLP_PROVISIONING_ADMIN_KEY_PATH` — path to admin client key PEM
- `DLP_PROVISIONING_TOKEN_HANDOFF_PATH` — path where `dlpctl` writes the token

Currently `Invoke-TrustedProvisioning.ps1` only sets AD GUID/SID and drive letter before calling `dlpctl`, so provisioning would fail.

## Steps

1. Read `scripts/lab/Invoke-TrustedProvisioning.ps1` and `scripts/lab/Invoke-Dc01Server.ps1` to identify available secrets and the local file layout on `LAB-DC01`.
2. Update `Invoke-TrustedProvisioning.ps1`:
   - Accept optional runtime-provider values or read them from environment variables.
   - Create `C:\dlp\provisioning\` on `LAB-DC01`.
   - Write `phase1-root-ca.pem`, `provisioning-admin-cert.pem`, `provisioning-admin-key.pem` from runtime-provider PEM content.
   - Set `DLP_PROVISIONING_ENDPOINT`, `DLP_PROVISIONING_ROOT_CA_PATH`, `DLP_PROVISIONING_ADMIN_CERT_PATH`, `DLP_PROVISIONING_ADMIN_KEY_PATH`, `DLP_PROVISIONING_TOKEN_HANDOFF_PATH`.
   - Call `dlpctl provision-device`.
   - Read the token from the handoff file.
   - Return a JSON object that includes `enrollment_token` along with the existing provenance fields.
3. Update `scripts/lab/Invoke-Dc01Server.ps1` `Invoke-TrustedProvisioningScenario` to:
   - Supply the new provisioning secrets to the remote script.
   - Capture the returned token from `Invoke-LabCommand` output.
   - Set `$env:DLP_AGENT_ENROLLMENT_TOKEN` so downstream orchestration can use it.
4. Update `scripts/lab/Invoke-Client01Runtime.ps1`:
   - Add `DLP_AGENT_ENROLLMENT_TOKEN` to `Assert-RuntimeSecretsPresent` (for first-start enrollment).
   - Pass the token through to the remote env file/registry.
5. Update `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md` to mention the token flow.
6. Run PowerShell parse checks and `git diff --check`.
7. Write `SUMMARY.md`, update `.planning/STATE.md`, and commit.

## Verification

- `Invoke-TrustedProvisioning.ps1` parses without errors.
- `Invoke-Dc01Server.ps1` parses without errors.
- `Invoke-Client01Runtime.ps1` parses without errors.
- `git diff --check` passes.
- The returned JSON from `Invoke-TrustedProvisioning.ps1` includes `enrollment_token` and preserves existing non-secret provenance.

## Security Notes

- The enrollment token is short-lived and must not be logged or committed.
- The token may be returned to the orchestrator process via stdout so it can be handed to the endpoint deployment script; avoid writing it to disk on `hungdinh-lt`.
- Admin cert/key material is written only to `LAB-DC01` and consumed by `dlpctl` from file paths.
