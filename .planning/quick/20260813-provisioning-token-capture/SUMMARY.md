---
gsd_summary_version: 1.0
quick_task: true
date: "2026-08-13"
slug: provisioning-token-capture
status: complete
---

# Quick Task Summary: Capture enrollment token from Invoke-TrustedProvisioning.ps1

## Result

Updated the trusted provisioning flow so `dlpctl provision-device` receives the environment variables it requires and returns the enrollment token to the orchestrator, which can then pass it to `Invoke-Client01Runtime.ps1`.

## Artifacts

- `scripts/lab/Invoke-TrustedProvisioning.ps1`
- `scripts/lab/Invoke-Dc01Server.ps1`
- `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md`

## Changes

- Added `Assert-ProvisioningMaterialPresent` to `Invoke-TrustedProvisioning.ps1`.
- Updated `Invoke-TrustedProvisioning.ps1` to:
  - Create `C:\dlp\provisioning\` on `LAB-DC01`.
  - Write `root-ca.pem`, `admin-cert.pem`, and `admin-key.pem` from runtime-provider PEM content.
  - Set `DLP_PROVISIONING_ENDPOINT`, `DLP_PROVISIONING_ROOT_CA_PATH`, `DLP_PROVISIONING_ADMIN_CERT_PATH`, `DLP_PROVISIONING_ADMIN_KEY_PATH`, and `DLP_PROVISIONING_TOKEN_HANDOFF_PATH`.
  - Invoke `dlpctl provision-device`.
  - Read the enrollment token from the handoff file.
  - Return the token in the JSON response alongside existing non-secret provenance.
- Updated `Invoke-Dc01Server.ps1` to:
  - Assert provisioning material secrets are present.
  - Pass the PEM content into the remote `Invoke-TrustedProvisioning.ps1` invocation.
  - Capture the returned `enrollment_token` and set `$env:DLP_AGENT_ENROLLMENT_TOKEN` in the orchestrator process.
- Updated `HYPERV-DLP-STARTUP-GUIDE.md` to clarify that the enrollment token comes from the `TrustedProvisioning` scenario and should not be persisted on `hungdinh-lt`.

## Verification

- PowerShell parse checks passed for all three scripts.
- `git diff --check` passed.

## Notes

- `Invoke-Client01Runtime.ps1` already requires `DLP_AGENT_ENROLLMENT_TOKEN` for first-start enrollment.
- Live VM execution remains blocked by VM reachability/token availability; the scripts are the source deliverables and are fail-closed when prerequisites are missing.
