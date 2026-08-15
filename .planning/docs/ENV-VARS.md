# Phase 1 Lab Environment Contract

This is the authoritative inventory of the Phase 1 lab environment. It is grounded in `config/*.env.example`, the Rust configuration loaders, and the lab PowerShell runners. Values are process/runtime inputs: do not commit a populated env file or a private key, password, token, or generated certificate.

`Initialize-DlpEnvironment.ps1` reads a strict one-line `NAME=value` env file. Consequently, env files carry **paths** for PEM/key material. A receiving script may accept inline PEM only when this table says so; use inline PEM only in a process environment or script handoff, never in a line-oriented env file.

## Names, owners, and representations

| Group and names | Consumer / host | Requiredness and defaults | Representation, sensitivity, source |
| --- | --- | --- | --- |
| `DATABASE_URL` | Direct `dlp-server` and `dlpctl` consumer on LAB-DC01. | Required by Rust; no default. | PostgreSQL URL, secret; supplied after LAB-SERVER01 provisioning. |
| `DLP_DATABASE_URL`, `DLP_DATABASE_NAME`, `DLP_DATABASE_USER` | Lab aliases consumed by `Invoke-Dc01Server.ps1`; it maps `DLP_DATABASE_URL` to `DATABASE_URL`. | URL required by the runner; `dlp` and `dlp_server` are lab defaults. | One-line URL/name/user; URL is secret. `DLP_DATABASE_URL` is not a Rust runtime name. |
| `DLP_LISTEN_ADDRESS` | `dlp-server` on LAB-DC01. | Binary default `0.0.0.0:8080`; lab override `0.0.0.0:8443`. | Host:port, non-secret; selected by topology. |
| `DLP_SERVER_CERT_PEM`, `DLP_SERVER_KEY_PEM`, `DLP_ADMIN_CA_CERT_PEM`, `DLP_PHASE1_ROOT_CA_CERT_PEM`, `DLP_DEVICE_ISSUING_CA_CERT_PEM`, `DLP_DEVICE_ISSUING_CA_KEY_PEM` | Required path inputs to the server TLS/peer-role configuration on LAB-DC01. | Required; no code defaults. | Existing PEM/key paths in env files; certificate may be an accepted inline-or-path input to the lab deployer, private keys are secret. Produced by the rotation scripts in `scripts/lab/`. |
| `DLP_TLS_EVENT_LOG_PATH` | Optional server TLS diagnostics. | Optional; code chooses its diagnostic behavior when absent. | Writable path, potentially sensitive diagnostics. |
| `DLP_AD_PRIMARY_LDAPS_URL`, `DLP_AD_SECONDARY_LDAPS_URL`, `DLP_AD_BASE_DN`, `DLP_AD_BIND_DN`, `DLP_AD_BIND_PASSWORD`, `DLP_AD_CA_CERT_PEM` | AD integration configured by the LAB-DC01 runner. | Required only when AD integration is enabled; no Rust fallback for supplied values. | URLs/DN/path/password; bind password is secret. Export the issuer of the active DC LDAPS certificate for the CA path. |
| `DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX`, `DLP_CONFIGURATION_KEY_ID` | Server signing setup and endpoint bundle identity. | Seed required for lab signing; key ID lab override `phase1-config-signing-key-v1`. Endpoint binary default is `phase1-config-signer`; both sides must agree. | 64-hex private seed (secret) and identifier (non-secret); generated/owned on LAB-DC01. |
| `DLP_DEVICE_ID`, `DLP_SERVER_URL`, `DLP_ROOT_CA_PEM`, `DLP_CONFIGURATION_PUBLIC_KEY_HEX`, `DLP_DATA_DIRECTORY`, `DLP_CACHE_DIRECTORY` | Required `dlp-windows-service` configuration on LAB-CLIENT01. | Required; no defaults. | Device ID, HTTPS URL, root certificate, 64-hex public key, writable paths. `DLP_ROOT_CA_PEM` accepts inline certificate PEM or a path in the service; `Invoke-Client01Runtime.ps1` always deploys certificate content then persists `C:\dlp\secrets\phase1-root-ca.pem`. |
| `DLP_AGENT_ENROLLMENT_TOKEN` | Optional initial enrollment input on LAB-CLIENT01. | Conditional: trusted provisioning obtains it automatically; set it only for manual/offline enrollment. | One-time secret token; do not put it in a committed/env-file template. |
| `DLP_POLL_INTERVAL_SECONDS`, `DLP_HEALTH_INTERVAL_SECONDS`, `DLP_START_TIMEOUT_SECONDS`, `DLP_STOP_TIMEOUT_SECONDS` | Endpoint service. | Binary defaults are **300/60/60/10** seconds. The older `300/60/30/30` example is not a code default. | Positive integer seconds, non-secret. |
| `DLP_WINFSP_INTERACTIVE_HOLD_MS`, `DLP_WINFSP_SMOKE_LETTER` | Lab smoke/interactive test inputs, not service configuration. | Optional; use only for the related smoke scenario. | Milliseconds and available drive letter, non-secret. |
| `DLP_PROVISIONING_ENDPOINT`, `DLP_PROVISIONING_ROOT_CA_PATH`, `DLP_PROVISIONING_ADMIN_CA_CERT_PATH`, `DLP_PROVISIONING_ADMIN_CERT_PATH`, `DLP_PROVISIONING_ADMIN_KEY_PATH`, `DLP_PROVISIONING_TOKEN_HANDOFF_PATH` | `dlpctl` trusted-provisioning call from LAB-DC01/hungdinh-lt. | Required for that flow; the helper derives several values. | HTTPS URL and one-line paths; admin key and token handoff are secret. `_PATH` names are file paths, unlike the PEM-content aliases below. |
| `DLP_PROVISIONING_ROOT_CA_PEM`, `DLP_PROVISIONING_ADMIN_CERT_PEM`, `DLP_PROVISIONING_ADMIN_KEY_PEM` | Inline-or-path aliases accepted by `Invoke-TrustedProvisioning.ps1`. | Optional compatibility/script inputs; helper materializes paths for `dlpctl`. | Inline PEM or existing path; private key is secret. |
| `DLP_PROVISIONING_AD_OBJECT_GUID`, `DLP_PROVISIONING_AD_OBJECT_SID`, `DLP_PROVISIONING_PREFERRED_DRIVE_LETTER`, `DLP_PROVISIONING_COMPUTER`, `DLP_PROVISIONING_DISK_MODE`, `DLP_PROVISIONING_DLPCTL_PATH`, `DLP_PROVISIONING_DIAGNOSTIC_PATH` | Provisioning helper/`dlpctl`. | GUID/SID/letter are required for a provision request; computer and disk mode have lab defaults (`LAB-CLIENT01.lab.local`, `lab-only`). | AD object bytes, drive letter, names/paths; diagnostic output can be sensitive. |
| `DLP_VM_ADMIN_USER`, `DLP_VM_ADMIN_PASSWORD`, `DLP_SERVER01_HOST`, `DLP_SERVER01_ADMIN_USER`, `DLP_SERVER01_ADMIN_PASSWORD`, `DLP_SERVER01_SSH_USER`, `DLP_PKI_DIR`, `DLP_SERVER_HOST` | Orchestration-only inputs to lab scripts; `-Credential` is an alternative to VM user/password vars. | Conditional on the script and supplied credential; lab hosts/paths have documented examples. | Credentials are secret; other values are host/path data. Not consumed by Rust runtime. |
| `DLP_APPROVED_PRIVILEGE_MANIFEST_DIGEST`, `DLP_LAB_ALLOW_VIRTUAL_DISK_UNIQUE_ID` | Lab orchestration/evidence controls. | Required only by scenarios that demand the privilege-manifest digest; virtual-disk flag is lab-only. | 64-hex digest and boolean, non-secret but integrity relevant. |

## Requiredness and precedence

The initializer resolves existing non-placeholder process values first. Without `-Force`, an `-EnvFile` only fills missing/placeholder values; with `-Force` it replaces them. Safe catalog defaults are then used. `-NonInteractive` never calls `Read-Host`: it reports all unresolved required/conditional names in one error. Any embedded `REPLACE_` marker or `<missing>` is unresolved.

Use `-OutEnvFile` only for a protected local file: it writes plaintext values and refuses to overwrite an existing path unless `-Force` is supplied. `-Clear` affects only `DLP_*` process variables, supports `-WhatIf`, and never edits User or Machine environment scopes.

## Compatibility and prohibited inputs

`DLP_ADMIN_PROVISIONING_KEY` is rejected legacy bearer configuration. Do not reintroduce it: provisioning authenticates with the administrator mTLS certificate/key and the separately trusted administrator CA. `DLP_DATABASE_URL` is an orchestration alias, while `DATABASE_URL` is the direct Rust consumer. Do not substitute `_PEM` values for `_PATH` inputs in an env file.

## Acquisition

Create/export all certificate and key paths through [PEM-KEY-GUIDE.md](PEM-KEY-GUIDE.md). The ordered operator workflow is [LAB-SETUP-GUIDE.md](LAB-SETUP-GUIDE.md). `config/lab.env.example` is a names-only starting point, not a secret file.
