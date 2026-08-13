# DLP Windows Endpoint Agent Environment Variables

This document lists every environment variable consumed by the DLP Windows endpoint agent service (`dlp-windows-service.exe`). These values are **runtime-only** secrets and configuration. They are supplied by the operator's secret provider at deployment time and are **never committed to source control**.

The service reads all runtime values through environment variables. In the lab, `scripts/lab/Invoke-Client01Runtime.ps1` collects them from the orchestration host, writes `C:\dlp\agent\agent.env` on `LAB-CLIENT01`, and persists the same values into the service registry so the SCM starts the service with them already loaded.

---

## Required Variables

These variables must be present before the service can start. If any are missing, the service exits with `service_config_missing` or `service_config_invalid`.

| Variable | Purpose | Format / Validation | Example | Default |
|----------|---------|---------------------|---------|---------|
| `DLP_DEVICE_ID` | Stable identifier for this endpoint, used in enrollment, health posts, and audit events. | Non-empty string accepted by `DeviceId::parse`. Avoid spaces, control characters, and shell-sensitive punctuation. Use hostname-derived or assigned identifiers. | `LAB-CLIENT01` | None (required) |
| `DLP_SERVER_URL` | Base URL of the management server the agent contacts for enrollment, configuration, and health. | Valid HTTPS URL including scheme and port. The agent pins TLS to the root CA in `DLP_ROOT_CA_PEM`. | `https://LAB-DC01:8443` | None (required) |
| `DLP_ROOT_CA_PEM` | Pinned public root CA used to validate the management server's TLS certificate. | Either the PEM content as a multi-line string starting with `-----BEGIN CERTIFICATE-----`, or an absolute filesystem path to a PEM file. Must be the **public root only**; never the private key. | `-----BEGIN CERTIFICATE-----\nMIIC...` or `C:\dlp\secrets\root-ca.pem` | None (required) |
| `DLP_DATA_DIRECTORY` | Directory for durable agent state, including the DPAPI-protected credential store. | Absolute filesystem path. The service creates subdirectories as needed. Must be writable by the service account (`NT AUTHORITY\SYSTEM` in the lab). | `C:\dlp\agent\data` | None (required) |
| `DLP_CACHE_DIRECTORY` | Directory for the signed configuration cache (`current` + last-known-good). | Absolute filesystem path. Must be writable by the service account. | `C:\dlp\agent\cache` | None (required) |
| `DLP_CONFIGURATION_PUBLIC_KEY_HEX` | Ed25519 public key used to verify signed configuration bundles. | Exactly 64 lowercase hexadecimal characters representing 32 bytes. | `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef` | None (required) |

---

## Optional Variables

| Variable | Purpose | Format / Validation | Example | Default |
|----------|---------|---------------------|---------|---------|
| `DLP_CONFIGURATION_KEY_ID` | Human-readable identifier for the configuration signer, recorded with the active bundle. | Any non-empty string. Must match the key ID the server uses when signing bundles. | `phase1-config-signer` | `phase1-config-signer` |
| `DLP_AGENT_ENROLLMENT_TOKEN` | One-time token used for initial enrollment. If omitted and no credential exists, the service enters `ReplacementEnrollmentRequired` mode. | String supplied by the management server's enrollment endpoint. Treat as a secret. | `eyJ...` | None (optional) |
| `DLP_POLL_INTERVAL_SECONDS` | How often the agent polls the server for a new signed configuration bundle. | Positive integer seconds. | `300` | `300` (5 minutes) |
| `DLP_HEALTH_INTERVAL_SECONDS` | How often the agent posts a redacted health snapshot to the server. | Positive integer seconds. | `60` | `60` (1 minute) |
| `DLP_START_TIMEOUT_SECONDS` | Internal timeout budget for the service start sequence. | Positive integer seconds. | `60` | `60` |
| `DLP_STOP_TIMEOUT_SECONDS` | Internal timeout budget for graceful service shutdown. | Positive integer seconds. | `10` | `10` |

---

## Collecting or Creating the Four Required Variables

This section explains how an operator obtains or generates the values that have no safe default.

### `DLP_DEVICE_ID`

Choose a stable, machine-scoped identifier. The service parses it with `DeviceId::parse`, which rejects empty values and most special characters.

Recommended approach:

1. Use the machine's short hostname, an asset tag, or an assigned fleet identifier.
2. Remove spaces and characters outside `[A-Za-z0-9_-]`.
3. Keep it consistent across reinstalls of the same machine so the management server recognizes it as the same device.

Example for a lab VM:

```powershell
$env:DLP_DEVICE_ID = 'LAB-CLIENT01'
```

### `DLP_SERVER_URL`

This is the HTTPS base URL of the deployed management server.

1. Identify the management server host (in the lab this is `LAB-DC01`).
2. Identify the listening port (the lab server listens on `8443`).
3. Combine them as `https://<host>:<port>`.

Example:

```powershell
$env:DLP_SERVER_URL = 'https://LAB-DC01:8443'
```

If DNS resolution is unreliable, use the IP address instead of the hostname, but ensure the server's certificate covers that IP or that the operator documents the exception for the lab.

### `DLP_ROOT_CA_PEM`

This is the **public** root certificate of the CA that issued the management server's TLS certificate. The agent uses it to pin TLS and refuses to connect if the server's chain does not anchor here.

How to obtain it:

1. If the lab uses the trusted-provisioning procedure, the root CA PEM is an output of that procedure.
2. If the server certificate was issued by an internal CA, export the root CA certificate (not the intermediate, not the server certificate, and never the private key).
3. Save the PEM content to your runtime secret provider.

How the service accepts it:

- As a multi-line PEM string in the environment variable, or
- As an absolute filesystem path. In the lab, `Invoke-Client01Runtime.ps1` writes the PEM to `C:\dlp\secrets\root-ca.pem` and sets the variable to that path.

Example PEM snippet (synthetic, not a real certificate):

```text
-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4nEHXqzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
YWItcm9vdENBMB4XDTI2MDEwMTAwMDAwMFoXDTI3MDEwMTAwMDAwMFowFDESMBAG
A1UEAwwJbGFiLXJvb3RDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
...
-----END CERTIFICATE-----
```

### `DLP_CONFIGURATION_PUBLIC_KEY_HEX`

This is the 32-byte Ed25519 public key that signs configuration bundles. The service expects exactly 64 lowercase hex characters.

How to obtain it:

1. The management server or trusted-provisioning output emits the public key alongside the configuration signing secret.
2. Convert the raw 32-byte key to lowercase hex. Do not include `0x`, spaces, or newlines.
3. Store only the **public** key in the runtime secret provider.

Example (synthetic, 64 hex characters):

```powershell
$env:DLP_CONFIGURATION_PUBLIC_KEY_HEX = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
```

The corresponding private key must remain on the management server or in its HSM/secret store.

---

## Runtime-Only vs. Committed Defaults

| Category | Examples | Where It Lives |
|----------|----------|----------------|
| Committed / example defaults | Hostnames, key IDs, interval seconds, directory paths | Example config files, documentation, lab topology diagrams |
| Runtime-only secrets | Certificates, private keys, enrollment tokens, device identity, Ed25519 public key | Runtime secret provider (password manager, HSM, Azure Key Vault, lab orchestration host secrets, etc.) |

A good rule of thumb: if leaking the value would let someone impersonate the device, decrypt data, or bypass TLS pinning, it is runtime-only and must never be committed.

The optional interval and timeout variables can be committed as defaults, but they should still be overridable at deployment time for different environments.

---

## Local PowerShell Setup Template

Copy this template into your orchestration host PowerShell session and fill in the placeholder values from your runtime secret provider. This template sets only the required variables; add optional ones as needed.

```powershell
# Required runtime secrets — replace placeholders with values from your secret provider.
$env:DLP_DEVICE_ID                    = 'LAB-CLIENT01'
$env:DLP_SERVER_URL                   = 'https://LAB-DC01:8443'
$env:DLP_ROOT_CA_PEM                  = '-----BEGIN CERTIFICATE-----...'  # or C:\dlp\secrets\root-ca.pem
$env:DLP_DATA_DIRECTORY               = 'C:\dlp\agent\data'
$env:DLP_CACHE_DIRECTORY              = 'C:\dlp\agent\cache'
$env:DLP_CONFIGURATION_PUBLIC_KEY_HEX = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'

# Optional overrides
$env:DLP_CONFIGURATION_KEY_ID         = 'phase1-config-signer'
$env:DLP_AGENT_ENROLLMENT_TOKEN       = '***from-runtime-provider***'
$env:DLP_POLL_INTERVAL_SECONDS        = '300'
$env:DLP_HEALTH_INTERVAL_SECONDS      = '60'
$env:DLP_START_TIMEOUT_SECONDS        = '60'
$env:DLP_STOP_TIMEOUT_SECONDS         = '10'
```

After the variables are set, run the lab deployment script:

```powershell
$cred = Get-Credential -Message "LAB-CLIENT01 admin credential"

$repoRoot = 'C:\Users\nhdinh\dev\dleakprevention'
Set-Location $repoRoot
.\scripts\lab\Invoke-Client01Runtime.ps1 `
    -CallerMachine    hungdinh-lt `
    -ExecutionMachine LAB-CLIENT01 `
    -ProbeMachine     LAB-DC01 `
    -SecretProvider   Runtime `
    -Scenario         Tracer `
    -Credential       $cred `
    -Apply
```

`Invoke-Client01Runtime.ps1` consumes these variables and persists them into the `DlpWindowsService` environment so the service starts with the correct configuration.

---

## Related Docs

- `scripts/lab/Invoke-Client01Runtime.ps1` — lab deployment script that consumes these variables.
- `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md` — end-to-end lab cold-start walkthrough.
- `crates/dlp-windows-service/src/service.rs` — service configuration loader that reads these variables.
