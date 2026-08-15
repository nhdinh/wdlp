# DLP Windows Endpoint Agent Runtime Environment Variables

This document is the operator reference for every environment variable consumed by the DLP Windows endpoint agent service (`dlp-windows-service.exe`).

All values listed here are **runtime-only secrets and configuration**. They are supplied by the operator's runtime secret provider or orchestration script and are **never committed to source control**. The lab deployment script [`scripts/lab/Invoke-Client01Runtime.ps1`](../../scripts/lab/Invoke-Client01Runtime.ps1) reads these variables, writes them to `C:\dlp\agent\agent.env`, and persists the same lines in the `DlpWindowsService` registry `Environment` value so the SCM starts the service with them already loaded.

For server-side, provisioning, and PKI material, see [PEM-KEY-GUIDE.md](PEM-KEY-GUIDE.md) and [LAB-SETUP-GUIDE.md](LAB-SETUP-GUIDE.md).

---

## Required variables

The service fails at startup with `service_config_missing` or `service_config_invalid` if any of these is missing or malformed.

| Variable | Purpose | Format / validation | Example | Default |
| --- | --- | --- | --- | --- |
| `DLP_DEVICE_ID` | Stable identifier for this endpoint. Used in enrollment, health posts, and configuration cache paths. | 1-128 ASCII characters; letters, digits, `-`, `_`, and `.` allowed; must not start/end with `.` and must not contain `..`. See [`DeviceId::parse`](../../crates/dlp-domain/src/lib.rs). | `LAB-CLIENT01.lab.local` | None |
| `DLP_SERVER_URL` | Base URL of the management server the agent contacts for enrollment, configuration polling, and health. | `https://<host>:<port>` with a TLS scheme. The host must resolve from the endpoint and match the server certificate. | `https://LAB-DC01:8443` | None |
| `DLP_ROOT_CA_PEM` | Public root CA certificate used to validate the management server's TLS certificate. | Either the PEM content (multi-line string beginning with `-----BEGIN CERTIFICATE-----`) or an absolute path to a `.pem` file containing the certificate. Must be the **public root only**, not a private key. | `-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiU...` | None |
| `DLP_DATA_DIRECTORY` | Writable directory for durable agent state: credentials, enrollment material, and per-user store roots. | Absolute Windows path. The service runs as `NT AUTHORITY\SYSTEM`; the directory must be writable by that identity. | `C:\dlp\agent\data` | None |
| `DLP_CACHE_DIRECTORY` | Writable directory for the signed configuration cache (current, LKG, and staged bundles). | Absolute Windows path, writable by `NT AUTHORITY\SYSTEM`. Should be on local storage. | `C:\dlp\agent\cache` | None |
| `DLP_CONFIGURATION_PUBLIC_KEY_HEX` | Ed25519 public key used to verify signed configuration bundles before activation. | Exactly 64 lowercase hexadecimal characters representing 32 bytes. Uppercase hex is accepted by the hex decoder but lowercase is preferred. | `a1b2c3d4e5f6...` (64 hex chars) | None |

---

## Optional variables

These variables have safe defaults in the service. Set them only when you need to override the default behavior.

| Variable | Purpose | Format / validation | Example | Default |
| --- | --- | --- | --- | --- |
| `DLP_CONFIGURATION_KEY_ID` | Identifier for the configuration signing key. Must match the key ID the server embeds in signed bundles. | Non-empty string, typically kebab-case. | `phase1-config-signer` | `phase1-config-signer` |
| `DLP_AGENT_ENROLLMENT_TOKEN` | Short-lived token used for initial or replacement enrollment. | JWT-safe token string; the lab orchestrator validates length `<=512` and charset `[A-Za-z0-9_.~/-]`. | `eyJ0eXAiOiJKV1Qi...` | None (omit when using trusted provisioning) |
| `DLP_POLL_INTERVAL_SECONDS` | How often the agent polls the management server for a new signed configuration. | Positive integer seconds. | `300` | `300` (5 minutes) |
| `DLP_HEALTH_INTERVAL_SECONDS` | How often the agent posts a redacted health snapshot. | Positive integer seconds. | `60` | `60` (1 minute) |
| `DLP_START_TIMEOUT_SECONDS` | Internal startup timeout used by some service helpers. | Positive integer seconds. | `60` | `60` |
| `DLP_STOP_TIMEOUT_SECONDS` | Internal stop timeout used by some service helpers. | Positive integer seconds. | `10` | `10` |
| `DLP_PREFERRED_DRIVE_LETTER` | Preferred drive letter for the per-user protected virtual drive. | Single ASCII letter. The service uppercases it. | `P` | `P` |
| `DLP_SIGN_OUT_GRACE_SECONDS` | Grace period after a user signs out before the drive is torn down. | Positive integer seconds. | `30` | `30` |
| `DLP_DRIVE_HOST_BINARY_PATH` | Absolute path to the `dlp-drive-host.exe` binary that mounts the WinFsp drive. | Absolute Windows path. | `C:\Program Files\DLP\dlp-drive-host.exe` | `C:\Program Files\DLP\dlp-drive-host.exe` |

---

## Collecting or creating the four required variables

Most `service_config_missing` failures come from these four values. Use the steps below to obtain or create each one safely.

### `DLP_DEVICE_ID`

Choose a stable identifier for `LAB-CLIENT01` that will not change across reinstalls. The canonical Phase 1 lab value is the computer's Active Directory DNS host name:

```text
LAB-CLIENT01.lab.local
```

Rules:

- 1 to 128 characters.
- Only ASCII letters, digits, hyphen (`-`), underscore (`_`), and dot (`.`).
- Must not start or end with a dot.
- Must not contain `..`.
- Avoid spaces, backslashes, colons, or other punctuation.

If you are not using Active Directory, use a hostname assigned during provisioning, e.g. `client01-lab` or `dlp-endpoint-01`. Record the chosen value in your runtime secret provider; do not commit it.

### `DLP_SERVER_URL`

This is the base URL of the management server (`dlp-server.exe`) running on `LAB-DC01`.

1. Confirm the management server host name from your lab topology. In the Phase 1 lab this is `LAB-DC01`.
2. Confirm the listening port. The lab default is `8443`.
3. Format the value as `https://<host>:<port>`.

Example:

```text
https://LAB-DC01:8443
```

If you access the server by IP address instead of host name, the server's TLS certificate must include that IP in the subject alternative name; otherwise the agent's TLS validation will fail. The lab uses host-name validation, so prefer the host name.

### `DLP_ROOT_CA_PEM`

This is the public root certificate that issued (or anchors the chain for) the management server's TLS certificate. It pins the agent to the lab PKI.

How to obtain it:

1. If you generated the lab PKI with the rotation scripts in `scripts/lab/`, the root CA certificate is written to `C:\dlp\secrets\phase1-root-ca.pem` after trusted provisioning.
2. If the server certificate was issued by a different CA, export that CA's public certificate in PEM format.
3. The value must contain only the public certificate PEM. It must never contain a private key.

You can supply the value to `Invoke-Client01Runtime.ps1` in either of these forms:

- **Inline PEM content**: a multi-line string starting with `-----BEGIN CERTIFICATE-----` and ending with `-----END CERTIFICATE-----`.
- **File path**: an absolute path to a `.pem` file on the orchestrator host. The script reads the file and copies the certificate to `C:\dlp\secrets\phase1-root-ca.pem` on `LAB-CLIENT01`.

The service loader (`crates/dlp-windows-service/src/service.rs`) accepts both forms: if the value contains `BEGIN CERTIFICATE` it uses it directly, otherwise it reads the file at the given path.

### `DLP_CONFIGURATION_PUBLIC_KEY_HEX`

This is the 32-byte Ed25519 public key that corresponds to the server's configuration signing private key. The agent uses it to verify the signature on every configuration bundle before activation.

How to obtain it:

1. The server signs configurations with a seed derived from `DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX`. The public key is the Ed25519 public key derived from that same seed.
2. In the lab, after the server PKI is generated, the corresponding public key is typically exported as a 64-character lowercase hex string.
3. You can also derive it locally if you have the seed, using `dlpctl` or any Ed25519 tool.

Format rules:

- Exactly 64 hexadecimal characters representing 32 bytes.
- Lowercase is preferred; the hex decoder accepts uppercase as well.
- No `0x` prefix, no spaces, no line breaks.

Example (synthetic):

```text
a1b2c3d4e5f60708192a3b4c5d6e7f8090a1b2c3d4e5f60708192a3b4c5d6e7f
```

The key ID that identifies this key on the server is configured separately via `DLP_CONFIGURATION_KEY_ID`; the default on both sides is `phase1-config-signer`.

---

## Runtime-only vs committed defaults

The DLP service is designed to start with **no committed secrets**. This boundary is what lets the same binary run in development, lab, and production without source changes.

| Category | What belongs here | Examples | Where it lives |
| --- | --- | --- | --- |
| Runtime-only secrets | Certificates, private keys, enrollment tokens, device identity, signing seeds. | `DLP_ROOT_CA_PEM`, `DLP_CONFIGURATION_PUBLIC_KEY_HEX`, `DLP_AGENT_ENROLLMENT_TOKEN`, `DLP_DEVICE_ID`. | Runtime secret provider, PowerShell session, `agent.env`, service registry `Environment`. |
| Committed / example defaults | Host names, key IDs, intervals, drive letter, paths that are safe to share. | `DLP_SERVER_URL=https://LAB-DC01:8443`, `DLP_CONFIGURATION_KEY_ID=phase1-config-signer`, `DLP_POLL_INTERVAL_SECONDS=300`. | Example configs, docs, and runbooks (with synthetic values only). |

Never paste a real PEM, key, token, or password into a committed file, a chat log, or this document. All examples above are synthetic placeholders.

---

## PowerShell setup template

Paste this block into your orchestration PowerShell session on `hungdinh-lt`, replacing every `***` value with material from your runtime secret provider.

```powershell
# Required endpoint identity and server target
$env:DLP_DEVICE_ID                    = 'LAB-CLIENT01.lab.local'
$env:DLP_SERVER_URL                   = 'https://LAB-DC01:8443'

# Required pinned root CA for server TLS validation.
# Inline PEM content is accepted here; Invoke-Client01Runtime.ps1 will deploy it
# to C:\dlp\secrets\phase1-root-ca.pem on LAB-CLIENT01.
$env:DLP_ROOT_CA_PEM                  = @'
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiU... *** from runtime provider ***
-----END CERTIFICATE-----
'@

# Required Ed25519 public key for signed configuration verification (64 hex chars)
$env:DLP_CONFIGURATION_PUBLIC_KEY_HEX = 'a1b2c3d4...'  # *** from runtime provider ***

# Required durable state directories on LAB-CLIENT01
$env:DLP_DATA_DIRECTORY               = 'C:\dlp\agent\data'
$env:DLP_CACHE_DIRECTORY              = 'C:\dlp\agent\cache'

# Optional overrides (safe defaults are shown)
$env:DLP_CONFIGURATION_KEY_ID         = 'phase1-config-signer'
$env:DLP_POLL_INTERVAL_SECONDS        = '300'
$env:DLP_HEALTH_INTERVAL_SECONDS      = '60'
$env:DLP_START_TIMEOUT_SECONDS        = '60'
$env:DLP_STOP_TIMEOUT_SECONDS         = '10'
$env:DLP_PREFERRED_DRIVE_LETTER       = 'P'
$env:DLP_SIGN_OUT_GRACE_SECONDS       = '30'

# Optional: only needed for manual/offline enrollment.
# With -EnrollmentTokenProvider TrustedProvisioning, Invoke-Client01Runtime.ps1
# obtains and cleans up this token automatically.
# $env:DLP_AGENT_ENROLLMENT_TOKEN      = '*** from runtime provider ***'
```

After setting the variables, run [`scripts/lab/Invoke-Client01Runtime.ps1`](../../scripts/lab/Invoke-Client01Runtime.ps1) to deploy the service and persist the environment on `LAB-CLIENT01`:

```powershell
$cred = Get-Credential -Message "LAB admin credential"
.\scripts\lab\Invoke-Client01Runtime.ps1 `
    -CallerMachine            hungdinh-lt `
    -ExecutionMachine         LAB-CLIENT01 `
    -ProbeMachine             LAB-DC01 `
    -SecretProvider           Runtime `
    -Scenario                 Tracer `
    -EnrollmentTokenProvider  TrustedProvisioning `
    -Credential               $cred `
    -Apply
```

This writes `C:\dlp\agent\agent.env`, installs or reconfigures `DlpWindowsService`, and starts the service with the runtime variables already loaded.

---

## Related documentation

- [HYPERV-DLP-STARTUP-GUIDE.md](HYPERV-DLP-STARTUP-GUIDE.md) — day-to-day lab startup, VM boot order, and service start/stop commands.
- [PEM-KEY-GUIDE.md](PEM-KEY-GUIDE.md) — how to obtain or generate the PEM/KEY files used by the server and provisioning flows.
- [LAB-SETUP-GUIDE.md](LAB-SETUP-GUIDE.md) — first-time provisioning sequence for the entire lab.
- [scripts/lab/Invoke-Client01Runtime.ps1](../../scripts/lab/Invoke-Client01Runtime.ps1) — lab deployment script that consumes these variables.
