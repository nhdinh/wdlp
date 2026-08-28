# Phase 1 Lab Setup: Start Here

This is the first-time, ordered setup path for the Phase 1 DLP lab. Run the orchestration commands from `hungdinh-lt` in an elevated PowerShell session; do not put passwords, tokens, or private keys in the repository. The specialist contracts are [ENV-VARS.md](ENV-VARS.md) and [PEM-KEY-GUIDE.md](PEM-KEY-GUIDE.md).

## 1. Preflight the topology

| Host | Role |
| --- | --- |
| `hungdinh-lt` | Orchestrator and protected secret source |
| `LAB-SERVER01` (`192.168.50.12`) | Native PostgreSQL |
| `LAB-DC01` (`192.168.50.10`) | Management server, primary AD, trusted provisioning |
| `LAB-DC02` | Secondary AD corroboration |
| `LAB-CLIENT01` | Endpoint service |

Confirm the VMs are running, their adapters are on the lab network, and DNS resolves `LAB-DC01.lab.local`, `LAB-DC02.lab.local`, and `LAB-CLIENT01.lab.local`. Confirm LAB-CLIENT01 has joined `lab.local`, both DCs offer LDAPS, and the client has WinFsp installed. For VM power/network commands see [HYPERV-VM-START-GUIDE.md](HYPERV-VM-START-GUIDE.md); for the native database setup see [LAB-SERVER01-SETUP.md](LAB-SERVER01-SETUP.md).

On the orchestration host install Rust, Git, OpenSSL, Hyper-V PowerShell tooling, `sqlx-cli`, `psql`, and Python/Paramiko for the reset helper. The workspace uses **Rust edition 2024**. Start from the checkout root:

```powershell
Set-Location C:\Users\nhdinh\dev\dleakprevention
cargo --version
openssl version
```

## 2. Build the process environment

The initializer manages only the current PowerShell process. It never changes User or Machine scope. Its precedence is existing non-placeholder process value, then `-EnvFile` value (unless `-Force`), then a safe catalog default. Embedded `REPLACE_` markers and `<missing>` are unresolved.

Use exactly one of these patterns:

```powershell
# Interactive: shows acquisition help and prompts for unresolved values.
.\scripts\lab\Initialize-DlpEnvironment.ps1

# Continue from a protected one-line NAME=value file; it fills missing values.
.\scripts\lab\Initialize-DlpEnvironment.ps1 -EnvFile .\config\lab.env.local

# Automation: never prompts. It reports every unresolved required/conditional name.
.\scripts\lab\Initialize-DlpEnvironment.ps1 -EnvFile .\config\lab.env.local -NonInteractive

# Same prompt/validation/results, but suppress only the acquisition prose.
.\scripts\lab\Initialize-DlpEnvironment.ps1 -NoHelp

# Explicit plaintext output: refuses an existing file unless -Force is supplied.
.\scripts\lab\Initialize-DlpEnvironment.ps1 -OutEnvFile .\config\lab.env.local

# Inspect then clear only DLP_* values in this PowerShell process.
.\scripts\lab\Initialize-DlpEnvironment.ps1 -Clear -WhatIf
.\scripts\lab\Initialize-DlpEnvironment.ps1 -Clear
```

`-Clear` cannot be combined with setup/output switches. An env file is strict: comments/blanks are allowed, each active line is a catalog `NAME=value`, no duplicates, and PEM/key entries must be one-line paths. `-OutEnvFile` deliberately writes plaintext secrets; protect and never commit it. See [ENV-VARS.md](ENV-VARS.md) for every consumer, default, requiredness, representation, and acquisition source rather than copying variable claims into this guide.

## 3. Generate and verify PKI

Use the separate Phase 1 root, administrator CA, device-issuing CA, and AD LDAPS issuer exactly as documented in [PEM-KEY-GUIDE.md](PEM-KEY-GUIDE.md). The recommended lab commands are:

```powershell
.\scripts\lab\New-DlpPhase1RootCa.ps1 -OutputDirectory C:\dlp\secrets
.\scripts\lab\Rotate-DlpAdminCa.ps1 -OutputDirectory C:\dlp\secrets
.\scripts\lab\Rotate-DlpDeviceIssuingCa.ps1 -OutputDirectory C:\dlp\secrets
.\scripts\lab\Rotate-DlpServerCert.ps1 -OutputDirectory C:\dlp\secrets
.\scripts\lab\Verify-DlpLabCertificates.ps1 -SecretsDirectory C:\dlp\secrets -ServerHostname LAB-DC01.lab.local
```

`New-DlpPhase1RootCa.ps1` is a first-time initialization command, not a routine rotation step. Do not use `-Force` unless you intend to replace the HTTPS trust root and redeploy every dependent certificate and endpoint trust anchor.

Export the issuer of the active DC LDAPS certificate to `ad-ca.pem`; creating an unrelated standalone root does not configure a DC for LDAPS. Use the reference for the correct `_PATH` versus `_PEM` aliases and file ownership. The endpoint runner accepts `DLP_ROOT_CA_PEM` as inline **certificate** PEM or a path, but deploys the certificate bytes and persists `C:\dlp\secrets\phase1-root-ca.pem` on LAB-CLIENT01.

## 4. Provision PostgreSQL and migrations

After LAB-SERVER01 has native PostgreSQL, its `dlp` database, and `dlp_server` role configured, run from the repository root:

```powershell
$env:DATABASE_URL = $env:DLP_DATABASE_URL
sqlx migrate run --source migrations/
psql "$env:DLP_DATABASE_URL" -c "SELECT COUNT(*) FROM _sqlx_migrations;"
```

The current migration set has three files: `202608070001_walking_skeleton.sql`, `202608070002_enrollment_authority.sql`, and `202608070003_authenticated_routes.sql`. The lab runner uses `DLP_DATABASE_URL` as an orchestration alias and sets the direct server consumer `DATABASE_URL` itself.

## 5. Start and check the management server

Supply a credential or the documented VM credential variables, then run a server scenario. With `-SecretProvider Runtime`, every scenario requires these values in the calling PowerShell process:

- `DLP_DATABASE_URL`
- `DLP_SERVER_CERT_PEM` and `DLP_SERVER_KEY_PEM`
- `DLP_ADMIN_CA_CERT_PEM`
- `DLP_PHASE1_ROOT_CA_CERT_PEM`
- `DLP_DEVICE_ISSUING_CA_CERT_PEM` and `DLP_DEVICE_ISSUING_CA_KEY_PEM`
- `DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX`

The `TrustedProvisioning` and `All` scenarios additionally require `DLP_PROVISIONING_ROOT_CA_PEM`, `DLP_PROVISIONING_ADMIN_CERT_PEM`, `DLP_PROVISIONING_ADMIN_KEY_PEM`, and the six `DLP_AD_*` LDAPS settings documented in [ENV-VARS.md](ENV-VARS.md). `DLP_ADMIN_PROVISIONING_KEY` is an obsolete bearer secret: do not create or set it. Current provisioning uses administrator mTLS credentials instead.

`Invoke-Dc01Server.ps1` has scenarios `Tracer`, `PostgresFresh`, `PostgresRepeat`, `MigrationFailure`, `ConcurrentStart`, `ReadinessConcurrency`, `TrustedProvisioning`, and `All`.

```powershell
$cred = Get-Credential -Message 'LAB-DC01 administrator credential'
.\scripts\lab\Invoke-Dc01Server.ps1 `
  -CallerMachine hungdinh-lt -ExecutionMachine LAB-DC01 -ProbeMachine LAB-CLIENT01 `
  -DatabaseMachine LAB-SERVER01 -SecondaryDcMachine LAB-DC02 `
  -SecretProvider Runtime -Scenario Tracer -Credential $cred
```

Do not treat `-Apply` as a management-server dry-run gate: select the intended scenario and follow its own behavior. The lab listens on `0.0.0.0:8443`, whereas the binary default is `0.0.0.0:8080`.

## 6. Trusted provisioning and endpoint deployment

The ordinary endpoint path uses TrustedProvisioning by default: `-Scenario ServiceInstall` obtains a fresh short-lived enrollment token without a manual copy, installs the automatic service, removes token state, and waits for first signed policy activation. `-RetainEnrollmentToken` is troubleshooting-only on a successful run and never suppresses failure cleanup. For an explicit Manual offline fallback, set `DLP_AGENT_ENROLLMENT_TOKEN='<FROM-RUNTIME-PROVIDER>'` and select `-EnrollmentTokenProvider Manual`.

```powershell
$cred = Get-Credential -Message 'LAB-CLIENT01 administrator credential'
.\scripts\lab\Invoke-Client01Runtime.ps1 `
  -CallerMachine hungdinh-lt -ExecutionMachine LAB-CLIENT01 -ProbeMachine LAB-DC01 `
  -SecretProvider Runtime -Scenario ServiceInstall `
  -Credential $cred -Apply
```

For this endpoint runner, omitting `-Apply` is a dry run; `-Apply` performs the selected `Tracer`, `ServiceInstall`, or `All` scenario. The runner writes its root certificate content to `C:\dlp\secrets\phase1-root-ca.pem` before the service receives that deployed path.

Administrator mTLS certificate/key material remains on LAB-DC01 throughout trusted provisioning and is never deployed to LAB-CLIENT01. A usable `C:\dlp\agent\data\credentials\device.dpapi` skips provisioning on ordinary reruns. Replacement is allowed only with `-ForceReenrollment -Apply`; `-ForceReenrollment` alone is a non-destructive preview. Replacement preserves the installed service, binaries, data directory, and cache directory.

After success or a failure following token handoff, the runner removes `DLP_AGENT_ENROLLMENT_TOKEN` from both `C:\dlp\agent\agent.env` and `HKLM:\SYSTEM\CurrentControlSet\Services\DlpWindowsService\Environment`. Cleanup failure is a hard error that names both paths. Repair them and rerun so TrustedProvisioning mints a fresh token; never reuse the prior attempt's token.

Normal output contains stable codes and high-level state only. Use `-Diagnostic` explicitly for redacted names, lengths, paths, fingerprints, counts, and bounded error metadata. Never collect enrollment tokens, administrator mTLS material, private keys, passwords, full certificates, or raw credential blobs.

## 7. Verify enrollment, service, and TLS

Check service, credential, and cleanup state on LAB-CLIENT01 without printing secret values:

```powershell
Invoke-Command -VMName LAB-CLIENT01 -Credential $cred -ScriptBlock {
  $serviceKey='HKLM:\SYSTEM\CurrentControlSet\Services\DlpWindowsService'
  $fileNames=@([IO.File]::ReadAllLines('C:\dlp\agent\agent.env') | ForEach-Object { ($_ -split '=',2)[0] })
  $scmNames=@((Get-ItemProperty -Path $serviceKey -Name Environment -ErrorAction Stop).Environment | ForEach-Object { ($_ -split '=',2)[0] })
  [pscustomobject]@{
    ServiceStatus=(Get-Service DlpWindowsService).Status
    CredentialPresent=Test-Path 'C:\dlp\agent\data\credentials\device.dpapi'
    AgentEnvTokenCount=@($fileNames | Where-Object { $_ -eq 'DLP_AGENT_ENROLLMENT_TOKEN' }).Count
    ScmTokenCount=@($scmNames | Where-Object { $_ -eq 'DLP_AGENT_ENROLLMENT_TOKEN' }).Count
  }
}
```

Both token counts must be zero after successful automatic enrollment. Then run the live smoke contract, which fails unless the first signed policy is active:

```powershell
.\tests\windows\Invoke-AgentServiceSmoke.ps1 `
  -CallerMachine hungdinh-lt -ExecutionMachine LAB-CLIENT01 -ServerMachine LAB-DC01 `
  -SecretProvider Runtime -Scenario InitialEnrollmentCredential -Credential $cred
```

Expected evidence includes `active_policy_version=<non-empty>` and `active_policy_state=Active`. Verify server health with the hostname covered by the certificate and the deployed root CA; do not install a permissive certificate callback:

```powershell
Invoke-Command -VMName LAB-CLIENT01 -Credential $cred -ScriptBlock {
  curl.exe --cacert C:\dlp\secrets\phase1-root-ca.pem https://LAB-DC01.lab.local:8443/health/live
  curl.exe --cacert C:\dlp\secrets\phase1-root-ca.pem https://LAB-DC01.lab.local:8443/health/ready
}
```

## 8. Cleanup and troubleshooting

Use `Initialize-DlpEnvironment.ps1 -Clear -WhatIf` before clearing local process environment values. For VM/service cleanup and daily cold starts see [HYPERV-DLP-STARTUP-GUIDE.md](HYPERV-DLP-STARTUP-GUIDE.md). If a certificate check fails, rerun `Verify-DlpLabCertificates.ps1`; if provisioning fails, inspect the LAB-DC01 provisioning diagnostics without copying token/key contents into tickets or source control.
