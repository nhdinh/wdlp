# DLP Windows Endpoint Environment Variables

This is the canonical operator reference for the environment consumed by `dlp-windows-service.exe`. It covers the Phase 1 path from `hungdinh-lt` through `LAB-CLIENT01` to `LAB-DC01`. Server, AD, provisioning, and orchestration-only catalogs remain in [LAB-SETUP-GUIDE.md](LAB-SETUP-GUIDE.md); certificate creation remains in [PEM-KEY-GUIDE.md](PEM-KEY-GUIDE.md).

## Handling classes

| Class | Examples | Handling rule |
| --- | --- | --- |
| Cryptographic secret | enrollment tokens, private keys, passwords | Use a protected runtime provider; never print or commit; rotate after exposure. |
| Sensitive identifier | `DLP_DEVICE_ID` | Disclose only where endpoint identification is needed; redact in public diagnostics. |
| Public trust/configuration | root CA, Ed25519 verification public key | Not secret, but integrity-critical: authenticate transfer and compare fingerprints. |
| Ordinary setting | URL, paths, key ID, intervals, drive letter | Safe to document; validate because wrong values can stop or misdirect the service. |

Sensitive examples use visibly non-runnable markers such as `<FROM-RUNTIME-PROVIDER>`. Never replace them in a committed file.

## Setup-first workflow

Run in an elevated PowerShell session on `hungdinh-lt`. The normal path is `Initialize-DlpEnvironment.ps1` followed by `Invoke-Client01Runtime.ps1`. The initializer changes only the current process, never User or Machine scope.

### 1. Collect

Interactive setup shows acquisition help and prompts for unresolved values. An existing non-placeholder process value wins, then a protected `-EnvFile` value (unless `-Force`), then a safe catalog default.

- `DLP_DEVICE_ID`: AD DNS identity `LAB-CLIENT01.lab.local`.
- `DLP_SERVER_URL`: hostname-aware endpoint `https://LAB-DC01:8443`.
- `DLP_ROOT_CA_PEM`: public Phase 1 root at `C:\dlp\secrets\phase1-root-ca.pem`.
- Data/cache paths: `C:\dlp\agent\data` and `C:\dlp\agent\cache`.
- Configuration public key: public Ed25519 key from the protected signing workflow.
- Enrollment token: normally obtained later by `TrustedProvisioning`; manual/offline mode uses a short-lived runtime-provider token.

```powershell
.\scripts\lab\Initialize-DlpEnvironment.ps1
.\scripts\lab\Initialize-DlpEnvironment.ps1 -EnvFile .\config\lab.env.local
.\scripts\lab\Initialize-DlpEnvironment.ps1 -EnvFile .\config\lab.env.local -NonInteractive
```

The protected env file uses one-line `NAME=value` records; PEM entries must therefore be absolute paths. `-OutEnvFile` deliberately writes plaintext sensitive material: protect it and never commit it.

Manual process-environment fallback:

```powershell
$env:DLP_DEVICE_ID = 'LAB-CLIENT01.lab.local'
$env:DLP_SERVER_URL = 'https://LAB-DC01:8443'
$env:DLP_ROOT_CA_PEM = 'C:\dlp\secrets\phase1-root-ca.pem'
$env:DLP_DATA_DIRECTORY = 'C:\dlp\agent\data'
$env:DLP_CACHE_DIRECTORY = 'C:\dlp\agent\cache'
$env:DLP_CONFIGURATION_PUBLIC_KEY_HEX = '<FROM-RUNTIME-PROVIDER-64-HEX>'
$env:DLP_CONFIGURATION_KEY_ID = 'phase1-config-signer'
$env:DLP_POLL_INTERVAL_SECONDS = '300'
$env:DLP_HEALTH_INTERVAL_SECONDS = '60'
# Manual enrollment only:
# $env:DLP_AGENT_ENROLLMENT_TOKEN = '<FROM-RUNTIME-PROVIDER>'
```

Expected result: the current process contains the six required endpoint inputs and selected runner-supported settings; nothing is persisted on `LAB-CLIENT01` yet.

### 2. Validate

These checks report only presence, shape, path access, and fingerprints:

```powershell
$required='DLP_DEVICE_ID','DLP_SERVER_URL','DLP_ROOT_CA_PEM','DLP_DATA_DIRECTORY','DLP_CACHE_DIRECTORY','DLP_CONFIGURATION_PUBLIC_KEY_HEX'
$required | ForEach-Object { [pscustomobject]@{Name=$_;Present=-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($_,'Process'))} }
$deviceOk=$env:DLP_DEVICE_ID -match '^[A-Za-z0-9_-](?:[A-Za-z0-9_.-]{0,126}[A-Za-z0-9_-])?$' -and $env:DLP_DEVICE_ID -notmatch '\.\.'
$serverOk=$env:DLP_SERVER_URL -match '^https://LAB-DC01:8443/?$'
$keyOk=$env:DLP_CONFIGURATION_PUBLIC_KEY_HEX -cmatch '^[0-9a-fA-F]{64}$'
[pscustomobject]@{DeviceShape=$deviceOk;HttpsTarget=$serverOk;PublicKeyShape=$keyOk}

$root=$env:DLP_ROOT_CA_PEM; $inline=$root -match 'BEGIN CERTIFICATE'
$pathOk=-not $inline -and [IO.Path]::IsPathRooted($root) -and (Test-Path -LiteralPath $root -PathType Leaf)
$text=if($inline){$root}elseif($pathOk){Get-Content -LiteralPath $root -Raw}else{''}
[pscustomobject]@{RootForm=if($inline){'inline PEM'}else{'absolute path'};Readable=($inline -or $pathOk);CertificateShape=($text -match 'BEGIN CERTIFICATE' -and $text -match 'END CERTIFICATE');Fingerprint=if($pathOk){(Get-FileHash $root -Algorithm SHA256).Hash}else{'<inline-present>'}}
```

`DLP_ROOT_CA_PEM` supports inline PEM certificate content and an absolute PEM path. The runner reads either form on `hungdinh-lt`, deploys the certificate bytes to `C:\dlp\secrets\phase1-root-ca.pem`, and persists that absolute path for the service.

Expected result: required names are present and the device, HTTPS target, public-key, and certificate checks pass.

### 3. Persist

There are three layers:

1. The operator or initializer writes transient values into the current `hungdinh-lt` PowerShell process.
2. `Invoke-Client01Runtime.ps1` generates `C:\dlp\agent\agent.env` on `LAB-CLIENT01` from ten selected values.
3. `Install-Client01Service` copies those lines to `HKLM:\SYSTEM\CurrentControlSet\Services\DlpWindowsService`, registry value `Environment` (`REG_MULTI_SZ`); SCM supplies them to the service process.

The env file and registry value are generated copies. Do not edit them independently; rerun the initializer/deployment path. Caller-only values omitted by the runner do not reach the service.

Expected result: the env file and registry expose the same persisted names without displaying values.

### 4. Deploy

Trusted provisioning is the normal token path. Manual/offline enrollment is the alternative and uses `DLP_AGENT_ENROLLMENT_TOKEN='<FROM-RUNTIME-PROVIDER>'` with provider `Manual`.

```powershell
$cred=Get-Credential -Message 'LAB-CLIENT01 administrator credential'
.\scripts\lab\Invoke-Client01Runtime.ps1 `
  -CallerMachine hungdinh-lt -ExecutionMachine LAB-CLIENT01 -ProbeMachine LAB-DC01 `
  -SecretProvider Runtime -Scenario Tracer -EnrollmentTokenProvider TrustedProvisioning `
  -Credential $cred -Apply
```

Expected result: binaries, public root, `agent.env`, registry `Environment`, and `DlpWindowsService` are deployed.

### 5. Verify

```powershell
Invoke-Command -VMName LAB-CLIENT01 -Credential $cred -ScriptBlock {
  $p='C:\dlp\agent\agent.env'
  $fn=@(Get-Content $p -ErrorAction Stop|%{($_ -split '=',2)[0]})
  $rl=@((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\DlpWindowsService' -Name Environment -ErrorAction Stop).Environment)
  $rn=@($rl|%{($_ -split '=',2)[0]})
  [pscustomobject]@{EnvFilePresent=Test-Path $p;EnvNames=$fn;RegistryNames=$rn;NameSetsMatch=-not(Compare-Object $fn $rn);RootReadable=Test-Path 'C:\dlp\secrets\phase1-root-ca.pem';RootFingerprint=(Get-FileHash 'C:\dlp\secrets\phase1-root-ca.pem' -Algorithm SHA256).Hash;ServiceStatus=(Get-Service DlpWindowsService).Status}
}
```

Use only redacted status/error diagnostics; never dump values. Acceptance covers generated configuration, registry visibility, service startup, and redacted diagnostics. Successful enrollment and first configuration polling are not required.

Expected result: name sets match, the root path is readable with the approved fingerprint, and the service is `Running` or returns a stable redacted failure code.

## Endpoint variable catalog

The equal-depth 15-variable catalog follows this workflow.

## Exposure response

If troubleshooting exposes material: **stop copying**; safely remove exposed files, transcripts, screenshots, clipboard contents, and attachments; rotate affected tokens, passwords, private keys, or identifiers through the canonical issuer; resume only with redacted diagnostics.

## Related documentation

- [LAB-SETUP-GUIDE.md](LAB-SETUP-GUIDE.md) — full lab sequence and unrelated catalogs.
- [PEM-KEY-GUIDE.md](PEM-KEY-GUIDE.md) — canonical PKI acquisition.
- [HYPERV-DLP-STARTUP-GUIDE.md](HYPERV-DLP-STARTUP-GUIDE.md) — daily startup navigation.
