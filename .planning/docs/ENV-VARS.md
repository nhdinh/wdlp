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

The service consumes exactly 15 names: six required, one conditional, and eight defaulted. Each entry uses the same auditable schema. Safe validations return metadata only.

<!-- env-var: DLP_DEVICE_ID -->
- Classification: required
- Purpose: Stable endpoint identity used for enrollment, health, cache identity, and trusted provisioning.
- Source/Create: Use the AD DNS name `LAB-CLIENT01.lab.local`; confirm with `$env:COMPUTERNAME` and DNS rather than inventing a new identity.
- Representation/Parsing: 1-128 ASCII letters, digits, hyphen, underscore, or dot; no leading/trailing dot or `..`.
- Safe validation: `$v=$env:DLP_DEVICE_ID; [pscustomobject]@{Present=!!$v;Length=$v.Length;Shape=($v -match '^[A-Za-z0-9_-](?:[A-Za-z0-9_.-]{0,126}[A-Za-z0-9_-])?$' -and $v -notmatch '\.\.')}`
- Persistence: runner-persisted by the env file and registry `Environment`; treat as a sensitive identifier.
- Default/Requiredness: Required; no service default.
- Likely error: `runtime_secrets_missing` before deployment or `service_config_invalid` for a malformed identity.
- Fix: Correct the transient value to the provisioned hostname and rerun deployment; do not independently edit generated copies.

<!-- env-var: DLP_SERVER_URL -->
- Classification: required
- Purpose: HTTPS base URL for enrollment, configuration polling, and health traffic.
- Source/Create: Use the LAB-DC01 listener and certificate hostname: `https://LAB-DC01:8443`.
- Representation/Parsing: Absolute HTTPS URL; its hostname must resolve on LAB-CLIENT01 and match the server certificate.
- Safe validation: `$u=$null; [pscustomobject]@{Present=!!$env:DLP_SERVER_URL;Valid=[uri]::TryCreate($env:DLP_SERVER_URL,[UriKind]::Absolute,[ref]$u);Https=($u.Scheme -eq 'https');Host=$u.Host;Port=$u.Port}`
- Persistence: runner-persisted to both generated layers as ordinary integrity-sensitive configuration.
- Default/Requiredness: Required; no service default.
- Likely error: `runtime_secrets_missing`, `service_config_missing`, or later TLS/hostname failure.
- Fix: Use the certificate-covered LAB-DC01 hostname and port 8443, verify DNS, then redeploy.

<!-- env-var: DLP_ROOT_CA_PEM -->
- Classification: required
- Purpose: Public trust anchor used to validate LAB-DC01 TLS.
- Source/Create: Obtain the public `phase1-root-ca.pem` through [PEM-KEY-GUIDE.md](PEM-KEY-GUIDE.md); never use a private key.
- Representation/Parsing: Inline PEM when the value contains `BEGIN CERTIFICATE`, otherwise an absolute readable PEM path; the runner deploys bytes and the service sees `C:\dlp\secrets\phase1-root-ca.pem`.
- Safe validation: `$v=$env:DLP_ROOT_CA_PEM;$i=$v -match 'BEGIN CERTIFICATE';$p=(-not$i -and [IO.Path]::IsPathRooted($v) -and (Test-Path $v));[pscustomobject]@{Present=!!$v;Form=if($i){'inline PEM'}else{'absolute path'};Readable=($i-or$p);Fingerprint=if($p){(Get-FileHash $v -Algorithm SHA256).Hash}else{'<verify-inline-with-approved-PKI-tool>'}}`
- Persistence: runner-persisted as the deployed absolute certificate path; public trust material whose integrity must be authenticated.
- Default/Requiredness: Required; no service default.
- Likely error: `runtime_secrets_missing` or `service_config_invalid` for unreadable/non-certificate input.
- Fix: Re-export the correct public Phase 1 root, verify its approved fingerprint, and redeploy.

<!-- env-var: DLP_DATA_DIRECTORY -->
- Classification: required
- Purpose: Durable service state including protected credentials and per-user store roots.
- Source/Create: The runner creates `C:\dlp\agent\data` on LAB-CLIENT01.
- Representation/Parsing: Absolute local Windows path writable by `NT AUTHORITY\SYSTEM` and the service identity.
- Safe validation: `$v=$env:DLP_DATA_DIRECTORY;[pscustomobject]@{Present=!!$v;Absolute=[IO.Path]::IsPathRooted($v);Expected=($v -eq 'C:\dlp\agent\data')}`
- Persistence: runner-persisted to both generated layers; filesystem ACLs protect stored credentials.
- Default/Requiredness: Required; no service default.
- Likely error: `service_config_missing` or a later path/permission failure.
- Fix: Use the runner-created absolute path, repair access through the canonical deployment, and redeploy.

<!-- env-var: DLP_CACHE_DIRECTORY -->
- Classification: required
- Purpose: Local cache for staged, current, and last-known-good signed configurations.
- Source/Create: The runner creates `C:\dlp\agent\cache` on LAB-CLIENT01.
- Representation/Parsing: Absolute local Windows path writable by the service identity.
- Safe validation: `$v=$env:DLP_CACHE_DIRECTORY;[pscustomobject]@{Present=!!$v;Absolute=[IO.Path]::IsPathRooted($v);Expected=($v -eq 'C:\dlp\agent\cache')}`
- Persistence: runner-persisted to both generated layers as ordinary path configuration.
- Default/Requiredness: Required; no service default.
- Likely error: `service_config_missing` or cache path/permission failure.
- Fix: Restore the runner-created path and permissions, then redeploy rather than editing the registry.

<!-- env-var: DLP_CONFIGURATION_PUBLIC_KEY_HEX -->
- Classification: required
- Purpose: Ed25519 public key that verifies signed configuration bundles before activation.
- Source/Create: Export the public key corresponding to the protected server signing seed; use `<FROM-RUNTIME-PROVIDER-64-HEX>` only as a non-runnable documentation marker.
- Representation/Parsing: Exactly 64 hexadecimal characters (32 decoded bytes), without `0x`, whitespace, or line breaks.
- Safe validation: `$v=$env:DLP_CONFIGURATION_PUBLIC_KEY_HEX;[pscustomobject]@{Present=!!$v;Length=$v.Length;Hex64=($v -cmatch '^[0-9a-fA-F]{64}$')}`
- Persistence: runner-persisted; public configuration whose provenance and integrity are critical.
- Default/Requiredness: Required; no service default.
- Likely error: `runtime_secrets_missing` or `service_config_invalid`.
- Fix: Re-export the matching public key, validate only its shape/fingerprint, and redeploy.

<!-- env-var: DLP_AGENT_ENROLLMENT_TOKEN -->
- Classification: conditional
- Purpose: One-time credential for initial or replacement enrollment when no DPAPI credential exists.
- Source/Create: Normal path is `TrustedProvisioning`; manual/offline mode obtains `<FROM-RUNTIME-PROVIDER>` from an authorized issuer.
- Representation/Parsing: Runner accepts at most 512 characters in `[A-Za-z0-9_.~/-]`; never print the token.
- Safe validation: `$v=$env:DLP_AGENT_ENROLLMENT_TOKEN;[pscustomobject]@{Present=!!$v;Length=if($v){$v.Length}else{0};Shape=(!$v -or ($v.Length-le512 -and $v -cmatch '^[A-Za-z0-9_.~/-]+$'))}`
- Persistence: runner-persisted only when needed; normally removed after successful enrollment unless explicitly retained for troubleshooting.
- Default/Requiredness: Conditional; omit when an existing credential is usable or TrustedProvisioning supplies it.
- Likely error: `runtime_secrets_missing` in Manual mode or enrollment rejection/expiry.
- Fix: Prefer a fresh TrustedProvisioning token; otherwise rotate/reissue manually and redeploy without logging it.

<!-- env-var: DLP_CONFIGURATION_KEY_ID -->
- Classification: defaulted
- Purpose: Identifies which verification key the signed bundle claims.
- Source/Create: Match the management-server signing configuration; Phase 1 uses `phase1-config-signer`.
- Representation/Parsing: Non-empty opaque string; equality with the signed bundle key ID is operationally required.
- Safe validation: `$v=$env:DLP_CONFIGURATION_KEY_ID;[pscustomobject]@{Present=!!$v;Expected=(!$v -or $v -eq 'phase1-config-signer');Length=if($v){$v.Length}else{0}}`
- Persistence: runner-persisted when supplied; otherwise the service applies the same Phase 1 default.
- Default/Requiredness: Defaulted to `phase1-config-signer`.
- Likely error: Signed configuration key-ID mismatch.
- Fix: Reconcile with the server signer ID and rerun deployment.

<!-- env-var: DLP_POLL_INTERVAL_SECONDS -->
- Classification: defaulted
- Purpose: Interval between configuration polls.
- Source/Create: Use Phase 1 value `300` unless an approved operating profile differs.
- Representation/Parsing: Unsigned integer seconds; parse failure falls back to 300 and zero is accepted by the service, though operators should require `1..86400`.
- Safe validation: `$n=0;$ok=[uint64]::TryParse($env:DLP_POLL_INTERVAL_SECONDS,[ref]$n);[pscustomobject]@{Present=!!$env:DLP_POLL_INTERVAL_SECONDS;Parses=$ok;Recommended=($ok-and$n-ge1-and$n-le86400)}`
- Persistence: runner-persisted when supplied; ordinary operational setting.
- Default/Requiredness: Defaulted to 300 seconds.
- Likely error: No stable config error for malformed input because the service falls back; zero may cause undesirable rapid work.
- Fix: Set a recommended positive bounded integer and redeploy.

<!-- env-var: DLP_HEALTH_INTERVAL_SECONDS -->
- Classification: defaulted
- Purpose: Interval between redacted endpoint health posts.
- Source/Create: Use Phase 1 value `60` unless an approved operating profile differs.
- Representation/Parsing: Unsigned integer seconds; malformed values fall back to 60 and zero parses, while operators should require `1..86400`.
- Safe validation: `$n=0;$ok=[uint64]::TryParse($env:DLP_HEALTH_INTERVAL_SECONDS,[ref]$n);[pscustomobject]@{Present=!!$env:DLP_HEALTH_INTERVAL_SECONDS;Parses=$ok;Recommended=($ok-and$n-ge1-and$n-le86400)}`
- Persistence: runner-persisted when supplied; ordinary operational setting.
- Default/Requiredness: Defaulted to 60 seconds.
- Likely error: No stable config error for malformed input because the service falls back.
- Fix: Set a recommended positive bounded integer and redeploy.

<!-- env-var: DLP_START_TIMEOUT_SECONDS -->
- Classification: defaulted
- Purpose: Bounds internal service start operations.
- Source/Create: Service default `60`; the current lab runner has no deployment override path.
- Representation/Parsing: Unsigned seconds; malformed input falls back and zero parses, although the recommended operator range is `1..600`.
- Safe validation: `$v=$env:DLP_START_TIMEOUT_SECONDS;$n=0;$ok=(!$v-or[uint64]::TryParse($v,[ref]$n));[pscustomobject]@{CallerSet=!!$v;Parses=$ok;DeployedEffective=60;RunnerOverrideSupported=$false}`
- Persistence: service-default-fallback; a caller-process value is not copied to SCM.
- Default/Requiredness: Defaulted to 60 seconds in the deployed service.
- Likely error: Operator assumes a caller-only override is active.
- Fix: Remove the unsupported caller override and rely on 60; request a separate runner change for a deployed override.

<!-- env-var: DLP_STOP_TIMEOUT_SECONDS -->
- Classification: defaulted
- Purpose: Bounds internal service stop operations.
- Source/Create: Service default `10`; current runner does not deploy an override.
- Representation/Parsing: Unsigned seconds; malformed input falls back and zero parses, while recommended range is `1..600`.
- Safe validation: `$v=$env:DLP_STOP_TIMEOUT_SECONDS;$n=0;$ok=(!$v-or[uint64]::TryParse($v,[ref]$n));[pscustomobject]@{CallerSet=!!$v;Parses=$ok;DeployedEffective=10;RunnerOverrideSupported=$false}`
- Persistence: service-default-fallback; absent from env file and registry by design.
- Default/Requiredness: Defaulted to 10 seconds.
- Likely error: Caller-only value is mistaken for service configuration.
- Fix: Rely on 10 or implement a separately reviewed runner enhancement.

<!-- env-var: DLP_PREFERRED_DRIVE_LETTER -->
- Classification: defaulted
- Purpose: Preferred letter for the per-user protected drive.
- Source/Create: Phase 1 uses `P`; current runner does not persist an override.
- Representation/Parsing: Service takes and uppercases the first character; the stricter recommended check requires exactly one ASCII letter.
- Safe validation: `$v=$env:DLP_PREFERRED_DRIVE_LETTER;[pscustomobject]@{CallerSet=!!$v;Recommended=(!$v-or$v -cmatch '^[A-Za-z]$');DeployedEffective='P';RunnerOverrideSupported=$false}`
- Persistence: service-default-fallback; caller input does not reach SCM.
- Default/Requiredness: Defaulted to `P`.
- Likely error: An invalid or caller-only letter is assumed to be deployed.
- Fix: Rely on `P`; use a separate orchestration change for configurable deployment.

<!-- env-var: DLP_SIGN_OUT_GRACE_SECONDS -->
- Classification: defaulted
- Purpose: Grace period between sign-out detection and protected-drive teardown.
- Source/Create: Service default `30`; current runner does not deploy an override.
- Representation/Parsing: Unsigned seconds; malformed input falls back and zero parses, while operators should require a positive approved bound.
- Safe validation: `$v=$env:DLP_SIGN_OUT_GRACE_SECONDS;$n=0;$ok=(!$v-or[uint64]::TryParse($v,[ref]$n));[pscustomobject]@{CallerSet=!!$v;Parses=$ok;DeployedEffective=30;RunnerOverrideSupported=$false}`
- Persistence: service-default-fallback; absent from generated layers.
- Default/Requiredness: Defaulted to 30 seconds.
- Likely error: Caller-only grace is mistaken for deployed behavior.
- Fix: Rely on 30 or request an explicit runner feature rather than writing the registry manually.

<!-- env-var: DLP_DRIVE_HOST_BINARY_PATH -->
- Classification: defaulted
- Purpose: Locates `dlp-drive-host.exe` for the WinFsp session process.
- Source/Create: Runner deploys the binary to `C:\Program Files\DLP\dlp-drive-host.exe`; it does not persist an override.
- Representation/Parsing: Absolute Windows executable path readable/executable by the service; service uses the literal string.
- Safe validation: `$p='C:\Program Files\DLP\dlp-drive-host.exe';[pscustomobject]@{CallerSet=!!$env:DLP_DRIVE_HOST_BINARY_PATH;DeployedEffective=$p;Absolute=[IO.Path]::IsPathRooted($p);ExistsOnEndpoint='<check-on-LAB-CLIENT01>';RunnerOverrideSupported=$false}`
- Persistence: service-default-fallback; the default matches the runner deployment destination.
- Default/Requiredness: Defaulted to `C:\Program Files\DLP\dlp-drive-host.exe`.
- Likely error: Missing binary/path access failure, or unsupported caller override assumed active.
- Fix: Redeploy the drive-host binary to the default path; do not invent a manual registry override.

## 15 consumed versus 10 persisted

| Variable group | Service behavior | Initializer | Runner input | `agent.env` | Registry `Environment` | Deployed behavior |
| --- | --- | --- | --- | --- | --- | --- |
| Six required values | Required | Supported | Required/injected paths | Yes | Yes | Supplied values |
| `DLP_CONFIGURATION_KEY_ID` | Default `phase1-config-signer` | Supported | Optional | When set | Same as file | Supplied or default |
| `DLP_AGENT_ENROLLMENT_TOKEN` | Conditional | Supported | TrustedProvisioning or Manual | When needed | Same as file | Token/credential path |
| Poll and health intervals | Defaults 300/60 | Supported | Optional | When set | Same as file | Supplied or defaults |
| Start/stop timeout, preferred drive, sign-out grace, drive-host path | Defaults 60/10/P/30/default path | May exist in caller | Not copied | No | No | Service defaults |

Thus the service consumes 15 names but the runner persists 10: the six required values, configuration key ID, conditional enrollment token, poll interval, and health interval. The five lifecycle/session overrides are caller-only under this workflow and use service defaults in the deployed SCM process. There is intentionally no manual registry-write procedure.

## Stable error-to-fix matrix

| Stable error | Likely variables | Redacted check | Action |
| --- | --- | --- | --- |
| `runtime_secrets_missing` | Device ID, URL, root CA, public key; token in Manual mode | Run the required-name presence/shape checks; print no values. | Restore the transient runtime-provider input or choose TrustedProvisioning, then rerun. |
| `service_config_missing` | Any of the six required service values absent from registry environment | Compare env-file and registry name sets only. | Rerun deployment so both generated copies are rebuilt together. |
| `service_config_invalid` | Device ID shape, root CA readability/certificate form, 64-hex public key, or later TLS construction | Check length/shape, absolute-path access, and approved fingerprints only. | Correct the authoritative input, verify provenance, and redeploy. |

## Exposure response

If troubleshooting exposes material: **stop copying**; safely remove exposed files, transcripts, screenshots, clipboard contents, and attachments; rotate affected tokens, passwords, private keys, or identifiers through the canonical issuer; resume only with redacted diagnostics.

## Related documentation

- [LAB-SETUP-GUIDE.md](LAB-SETUP-GUIDE.md) — full lab sequence and unrelated catalogs.
- [PEM-KEY-GUIDE.md](PEM-KEY-GUIDE.md) — canonical PKI acquisition.
- [HYPERV-DLP-STARTUP-GUIDE.md](HYPERV-DLP-STARTUP-GUIDE.md) — daily startup navigation.
