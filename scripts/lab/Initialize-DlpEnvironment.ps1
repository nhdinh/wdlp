[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter()][string]$EnvFile,
    [Parameter()][string]$OutEnvFile,
    [Parameter()][switch]$SkipValidation,
    [Parameter()][switch]$Force,
    [Parameter()][switch]$NoHelp,
    [Parameter()][switch]$Clear,
    [Parameter()][switch]$NonInteractive
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

#region Helpers

function Test-IsPlaceholder {
    param([Parameter()][AllowEmptyString()][string]$Value)
    return [string]::IsNullOrWhiteSpace($Value) -or ($Value -match 'REPLACE_') -or ($Value -match '<missing>')
}

function Get-EntryProperty {
    param(
        [Parameter(Mandatory)]$Entry,
        [Parameter(Mandatory)][string]$Name
    )
    if ($Entry.PSObject.Properties[$Name]) {
        return $Entry.$Name
    }
    return $null
}

function Read-DlpValue {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter()][string]$Default = '',
        [Parameter()][switch]$Secure,
        [Parameter()][switch]$AllowEmpty,
        [Parameter()][scriptblock]$Validate,
        [Parameter()][string]$ValidateMessage = 'Value is not valid.',
        [Parameter()][string]$HelpText = '',
        [Parameter()][switch]$NonInteractive
    )

    $current = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if (-not (Test-IsPlaceholder $current)) {
        return $current
    }

    if ($NonInteractive) {
        if (Test-IsPlaceholder $Default) {
            return $null
        }
        # Catalog defaults are trusted setup targets. Several are paths to
        # certificates or binaries created by later setup steps, so requiring
        # them to exist here would make first-time initialization impossible.
        return $Default
    }

    if (-not $NoHelp -and -not [string]::IsNullOrWhiteSpace($HelpText)) {
        Write-Host ''
        Write-Host "How to obtain `$Name:" -ForegroundColor DarkCyan
        Write-Host $HelpText -ForegroundColor DarkGray
    }

    $fullPrompt = if (Test-IsPlaceholder $Default) {
        if ($AllowEmpty) {
            "[$Name] $Prompt [optional: press Enter for automatic provisioning]`: "
        } else {
            "[$Name] $Prompt`: "
        }
    } else {
        "[$Name] $Prompt [default: $Default]`: "
    }

    while ($true) {
        $acceptedDefault = $false
        if ($Secure) {
            $secureValue = Read-Host -Prompt $fullPrompt -AsSecureString
            $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureValue))
            if ([string]::IsNullOrWhiteSpace($plain) -and -not (Test-IsPlaceholder $Default)) {
                $plain = $Default
                $acceptedDefault = $true
            }
        } else {
            $plain = Read-Host -Prompt $fullPrompt
            if ([string]::IsNullOrWhiteSpace($plain) -and -not (Test-IsPlaceholder $Default)) {
                $plain = $Default
                $acceptedDefault = $true
            }
        }

        if ($AllowEmpty -and [string]::IsNullOrWhiteSpace($plain)) {
            Write-Host "Skipping ${Name}; trusted provisioning will obtain it when the endpoint runner starts." -ForegroundColor DarkGray
            return $null
        }

        if (Test-IsPlaceholder $plain) {
            Write-Warning "$Name is required. Please provide a value."
            continue
        }

        if ($acceptedDefault) {
            Write-Host "Using default for ${Name}: $Default" -ForegroundColor DarkGray
        }

        if (-not $acceptedDefault -and $Validate -and -not $SkipValidation) {
            $valid = & $Validate $plain
            if (-not $valid) {
                $message = if ($ValidateMessage) { $ValidateMessage } else { 'Value is not valid.' }
                Write-Warning $message
                continue
            }
        }

        return $plain
    }
}

function Invoke-EnvFile {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Env file not found: $Path"
    }
    $seen = @{}
    $lineNumber = 0
    Get-Content -LiteralPath $Path | ForEach-Object {
        $lineNumber++
        $line = $_.Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { return }
        if ($line -notmatch '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
            throw "Malformed env file entry at line $lineNumber. Use NAME=value with one value per line."
        }
        $name = $Matches[1]
        $value = $Matches[2]
        if ($seen.ContainsKey($name)) { throw "Duplicate env file key: $name" }
        $seen[$name] = $true
        if ($script:CatalogNames -notcontains $name) { throw "Env file key is not in the DLP catalog: $name" }
        # Strip surrounding quotes
        if (($value.StartsWith('"') -and $value.EndsWith('"')) -or
            ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        if ($Force -or (Test-IsPlaceholder ([Environment]::GetEnvironmentVariable($name, 'Process')))) {
            [Environment]::SetEnvironmentVariable($name, $value, 'Process')
        }
    }
}

function Get-HelpText {
    param([Parameter(Mandatory)][string]$Name)

    switch ($Name) {
        'DLP_LISTEN_ADDRESS' {
            return @'
  Use the lab topology default 0.0.0.0:8443 unless the server should bind elsewhere.
  Example: 0.0.0.0:8443
'@
        }
        'DLP_DATABASE_URL' {
            return @'
  PostgreSQL connection string in the format: postgres://<user>:<password>@<host>:<port>/<db>
  The password is set when the database user is created (e.g. during LAB-SERVER01 setup).
  Example: postgres://dlp_server:MyPassword@192.168.50.12:5432/dlp
'@
        }
        'DLP_DATABASE_NAME' {
            return @'
  Name of the PostgreSQL database created for DLP.
  Example: dlp
'@
        }
        'DLP_DATABASE_USER' {
            return @'
  PostgreSQL user that owns the DLP database.
  Example: dlp_server
'@
        }
        'DLP_SERVER_CERT_PEM' {
            return @'
  Path to the management server TLS certificate PEM.
  Generate by signing a CSR with the Phase 1 root CA (see .planning/docs/PEM-KEY-GUIDE.md).
  Example: C:\dlp\secrets\server-cert.pem
'@
        }
        'DLP_SERVER_KEY_PEM' {
            return @'
  Path to the management server TLS private key PEM.
  Generated alongside DLP_SERVER_CERT_PEM. Keep secret.
  Example: C:\dlp\secrets\server-key.pem
'@
        }
        'DLP_ADMIN_CA_CERT_PEM' {
            return @'
  Path to the administrator CA certificate PEM.
  This CA signs the provisioning admin certificate used by dlpctl.
  Example: C:\dlp\secrets\admin-ca.pem
'@
        }
        'DLP_PHASE1_ROOT_CA_CERT_PEM' {
            return @'
  Path to the Phase 1 root CA certificate PEM.
  Generate a self-signed root CA once and reuse it for server TLS and agent pinning.
  Example: C:\dlp\secrets\phase1-root-ca.pem
  See .planning/docs/PEM-KEY-GUIDE.md for OpenSSL commands.
'@
        }
        'DLP_DEVICE_ISSUING_CA_CERT_PEM' {
            return @'
  Path to the device-issuing CA certificate PEM.
  This CA issues mTLS client certificates to enrolled endpoints.
  Example: C:\dlp\secrets\device-issuing-ca.pem
'@
        }
        'DLP_DEVICE_ISSUING_CA_KEY_PEM' {
            return @'
  Path to the device-issuing CA private key PEM.
  The server needs this to issue device certificates during enrollment. Keep secret.
  Example: C:\dlp\secrets\device-issuing-ca-key.pem
'@
        }
        'DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX' {
            return @'
  64-character hexadecimal Ed25519 private seed used to sign configuration bundles.
  Generate with:
    -join ((1..32 | ForEach-Object { "{0:x2}" -f (Get-Random -Maximum 256) }))
  Store only on the management server.
'@
        }
        'DLP_AD_PRIMARY_LDAPS_URL' {
            return @'
  LDAP-over-SSL URL of the primary domain controller.
  Use the hostname, not an IP literal, so TLS hostname verification works.
  Example: ldaps://LAB-DC01.lab.local:636
'@
        }
        'DLP_AD_SECONDARY_LDAPS_URL' {
            return @'
  LDAP-over-SSL URL of the secondary/backup domain controller.
  Example: ldaps://LAB-DC02.lab.local:636
'@
        }
        'DLP_AD_BASE_DN' {
            return @'
  Active Directory base distinguished name.
  Derive from the DNS domain: lab.local becomes DC=lab,DC=local.
  Example: DC=lab,DC=local
'@
        }
        'DLP_AD_BIND_DN' {
            return @'
  Distinguished name of the AD service account used by the server to query LDAP.
  Example: CN=dlp-service,OU=Service Accounts,DC=lab,DC=local
'@
        }
        'DLP_AD_BIND_PASSWORD' {
            return @'
  Password for the AD service account (DLP_AD_BIND_DN).
  Set this password when creating the service account in Active Directory.
'@
        }
        'DLP_AD_CA_CERT_PEM' {
            return @'
  Path to the AD Certificate Services root CA PEM used to validate LDAPS connections.
  Export from LAB-DC01: certlm.msc -> Trusted Root CAs -> Export as Base-64 .CER.
  Example: C:\dlp\secrets\ad-ca.pem
'@
        }
        'DLP_PROVISIONING_ENDPOINT' {
            return @'
  HTTPS URL of the trusted-provisioning API.
  Compose from the server FQDN and fixed path: https://<server>:8443/api/v1/admin/provisioning
  Example: https://LAB-DC01.lab.local:8443/api/v1/admin/provisioning
'@
        }
        'DLP_PROVISIONING_ROOT_CA_PATH' {
            return @'
  Path to the root CA PEM that dlpctl trusts for the provisioning HTTPS connection.
  Usually the same as DLP_PHASE1_ROOT_CA_CERT_PEM.
  Example: C:\dlp\secrets\phase1-root-ca.pem
'@
        }
        'DLP_PROVISIONING_ADMIN_CERT_PATH' {
            return @'
  Path to the administrator client certificate PEM used by dlpctl for mTLS.
  Generate by signing a CSR with the admin CA (DLP_ADMIN_CA_CERT_PEM).
  Example: C:\dlp\secrets\provisioning-admin-cert.pem
'@
        }
        'DLP_PROVISIONING_ADMIN_KEY_PATH' {
            return @'
  Path to the private key PEM for the provisioning admin certificate.
  Generated alongside DLP_PROVISIONING_ADMIN_CERT_PATH. Keep secret.
  Example: C:\dlp\secrets\provisioning-admin-key.pem
'@
        }
        'DLP_PROVISIONING_AD_OBJECT_GUID' {
            return @'
  Hex GUID of the LAB-CLIENT01 computer object in Active Directory.
  Run on LAB-DC01:
    (Get-ADComputer -Identity LAB-CLIENT01).ObjectGUID.ToString().Replace("-","").ToLower()
  Example: 1234567890abcdef1234567890abcdef
'@
        }
        'DLP_PROVISIONING_AD_OBJECT_SID' {
            return @'
  Hex SID of the LAB-CLIENT01 computer object in Active Directory.
  Run on LAB-DC01:
    $sid = (Get-ADComputer -Identity LAB-CLIENT01).SID
    if ($null -eq $sid) { throw "LAB-CLIENT01 SID was not returned by Active Directory." }
    $bytes = [byte[]]::new($sid.BinaryLength)
    $sid.GetBinaryForm($bytes, 0)
    [BitConverter]::ToString($bytes).Replace("-","").ToLowerInvariant()
  Example: 010500000000000515000000...
'@
        }
        'DLP_PROVISIONING_TOKEN_HANDOFF_PATH' {
            return @'
  Writable path where dlpctl will write the enrollment token on LAB-DC01.
  Example: C:\dlp\secrets\LAB-CLIENT01.enrollment-token
'@
        }
        'DLP_PROVISIONING_PREFERRED_DRIVE_LETTER' {
            return @'
  Single uppercase drive letter for the virtual protected drive.
  Choose a letter that is not already in use on LAB-CLIENT01.
  Example: P
'@
        }
        'DLP_PROVISIONING_DLPCTL_PATH' {
            return @'
  Path to the dlpctl.exe binary used for trusted provisioning.
  Build it from source:
    cargo build --release -p dlpctl
  Example: C:\Users\nhdinh\dev\dleakprevention\target\release\dlpctl.exe
'@
        }
        'DLP_PROVISIONING_COMPUTER' {
            return @'
  FQDN of the computer to be provisioned.
  Example: LAB-CLIENT01.lab.local
'@
        }
        'DLP_PROVISIONING_DISK_MODE' {
            return @'
  Disk fingerprint source used during trusted provisioning.
  auto = try SerialNumber first, fall back to PNPDeviceID for virtual disks.
  Allowed: auto, serial, pnp.
  Example: auto
'@
        }
        'DLP_APPROVED_PRIVILEGE_MANIFEST_DIGEST' {
            return @'
  Approval digest embedded in the unique 01-13 privilege manifest.
  On LAB-DC01, read it from the deployed server configuration:
    $configPath = 'C:\dlp\server\config\lab.phase1.example.yaml'
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "Missing deployed configuration: $configPath" }
    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $manifest = @($config.privilege_manifests | Where-Object { $_.plan_id -eq '01-13' })
    if ($manifest.Count -ne 1) { throw "Expected exactly one 01-13 privilege manifest; found $($manifest.Count)." }
    $digest = [string]$manifest[0].approval_digest
    if ($digest -notmatch '^[A-Fa-f0-9]{64}$') { throw "The 01-13 approval_digest is not 64 hexadecimal characters." }
    $digest.ToLowerInvariant()
  Do not use Get-FileHash on the whole configuration file; that produces a different digest.
  Must be 64 lowercase hex characters.
'@
        }
        'DLP_LAB_ALLOW_VIRTUAL_DISK_UNIQUE_ID' {
            return @'
  Set to true only in a disposable Hyper-V lab where Win32_DiskDrive.SerialNumber is absent.
  Production should omit this variable.
  Example: true
'@
        }
        'DLP_AGENT_ENROLLMENT_TOKEN' {
            return @'
  Preferred automatic flow (do this for a normal first-time installation):
    1. Press Enter at this prompt. Do not type the REPLACE_ placeholder.
    2. Finish the remaining environment prompts on hungdinh-lt.
    3. From the repository root on hungdinh-lt, run:
         $cred = Get-Credential -Message 'LAB-CLIENT01 administrator credential'
         .\scripts\lab\Invoke-Client01Runtime.ps1 `
           -CallerMachine hungdinh-lt -ExecutionMachine LAB-CLIENT01 -ProbeMachine LAB-DC01 `
           -SecretProvider Runtime -Scenario ServiceInstall `
           -EnrollmentTokenProvider TrustedProvisioning -Credential $cred -Apply
    The runner invokes trusted provisioning on LAB-DC01, receives the short-lived
    one-time token through the authenticated PowerShell session, installs it on
    LAB-CLIENT01, and removes it after successful enrollment. You do not obtain,
    display, copy, or save the token yourself.

  Manual/troubleshooting flow only:
    Run Invoke-Dc01Server.ps1 with -Scenario TrustedProvisioning in the SAME
    PowerShell process on hungdinh-lt. That runner places the returned token in
    $env:DLP_AGENT_ENROLLMENT_TOKEN without printing it. Then run
    Invoke-Client01Runtime.ps1 with -EnrollmentTokenProvider Manual in that same
    process. Never put this token in a committed env file, console transcript,
    ticket, or chat. It is single-use and short-lived.
'@
        }
        'DLP_DEVICE_ID' {
            return @'
  Stable identifier for this endpoint.
  Recommended: use the machine short hostname or asset tag, keeping only [A-Za-z0-9_-].
  Example: LAB-CLIENT01
'@
        }
        'DLP_SERVER_URL' {
            return @'
  Base HTTPS URL the agent uses to reach the management server.
  Example: https://LAB-DC01.lab.local:8443
'@
        }
        'DLP_ROOT_CA_PEM' {
            return @'
  Path to the public root CA PEM the agent pins for TLS validation.
  Must be the same root that signed the server certificate.
  Example: C:\dlp\secrets\phase1-root-ca.pem
'@
        }
        'DLP_CONFIGURATION_PUBLIC_KEY_HEX' {
            return @'
  Ed25519 public key paired with the server's DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX.
  Derive it on hungdinh-lt from the SAME protected process environment used to
  deploy LAB-DC01. Never paste the private signing seed into this prompt.

  From the repository root on hungdinh-lt:
    1. Confirm the private seed is already loaded into the current process:
         if ($env:DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Load the 64-hex server signing seed first.' }
    2. Build the derivation command:
         cargo build --release -p dlpctl
    3. Derive and validate the public key without displaying the private seed:
         $publicKey = (& .\target\release\dlpctl.exe configuration-public-key).Trim()
         if ($LASTEXITCODE -ne 0 -or $publicKey -notmatch '^[a-f0-9]{64}$') { throw 'Public-key derivation failed.' }
         $publicKey
    4. Copy only the displayed $publicKey value into this prompt.

  DLP_CONFIGURATION_KEY_ID must match on server and endpoint. The lab value is
  phase1-config-signing-key-v1. When the signing seed changes, derive and deploy
  the new public key before accepting configurations signed with the new seed.
'@
        }
        'DLP_DATA_DIRECTORY' {
            return @'
  Directory where the agent stores durable state (DPAPI credential store, etc.).
  The service account must have write access.
  Example: C:\ProgramData\DLP\agent
'@
        }
        'DLP_CACHE_DIRECTORY' {
            return @'
  Directory where the agent caches signed configuration bundles.
  Example: C:\ProgramData\DLP\cache
'@
        }
        'DLP_POLL_INTERVAL_SECONDS' {
            return @'
  How often the agent polls the server for a new signed configuration bundle.
  Default: 300 (5 minutes).
'@
        }
        'DLP_HEALTH_INTERVAL_SECONDS' {
            return @'
  How often the agent posts a redacted health snapshot to the server.
  Default: 60 (1 minute).
'@
        }
        'DLP_START_TIMEOUT_SECONDS' {
            return @'
  Internal timeout budget for the service start sequence.
  Default: 30.
'@
        }
        'DLP_STOP_TIMEOUT_SECONDS' {
            return @'
  Internal timeout budget for graceful service shutdown.
  Default: 30.
'@
        }
        'DLP_WINFSP_INTERACTIVE_HOLD_MS' {
            return @'
  Delay before exiting when running WinFsp in interactive mode. Use 0 for service runs.
  Default: 0.
'@
        }
        'DLP_WINFSP_SMOKE_LETTER' {
            return @'
  Drive letter used by WinFsp smoke tests.
  Example: P
'@
        }
        'DLP_VM_ADMIN_USER' {
            return @'
  Username with administrator rights on the Hyper-V VMs, used for PowerShell Direct.
  Example: LAB\Administrator or Administrator
'@
        }
        'DLP_VM_ADMIN_PASSWORD' {
            return @'
  Password for DLP_VM_ADMIN_USER.
'@
        }
        'DLP_SERVER01_HOST' {
            return @'
  IP address or hostname of LAB-SERVER01 (PostgreSQL host).
  Example: 192.168.50.12
'@
        }
        'DLP_SERVER01_ADMIN_USER' {
            return @'
  Admin username on LAB-SERVER01.
  Example: admin
'@
        }
        'DLP_SERVER01_ADMIN_PASSWORD' {
            return @'
  Admin password on LAB-SERVER01.
'@
        }
        'DLP_SERVER01_SSH_USER' {
            return @'
  SSH username on LAB-SERVER01.
  Example: admin
'@
        }
        'DLP_PKI_DIR' {
            return @'
  Local directory where PKI artifacts are generated or stored.
  Example: C:\Users\nhdinh\dev\dleakprevention\pki
'@
        }
        'DLP_SERVER_HOST' {
            return @'
  IP address of LAB-DC01 (the management server host).
  Example: 192.168.50.10
'@
        }
        'DLP_CONFIGURATION_KEY_ID' {
            return @'
  Human-readable label for the active configuration-signing key.
  Example: phase1-config-signing-key-v1
'@
        }
        default { return '' }
    }
}

function Test-PathExists {
    param([Parameter(Mandatory)][string]$Path)
    return Test-Path -LiteralPath $Path
}

function Test-HexLength {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][int]$Length
    )
    return $Value -match ('^[A-Fa-f0-9]{' + $Length + '}$')
}

function Test-Url {
    param([Parameter(Mandatory)][string]$Value)
    try {
        $uri = [System.Uri]$Value
        return $uri.Scheme -in @('https', 'ldaps')
    } catch {
        return $false
    }
}

function Test-DriveLetter {
    param([Parameter(Mandatory)][string]$Value)
    return $Value -match '^[A-Z]$'
}

#endregion

#region Variable catalog

# Each entry defines: name, prompt, default, secure flag, validation block, and validation message.
# The groups are presented in the same order as config/lab.env.example.

$Catalog = @(
    # Server
    [pscustomobject]@{
        Group = 'Server'
        Name  = 'DLP_LISTEN_ADDRESS'
        Prompt = 'Management server listen address'
        Default = '0.0.0.0:8443'
        Secure = $false
        Validate = { param($v) $v -match '^[\d.]+:\d+$' }
        ValidateMessage = 'Expected format: ip:port (e.g. 0.0.0.0:8443)'
    },
    [pscustomobject]@{
        Group = 'Server'
        Name  = 'DLP_DATABASE_URL'
        Prompt = 'PostgreSQL connection URL'
        Default = 'postgres://dlp_server:REPLACE_PASSWORD@192.168.50.12:5432/dlp'
        Secure = $false
        Validate = { param($v) $v -match '^postgres://' }
        ValidateMessage = 'Expected a postgres:// URL'
    },
    [pscustomobject]@{
        Group = 'Server'
        Name  = 'DLP_DATABASE_NAME'
        Prompt = 'PostgreSQL database name'
        Default = 'dlp'
        Secure = $false
    },
    [pscustomobject]@{
        Group = 'Server'
        Name  = 'DLP_DATABASE_USER'
        Prompt = 'PostgreSQL database user'
        Default = 'dlp_server'
        Secure = $false
    },
    [pscustomobject]@{
        Group = 'Server'
        Name  = 'DLP_SERVER_CERT_PEM'
        Prompt = 'Path to server certificate PEM'
        Default = 'C:\dlp\secrets\server-cert.pem'
        Secure = $false
        Validate = { param($v) Test-PathExists $v }
        ValidateMessage = 'File does not exist. Use -SkipValidation to bypass file checks.'
    },
    [pscustomobject]@{
        Group = 'Server'
        Name  = 'DLP_SERVER_KEY_PEM'
        Prompt = 'Path to server private key PEM'
        Default = 'C:\dlp\secrets\server-key.pem'
        Secure = $false
        Validate = { param($v) Test-PathExists $v }
        ValidateMessage = 'File does not exist. Use -SkipValidation to bypass file checks.'
    },
    [pscustomobject]@{
        Group = 'Server'
        Name  = 'DLP_ADMIN_CA_CERT_PEM'
        Prompt = 'Path to admin CA certificate PEM'
        Default = 'C:\dlp\secrets\admin-ca.pem'
        Secure = $false
        Validate = { param($v) Test-PathExists $v }
        ValidateMessage = 'File does not exist. Use -SkipValidation to bypass file checks.'
    },
    [pscustomobject]@{
        Group = 'Server'
        Name  = 'DLP_PHASE1_ROOT_CA_CERT_PEM'
        Prompt = 'Path to Phase 1 root CA certificate PEM'
        Default = 'C:\dlp\secrets\phase1-root-ca.pem'
        Secure = $false
        Validate = { param($v) Test-PathExists $v }
        ValidateMessage = 'File does not exist. Use -SkipValidation to bypass file checks.'
    },
    [pscustomobject]@{
        Group = 'Server'
        Name  = 'DLP_DEVICE_ISSUING_CA_CERT_PEM'
        Prompt = 'Path to device-issuing CA certificate PEM'
        Default = 'C:\dlp\secrets\device-issuing-ca.pem'
        Secure = $false
        Validate = { param($v) Test-PathExists $v }
        ValidateMessage = 'File does not exist. Use -SkipValidation to bypass file checks.'
    },
    [pscustomobject]@{
        Group = 'Server'
        Name  = 'DLP_DEVICE_ISSUING_CA_KEY_PEM'
        Prompt = 'Path to device-issuing CA private key PEM'
        Default = 'C:\dlp\secrets\device-issuing-ca-key.pem'
        Secure = $false
        Validate = { param($v) Test-PathExists $v }
        ValidateMessage = 'File does not exist. Use -SkipValidation to bypass file checks.'
    },
    [pscustomobject]@{
        Group = 'Server'
        Name  = 'DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX'
        Prompt = 'Ed25519 configuration-signing seed (64 hex chars)'
        Default = 'REPLACE_WITH_64_HEX_CHARS'
        Secure = $true
        Validate = { param($v) Test-HexLength $v 64 }
        ValidateMessage = 'Expected exactly 64 hexadecimal characters.'
    },

    # Active Directory / LDAPS
    [pscustomobject]@{
        Group = 'Active Directory'
        Name  = 'DLP_AD_PRIMARY_LDAPS_URL'
        Prompt = 'Primary AD LDAPS URL'
        Default = 'ldaps://LAB-DC01.lab.local:636'
        Secure = $false
        Validate = { param($v) Test-Url $v }
        ValidateMessage = 'Expected an ldaps:// or https:// URL.'
    },
    [pscustomobject]@{
        Group = 'Active Directory'
        Name  = 'DLP_AD_SECONDARY_LDAPS_URL'
        Prompt = 'Secondary AD LDAPS URL'
        Default = 'ldaps://LAB-DC02.lab.local:636'
        Secure = $false
        Validate = { param($v) Test-Url $v }
        ValidateMessage = 'Expected an ldaps:// or https:// URL.'
    },
    [pscustomobject]@{
        Group = 'Active Directory'
        Name  = 'DLP_AD_BASE_DN'
        Prompt = 'AD base DN'
        Default = 'DC=lab,DC=local'
        Secure = $false
    },
    [pscustomobject]@{
        Group = 'Active Directory'
        Name  = 'DLP_AD_BIND_DN'
        Prompt = 'AD service-account bind DN'
        Default = 'CN=dlp-service,OU=Service Accounts,DC=lab,DC=local'
        Secure = $false
    },
    [pscustomobject]@{
        Group = 'Active Directory'
        Name  = 'DLP_AD_BIND_PASSWORD'
        Prompt = 'AD service-account bind password'
        Default = 'REPLACE_PASSWORD'
        Secure = $true
    },
    [pscustomobject]@{
        Group = 'Active Directory'
        Name  = 'DLP_AD_CA_CERT_PEM'
        Prompt = 'Path to AD CA certificate PEM'
        Default = 'C:\dlp\secrets\ad-ca.pem'
        Secure = $false
        Validate = { param($v) Test-PathExists $v }
        ValidateMessage = 'File does not exist. Use -SkipValidation to bypass file checks.'
    },

    # Trusted provisioning
    [pscustomobject]@{
        Group = 'Trusted provisioning'
        Name  = 'DLP_PROVISIONING_ENDPOINT'
        Prompt = 'Trusted-provisioning API endpoint'
        Default = 'https://LAB-DC01.lab.local:8443/api/v1/admin/provisioning'
        Secure = $false
        Validate = { param($v) Test-Url $v }
        ValidateMessage = 'Expected an https:// URL.'
    },
    [pscustomobject]@{
        Group = 'Trusted provisioning'
        Name  = 'DLP_PROVISIONING_ROOT_CA_PATH'
        Prompt = 'Path to provisioning root CA PEM'
        Default = 'C:\dlp\secrets\phase1-root-ca.pem'
        Secure = $false
        Validate = { param($v) Test-PathExists $v }
        ValidateMessage = 'File does not exist. Use -SkipValidation to bypass file checks.'
    },
    [pscustomobject]@{
        Group = 'Trusted provisioning'
        Name  = 'DLP_PROVISIONING_ADMIN_CERT_PATH'
        Prompt = 'Path to provisioning admin certificate PEM'
        Default = 'C:\dlp\secrets\provisioning-admin-cert.pem'
        Secure = $false
        Validate = { param($v) Test-PathExists $v }
        ValidateMessage = 'File does not exist. Use -SkipValidation to bypass file checks.'
    },
    [pscustomobject]@{
        Group = 'Trusted provisioning'
        Name  = 'DLP_PROVISIONING_ADMIN_KEY_PATH'
        Prompt = 'Path to provisioning admin private key PEM'
        Default = 'C:\dlp\secrets\provisioning-admin-key.pem'
        Secure = $false
        Validate = { param($v) Test-PathExists $v }
        ValidateMessage = 'File does not exist. Use -SkipValidation to bypass file checks.'
    },
    [pscustomobject]@{
        Group = 'Trusted provisioning'
        Name  = 'DLP_PROVISIONING_AD_OBJECT_GUID'
        Prompt = 'LAB-CLIENT01 computer object GUID (hex)'
        Default = 'REPLACE_WITH_HEX_GUID'
        Secure = $false
        Validate = { param($v) Test-HexLength $v 32 }
        ValidateMessage = 'Expected exactly 32 hexadecimal characters (GUID without dashes).'
    },
    [pscustomobject]@{
        Group = 'Trusted provisioning'
        Name  = 'DLP_PROVISIONING_AD_OBJECT_SID'
        Prompt = 'LAB-CLIENT01 computer object SID (hex)'
        Default = 'REPLACE_WITH_HEX_SID'
        Secure = $false
    },
    [pscustomobject]@{
        Group = 'Trusted provisioning'
        Name  = 'DLP_PROVISIONING_TOKEN_HANDOFF_PATH'
        Prompt = 'Path where the enrollment token will be written'
        Default = 'C:\dlp\secrets\LAB-CLIENT01.enrollment-token'
        Secure = $false
    },
    [pscustomobject]@{
        Group = 'Trusted provisioning'
        Name  = 'DLP_PROVISIONING_PREFERRED_DRIVE_LETTER'
        Prompt = 'Preferred virtual-drive letter'
        Default = 'P'
        Secure = $false
        Validate = { param($v) Test-DriveLetter $v }
        ValidateMessage = 'Expected a single uppercase letter A-Z.'
    },
    [pscustomobject]@{
        Group = 'Trusted provisioning'
        Name  = 'DLP_PROVISIONING_DLPCTL_PATH'
        Prompt = 'Path to dlpctl.exe'
        Default = 'C:\Users\nhdinh\dev\dleakprevention\target\release\dlpctl.exe'
        Secure = $false
        Validate = { param($v) Test-PathExists $v }
        ValidateMessage = 'File does not exist. Use -SkipValidation to bypass file checks.'
    },
    [pscustomobject]@{
        Group = 'Trusted provisioning'
        Name  = 'DLP_PROVISIONING_COMPUTER'
        Prompt = 'Target computer FQDN for provisioning'
        Default = 'LAB-CLIENT01.lab.local'
        Secure = $false
    },
    [pscustomobject]@{
        Group = 'Trusted provisioning'
        Name  = 'DLP_PROVISIONING_DISK_MODE'
        Prompt = 'Disk fingerprint mode'
        Default = 'auto'
        Secure = $false
        Validate = { param($v) $v -in @('auto', 'serial', 'pnp') }
        ValidateMessage = 'Expected one of: auto, serial, pnp.'
    },
    [pscustomobject]@{
        Group = 'Trusted provisioning'
        Name  = 'DLP_APPROVED_PRIVILEGE_MANIFEST_DIGEST'
        Prompt = 'Approved privilege manifest digest (64 hex chars)'
        Default = 'REPLACE_WITH_64_HEX_DIGEST'
        Secure = $false
        Validate = { param($v) Test-HexLength $v 64 }
        ValidateMessage = 'Expected exactly 64 hexadecimal characters.'
    },
    [pscustomobject]@{
        Group = 'Trusted provisioning'
        Name  = 'DLP_LAB_ALLOW_VIRTUAL_DISK_UNIQUE_ID'
        Prompt = 'Allow virtual-disk unique ID fallback in lab'
        Default = 'true'
        Secure = $false
        Validate = { param($v) $v -in @('true', 'false') }
        ValidateMessage = 'Expected true or false.'
    },

    # Agent runtime
    [pscustomobject]@{
        Group = 'Agent runtime'
        Name  = 'DLP_AGENT_ENROLLMENT_TOKEN'
        Prompt = 'Enrollment token for the endpoint agent'
        Default = 'REPLACE_WITH_TOKEN_FROM_PROVISIONING'
        Secure = $true
        AllowEmpty = $true
    },
    [pscustomobject]@{
        Group = 'Agent runtime'
        Name  = 'DLP_DEVICE_ID'
        Prompt = 'Device ID assigned during enrollment'
        Default = 'REPLACE_WITH_DEVICE_ID'
        Secure = $false
    },
    [pscustomobject]@{
        Group = 'Agent runtime'
        Name  = 'DLP_SERVER_URL'
        Prompt = 'Management server URL seen by the agent'
        Default = 'https://LAB-DC01.lab.local:8443'
        Secure = $false
        Validate = { param($v) Test-Url $v }
        ValidateMessage = 'Expected an https:// URL.'
    },
    [pscustomobject]@{
        Group = 'Agent runtime'
        Name  = 'DLP_ROOT_CA_PEM'
        Prompt = 'Path to root CA PEM trusted by the agent'
        Default = 'C:\dlp\secrets\phase1-root-ca.pem'
        Secure = $false
        Validate = { param($v) Test-PathExists $v }
        ValidateMessage = 'File does not exist. Use -SkipValidation to bypass file checks.'
    },
    [pscustomobject]@{
        Group = 'Agent runtime'
        Name  = 'DLP_CONFIGURATION_PUBLIC_KEY_HEX'
        Prompt = 'Ed25519 public key for configuration signing (64 hex chars)'
        Default = 'REPLACE_WITH_64_HEX_CHARS'
        Secure = $false
        Validate = { param($v) Test-HexLength $v 64 }
        ValidateMessage = 'Expected exactly 64 hexadecimal characters.'
    },
    [pscustomobject]@{
        Group = 'Agent runtime'
        Name  = 'DLP_DATA_DIRECTORY'
        Prompt = 'Agent data directory'
        Default = 'C:\ProgramData\DLP\agent'
        Secure = $false
    },
    [pscustomobject]@{
        Group = 'Agent runtime'
        Name  = 'DLP_CACHE_DIRECTORY'
        Prompt = 'Agent cache directory'
        Default = 'C:\ProgramData\DLP\cache'
        Secure = $false
    },
    [pscustomobject]@{
        Group = 'Agent runtime'
        Name  = 'DLP_POLL_INTERVAL_SECONDS'
        Prompt = 'Policy poll interval in seconds'
        Default = '300'
        Secure = $false
        Validate = { param($v) $v -match '^\d+$' }
        ValidateMessage = 'Expected a positive integer.'
    },
    [pscustomobject]@{
        Group = 'Agent runtime'
        Name  = 'DLP_HEALTH_INTERVAL_SECONDS'
        Prompt = 'Health check interval in seconds'
        Default = '60'
        Secure = $false
        Validate = { param($v) $v -match '^\d+$' }
        ValidateMessage = 'Expected a positive integer.'
    },
    [pscustomobject]@{
        Group = 'Agent runtime'
        Name  = 'DLP_START_TIMEOUT_SECONDS'
        Prompt = 'Service start timeout in seconds'
        Default = '30'
        Secure = $false
        Validate = { param($v) $v -match '^\d+$' }
        ValidateMessage = 'Expected a positive integer.'
    },
    [pscustomobject]@{
        Group = 'Agent runtime'
        Name  = 'DLP_STOP_TIMEOUT_SECONDS'
        Prompt = 'Service stop timeout in seconds'
        Default = '30'
        Secure = $false
        Validate = { param($v) $v -match '^\d+$' }
        ValidateMessage = 'Expected a positive integer.'
    },
    [pscustomobject]@{
        Group = 'Agent runtime'
        Name  = 'DLP_WINFSP_INTERACTIVE_HOLD_MS'
        Prompt = 'WinFsp interactive hold milliseconds'
        Default = '0'
        Secure = $false
        Validate = { param($v) $v -match '^\d+$' }
        ValidateMessage = 'Expected a non-negative integer.'
    },
    [pscustomobject]@{
        Group = 'Agent runtime'
        Name  = 'DLP_WINFSP_SMOKE_LETTER'
        Prompt = 'WinFsp smoke-test drive letter'
        Default = 'P'
        Secure = $false
        Validate = { param($v) Test-DriveLetter $v }
        ValidateMessage = 'Expected a single uppercase letter A-Z.'
    },

    # Lab orchestration
    [pscustomobject]@{
        Group = 'Lab orchestration'
        Name  = 'DLP_VM_ADMIN_USER'
        Prompt = 'VM admin username for PowerShell Direct'
        Default = 'Administrator'
        Secure = $false
    },
    [pscustomobject]@{
        Group = 'Lab orchestration'
        Name  = 'DLP_VM_ADMIN_PASSWORD'
        Prompt = 'VM admin password for PowerShell Direct'
        Default = 'REPLACE_PASSWORD'
        Secure = $true
    },
    [pscustomobject]@{
        Group = 'Lab orchestration'
        Name  = 'DLP_SERVER01_HOST'
        Prompt = 'Server01 host IP or hostname'
        Default = '192.168.50.12'
        Secure = $false
    },
    [pscustomobject]@{
        Group = 'Lab orchestration'
        Name  = 'DLP_SERVER01_ADMIN_USER'
        Prompt = 'Server01 admin username'
        Default = 'admin'
        Secure = $false
    },
    [pscustomobject]@{
        Group = 'Lab orchestration'
        Name  = 'DLP_SERVER01_ADMIN_PASSWORD'
        Prompt = 'Server01 admin password'
        Default = 'REPLACE_PASSWORD'
        Secure = $true
    },
    [pscustomobject]@{
        Group = 'Lab orchestration'
        Name  = 'DLP_SERVER01_SSH_USER'
        Prompt = 'Server01 SSH username'
        Default = 'admin'
        Secure = $false
    },
    [pscustomobject]@{
        Group = 'Lab orchestration'
        Name  = 'DLP_PKI_DIR'
        Prompt = 'Local PKI directory'
        Default = 'C:\Users\nhdinh\dev\dleakprevention\pki'
        Secure = $false
        Validate = { param($v) Test-PathExists $v }
        ValidateMessage = 'Directory does not exist. Use -SkipValidation to bypass file checks.'
    },
    [pscustomobject]@{
        Group = 'Lab orchestration'
        Name  = 'DLP_SERVER_HOST'
        Prompt = 'Management server host IP'
        Default = '192.168.50.10'
        Secure = $false
    },
    [pscustomobject]@{
        Group = 'Lab orchestration'
        Name  = 'DLP_CONFIGURATION_KEY_ID'
        Prompt = 'Configuration signing key ID'
        Default = 'phase1-config-signing-key-v1'
        Secure = $false
    }
)

#endregion

if ($Clear) {
    $incompatible = @(@('EnvFile', 'OutEnvFile', 'SkipValidation', 'Force', 'NoHelp', 'NonInteractive') |
        Where-Object { $PSBoundParameters.ContainsKey($_) })
    if ($incompatible.Count -gt 0) {
        throw 'Clear cannot be combined with initialization or output switches.'
    }
    $processNames = @([Environment]::GetEnvironmentVariables('Process').Keys | Where-Object { $_ -like 'DLP_*' })
    foreach ($name in $processNames) {
        if ($PSCmdlet.ShouldProcess("process environment variable $name", 'Clear')) {
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        }
    }
    Write-Host "Cleared $($processNames.Count) DLP process environment variable(s)." -ForegroundColor Green
    return
}

$CatalogMetadata = @{
    'DLP_AGENT_ENROLLMENT_TOKEN' = @{ Required = $false; Conditional = $true; Sensitivity = 'secret'; Representation = 'token' }
}
foreach ($entry in $Catalog) {
    $metadata = if ($CatalogMetadata.ContainsKey($entry.Name)) { $CatalogMetadata[$entry.Name] } else { @{} }
    $entry | Add-Member -NotePropertyName Required -NotePropertyValue $(if ($metadata.ContainsKey('Required')) { $metadata.Required } else { Test-IsPlaceholder $entry.Default })
    $entry | Add-Member -NotePropertyName Conditional -NotePropertyValue $(if ($metadata.ContainsKey('Conditional')) { $metadata.Conditional } else { $false })
    $entry | Add-Member -NotePropertyName Sensitivity -NotePropertyValue $(if ($metadata.ContainsKey('Sensitivity')) { $metadata.Sensitivity } elseif ($entry.Secure) { 'secret' } else { 'non-secret' })
    $entry | Add-Member -NotePropertyName Representation -NotePropertyValue $(if ($metadata.ContainsKey('Representation')) { $metadata.Representation } elseif ($entry.Name -match '(_PEM|_PATH)$') { 'single-line path or supported process PEM input' } else { 'single-line value' })
}
$script:CatalogNames = @($Catalog | ForEach-Object { $_.Name })

if ($EnvFile) {
    Invoke-EnvFile -Path $EnvFile
}

$resolved = [ordered]@{}
$unresolved = [System.Collections.Generic.List[string]]::new()
$currentGroup = $null

foreach ($entry in $Catalog) {
    if ($entry.Group -ne $currentGroup) {
        $currentGroup = $entry.Group
        Write-Host ""
        Write-Host "-- $currentGroup --" -ForegroundColor Cyan
    }

    $value = Read-DlpValue `
        -Name $entry.Name `
        -Prompt $entry.Prompt `
        -Default $entry.Default `
        -Secure:([bool](Get-EntryProperty $entry 'Secure')) `
        -AllowEmpty:([bool](Get-EntryProperty $entry 'AllowEmpty')) `
        -Validate (Get-EntryProperty $entry 'Validate') `
        -ValidateMessage (Get-EntryProperty $entry 'ValidateMessage') `
        -HelpText (Get-HelpText $entry.Name) `
        -NonInteractive:$NonInteractive

    if (Test-IsPlaceholder $value) {
        if ($entry.Required -or $entry.Conditional) { $unresolved.Add($entry.Name) }
        continue
    }

    $resolved[$entry.Name] = $value

    if ($PSCmdlet.ShouldProcess("process environment variable $($entry.Name)", 'Set')) {
        [Environment]::SetEnvironmentVariable($entry.Name, $value, 'Process')
    }
}

if ($NonInteractive -and $unresolved.Count -gt 0) {
    throw "Non-interactive initialization requires values for: $($unresolved -join ', ')"
}

# Summary
Write-Host ""
Write-Host "DLP environment initialized." -ForegroundColor Green
Write-Host "Variables set: $($resolved.Count)" -ForegroundColor Green

$stillPlaceholder = $resolved.GetEnumerator() | Where-Object { Test-IsPlaceholder $_.Value } | Select-Object -ExpandProperty Key
if ($stillPlaceholder) {
    Write-Warning "Some variables are still empty or placeholders:"
    $stillPlaceholder | ForEach-Object { Write-Warning "  $_" }
}

if ($OutEnvFile) {
    if ((Test-Path -LiteralPath $OutEnvFile) -and -not $Force) {
        throw "OutEnvFile already exists. Re-run with -Force to overwrite: $OutEnvFile"
    }
    Write-Warning 'OutEnvFile stores plaintext secrets. Protect the file and do not commit it.'
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('# DLP Phase 1 lab environment')
    $lines.Add("# Generated by Initialize-DlpEnvironment.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')")
    $lines.Add('# Do NOT commit this file.')
    $lines.Add('')
    $currentGroup = $null
    foreach ($entry in $Catalog) {
        if ($entry.Group -ne $currentGroup) {
            $currentGroup = $entry.Group
            $lines.Add("")
            $lines.Add("# -- $currentGroup --")
        }
        $value = $resolved[$entry.Name]
        $lines.Add("$($entry.Name)=$value")
    }

    $dir = Split-Path -Parent $OutEnvFile
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    if ($PSCmdlet.ShouldProcess($OutEnvFile, 'Write env file')) {
        [System.IO.File]::WriteAllLines($OutEnvFile, $lines, (New-Object System.Text.UTF8Encoding($false)))
        Write-Host "Wrote env file: $OutEnvFile" -ForegroundColor Green
    }
}

if (-not $OutEnvFile -and -not $WhatIfPreference) {
    Write-Host ""
    Write-Host "Tip: re-run with -OutEnvFile '.\config\lab.env.local' to persist these values." -ForegroundColor DarkGray
}
