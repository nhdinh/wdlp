[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter()][string]$EnvFile,
    [Parameter()][string]$OutEnvFile,
    [Parameter()][switch]$SkipValidation,
    [Parameter()][switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

#region Helpers

function Test-IsPlaceholder {
    param([Parameter()][AllowEmptyString()][string]$Value)
    return [string]::IsNullOrWhiteSpace($Value) -or ($Value -like 'REPLACE_*') -or ($Value -eq '<missing>')
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
        [Parameter()][scriptblock]$Validate,
        [Parameter()][string]$ValidateMessage = 'Value is not valid.'
    )

    $current = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if (-not (Test-IsPlaceholder $current)) {
        return $current
    }

    $fullPrompt = if (Test-IsPlaceholder $Default) {
        "$Prompt`: "
    } else {
        "$Prompt [default: $Default]`: "
    }

    while ($true) {
        if ($Secure) {
            $secureValue = Read-Host -Prompt $fullPrompt -AsSecureString
            $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureValue))
            if ([string]::IsNullOrWhiteSpace($plain) -and -not (Test-IsPlaceholder $Default)) {
                $plain = $Default
            }
        } else {
            $plain = Read-Host -Prompt $fullPrompt
            if ([string]::IsNullOrWhiteSpace($plain) -and -not (Test-IsPlaceholder $Default)) {
                $plain = $Default
            }
        }

        if (Test-IsPlaceholder $plain) {
            Write-Warning "$Name is required. Please provide a value."
            continue
        }

        if ($Validate -and -not $SkipValidation) {
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
    Get-Content -LiteralPath $Path | ForEach-Object {
        $line = $_.Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { return }
        if ($line -notmatch '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') { return }
        $name = $Matches[1]
        $value = $Matches[2]
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

if ($EnvFile) {
    Invoke-EnvFile -Path $EnvFile
}

$resolved = [ordered]@{}
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
        -Validate (Get-EntryProperty $entry 'Validate') `
        -ValidateMessage (Get-EntryProperty $entry 'ValidateMessage')

    $resolved[$entry.Name] = $value

    if ($PSCmdlet.ShouldProcess("process environment variable $($entry.Name)", 'Set')) {
        [Environment]::SetEnvironmentVariable($entry.Name, $value, 'Process')
    }
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
