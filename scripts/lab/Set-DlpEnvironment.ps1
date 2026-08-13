[CmdletBinding()]
param(
    [Parameter()][string]$EnvFile,
    [Parameter()][switch]$Force,
    [Parameter()][switch]$ShowValues
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Set-DlpEnv {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value,
        [Parameter()][switch]$Force
    )
    if ($Force -or [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($Name, 'Process'))) {
        [Environment]::SetEnvironmentVariable($Name, $Value, 'Process')
    }
}

function Get-DlpEnvOrDefault {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Default
    )
    $existing = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if (-not [string]::IsNullOrWhiteSpace($existing)) { return $existing }
    return $Default
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
        if ($Force -or [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name, 'Process'))) {
            [Environment]::SetEnvironmentVariable($name, $value, 'Process')
        }
    }
}

# Phase 1 lab topology defaults
$LabDefaults = @{
    # Server (LAB-DC01 / Docker)
    DLP_LISTEN_ADDRESS              = '0.0.0.0:8443'
    DLP_DATABASE_URL                = 'postgres://dlp_server:REPLACE_ME@192.168.50.12:5432/dlp'
    DLP_DATABASE_NAME               = 'dlp'
    DLP_DATABASE_USER               = 'dlp_server'
    DLP_SERVER_CERT_PEM             = 'C:\dlp\secrets\server-cert.pem'
    DLP_SERVER_KEY_PEM              = 'C:\dlp\secrets\server-key.pem'
    DLP_ADMIN_CA_CERT_PEM           = 'C:\dlp\secrets\admin-ca.pem'
    DLP_PHASE1_ROOT_CA_CERT_PEM     = 'C:\dlp\secrets\phase1-root-ca.pem'
    DLP_DEVICE_ISSUING_CA_CERT_PEM  = 'C:\dlp\secrets\device-issuing-ca.pem'
    DLP_DEVICE_ISSUING_CA_KEY_PEM   = 'C:\dlp\secrets\device-issuing-ca-key.pem'
    DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX = 'REPLACE_WITH_64_HEX_CHARS'

    # Active Directory / LDAPS
    DLP_AD_PRIMARY_LDAPS_URL        = 'ldaps://LAB-DC01.lab.local:636'
    DLP_AD_SECONDARY_LDAPS_URL      = 'ldaps://LAB-DC02.lab.local:636'
    DLP_AD_BASE_DN                  = 'DC=lab,DC=local'
    DLP_AD_BIND_DN                  = 'CN=dlp-service,OU=Service Accounts,DC=lab,DC=local'
    DLP_AD_BIND_PASSWORD            = 'REPLACE_ME'
    DLP_AD_CA_CERT_PEM              = 'C:\dlp\secrets\ad-ca.pem'

    # Trusted provisioning (dlpctl on hungdinh-lt / LAB-DC01)
    DLP_PROVISIONING_ENDPOINT            = 'https://LAB-DC01.lab.local:8443/api/v1/admin/provisioning'
    DLP_PROVISIONING_ROOT_CA_PATH        = 'C:\dlp\secrets\phase1-root-ca.pem'
    DLP_PROVISIONING_ADMIN_CERT_PATH     = 'C:\dlp\secrets\provisioning-admin-cert.pem'
    DLP_PROVISIONING_ADMIN_KEY_PATH      = 'C:\dlp\secrets\provisioning-admin-key.pem'
    DLP_PROVISIONING_AD_OBJECT_GUID      = 'REPLACE_WITH_HEX_GUID'
    DLP_PROVISIONING_AD_OBJECT_SID       = 'REPLACE_WITH_HEX_SID'
    DLP_PROVISIONING_TOKEN_HANDOFF_PATH  = 'C:\dlp\secrets\LAB-CLIENT01.enrollment-token'
    DLP_PROVISIONING_PREFERRED_DRIVE_LETTER = 'P'
    DLP_PROVISIONING_DLPCTL_PATH         = 'C:\Users\nhdinh\dev\dleakprevention\target\release\dlpctl.exe'
    DLP_PROVISIONING_COMPUTER            = 'LAB-CLIENT01.lab.local'
    DLP_PROVISIONING_DISK_MODE           = 'auto'
    DLP_APPROVED_PRIVILEGE_MANIFEST_DIGEST = 'REPLACE_WITH_64_HEX_DIGEST'
    DLP_LAB_ALLOW_VIRTUAL_DISK_UNIQUE_ID = 'true'

    # Agent runtime (LAB-CLIENT01)
    DLP_AGENT_ENROLLMENT_TOKEN       = 'REPLACE_WITH_TOKEN_FROM_PROVISIONING'
    DLP_DEVICE_ID                    = 'REPLACE_WITH_DEVICE_ID'
    DLP_SERVER_URL                   = 'https://LAB-DC01.lab.local:8443'
    DLP_ROOT_CA_PEM                  = 'C:\dlp\secrets\phase1-root-ca.pem'
    DLP_CONFIGURATION_PUBLIC_KEY_HEX = 'REPLACE_WITH_64_HEX_CHARS'
    DLP_DATA_DIRECTORY               = 'C:\ProgramData\DLP\agent'
    DLP_CACHE_DIRECTORY              = 'C:\ProgramData\DLP\cache'
    DLP_POLL_INTERVAL_SECONDS        = '300'
    DLP_HEALTH_INTERVAL_SECONDS      = '60'
    DLP_START_TIMEOUT_SECONDS        = '30'
    DLP_STOP_TIMEOUT_SECONDS         = '30'
    DLP_WINFSP_INTERACTIVE_HOLD_MS   = '0'
    DLP_WINFSP_SMOKE_LETTER          = 'P'

    # Lab orchestration (hungdinh-lt)
    DLP_VM_ADMIN_USER                = 'Administrator'
    DLP_VM_ADMIN_PASSWORD            = 'REPLACE_ME'
    DLP_SERVER01_HOST                = '192.168.50.12'
    DLP_SERVER01_ADMIN_USER          = 'admin'
    DLP_SERVER01_ADMIN_PASSWORD      = 'REPLACE_ME'
    DLP_SERVER01_SSH_USER            = 'admin'
    DLP_PKI_DIR                      = 'C:\Users\nhdinh\dev\dleakprevention\pki'
    DLP_SERVER_HOST                  = '192.168.50.10'
    DLP_CONFIGURATION_KEY_ID         = 'phase1-config-signing-key-v1'
}

if ($EnvFile) {
    Invoke-EnvFile -Path $EnvFile
}

$setCount = 0
$skippedCount = 0
foreach ($entry in $LabDefaults.GetEnumerator() | Sort-Object Key) {
    $current = [Environment]::GetEnvironmentVariable($entry.Key, 'Process')
    if ($Force -or [string]::IsNullOrWhiteSpace($current)) {
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
        $setCount++
    } else {
        $skippedCount++
    }
}

Write-Host "DLP environment loaded." -ForegroundColor Green
Write-Host "  Set:     $setCount"
Write-Host "  Skipped: $skippedCount (already present; use -Force to overwrite)"

$missing = $LabDefaults.Keys | Where-Object {
    $v = [Environment]::GetEnvironmentVariable($_, 'Process')
    [string]::IsNullOrWhiteSpace($v) -or $v -like 'REPLACE_*'
} | Sort-Object

if ($missing) {
    Write-Host ""
    Write-Host "Variables still empty or using placeholder defaults:" -ForegroundColor Yellow
    $missing | ForEach-Object { Write-Host "  $_" }
}

if ($ShowValues) {
    Write-Host ""
    Write-Host "Current DLP_* process environment values:" -ForegroundColor Cyan
    Get-ChildItem Env: | Where-Object { $_.Name -like 'DLP_*' } | Sort-Object Name | Format-Table -AutoSize
}
