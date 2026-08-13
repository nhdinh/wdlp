[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('LAB-DC01')][string]$ExecutionMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-CLIENT01.lab.local')][string]$TargetComputer,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$PrivilegeManifestDigest,
    [Parameter(Mandatory)][ValidatePattern('^[A-Z]$')][string]$PreferredDriveLetter
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Stop-TrustedProvisioning([string]$Code) { throw $Code }
function Assert-TrustedProvisioning([bool]$Condition, [string]$Code) {
    if (-not $Condition) { Stop-TrustedProvisioning $Code }
}

$script:InvalidObservations = @('UNKNOWN', 'NONE', 'N/A', 'TO BE FILLED BY O.E.M.', 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF')

function Test-ObservationValid([string]$Value) {
    $normalized = $Value.Trim().ToUpperInvariant()
    return -not ([string]::IsNullOrWhiteSpace($normalized) -or $normalized -in $script:InvalidObservations)
}

function Normalize-Observation([string]$Value) {
    $normalized = $Value.Trim().ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($normalized) -or $normalized -in $script:InvalidObservations) {
        Stop-TrustedProvisioning 'fingerprint_source_invalid'
    }
    return $normalized
}

function Get-SystemDiskIdentity($Disk) {
    # Physical serial is preferred. Hyper-V virtual disks expose a null
    # SerialNumber but a stable PNPDeviceID, which the Phase 1 lab contract
    # explicitly allows as a virtual-disk identifier substitute.
    if (Test-ObservationValid $Disk.SerialNumber) {
        return [pscustomobject]@{ value = $Disk.SerialNumber; source = 'Win32_DiskDrive.SerialNumber' }
    }
    if (Test-ObservationValid $Disk.PNPDeviceID) {
        return [pscustomobject]@{ value = $Disk.PNPDeviceID; source = 'Win32_DiskDrive.PNPDeviceID' }
    }
    Stop-TrustedProvisioning 'fingerprint_source_invalid'
}
function Get-ObservationDigest([string[]]$Values) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $buffer = New-Object System.Collections.Generic.List[byte]
        $buffer.AddRange([byte[]][Text.Encoding]::UTF8.GetBytes("dlp-fingerprint/v1`0"))
        $names = @('smbios_uuid', 'bios_serial', 'system_disk_serial')
        for ($index = 0; $index -lt 3; $index++) {
            $name = [byte[]][Text.Encoding]::UTF8.GetBytes($names[$index])
            $value = [byte[]][Text.Encoding]::UTF8.GetBytes($Values[$index])
            $buffer.AddRange([byte[]][BitConverter]::GetBytes([UInt16]$name.Length)[1..0])
            $buffer.AddRange($name)
            $buffer.AddRange([byte[]][BitConverter]::GetBytes([UInt16]$value.Length)[1..0])
            $buffer.AddRange($value)
        }
        return ([System.BitConverter]::ToString($sha.ComputeHash($buffer.ToArray())) -replace '-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Assert-ProvisioningMaterialPresent {
    $required = @(
        'DLP_PROVISIONING_ROOT_CA_PEM',
        'DLP_PROVISIONING_ADMIN_CERT_PEM',
        'DLP_PROVISIONING_ADMIN_KEY_PEM'
    )
    foreach ($name in $required) {
        if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
            Stop-TrustedProvisioning "provisioning_material_missing: $name"
        }
    }
}

# All guards run before directory or remote-CIM access.
Assert-TrustedProvisioning ($env:COMPUTERNAME -eq 'LAB-DC01' -and $ExecutionMachine -eq 'LAB-DC01') 'execution_machine_denied'
Assert-TrustedProvisioning ($TargetComputer -eq 'LAB-CLIENT01.lab.local') 'target_denied'
Assert-TrustedProvisioning ($PrivilegeManifestDigest -eq $env:DLP_APPROVED_PRIVILEGE_MANIFEST_DIGEST) 'privilege_manifest_denied'
Assert-ProvisioningMaterialPresent
$domainTime = (Get-Date).ToUniversalTime()
Assert-TrustedProvisioning ([math]::Abs(((Get-Date).ToUniversalTime() - $domainTime).TotalSeconds) -le 300) 'domain_time_skew'

$primary = Get-ADComputer -Server 'LAB-DC01.lab.local' -Identity 'LAB-CLIENT01' -Properties Enabled,ObjectGUID,ObjectSID,DNSHostName
$secondary = Get-ADComputer -Server 'LAB-DC02.lab.local' -Identity 'LAB-CLIENT01' -Properties Enabled,ObjectGUID,ObjectSID,DNSHostName
$primaryIdentity = "$($primary.ObjectGUID)|$($primary.ObjectSID.Value)|$($primary.DNSHostName)|$($primary.Enabled)"
$secondaryIdentity = "$($secondary.ObjectGUID)|$($secondary.ObjectSID.Value)|$($secondary.DNSHostName)|$($secondary.Enabled)"
Assert-TrustedProvisioning ($primary.Enabled -and $secondary.Enabled -and $primaryIdentity -eq $secondaryIdentity -and $primary.DNSHostName -eq $TargetComputer) 'directory_corroboration_denied'

$guidBytes = New-Object byte[] 16
$primary.ObjectGUID.ToByteArray().CopyTo($guidBytes, 0)
$guidHex = [System.BitConverter]::ToString($guidBytes).Replace('-', '').ToLowerInvariant()
$sidBytes = New-Object byte[] $primary.ObjectSID.BinaryLength
$primary.ObjectSID.GetBinaryForm($sidBytes, 0)
$sidHex = [System.BitConverter]::ToString($sidBytes).Replace('-', '').ToLowerInvariant()

$cimOption = New-CimSessionOption -UseSSL
$session = New-CimSession -ComputerName $TargetComputer -Authentication Kerberos -SessionOption $cimOption
try {
    $product = @(Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystemProduct)
    $bios = @(Get-CimInstance -CimSession $session -ClassName Win32_BIOS)
    $logical = @(Get-CimInstance -CimSession $session -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'")
    $partition = @($logical | Get-CimAssociatedInstance -Association Win32_LogicalDiskToPartition)
    $disk = @($partition | Get-CimAssociatedInstance -Association Win32_DiskDriveToDiskPartition)
    Assert-TrustedProvisioning ($product.Count -eq 1 -and $bios.Count -eq 1 -and $logical.Count -eq 1 -and $partition.Count -eq 1 -and $disk.Count -eq 1) 'fingerprint_source_ambiguous'
    $diskIdentity = Get-SystemDiskIdentity $disk[0]
    $digest = Get-ObservationDigest @(
        (Normalize-Observation $product[0].UUID),
        (Normalize-Observation $bios[0].SerialNumber),
        (Normalize-Observation $diskIdentity.value)
    )

    $env:DLP_PROVISIONING_AD_OBJECT_GUID = $guidHex
    $env:DLP_PROVISIONING_AD_OBJECT_SID = $sidHex
    $env:DLP_PROVISIONING_PREFERRED_DRIVE_LETTER = $PreferredDriveLetter

    # Write provisioning material to files so dlpctl can load them by path.
    $provDir = 'C:\dlp\provisioning'
    New-Item -ItemType Directory -Path $provDir -Force | Out-Null
    $rootCaPath = Join-Path $provDir 'phase1-root-ca.pem'
    $adminCertPath = Join-Path $provDir 'provisioning-admin-cert.pem'
    $adminKeyPath = Join-Path $provDir 'provisioning-admin-key.pem'
    $tokenHandoffPath = Join-Path $provDir 'enrollment-token.txt'
    [System.IO.File]::WriteAllText($rootCaPath, $env:DLP_PROVISIONING_ROOT_CA_PEM, (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText($adminCertPath, $env:DLP_PROVISIONING_ADMIN_CERT_PEM, (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText($adminKeyPath, $env:DLP_PROVISIONING_ADMIN_KEY_PEM, (New-Object System.Text.UTF8Encoding($false)))

    $env:DLP_PROVISIONING_ENDPOINT = "https://${env:COMPUTERNAME}:8443/api/v1/admin/provisioning"
    $env:DLP_PROVISIONING_ROOT_CA_PATH = $rootCaPath
    $env:DLP_PROVISIONING_ADMIN_CERT_PATH = $adminCertPath
    $env:DLP_PROVISIONING_ADMIN_KEY_PATH = $adminKeyPath
    $env:DLP_PROVISIONING_TOKEN_HANDOFF_PATH = $tokenHandoffPath

    $dlpctl = if ($env:DLP_PROVISIONING_DLPCTL_PATH) { $env:DLP_PROVISIONING_DLPCTL_PATH } else { 'dlpctl' }
    & $dlpctl provision-device --computer $TargetComputer
    if ($LASTEXITCODE -ne 0) { Stop-TrustedProvisioning 'provisioning_client_failed' }

    Assert-TrustedProvisioning (Test-Path -LiteralPath $tokenHandoffPath) 'provisioning_token_handoff_missing'
    $token = [System.IO.File]::ReadAllText($tokenHandoffPath)
    Assert-TrustedProvisioning (-not [string]::IsNullOrWhiteSpace($token)) 'provisioning_token_empty'

    # Plan 01-13 performs the actual runtime-provider handoff and lab mutation.
    # This source-complete preflight emits only non-secret provenance, digest,
    # and the short-lived enrollment token for the next orchestration step.
    [pscustomobject]@{
        procedure_version = 1
        target = $TargetComputer
        fingerprint_digest = $digest
        preferred_drive_letter = $PreferredDriveLetter
        transport = 'Kerberos WinRM HTTPS'
        disk_identity_source = $diskIdentity.source
        enrollment_token = $token
        evidence = 'sanitized'
    } | ConvertTo-Json -Compress
} finally {
    if ($null -ne $session) { Remove-CimSession -CimSession $session }
}
