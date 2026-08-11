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
        return [Convert]::ToHexString($sha.ComputeHash($buffer.ToArray()))
    } finally { $sha.Dispose() }
}

# All guards run before directory or remote-CIM access.
Assert-TrustedProvisioning ($env:COMPUTERNAME -eq 'LAB-DC01' -and $ExecutionMachine -eq 'LAB-DC01') 'execution_machine_denied'
Assert-TrustedProvisioning ($TargetComputer -eq 'LAB-CLIENT01.lab.local') 'target_denied'
Assert-TrustedProvisioning ($PrivilegeManifestDigest -eq $env:DLP_APPROVED_PRIVILEGE_MANIFEST_DIGEST) 'privilege_manifest_denied'
$domainTime = (Get-Date).ToUniversalTime()
Assert-TrustedProvisioning ([math]::Abs(((Get-Date).ToUniversalTime() - $domainTime).TotalSeconds) -le 300) 'domain_time_skew'

$primary = Get-ADComputer -Server 'LAB-DC01.lab.local' -Identity 'LAB-CLIENT01' -Properties Enabled,ObjectGUID,ObjectSID,DNSHostName
$secondary = Get-ADComputer -Server 'LAB-DC02.lab.local' -Identity 'LAB-CLIENT01' -Properties Enabled,ObjectGUID,ObjectSID,DNSHostName
$primaryIdentity = "$($primary.ObjectGUID)|$($primary.ObjectSID.Value)|$($primary.DNSHostName)|$($primary.Enabled)"
$secondaryIdentity = "$($secondary.ObjectGUID)|$($secondary.ObjectSID.Value)|$($secondary.DNSHostName)|$($secondary.Enabled)"
Assert-TrustedProvisioning ($primary.Enabled -and $secondary.Enabled -and $primaryIdentity -eq $secondaryIdentity -and $primary.DNSHostName -eq $TargetComputer) 'directory_corroboration_denied'

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
    # Plan 01-13 performs the actual runtime-provider handoff and lab mutation.
    # This source-complete preflight emits only non-secret provenance and digest.
    [pscustomobject]@{ procedure_version = 1; target = $TargetComputer; fingerprint_digest = $digest; preferred_drive_letter = $PreferredDriveLetter; transport = 'Kerberos WinRM HTTPS'; disk_identity_source = $diskIdentity.source; evidence = 'sanitized' } | ConvertTo-Json -Compress
} finally {
    if ($null -ne $session) { Remove-CimSession -CimSession $session }
}
