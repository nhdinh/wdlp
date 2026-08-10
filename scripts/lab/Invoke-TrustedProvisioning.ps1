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
function Normalize-Observation([string]$Value) {
    $normalized = $Value.Trim().ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($normalized) -or $normalized -in @('UNKNOWN', 'NONE', 'N/A', 'TO BE FILLED BY O.E.M.', 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF')) {
        Stop-TrustedProvisioning 'fingerprint_source_invalid'
    }
    return $normalized
}
function Get-ObservationDigest([string[]]$Values) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $buffer = New-Object System.Collections.Generic.List[byte]
        $buffer.AddRange([Text.Encoding]::UTF8.GetBytes("dlp-fingerprint/v1`0"))
        $names = @('smbios_uuid', 'bios_serial', 'system_disk_serial')
        for ($index = 0; $index -lt 3; $index++) {
            $name = [Text.Encoding]::UTF8.GetBytes($names[$index]); $value = [Text.Encoding]::UTF8.GetBytes($Values[$index])
            $buffer.AddRange([BitConverter]::GetBytes([UInt16]$name.Length)[1..0]); $buffer.AddRange($name)
            $buffer.AddRange([BitConverter]::GetBytes([UInt16]$value.Length)[1..0]); $buffer.AddRange($value)
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
    $digest = Get-ObservationDigest @(
        (Normalize-Observation $product[0].UUID),
        (Normalize-Observation $bios[0].SerialNumber),
        (Normalize-Observation $disk[0].SerialNumber)
    )
    # Plan 01-13 performs the actual runtime-provider handoff and lab mutation.
    # This source-complete preflight emits only non-secret provenance and digest.
    [pscustomobject]@{ procedure_version = 1; target = $TargetComputer; fingerprint_digest = $digest; preferred_drive_letter = $PreferredDriveLetter; transport = 'Kerberos WinRM HTTPS'; evidence = 'sanitized' } | ConvertTo-Json -Compress
} finally {
    if ($null -ne $session) { Remove-CimSession -CimSession $session }
}
