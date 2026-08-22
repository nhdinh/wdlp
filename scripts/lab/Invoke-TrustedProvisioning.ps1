[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('LAB-DC01')][string]$ExecutionMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-CLIENT01.lab.local')][string]$TargetComputer,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$PrivilegeManifestDigest,
    [Parameter(Mandatory)][ValidatePattern('^[A-Z]$')][string]$PreferredDriveLetter,
    [Parameter(Mandatory)][string]$AdminCaPem,
    [Parameter()][switch]$RecoverCredential
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Stop-TrustedProvisioning([string]$Code) { throw $Code }
function Assert-TrustedProvisioning([bool]$Condition, [string]$Code) {
    if (-not $Condition) { Stop-TrustedProvisioning $Code }
}

function Resolve-PemContent {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )
    # Environment variables may contain either inline PEM material or a path to a
    # PEM file. Always return the actual PEM content so dlpctl receives
    # certificates/keys instead of path strings.
    $trimmed = $Value.Trim()
    if ($trimmed -match '^-----BEGIN') { return $Value }
    if (Test-Path -LiteralPath $trimmed -PathType Leaf) {
        $content = Get-Content -Raw -LiteralPath $trimmed
        if ($content.Trim() -match '^-----BEGIN') { return $content }
        Stop-TrustedProvisioning "pem_file_invalid:$Name" "'$trimmed' does not contain PEM content."
    }
    Stop-TrustedProvisioning "pem_unresolvable:$Name" "$Name is neither inline PEM nor an existing file path: $trimmed"
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
    if (-not ($AdminCaPem -match '^-----BEGIN CERTIFICATE-----')) {
        Stop-TrustedProvisioning 'provisioning_material_missing: AdminCaPem must be a PEM certificate'
    }
}

function New-ProtectedProvisioningDirectory {
    $path = Join-Path 'C:\dlp\provisioning' ([Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $path -Force | Out-Null

    $acl = Get-Acl -LiteralPath $path
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    foreach ($identity in @('SYSTEM', [System.Security.Principal.WindowsIdentity]::GetCurrent().Name)) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            $propagation,
            $allow
        ))
    }
    Set-Acl -LiteralPath $path -AclObject $acl
    return $path
}

function Assert-DomainTimeSkew([string]$ComputerName) {
    # w32tm is the Windows Time service diagnostic tool. A single stripchart
    # sample against the authoritative DC reports the local clock offset. Fail
    # closed if the tool is unavailable or the offset cannot be parsed.
    $output = @(w32tm /stripchart /computer:$ComputerName /samples:1 /dataonly 2>&1)
    $line = $output | Select-Object -Last 1
    if ($line -notmatch '([\+\-]?\d+\.?\d*)\s*s') {
        Stop-TrustedProvisioning 'domain_time_skew'
    }
    $offset = [math]::Abs([double]$matches[1])
    Assert-TrustedProvisioning ($offset -le 300) 'domain_time_skew'
}

# All guards run before directory or remote-CIM access.
Assert-TrustedProvisioning ($env:COMPUTERNAME -eq 'LAB-DC01' -and $ExecutionMachine -eq 'LAB-DC01') 'execution_machine_denied'
Assert-TrustedProvisioning ($TargetComputer -eq 'LAB-CLIENT01.lab.local') 'target_denied'
Assert-TrustedProvisioning ($PrivilegeManifestDigest -eq $env:DLP_APPROVED_PRIVILEGE_MANIFEST_DIGEST) 'privilege_manifest_denied'
Assert-ProvisioningMaterialPresent
Assert-DomainTimeSkew -ComputerName 'LAB-DC01.lab.local'

$primary = Get-ADComputer -Server 'LAB-DC01.lab.local' -Identity 'LAB-CLIENT01' -Properties Enabled,ObjectGUID,DNSHostName
$secondary = Get-ADComputer -Server 'LAB-DC02.lab.local' -Identity 'LAB-CLIENT01' -Properties Enabled,ObjectGUID,DNSHostName
Assert-TrustedProvisioning ($null -ne $primary.SID -and $null -ne $secondary.SID) 'directory_sid_missing'
$primaryIdentity = "$($primary.ObjectGUID)|$($primary.SID.Value)|$($primary.DNSHostName)|$($primary.Enabled)"
$secondaryIdentity = "$($secondary.ObjectGUID)|$($secondary.SID.Value)|$($secondary.DNSHostName)|$($secondary.Enabled)"
Assert-TrustedProvisioning ($primary.Enabled -and $secondary.Enabled -and $primaryIdentity -eq $secondaryIdentity -and $primary.DNSHostName -eq $TargetComputer) 'directory_corroboration_denied'

$guidBytes = [byte[]]::new(16)
$primary.ObjectGUID.ToByteArray().CopyTo($guidBytes, 0)
$guidHex = [System.BitConverter]::ToString($guidBytes).Replace('-', '').ToLowerInvariant()
$sidBytes = [byte[]]::new($primary.SID.BinaryLength)
$primary.SID.GetBinaryForm($sidBytes, 0)
$sidHex = [System.BitConverter]::ToString($sidBytes).Replace('-', '').ToLowerInvariant()

$cimOption = New-CimSessionOption -UseSSL
$session = New-CimSession -ComputerName $TargetComputer -Authentication Kerberos -SessionOption $cimOption
$secretPaths = @()
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

    # A protected per-run directory prevents inherited ACLs from exposing
    # administrator material or the short-lived handoff token.
    $provDir = New-ProtectedProvisioningDirectory
    $rootCaPath = Join-Path $provDir 'phase1-root-ca.pem'
    $adminCaPath = Join-Path $provDir 'admin-ca.pem'
    $adminCertPath = Join-Path $provDir 'provisioning-admin-cert.pem'
    $adminKeyPath = Join-Path $provDir 'provisioning-admin-key.pem'
    $tokenHandoffPath = Join-Path $provDir 'enrollment-token.txt'
    $secretPaths = @($rootCaPath, $adminCaPath, $adminCertPath, $adminKeyPath, $tokenHandoffPath)
    $rootCaPem = Resolve-PemContent -Name 'DLP_PROVISIONING_ROOT_CA_PEM' -Value $env:DLP_PROVISIONING_ROOT_CA_PEM
    $adminCertPem = Resolve-PemContent -Name 'DLP_PROVISIONING_ADMIN_CERT_PEM' -Value $env:DLP_PROVISIONING_ADMIN_CERT_PEM
    $adminKeyPem = Resolve-PemContent -Name 'DLP_PROVISIONING_ADMIN_KEY_PEM' -Value $env:DLP_PROVISIONING_ADMIN_KEY_PEM
    [System.IO.File]::WriteAllText($rootCaPath, $rootCaPem, (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText($adminCaPath, $AdminCaPem, (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText($adminCertPath, $adminCertPem, (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText($adminKeyPath, $adminKeyPem, (New-Object System.Text.UTF8Encoding($false)))

    $fqdn = ([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)).HostName
    $env:DLP_PROVISIONING_ENDPOINT = "https://${fqdn}:8443/api/v1/admin/provisioning"
    $env:DLP_PROVISIONING_ROOT_CA_PATH = $rootCaPath
    $env:DLP_PROVISIONING_ADMIN_CA_CERT_PATH = $adminCaPath
    $env:DLP_PROVISIONING_ADMIN_CERT_PATH = $adminCertPath
    $env:DLP_PROVISIONING_ADMIN_KEY_PATH = $adminKeyPath
    $env:DLP_PROVISIONING_TOKEN_HANDOFF_PATH = $tokenHandoffPath
    # Ensure the Rust side can write diagnostics even if PowerShell stream
    # redirection fails inside the remote session.
    $env:DLP_PROVISIONING_DIAGNOSTIC_PATH = Join-Path $provDir 'dlpctl-rust.err'
    # The lab runs on Hyper-V VMs whose Win32_DiskDrive.SerialNumber is empty;
    # dlpctl must use lab-only mode so it falls back to MSFT_Disk.UniqueId.
    $env:DLP_LAB_ALLOW_VIRTUAL_DISK_UNIQUE_ID = 'true'
    # Capture rustls certificate-verification trace output when the handshake
    # aborts, so the exact webpki/platform-verifier decision is visible.
    $env:RUST_LOG = 'rustls=trace'

    $dlpctl = if ($env:DLP_PROVISIONING_DLPCTL_PATH) { $env:DLP_PROVISIONING_DLPCTL_PATH } else { 'dlpctl' }

    # Pre-flight: confirm the management server is reachable before invoking dlpctl.
    # This separates a dead/stale listener from a TLS/certificate failure.
    $endpointHost = ([System.Uri]$env:DLP_PROVISIONING_ENDPOINT).Host
    $endpointPort = ([System.Uri]$env:DLP_PROVISIONING_ENDPOINT).Port
    $tcpClient = [System.Net.Sockets.TcpClient]::new()
    $tcpConnected = $false
    try {
        $pendingConnect = $tcpClient.BeginConnect($endpointHost, $endpointPort, $null, $null)
        if ($pendingConnect.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds(5))) {
            $tcpClient.EndConnect($pendingConnect)
            $tcpConnected = $true
        }
    } catch {
        $tcpConnected = $false
    } finally {
        $tcpClient.Dispose()
    }
    if (-not $tcpConnected) {
        Write-Host "pre-flight TCP test failed: ${endpointHost}:${endpointPort} is not reachable"
        Stop-TrustedProvisioning 'provisioning_endpoint_unreachable'
    }

    # Capture dlpctl stderr/stdout reliably using Start-Process redirection.
    # The `&` call operator's `2>` redirection does not consistently capture
    # native-executable stderr inside PowerShell Direct sessions.
    $errPath = Join-Path $provDir 'dlpctl.err'
    $logPath = Join-Path $provDir 'dlpctl.log'
    $rustErrPath = Join-Path $provDir 'dlpctl-rust.err'
    Remove-Item -LiteralPath $errPath, $logPath, $rustErrPath -Force -ErrorAction SilentlyContinue
    $dlpctlArguments = @('provision-device', '--computer', $TargetComputer)
    if ($RecoverCredential) { $dlpctlArguments += '--recover' }
    $proc = Start-Process -FilePath $dlpctl `
        -ArgumentList $dlpctlArguments `
        -WorkingDirectory $provDir `
        -RedirectStandardError $errPath `
        -RedirectStandardOutput $logPath `
        -WindowStyle Hidden `
        -Wait -PassThru
    $exitCode = $proc.ExitCode
    if ($exitCode -ne 0) {
        Write-Host "dlpctl exit code: $exitCode"
        Write-Host 'dlpctl diagnostics retained only in the protected run directory.'
        Stop-TrustedProvisioning 'provisioning_client_failed'
    }

    Assert-TrustedProvisioning (Test-Path -LiteralPath $tokenHandoffPath) 'provisioning_token_handoff_missing'
    $token = [System.IO.File]::ReadAllText($tokenHandoffPath)
    Assert-TrustedProvisioning (-not [string]::IsNullOrWhiteSpace($token)) 'provisioning_token_empty'
    Remove-Item -LiteralPath $tokenHandoffPath -Force

    # Return the one-time token only through the existing authenticated
    # PowerShell Direct session. The caller consumes it immediately to set the
    # LAB-CLIENT01 service environment, and neither this helper nor the caller
    # writes it to diagnostics or evidence.
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
    foreach ($path in $secretPaths) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    }
    if ($null -ne $session) { Remove-CimSession -CimSession $session }
}
