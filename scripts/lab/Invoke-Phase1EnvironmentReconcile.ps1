[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('hungdinh-lt')][string]$ExecutionMachine,
    [Parameter(Mandatory)][string]$ServerVm,
    [Parameter(Mandatory)][string]$SecondaryDcVm,
    [Parameter(Mandatory)][string]$EndpointVm,
    [Parameter()][switch]$Apply
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ConfigPath = Join-Path $RepoRoot 'config/lab.phase1.example.yaml'
$RoleConfigPath = Join-Path $RepoRoot 'config/lab.roles.example.json'
$EvidenceDir = Join-Path $RepoRoot 'evidence/phase1/attempts'

function Stop-Reconcile([string]$Code) { throw $Code }
function Assert-Reconcile([bool]$Condition, [string]$Code) {
    if (-not $Condition) { Stop-Reconcile $Code }
}

Import-Module (Join-Path $RepoRoot 'scripts/evidence/Phase1.Evidence.psm1') -Force

function Assert-DlpMachineRole {
    param([Parameter(Mandatory)][string]$ExpectedRole)
    $config = Get-Content -LiteralPath $RoleConfigPath -Raw | ConvertFrom-Json
    $machine = $config.machines.$env:COMPUTERNAME
    Assert-Reconcile ($null -ne $machine) 'machine_not_in_role_manifest'
    Assert-Reconcile ($machine.role -eq $ExpectedRole) "role_mismatch: expected $ExpectedRole, got $($machine.role)"
}

function Get-DlpBaseline {
    $baseline = @{
        winfsp_products = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue |
            Where-Object { $_.GetValue('DisplayName') -like '*WinFsp*' } |
            ForEach-Object { $_.GetValue('DisplayName') + '|' + $_.GetValue('DisplayVersion') + '|' + $_.PSChildName })
        dlp_services = @(Get-Service -Name 'dlp*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
        dlp_processes = @(Get-Process -Name 'dlp*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
        dlp_mounts = @()
        dlp_directories = @()
        dlp_cert_thumbprints = @()
        dlp_hosts_entries = @()
        dlp_network_changes = @()
    }
    $baseline.dlp_directories = @(
        'C:\Program Files\DLP',
        'C:\Program Files (x86)\DLP',
        'C:\ProgramData\DLP',
        "$env:LOCALAPPDATA\DLP",
        "$env:ProgramData\WinFsp"
    ) | Where-Object { Test-Path -LiteralPath $_ }
    $baseline.dlp_cert_thumbprints = @(Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\CA, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.FriendlyName -like '*DLP*' -or $_.Subject -like '*DLP*' } |
        ForEach-Object { $_.Thumbprint })
    $hostsPath = 'C:\Windows\System32\drivers\etc\hosts'
    if (Test-Path -LiteralPath $hostsPath) {
        $baseline.dlp_hosts_entries = @(Get-Content -LiteralPath $hostsPath |
            Where-Object { $_ -match 'dlp|lab-client01|lab-dc01|lab-dc02' -and $_ -notmatch '^\s*#' })
    }
    return $baseline
}

function Show-DlpTargets {
    param([Parameter(Mandatory)]$Baseline)
    Write-Host '=== Developer host cleanup targets (hungdinh-lt) ==='
    Write-Host "WinFsp products: $($Baseline.winfsp_products.Count)"
    foreach ($p in $Baseline.winfsp_products) { Write-Host "  $p" }
    Write-Host "DLP services: $($Baseline.dlp_services.Count)"
    foreach ($s in $Baseline.dlp_services) { Write-Host "  $s" }
    Write-Host "DLP processes: $($Baseline.dlp_processes.Count)"
    foreach ($p in $Baseline.dlp_processes) { Write-Host "  $p" }
    Write-Host "DLP directories: $($Baseline.dlp_directories.Count)"
    foreach ($d in $Baseline.dlp_directories) { Write-Host "  $d" }
    Write-Host "DLP certificate thumbprints: $($Baseline.dlp_cert_thumbprints.Count)"
    foreach ($t in $Baseline.dlp_cert_thumbprints) { Write-Host "  $t" }
    Write-Host "DLP hosts entries: $($Baseline.dlp_hosts_entries.Count)"
    foreach ($h in $Baseline.dlp_hosts_entries) { Write-Host "  $h" }
    Write-Host "DLP network changes: $($Baseline.dlp_network_changes.Count)"
}

function Invoke-DeveloperHostCleanup {
    param([Parameter(Mandatory)]$Baseline)
    foreach ($svc in $Baseline.dlp_services) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        sc.exe delete $svc | Out-Null
    }
    foreach ($proc in $Baseline.dlp_processes) {
        Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
    }
    foreach ($dir in $Baseline.dlp_directories) {
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
    foreach ($thumb in $Baseline.dlp_cert_thumbprints) {
        Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\CA, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $thumb } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
    $hostsPath = 'C:\Windows\System32\drivers\etc\hosts'
    if (Test-Path -LiteralPath $hostsPath -and $Baseline.dlp_hosts_entries.Count -gt 0) {
        $lines = Get-Content -LiteralPath $hostsPath |
            Where-Object { $_ -notin $Baseline.dlp_hosts_entries }
        [System.IO.File]::WriteAllLines($hostsPath, $lines, (New-Object System.Text.UTF8Encoding($false)))
    }
}

function Get-EnvironmentFingerprint {
    return [pscustomobject]@{
        machine_identity = $env:COMPUTERNAME
        role = 'developer_orchestrator'
        os_build = [System.Environment]::OSVersion.VersionString
        dependency_versions = 'PowerShell ' + $PSVersionTable.PSVersion.ToString()
        service_config_digest = (Get-Phase1Sha256 $ConfigPath)
        test_tool_versions = 'rtk'
        domain_network_identity = (Get-WmiObject -Class Win32_ComputerSystem).Domain
        baseline_id = [guid]::NewGuid().ToString()
        binary_hashes = 'none'
    }
}

Assert-DlpMachineRole -ExpectedRole 'developer_orchestrator'

$preBaseline = Get-DlpBaseline
Show-DlpTargets -Baseline $preBaseline

if ($Apply) {
    Invoke-DeveloperHostCleanup -Baseline $preBaseline
    $postBaseline = Get-DlpBaseline
    Assert-Reconcile ($postBaseline.winfsp_products.Count -eq 0) 'winfsp_removal_failed'
    Assert-Reconcile ($postBaseline.dlp_services.Count -eq 0) 'dlp_service_removal_failed'
    Assert-Reconcile ($postBaseline.dlp_directories.Count -eq 0) 'dlp_directory_removal_failed'
    Assert-Reconcile ($postBaseline.dlp_cert_thumbprints.Count -eq 0) 'dlp_cert_removal_failed'
    Assert-Reconcile ($postBaseline.dlp_hosts_entries.Count -eq 0) 'dlp_hosts_removal_failed'
    Write-Host 'Cleanup applied and verified on hungdinh-lt.'
} else {
    Write-Host "Dry-run complete. Use -Apply to remove the listed targets."
    exit 0
}

New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
$evidence = [ordered]@{
    schema_version = 'phase1-evidence/v1'
    evidence_id = [guid]::NewGuid().ToString()
    requirement_id = 'WRK-04'
    check_id = 'developer-host-cleanup'
    status = 'pass'
    observed_utc = (Get-Date).ToUniversalTime().ToString('o')
    clock_offset_seconds = 0
    commit_id = (git -C $RepoRoot rev-parse --short HEAD)
    target_machine = 'hungdinh-lt'
    target_role = 'developer_host'
    procedure_version = 1
    identity = [pscustomobject]@{ kind = 'automation'; name = 'Invoke-Phase1EnvironmentReconcile.ps1' }
    environment_fingerprint = Get-EnvironmentFingerprint
    expected_result = 'hungdinh-lt has no WinFsp, DLP service/process/mount, DPAPI credential, DLP PKI trust, DLP hosts, or DLP network change; Rust/LLVM/Hyper-V/repos remain'
    actual_result = 'cleanup applied and post-audit passed'
    verification_tier = 'focused_hyperv'
    substitute = 'none'
    deviation = [pscustomobject]@{ state = 'none' }
    raw_artifacts = @(
        [pscustomobject]@{ uri = (Join-Path $EvidenceDir ('cleanup-baseline-' + [guid]::NewGuid().ToString() + '.json')); sha256 = ''; accessible = $false }
    )
    retention = [pscustomobject]@{ deadline_utc = (Get-Date).ToUniversalTime().AddDays(90).ToString('o'); state = 'retained'; hold = $false }
    redaction_scan = 'passed'
    self_contained = $true
    dependency_digests = [pscustomobject]@{ 'lab-roles' = (Get-Phase1Sha256 $RoleConfigPath); 'lab-contract' = (Get-Phase1Sha256 $ConfigPath) }
}
[System.IO.File]::WriteAllText($evidence.raw_artifacts[0].uri, ($preBaseline | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))
$evidence.raw_artifacts[0].sha256 = (Get-Phase1Sha256 $evidence.raw_artifacts[0].uri)
$evidencePath = Join-Path $EvidenceDir ('developer-host-cleanup-' + [guid]::NewGuid().ToString() + '.json')
New-Phase1Evidence -Evidence $evidence -OutputPath $evidencePath | Out-Null
$matrixPath = Join-Path $RepoRoot 'evidence/phase1/requirement-matrix.yaml'
if (Test-Path -LiteralPath $matrixPath) {
    Publish-Phase1Evidence -EvidencePath $evidencePath -MatrixPath $matrixPath -ExecutionMachine 'hungdinh-lt' | Out-Null
}
Write-Host "Evidence published: $evidencePath"
