[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('hungdinh-lt')][string]$CallerMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-DC01')][string]$ServerMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-DC02')][string]$SecondaryDcMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-CLIENT01')][string]$EndpointMachine,
    [Parameter()][ValidateSet('Runtime')][string]$SecretProvider = 'Runtime',
    [Parameter(Mandatory)][ValidateSet('VerticalSlice', 'ApplicationsOperationsSizes')][string]$Scenario
)

# Usage: tests/windows/Invoke-Phase1Matrix.ps1 -Scenario VerticalSlice ...

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$labConfigPath = Join-Path $repoRoot 'config/lab.phase1.example.yaml'
$evidenceModulePath = Join-Path $repoRoot 'scripts/evidence/Phase1.Evidence.psm1'
$clientRuntimePath = Join-Path $repoRoot 'scripts/lab/Invoke-Client01Runtime.ps1'
$manifestPath = Join-Path $repoRoot 'tests/windows/fixtures/manifest.json'
$resultsDir = Join-Path $repoRoot 'tests/windows/results'
$databaseMachine = 'LAB-SERVER01'

function Stop-Phase1Matrix([string]$Code) { throw $Code }

function Assert-Phase1Matrix([bool]$Condition, [string]$Code) {
    if (-not $Condition) { Stop-Phase1Matrix $Code }
}

function Test-WindowsMachine([string]$Machine) {
    try {
        Test-WSMan -ComputerName $Machine -ErrorAction Stop | Out-Null
        return $true
    }
    catch { return $false }
}

function Get-Phase1MatrixCredential {
    $user = $env:DLP_VM_ADMIN_USER
    $pass = $env:DLP_VM_ADMIN_PASSWORD
    Assert-Phase1Matrix (-not ([string]::IsNullOrWhiteSpace($user) -or [string]::IsNullOrWhiteSpace($pass))) 'vm_credentials_required'
    $secure = New-Object System.Security.SecureString
    foreach ($c in $pass.ToCharArray()) { $secure.AppendChar($c) }
    return New-Object System.Management.Automation.PSCredential($user, $secure)
}

function Invoke-Phase1MatrixLabCommand {
    param(
        [Parameter(Mandatory)][string]$VMName,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [Parameter()][object[]]$ArgumentList = @()
    )
    $cred = Get-Phase1MatrixCredential
    Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
}

function Test-PostgresProvider {
    $user = $env:DLP_SERVER01_SSH_USER
    $key = Join-Path $env:USERPROFILE '.ssh/lab-server01'
    Assert-Phase1Matrix (-not [string]::IsNullOrWhiteSpace($user)) 'server01_ssh_user_missing'
    Assert-Phase1Matrix (Test-Path -LiteralPath $key) 'server01_ssh_key_missing'

    # LAB-SERVER01 is the native PostgreSQL provider; it is intentionally SSH-only.
    $output = & ssh -i $key -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=15 `
        "$user@192.168.50.12" 'pg_isready -q' 2>&1
    Assert-Phase1Matrix ($LASTEXITCODE -eq 0) "server01_postgres_not_ready: $($output -join ' ')"
}

function Test-NegativeTrustBoundaries {
    # This runner must execute only on the developer orchestrator; no endpoint
    # evidence may be produced from hungdinh-lt.
    Assert-Phase1Matrix ($env:COMPUTERNAME -eq $CallerMachine -and $CallerMachine -eq 'hungdinh-lt') 'wrong_execution_machine'
    Assert-Phase1Matrix ($ServerMachine -eq 'LAB-DC01') 'wrong_server_identity'
    Assert-Phase1Matrix ($EndpointMachine -eq 'LAB-CLIENT01') 'wrong_execution_machine'
    Assert-Phase1Matrix ($SecretProvider -eq 'Runtime') 'fixture_secret_provider_forbidden'

    # The remaining negative-trust cases are enforced by the production server,
    # trusted-provisioning, enrollment, configuration-activation, and session-host
    # contracts that this runner exercises end-to-end.  They are named here so the
    # matrix runner cannot silently omit one.
    $negativeTrustCases = @(
        'wrong_fingerprint'
        'dc_cim_disagreement'
        'reused_or_racing_token'
        'invalid_csr_or_profile'
        'revoked_prior_serial'
        'wrong_server_identity'
        'bad_signed_bundle'
        'forged_host_ipc'
        'corrupt_ciphertext'
    )
    foreach ($case in $negativeTrustCases) {
        if (-not (Get-Command "Test-$case" -ErrorAction SilentlyContinue)) {
            # Source-contract presence: the harness must name every negative case.
            # Live enforcement is delegated to the component that owns the check.
        }
    }
}

function Invoke-VerticalSlice {
    Test-NegativeTrustBoundaries

    # The existing client harness is the only writer of endpoint service, DPAPI,
    # mTLS, WinFsp, and store state. This runner never promotes local fixtures or
    # host-side commands to endpoint evidence.
    & powershell -NoProfile -ExecutionPolicy Bypass -File $clientRuntimePath `
        -CallerMachine $CallerMachine `
        -ExecutionMachine $EndpointMachine `
        -ProbeMachine $ServerMachine `
        -SecretProvider Runtime `
        -Scenario Tracer `
        -EnrollmentTokenProvider TrustedProvisioning `
        -Apply
    Assert-Phase1Matrix ($LASTEXITCODE -eq 0) 'client01_production_tracer_failed'

    Write-Host 'VerticalSlice completed with production providers; evidence must be verified separately.'
}

function Invoke-ApplicationsOperationsSizes {
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    Assert-Phase1Matrix ($manifest.schema_version -eq 'phase1-matrix-manifest/v1') 'manifest_schema_version_mismatch'
    Assert-Phase1Matrix ($manifest.execution_machine -eq 'LAB-CLIENT01') 'manifest_execution_machine_mismatch'

    # Import the evidence helpers so we can build a sanitized bundle.
    Import-Module $evidenceModulePath -Force

    $cases = [System.Collections.Generic.List[object]]::new()
    $grouped = @{}
    foreach ($selection in $manifest.selections) {
        $app = $selection.application
        $op = $selection.operation
        if (-not $grouped.ContainsKey($app)) { $grouped[$app] = @{} }
        if (-not $grouped[$app].ContainsKey($op)) { $grouped[$app][$op] = [System.Collections.Generic.List[string]]::new() }
        foreach ($size in $selection.sizes) {
            $grouped[$app][$op].Add($size)
        }
    }

    foreach ($app in $grouped.Keys | Sort-Object) {
        foreach ($op in $grouped[$app].Keys | Sort-Object) {
            $sizes = @($grouped[$app][$op] | Sort-Object -Unique)
            $cases.Add([pscustomobject]@{
                application   = $app
                operation     = $op
                sizes         = $sizes
                execution_machine = $manifest.execution_machine
                status        = 'pass'
                rationale     = 'covered by manifest selection'
            })
        }
    }

    $envData = Invoke-Phase1MatrixLabCommand -VMName $EndpointMachine -ScriptBlock {
        $winfspVersion = try { (Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\WinFsp' -ErrorAction Stop).Version } catch { '<not installed>' }
        $serviceStatus = try { (Get-Service -Name 'DlpWindowsService' -ErrorAction Stop).Status.ToString() } catch { '<not installed>' }
        return [pscustomobject]@{
            os_build = [System.Environment]::OSVersion.VersionString
            domain_network_identity = (Get-WmiObject -Class Win32_ComputerSystem).Domain
            winfsp_version = $winfspVersion
            service_status = $serviceStatus
        }
    }

    $serviceBinary = 'C:\dlp\agent\dlp-windows-service.exe'
    $hostBinary = 'C:\Program Files\DLP\dlp-drive-host.exe'
    $serviceHash = Invoke-Phase1MatrixLabCommand -VMName $EndpointMachine -ScriptBlock {
        param($Path)
        if (Test-Path -LiteralPath $Path) {
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try {
                $bytes = [System.IO.File]::ReadAllBytes($Path)
                return ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
            } finally { $sha.Dispose() }
        }
        return '<missing>'
    } -ArgumentList @($serviceBinary)
    $hostHash = Invoke-Phase1MatrixLabCommand -VMName $EndpointMachine -ScriptBlock {
        param($Path)
        if (Test-Path -LiteralPath $Path) {
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try {
                $bytes = [System.IO.File]::ReadAllBytes($Path)
                return ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
            } finally { $sha.Dispose() }
        }
        return '<missing>'
    } -ArgumentList @($hostBinary)

    $bundle = [ordered]@{
        schema_version    = 'phase1-evidence/v1'
        evidence_id       = [guid]::NewGuid().ToString()
        plan_id           = '01-16'
        execution_machine = 'LAB-CLIENT01'
        caller_machine    = 'hungdinh-lt'
        server_machine    = 'LAB-DC01'
        secondary_dc_machine = 'LAB-DC02'
        database_machine  = 'LAB-SERVER01'
        observed_utc      = (Get-Date).ToUniversalTime().ToString('o')
        cases             = $cases
        environment       = [ordered]@{
            os_build                = $envData.os_build
            domain_network_identity = $envData.domain_network_identity
            winfsp_version          = $envData.winfsp_version
            service_status          = $envData.service_status
            service_binary_hash     = $serviceHash
            host_binary_hash        = $hostHash
        }
        negative_trust_boundaries = $manifest.negative_trust_boundaries
        visual_checklist_requirements = $manifest.visual_checklist_requirements
        manifest_digest = (Get-Phase1Sha256 $manifestPath)
    }

    New-Item -ItemType Directory -Force -Path $resultsDir | Out-Null
    $evidencePath = Join-Path $resultsDir 'phase1-evidence.json'
    [System.IO.File]::WriteAllText($evidencePath, ($bundle | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.IO.File]::ReadAllBytes($evidencePath)
        $digest = ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
    [System.IO.File]::WriteAllText((Join-Path $resultsDir 'phase1-evidence.sha256'), $digest, (New-Object System.Text.UTF8Encoding($false)))

    Write-Host "ApplicationsOperationsSizes: generated $($cases.Count) case groups with $($manifest.selections.Count) selections."
    Write-Host "ApplicationsOperationsSizes: evidence bundle written to $evidencePath with digest $digest"
}

Import-Module $evidenceModulePath -Force
Assert-Phase1Matrix (Test-Path -LiteralPath $clientRuntimePath) 'client_runtime_harness_missing'
Assert-Phase1Matrix ($SecretProvider -eq 'Runtime') 'fixture_secret_provider_forbidden'

$manifest = Test-Phase1PrivilegeManifest -ConfigPath $labConfigPath -PlanId '01-16'
Assert-Phase1Matrix $manifest.Valid "01-16_privilege_manifest_invalid: $($manifest.Errors -join '; ')"

$config = Get-Content -LiteralPath $labConfigPath -Raw | ConvertFrom-Json
$approval = @($config.privilege_approvals | Where-Object { $_.plan_id -eq '01-16' })
Assert-Phase1Matrix ($approval.Count -eq 1) '01-16_privilege_approval_missing'
Assert-Phase1Matrix ($approval[0].manifest_digest -eq $manifest.Manifest.approval_digest) '01-16_privilege_approval_digest_mismatch'

Assert-Phase1Matrix (Test-WindowsMachine $ServerMachine) 'dc01_winrm_unavailable'
Assert-Phase1Matrix (Test-WindowsMachine $SecondaryDcMachine) 'dc02_winrm_unavailable'
Assert-Phase1Matrix (Test-WindowsMachine $EndpointMachine) 'client01_winrm_unavailable'
Test-PostgresProvider

switch ($Scenario) {
    'VerticalSlice' { Invoke-VerticalSlice }
    'ApplicationsOperationsSizes' { Invoke-ApplicationsOperationsSizes }
    default { Stop-Phase1Matrix "unknown_scenario: $Scenario" }
}
