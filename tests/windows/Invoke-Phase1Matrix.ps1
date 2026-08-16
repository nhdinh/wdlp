[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('hungdinh-lt')][string]$CallerMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-DC01')][string]$ServerMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-DC02')][string]$SecondaryDcMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-CLIENT01')][string]$EndpointMachine,
    [Parameter()][ValidateSet('Runtime')][string]$SecretProvider = 'Runtime',
    [Parameter(Mandatory)][ValidateSet('VerticalSlice')][string]$Scenario
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$labConfigPath = Join-Path $repoRoot 'config/lab.phase1.example.yaml'
$evidenceModulePath = Join-Path $repoRoot 'scripts/evidence/Phase1.Evidence.psm1'
$clientRuntimePath = Join-Path $repoRoot 'scripts/lab/Invoke-Client01Runtime.ps1'
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
