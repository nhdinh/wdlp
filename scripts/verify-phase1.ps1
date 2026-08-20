[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('hungdinh-lt')][string]$CallerMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-DC01')][string]$ServerMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-DC02')][string]$SecondaryDcMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-CLIENT01')][string]$EndpointMachine,
    [Parameter()][ValidateSet('AbruptLossRecovery','FinalGate','ContractsAndPrivileges')][string]$Scenario = 'FinalGate'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$evidenceModulePath = Join-Path $repoRoot 'scripts/evidence/Phase1.Evidence.psm1'
$matrixPath = Join-Path $repoRoot 'evidence/phase1/requirement-matrix.yaml'
$configPath = Join-Path $repoRoot 'config/lab.phase1.example.yaml'
$evidencePath = Join-Path $repoRoot 'tests/windows/results/phase1-evidence.json'
$digestPath = Join-Path $repoRoot 'tests/windows/results/phase1-evidence.sha256'

function Assert-Phase1 {
    param([Parameter(Mandatory)][bool]$Condition, [Parameter(Mandatory)][string]$Message)
    if (-not $Condition) { throw $Message }
}

function Import-Phase1EvidenceModule {
    Assert-Phase1 (Test-Path -LiteralPath $evidenceModulePath) 'evidence module missing'
    Import-Module $evidenceModulePath -Force
}

function Test-EvidenceHash {
    Assert-Phase1 (Test-Path -LiteralPath $evidencePath) 'evidence bundle missing'
    Assert-Phase1 (Test-Path -LiteralPath $digestPath) 'evidence digest missing'
    $expected = (Get-Content -LiteralPath $digestPath -Raw).Trim()
    $actual = (Get-Phase1Sha256 $evidencePath)
    Assert-Phase1 ($expected -eq $actual) 'evidence hash mismatch'
}

function Invoke-AbruptLossRecovery {
    Assert-Phase1 ($CallerMachine -eq 'hungdinh-lt') 'AbruptLossRecovery verifier must run on hungdinh-lt'
    Test-EvidenceHash
    $bundle = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json
    Assert-Phase1 ($bundle.schema_version -eq 'phase1-evidence/v1') 'wrong evidence schema version'
    Assert-Phase1 ($bundle.execution_machine -eq 'LAB-CLIENT01') 'evidence must originate from LAB-CLIENT01'
    Assert-Phase1 ($bundle.caller_machine -eq 'hungdinh-lt') 'evidence caller must be hungdinh-lt'
    Assert-Phase1 ($bundle.abrupt_loss_cases) 'no abrupt_loss_cases section'
    Assert-Phase1 ($bundle.abrupt_loss_cases.Count -ge 1) 'abrupt_loss_cases is empty'

    $requiredScenarios = @('CleanServiceRestart','WindowsReboot','ForcedTerminationDuringActiveWrite','HostControlledAbruptLoss')
    $found = @($bundle.abrupt_loss_cases | ForEach-Object { $_.scenario } | Sort-Object -Unique)
    foreach ($req in $requiredScenarios) {
        Assert-Phase1 ($found -contains $req) "missing abrupt-loss scenario: $req"
    }

    foreach ($case in $bundle.abrupt_loss_cases) {
        Assert-Phase1 ($case.status -in @('pass','blocked','fail')) "invalid case status in $($case.scenario)"
        Assert-Phase1 (-not [string]::IsNullOrWhiteSpace($case.rationale)) "missing rationale in $($case.scenario)"
        Assert-Phase1 ($case.execution_machine -eq 'LAB-CLIENT01') "wrong execution machine in $($case.scenario)"
        if ($case.scenario -eq 'HostControlledAbruptLoss') {
            Assert-Phase1 ($case.host_command -match 'Stop-VM' -and $case.host_command -match '-TurnOff') 'abrupt-loss case must record a host Stop-VM -TurnOff command'
            Assert-Phase1 ($case.graceful_shutdown_observed -eq $false) 'abrupt-loss case observed a graceful shutdown substitute'
        }
        if ($case.status -eq 'pass') {
            Assert-Phase1 ($case.rationale -notmatch 'partial|mixed|corrupted') "passing case indicates partial/mixed recovery in $($case.scenario)"
        }
    }

    $failures = @($bundle.abrupt_loss_cases | Where-Object { $_.status -eq 'fail' })
    Assert-Phase1 ($failures.Count -eq 0) "abrupt-loss failures: $($failures.scenario -join ', ')"
}

function Invoke-ContractsAndPrivileges {
    Assert-Phase1 (Test-Path -LiteralPath $matrixPath) 'requirement matrix missing'
    Assert-Phase1 (Test-Path -LiteralPath $configPath) 'lab config missing'

    $matrix = Get-Content -LiteralPath $matrixPath -Raw | ConvertFrom-Json
    Assert-Phase1 (@($matrix.requirements).Count -eq 32) 'matrix must contain 32 Phase 1 requirements'
    Assert-Phase1 (@($matrix.success_criteria).Count -eq 7) 'matrix must contain 7 success criteria'
    Assert-Phase1 (@($matrix.decisions).Count -eq 50) 'matrix must contain D-01 through D-50'

    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    foreach ($plan in @('01-13','01-14','01-18','01-19','01-15','01-20','01-16','01-21','01-24')) {
        $result = Test-Phase1PrivilegeManifest -ConfigPath $configPath -PlanId $plan
        Assert-Phase1 $result.Valid "privilege manifest invalid for ${plan}: $($result.Errors -join '; ')"
        $approval = @($config.privilege_approvals | Where-Object { $_.plan_id -eq $plan })
        Assert-Phase1 ($approval.Count -eq 1) "missing or duplicate approval for $plan"
        Assert-Phase1 ($approval[0].manifest_digest -eq $result.Manifest.approval_digest) "approval digest does not bind manifest for $plan"
    }
}

function Invoke-FinalGate {
    Assert-Phase1 ($CallerMachine -eq 'hungdinh-lt') 'FinalGate verifier must run on hungdinh-lt'
    Invoke-ContractsAndPrivileges
    Test-EvidenceHash

    $matrix = Get-Content -LiteralPath $matrixPath -Raw | ConvertFrom-Json
    $bundle = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json

    # All required rows must be passing and current.
    foreach ($row in @($matrix.requirements)) {
        Assert-Phase1 ($row.status -eq 'pass') "requirement $($row.id) is not pass"
        Assert-Phase1 (-not [string]::IsNullOrWhiteSpace($row.current_evidence_id)) "requirement $($row.id) has no current evidence"
    }
    foreach ($sc in @($matrix.success_criteria)) {
        Assert-Phase1 ($sc.status -eq 'pass') "success criterion $($sc.id) is not pass"
        Assert-Phase1 (-not [string]::IsNullOrWhiteSpace($sc.current_evidence_id)) "success criterion $($sc.id) has no current evidence"
    }
    foreach ($decision in @($matrix.decisions)) {
        Assert-Phase1 ($decision.status -eq 'pass') "decision $($decision.id) is not pass"
        Assert-Phase1 (-not [string]::IsNullOrWhiteSpace($decision.current_evidence_id)) "decision $($decision.id) has no current evidence"
    }

    # Independent phase-exit review must be present and bound to the current matrix digest.
    Assert-Phase1 ($bundle.independent_review) 'independent review record missing'
    $review = $bundle.independent_review
    Assert-Phase1 ($review.authenticated_identity.kind -eq 'independent_verifier') 'reviewer is not independent'
    Assert-Phase1 (-not [string]::IsNullOrWhiteSpace($review.matrix_digest)) 'review missing matrix digest'
    $matrixBytes = [System.Text.Encoding]::UTF8.GetBytes((Get-Content -LiteralPath $matrixPath -Raw))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $matrixDigest = ([System.BitConverter]::ToString($sha.ComputeHash($matrixBytes)) -replace '-', '').ToLowerInvariant() } finally { $sha.Dispose() }
    Assert-Phase1 ($review.matrix_digest -eq $matrixDigest) 'review matrix digest does not match current matrix'

    # Sanitization gate
    $json = $bundle | ConvertTo-Json -Depth 20
    Assert-Phase1 ($json -notmatch '(?i)password\s*[:=]|private[ _-]?key|bearer\s+\S+|api[ _-]?key|secret\s*[:=]|protected\s+plaintext') 'evidence contains forbidden secret pattern'
}

Import-Phase1EvidenceModule

switch ($Scenario) {
    'AbruptLossRecovery' { Invoke-AbruptLossRecovery }
    'FinalGate' { Invoke-FinalGate }
    'ContractsAndPrivileges' { Invoke-ContractsAndPrivileges }
    default { throw "unknown scenario: $Scenario" }
}

Write-Host "verify-phase1: $Scenario passed"
