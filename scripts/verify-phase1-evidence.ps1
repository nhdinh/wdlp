[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('hungdinh-lt', 'LAB-DC01', 'LAB-DC02', 'LAB-CLIENT01')][string]$ExecutionMachine,
    [Parameter(Mandatory)][ValidateSet('PortableTracer', 'ContractFixtures', 'ContractsAndPrivileges', 'PrivilegeApprovals')][string]$Scenario
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'scripts/evidence/Phase1.Evidence.psm1') -Force
$manifestPath = Join-Path $repoRoot 'evidence/phase1/manifests/tst-01-portable-policy.json'
$matrixPath = Join-Path $repoRoot 'evidence/phase1/requirement-matrix.yaml'
$configPath = Join-Path $repoRoot 'config/lab.phase1.example.yaml'

function Assert-Phase1 {
    param([Parameter(Mandatory)][bool]$Condition, [Parameter(Mandatory)][string]$Message)
    if (-not $Condition) { throw $Message }
}

function Write-Phase1Fixture {
    param([Parameter(Mandatory)]$Value, [Parameter(Mandatory)][string]$Path)
    [System.IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))
}

function Invoke-PortableTracer {
    Assert-Phase1 (Test-Path -LiteralPath $manifestPath) 'portable evidence manifest is missing'
    Assert-Phase1 (Test-Path -LiteralPath $matrixPath) 'requirement matrix is missing'
    $schema = Get-Content -LiteralPath (Join-Path $repoRoot 'evidence/phase1/schema/evidence-manifest.schema.json') -Raw | ConvertFrom-Json
    Assert-Phase1 ($schema.properties.schema_version.const -eq 'phase1-evidence/v1') 'evidence schema is not versioned'
    $result = Test-Phase1Evidence -EvidencePath $manifestPath -ExecutionMachine $ExecutionMachine
    Assert-Phase1 $result.Valid "portable evidence is invalid: $($result.Errors -join '; ')"
    $matrix = Get-Content -LiteralPath $matrixPath -Raw | ConvertFrom-Json
    $row = @($matrix.requirements | Where-Object { $_.id -eq 'TST-01' })
    Assert-Phase1 ($row.Count -eq 1 -and $row[0].current_evidence_id -eq $result.Evidence.evidence_id -and $row[0].status -eq 'pass') 'TST-01 matrix linkage is not current'
}

function Invoke-ContractFixtures {
    Invoke-PortableTracer
    $temp = Join-Path $repoRoot ('target/phase1-evidence/fixtures-' + [guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Force -Path $temp | Out-Null
    try {
        $base = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $valid = Join-Path $temp 'valid.json'
        Write-Phase1Fixture $base $valid
        Assert-Phase1 (Test-Phase1Evidence -EvidencePath $valid -ExecutionMachine 'hungdinh-lt').Valid 'baseline fixture must validate'

        $duplicate = Test-Phase1Evidence -EvidencePath $valid -ExecutionMachine 'hungdinh-lt' -ExistingEvidencePaths @($manifestPath)
        Assert-Phase1 (-not $duplicate.Valid -and $duplicate.Errors -match 'reused evidence ID') 'duplicate evidence ID was accepted'
        $bad = Get-Content $valid -Raw | ConvertFrom-Json; $bad.PSObject.Properties.Remove('procedure_version'); $path = Join-Path $temp 'missing.json'; Write-Phase1Fixture $bad $path
        Assert-Phase1 (-not (Test-Phase1Evidence -EvidencePath $path).Valid) 'missing required field was accepted'
        $bad = Get-Content $valid -Raw | ConvertFrom-Json; $bad.raw_artifacts[0].sha256 = ('0' * 64); $path = Join-Path $temp 'hash.json'; Write-Phase1Fixture $bad $path
        Assert-Phase1 (-not (Test-Phase1Evidence -EvidencePath $path).Valid) 'hash mismatch was accepted'
        $bad = Get-Content $valid -Raw | ConvertFrom-Json; $bad.clock_offset_seconds = 301; $path = Join-Path $temp 'skew.json'; Write-Phase1Fixture $bad $path
        Assert-Phase1 (-not (Test-Phase1Evidence -EvidencePath $path).Valid) 'excessive clock skew was accepted'
        $bad = Get-Content $valid -Raw | ConvertFrom-Json; $bad.expected_result = 'password=forbidden'; $path = Join-Path $temp 'secret.json'; Write-Phase1Fixture $bad $path
        Assert-Phase1 (-not (Test-Phase1Evidence -EvidencePath $path).Valid) 'secret-bearing evidence was accepted'
        $bad = Get-Content $valid -Raw | ConvertFrom-Json; $bad.deviation.state = 'recorded'; $path = Join-Path $temp 'deviation.json'; Write-Phase1Fixture $bad $path
        Assert-Phase1 (-not (Test-Phase1Evidence -EvidencePath $path).Valid) 'unreviewed deviation was accepted as pass'
        $wrongMachine = Test-Phase1Evidence -EvidencePath $valid -ExecutionMachine 'LAB-CLIENT01'
        Assert-Phase1 (-not $wrongMachine.Valid -and $wrongMachine.Errors -match 'wrong execution machine') 'wrong machine was accepted'

        $failed = Get-Content $valid -Raw | ConvertFrom-Json; $failed.evidence_id = [guid]::NewGuid().ToString(); $failed.status = 'fail'; $failed.actual_result = 'first attempt failed'; $failedPath = Join-Path $temp 'failed.json'; Write-Phase1Fixture $failed $failedPath
        Assert-Phase1 (Test-Phase1Evidence -EvidencePath $failedPath -ExecutionMachine 'hungdinh-lt').Valid 'failed attempt is not retained as valid evidence'
        $rerun = Get-Content $valid -Raw | ConvertFrom-Json; $rerun.evidence_id = [guid]::NewGuid().ToString(); $rerun | Add-Member -NotePropertyName prior_attempt_id -NotePropertyValue $failed.evidence_id; $rerun | Add-Member -NotePropertyName supersedes_evidence_id -NotePropertyValue $failed.evidence_id; $rerun | Add-Member -NotePropertyName remediation_commit -NotePropertyValue '8eea2174cd3585eb0bce30990b09fce899ddc2c2'; $rerun.dependency_digests = [pscustomobject]@{ 'policy-source' = 'baseline' }; $rerunPath = Join-Path $temp 'rerun.json'; Write-Phase1Fixture $rerun $rerunPath
        $copiedMatrix = Join-Path $temp 'matrix.json'; Copy-Item -LiteralPath $matrixPath -Destination $copiedMatrix
        Publish-Phase1Evidence -EvidencePath $rerunPath -MatrixPath $copiedMatrix -ExecutionMachine 'hungdinh-lt' | Out-Null
        $published = Get-Content $copiedMatrix -Raw | ConvertFrom-Json; $changed = @($published.requirements | Where-Object { $_.id -eq 'TST-01' })[0]
        Assert-Phase1 ($changed.current_evidence_id -eq $rerun.evidence_id -and $changed.status -eq 'pass') 'rerun did not update only its matrix pointer'
        Assert-Phase1 ((Resolve-Phase1EvidenceStatus -EvidencePath $rerunPath -CurrentDependencyDigests @{ 'policy-source' = 'changed' }).Status -eq 'stale') 'changed dependency did not stale evidence'
        Assert-Phase1 ((Resolve-Phase1EvidenceStatus -EvidencePath $rerunPath -CurrentDependencyDigests @{ 'unrelated' = 'changed' }).Status -eq 'pass') 'unrelated dependency incorrectly staled evidence'
    }
    finally { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
}

function Invoke-ContractsAndPrivileges {
    Invoke-ContractFixtures
    $matrix = Get-Content -LiteralPath $matrixPath -Raw | ConvertFrom-Json
    Assert-Phase1 (@($matrix.requirements).Count -eq 30) 'matrix must contain all 30 Phase 1 requirements'
    Assert-Phase1 (@($matrix.success_criteria).Count -eq 7) 'matrix must contain all seven success criteria'
    Assert-Phase1 (@($matrix.decisions).Count -eq 50) 'matrix must contain D-01 through D-50'
    Assert-Phase1 ((@($matrix.requirements | Where-Object { $_.current_evidence_id -ne '' }).Count) -eq 1) 'matrix contains synthetic current evidence'
    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    Assert-Phase1 (@($config.source_only_plans).Count -eq 2) '01-22/01-23 source-only declarations are missing'
    foreach ($plan in @('01-13', '01-14', '01-18', '01-19', '01-15', '01-20', '01-16', '01-21')) {
        $result = Test-Phase1PrivilegeManifest -ConfigPath $configPath -PlanId $plan
        Assert-Phase1 $result.Valid "privilege manifest failed for ${plan}: $($result.Errors -join '; ')"
    }
    Assert-Phase1 (@($config.visual_checklists | Where-Object { $_.machine -eq 'LAB-CLIENT01' }).Count -eq 5) 'LAB-CLIENT01 visual contract is incomplete'
    Assert-Phase1 (@($config.review_contract.required_fields).Count -eq 9) 'independent review contract is incomplete'
}

switch ($Scenario) {
    'PortableTracer' { Invoke-PortableTracer }
    'ContractFixtures' { Invoke-ContractFixtures }
    'ContractsAndPrivileges' { Invoke-ContractsAndPrivileges }
    'PrivilegeApprovals' { throw 'Privilege approvals are intentionally blocking until an authenticated operator records each exact manifest digest.' }
}
