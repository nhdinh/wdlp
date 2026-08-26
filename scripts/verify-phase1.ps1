[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('hungdinh-lt')][string]$CallerMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-DC01')][string]$ServerMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-DC02')][string]$SecondaryDcMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-CLIENT01')][string]$EndpointMachine,
    [Parameter(Mandatory)][string]$TrustedRootPath,
    [Parameter(Mandatory)][string]$ReviewerPolicyPath,
    [string]$IndependentReviewerPolicyPath,
    [string]$IndependentReviewerRootPath,
    [string]$IndependentReviewIndexPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $IndependentReviewerPolicyPath) { $IndependentReviewerPolicyPath = Join-Path $repoRoot 'evidence-private/phase1/independent-reviewer-policy.json' }
if (-not $IndependentReviewerRootPath) { $IndependentReviewerRootPath = Join-Path $repoRoot 'evidence-private/phase1/independent-reviewer-root.cer' }
if (-not $IndependentReviewIndexPath) { $IndependentReviewIndexPath = Join-Path $repoRoot 'evidence/phase1/independent-reviews/index.json' }
$evidenceModulePath = Join-Path $repoRoot 'scripts/evidence/Phase1.Evidence.psm1'
$matrixPath = Join-Path $repoRoot 'evidence/phase1/requirement-matrix.yaml'
$configPath = Join-Path $repoRoot 'config/lab.phase1.example.yaml'
$evidencePath = Join-Path $repoRoot 'tests/windows/results/phase1-evidence.json'
$digestPath = Join-Path $repoRoot 'tests/windows/results/phase1-evidence.sha256'
$matrixDigestPath = Join-Path $repoRoot 'tests/windows/results/phase1-matrix.sha256'

# Phase 1 requirement IDs from REQUIREMENTS.md that must be pass with current evidence.
$script:RequiredRequirementIds = @(
    'WRK-01','WRK-02','WRK-03','WRK-04',
    'SRV-01','SRV-03','SRV-11','SRV-12',
    'CRY-01','CRY-02','CRY-04',
    'AGT-01','AGT-02','AGT-03','AGT-04','AGT-05','AGT-06','AGT-07',
    'DRV-01','DRV-02','DRV-03','DRV-04','DRV-06','DRV-07','DRV-09',
    'TST-01','TST-02','TST-03','TST-05','TST-08'
)

$script:MachineRoles = @{
    'hungdinh-lt' = 'developer_orchestrator'
    'LAB-SERVER01' = 'database_server'
    'LAB-DC01' = 'primary_directory_server'
    'LAB-DC02' = 'secondary_directory_server'
    'LAB-CLIENT01' = 'endpoint_runtime'
}

$script:PrivilegedPlanIds = @('01-13','01-14','01-18','01-19','01-15','01-20','01-16','01-21','01-24')

$script:Report = [ordered]@{
    checks = 0
    passed = 0
    failed = 0
    warnings = 0
    requirements_pass = 0
    requirements_fail = @()
    success_criteria_pass = 0
    success_criteria_fail = @()
    decisions_pass = 0
    decisions_fail = @()
    privilege_manifests_pass = 0
    privilege_manifests_fail = @()
    coverage_integrate = 0
    coverage_optout = 0
    coverage_fail = @()
    evidence_bundle_valid = $false
    evidence_hash_valid = $false
    matrix_digest = $null
    sanitization_pass = $false
    independent_review_present = $false
    independent_review_valid = $false
}

function Assert-Phase1 {
    param([Parameter(Mandatory)][bool]$Condition, [Parameter(Mandatory)][string]$Message)
    $script:Report.checks++
    if ($Condition) { $script:Report.passed++ }
    else { $script:Report.failed++; throw $Message }
}

function Warn-Phase1 {
    param([Parameter(Mandatory)][string]$Message)
    $script:Report.checks++
    $script:Report.warnings++
    Write-Warning $Message
}

function Test-Phase1Redaction {
    param([Parameter(Mandatory)][string]$Text)
    $pattern = '(?i)(password\s*[:=]|private[ _-]?key|bearer\s+\S+|api[ _-]?key|secret\s*[:=]|protected\s+plaintext)'
    return ($Text -notmatch $pattern)
}

Import-Module $evidenceModulePath -Force

# 1. Matrix structure and required rows.
Assert-Phase1 (Test-Path -LiteralPath $matrixPath) 'requirement matrix missing'
$matrix = Get-Content -LiteralPath $matrixPath -Raw | ConvertFrom-Json
Assert-Phase1 ($matrix.schema_version -eq 'phase1-requirement-matrix/v1') 'matrix has wrong schema version'
Assert-Phase1 (@($matrix.requirements).Count -eq 32) 'matrix must contain 32 requirement rows (30 Phase 1 + SRV-13 + SRV-14)'
Assert-Phase1 (@($matrix.success_criteria).Count -eq 7) 'matrix must contain 7 success criteria'
Assert-Phase1 (@($matrix.decisions).Count -eq 50) 'matrix must contain D-01 through D-50'

$matrixById = @{}
foreach ($row in $matrix.requirements) { $matrixById[$row.id] = $row }

foreach ($reqId in $script:RequiredRequirementIds) {
    $row = $matrixById[$reqId]
    if ($null -eq $row) {
        $script:Report.requirements_fail += "$reqId missing"
        continue
    }
    if ($row.status -eq 'pass' -and -not [string]::IsNullOrWhiteSpace($row.current_evidence_id)) {
        $script:Report.requirements_pass++
    } else {
        $script:Report.requirements_fail += "$reqId $($row.status)"
    }
}

# Non-required rows are allowed to be unverified, but warn so the report is complete.
foreach ($row in $matrix.requirements) {
    if ($script:RequiredRequirementIds -notcontains $row.id -and $row.status -ne 'pass') {
        Warn-Phase1 "non-required requirement $($row.id) is $($row.status)"
    }
}

foreach ($sc in $matrix.success_criteria) {
    if ($sc.status -eq 'pass' -and -not [string]::IsNullOrWhiteSpace($sc.current_evidence_id)) {
        $script:Report.success_criteria_pass++
    } else {
        $script:Report.success_criteria_fail += "$($sc.id) $($sc.status)"
    }
}

foreach ($decision in $matrix.decisions) {
    if ($decision.status -eq 'pass' -and -not [string]::IsNullOrWhiteSpace($decision.current_evidence_id)) {
        $script:Report.decisions_pass++
    } else {
        $script:Report.decisions_fail += "$($decision.id) $($decision.status)"
    }
}

# 2. Lab config: machine roles, privilege manifests/approvals, visual checklists, review contract.
Assert-Phase1 (Test-Path -LiteralPath $configPath) 'lab config missing'
$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json

foreach ($machine in $script:MachineRoles.Keys) {
    $role = $config.machine_roles.$machine
    Assert-Phase1 ($null -ne $role) "machine role missing for $machine"
    Assert-Phase1 ($role.role -eq $script:MachineRoles[$machine]) "machine role mismatch for $machine"
}

$sourceOnly = @($config.source_only_plans | Where-Object { $_.plan_id -in @('01-22','01-23') -and $_.allowed_mutations.Count -eq 0 -and $_.deployment_owner -eq '01-13' })
Assert-Phase1 ($sourceOnly.Count -eq 2) 'source-only declarations for 01-22/01-23 are missing or invalid'

$visualIds = @($config.visual_checklists | ForEach-Object { $_.id } | Sort-Object -Unique)
$expectedVisual = @('VIS-DRV-PRESENCE','VIS-EXPLORER','VIS-WORD','VIS-EXCEL','VIS-MOUNT-RECOVERY')
foreach ($vis in $expectedVisual) {
    Assert-Phase1 ($visualIds -contains $vis) "visual checklist $vis missing"
}

$reviewFields = @($config.review_contract.required_fields)
Assert-Phase1 ($reviewFields.Count -eq 9) 'review contract required_fields count mismatch'
Assert-Phase1 ($config.review_contract.independent_role -eq 'independent_verifier') 'review contract independent_role mismatch'

foreach ($planId in $script:PrivilegedPlanIds) {
    $result = Test-Phase1PrivilegeManifest -ConfigPath $configPath -PlanId $planId
    if ($result.Valid -and $result.Manifest.machine -in @($script:MachineRoles.Keys)) {
        $script:Report.privilege_manifests_pass++
    } else {
        $script:Report.privilege_manifests_fail += "$planId : $($result.Errors -join '; ')"
    }
    $approval = @($config.privilege_approvals | Where-Object { $_.plan_id -eq $planId })
    if ($approval.Count -ne 1) {
        $script:Report.privilege_manifests_fail += "$planId approval count $($approval.Count)"
    } else {
        if ($approval[0].decision -ne 'approve-listed-digests') {
            $script:Report.privilege_manifests_fail += "$planId approval decision invalid"
        }
        if ($approval[0].manifest_digest -ne $result.Manifest.approval_digest) {
            $script:Report.privilege_manifests_fail += "$planId approval digest mismatch"
        }
    }
}

# 3. COVERAGE.md: every INTEGRATE has a plan and machine role; every OPT-OUT has a reason.
$coveragePath = Join-Path $repoRoot '.planning/phases/01-first-encrypted-drive-vertical-slice/COVERAGE.md'
if (Test-Path -LiteralPath $coveragePath) {
    $coverage = Get-Content -LiteralPath $coveragePath -Raw
    $rows = [regex]::Matches($coverage, '\|\s*(\S+)\s*\|\s*(INTEGRATE|OPT-OUT)\s*\|\s*(.*?)\s*\|') | ForEach-Object {
        [pscustomobject]@{ capability = $_.Groups[1].Value.Trim(); decision = $_.Groups[2].Value.Trim(); reason = $_.Groups[3].Value.Trim() }
    }
    foreach ($row in $rows) {
        if ($row.decision -eq 'INTEGRATE') {
            $script:Report.coverage_integrate++
            $hasPlan = $row.reason -match 'Plan\s+01-\d+'
            $hasDecision = $row.reason -match 'D-\d+'
            if (-not $hasPlan -and -not $hasDecision -and $row.reason.Length -lt 10) {
                $script:Report.coverage_fail += "$($row.capability) INTEGRATE lacks owning plan or decision"
            }
        } else {
            $script:Report.coverage_optout++
            if ($row.reason.Length -lt 10 -or $row.reason -match '^\s*(TBD|TODO|N/A)\s*$') {
                $script:Report.coverage_fail += "$($row.capability) OPT-OUT lacks rationale"
            }
        }
    }
}

# 4. Evidence bundle and hash.
Assert-Phase1 (Test-Path -LiteralPath $evidencePath) 'matrix evidence bundle missing'
Assert-Phase1 (Test-Path -LiteralPath $digestPath) 'matrix evidence digest missing'
$bundle = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json
Assert-Phase1 ($bundle.schema_version -eq 'phase1-evidence/v1') 'evidence bundle has wrong schema version'
Assert-Phase1 ($bundle.execution_machine -eq $EndpointMachine) 'evidence execution_machine mismatch'
Assert-Phase1 ($bundle.caller_machine -eq $CallerMachine) 'evidence caller_machine mismatch'
Assert-Phase1 ($bundle.server_machine -eq $ServerMachine) 'evidence server_machine mismatch'
Assert-Phase1 ($bundle.secondary_dc_machine -eq $SecondaryDcMachine) 'evidence secondary_dc_machine mismatch'
Assert-Phase1 ($bundle.cases.Count -gt 0) 'evidence bundle contains no cases'
$script:Report.evidence_bundle_valid = $true

$expectedHash = (Get-Content -LiteralPath $digestPath -Raw).Trim()
$actualHash = Get-Phase1Sha256 -Path $evidencePath
Assert-Phase1 ($expectedHash -eq $actualHash) "evidence hash mismatch: expected $expectedHash, got $actualHash"
$script:Report.evidence_hash_valid = $true

# 5. Sanitization gate on the bundle.
$bundleJson = $bundle | ConvertTo-Json -Depth 20
$script:Report.sanitization_pass = Test-Phase1Redaction -Text $bundleJson
Assert-Phase1 $script:Report.sanitization_pass 'evidence bundle contains forbidden secret pattern'

# 6. The immutable signed generation/index is the sole authoritative D-48 record.
$reviewResult = Test-Phase1IndependentReview -RepositoryRoot $repoRoot -IndexPath $IndependentReviewIndexPath -ReviewerPolicyPath $IndependentReviewerPolicyPath -ReviewerRootPath $IndependentReviewerRootPath -ArchivalPolicyPath $ReviewerPolicyPath
$script:Report.independent_review_present = [bool]$reviewResult.Present
$script:Report.independent_review_valid = [bool]$reviewResult.Valid
if (-not $reviewResult.Valid) { Warn-Phase1 "independent review invalid: $($reviewResult.Errors -join '; ')" }

# 7. Compute and write final sanitized matrix digest.
$matrixBytes = [System.Text.Encoding]::UTF8.GetBytes((Get-Content -LiteralPath $matrixPath -Raw))
$sha = [System.Security.Cryptography.SHA256]::Create()
try { $matrixDigest = ([System.BitConverter]::ToString($sha.ComputeHash($matrixBytes)) -replace '-', '').ToLowerInvariant() } finally { $sha.Dispose() }
$script:Report.matrix_digest = $matrixDigest
[System.IO.File]::WriteAllText($matrixDigestPath, "$matrixDigest  phase1-requirement-matrix`n", (New-Object System.Text.UTF8Encoding($false)))

# 8. Authenticated security closure subgate. This must pass before FinalGate can pass.
$securityVerifier = Join-Path $repoRoot 'scripts/verify-phase1-security.ps1'
$closurePath = Join-Path $repoRoot 'evidence/phase1/security-closure.yaml'
$securityJson = & powershell -NoProfile -ExecutionPolicy Bypass -File $securityVerifier -ClosurePath $closurePath -TrustedRootPath $TrustedRootPath -ReviewerPolicyPath $ReviewerPolicyPath -RequireSignedOff -DiagnosticFormat Json
$securityExit = $LASTEXITCODE
if ($securityExit -ne 0) { throw "authenticated security subgate failed ($securityExit): $securityJson" }
$securityResult = $securityJson | ConvertFrom-Json
Write-Host "Security manifest digest : $($securityResult.manifest_digest)"
Write-Host "Reviewer policy identity: $($securityResult.reviewer_policy_identity)"

# 9. Report.
Write-Host "`n=== Phase 1 Final Verifier Report ==="
Write-Host "Checks run        : $($script:Report.checks)"
Write-Host "Passed            : $($script:Report.passed)"
Write-Host "Failed            : $($script:Report.failed)"
Write-Host "Warnings          : $($script:Report.warnings)"
Write-Host "Requirements pass : $($script:Report.requirements_pass)/$($script:RequiredRequirementIds.Count)"
if ($script:Report.requirements_fail.Count -gt 0) { Write-Host "Requirements fail : $($script:Report.requirements_fail -join ', ')" }
Write-Host "Success criteria  : $($script:Report.success_criteria_pass)/7"
if ($script:Report.success_criteria_fail.Count -gt 0) { Write-Host "Success criteria fail : $($script:Report.success_criteria_fail -join ', ')" }
Write-Host "Decisions         : $($script:Report.decisions_pass)/50"
if ($script:Report.decisions_fail.Count -gt 0) { Write-Host "Decisions fail    : $($script:Report.decisions_fail -join ', ')" }
Write-Host "Privilege manifests: $($script:Report.privilege_manifests_pass)/$($script:PrivilegedPlanIds.Count)"
if ($script:Report.privilege_manifests_fail.Count -gt 0) { Write-Host "Privilege manifest fail: $($script:Report.privilege_manifests_fail -join '; ')" }
Write-Host "Coverage INTEGRATE: $($script:Report.coverage_integrate); OPT-OUT: $($script:Report.coverage_optout)"
if ($script:Report.coverage_fail.Count -gt 0) { Write-Host "Coverage fail     : $($script:Report.coverage_fail -join '; ')" }
Write-Host "Evidence bundle   : $($script:Report.evidence_bundle_valid)"
Write-Host "Evidence hash     : $($script:Report.evidence_hash_valid)"
Write-Host "Sanitization      : $($script:Report.sanitization_pass)"
Write-Host "Independent review: present=$($script:Report.independent_review_present) valid=$($script:Report.independent_review_valid)"
Write-Host "Matrix digest     : $matrixDigest"
Write-Host "Matrix digest file: $matrixDigestPath"

$overall = (
    $script:Report.failed -eq 0 -and
    $script:Report.requirements_fail.Count -eq 0 -and
    $script:Report.success_criteria_fail.Count -eq 0 -and
    $script:Report.decisions_fail.Count -eq 0 -and
    $script:Report.privilege_manifests_fail.Count -eq 0 -and
    $script:Report.coverage_fail.Count -eq 0 -and
    $script:Report.evidence_bundle_valid -and
    $script:Report.evidence_hash_valid -and
    $script:Report.sanitization_pass -and
    $script:Report.independent_review_present -and
    $script:Report.independent_review_valid
)

if ($overall) {
    Write-Host "`nverify-phase1: FinalGate PASSED"
    exit 0
} else {
    Write-Host "`nverify-phase1: FinalGate FAILED (see report above)"
    exit 1
}
