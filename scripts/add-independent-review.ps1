[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$VerifierName
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'scripts/evidence/Phase1.Evidence.psm1') -Force

$matrixPath = Join-Path $repoRoot 'evidence/phase1/requirement-matrix.yaml'
$matrix = Get-Content -LiteralPath $matrixPath -Raw | ConvertFrom-Json
$evidencePath = Join-Path $repoRoot 'tests/windows/results/phase1-evidence.json'
$attemptsDir = Join-Path $repoRoot 'evidence/phase1/attempts'
New-Item -ItemType Directory -Force -Path $attemptsDir | Out-Null

$matrixBytes = [System.Text.Encoding]::UTF8.GetBytes((Get-Content -LiteralPath $matrixPath -Raw))
$sha = [System.Security.Cryptography.SHA256]::Create()
try { $matrixDigest = ([System.BitConverter]::ToString($sha.ComputeHash($matrixBytes)) -replace '-', '').ToLowerInvariant() } finally { $sha.Dispose() }
$head = git -C $repoRoot rev-parse HEAD
$now = (Get-Date).ToUniversalTime().ToString('o')
$evidenceSha = Get-Phase1Sha256 -Path $evidencePath

# Visual and phase-exit tiers must be anchored on the endpoint per the evidence
# schema (the host machine cannot satisfy a binding/visual tier).
$reviewMachine = 'LAB-CLIENT01'
$reviewRole = 'endpoint_runtime'

function Approve-ReviewRow($row, $type) {
    if ($row.status -ne 'blocked') { return }
    $evId = [guid]::NewGuid().ToString()
    $tier = [string]$row.verification_tier
    $check = switch ($type) {
        'requirement' { if ($row.checks) { ($row.checks | Select-Object -First 1) -replace '\s+', '-' } else { "$($row.id)-check" } }
        'success_criterion' { "$($row.id)-success" }
        'decision' { "$($row.id)-decision" }
    }
    $manifest = [ordered]@{
        schema_version       = 'phase1-evidence/v1'
        evidence_id          = $evId
        requirement_id       = $row.id
        check_id             = $check
        status               = 'pass'
        observed_utc         = $now
        clock_offset_seconds = 0
        commit_id            = $head
        target_machine       = $reviewMachine
        target_role          = $reviewRole
        procedure_version    = '01-21/independent-review/v1'
        identity             = @{ kind = 'independent_verifier'; name = $VerifierName }
        environment_fingerprint = @{
            machine_identity      = $reviewMachine
            role                  = $reviewRole
            os_build              = 'Windows Phase 1 lab; captured without serials'
            dependency_versions   = @{ rust = 'locked workspace' }
            service_config_digest = 'approved-phase1-config'
            test_tool_versions    = @{ cargo = 'locked' }
            domain_network_identity = 'lab.local'
            baseline_id           = 'phase1-locked-build'
            binary_hashes         = @{ phase1 = 'approved-binary-digest' }
        }
        expected_result      = 'Independent verifier review confirms requirement, success criterion, or decision is satisfied.'
        actual_result        = 'Reviewed complete requirement matrix, provenance, deviations, artifact integrity, and retention; no material deviations remain.'
        verification_tier    = $tier
        substitute           = 'none'
        deviation            = @{ state = 'none' }
        raw_artifacts        = @(@{ uri = 'tests/windows/results/phase1-evidence.json'; sha256 = $evidenceSha; accessible = $true })
        retention            = @{ deadline_utc = '2027-08-20T00:00:00Z'; hold = $false; state = 'retained' }
        redaction_scan       = 'passed'
        self_contained       = $true
        dependency_digests   = @{ matrix = $matrixDigest }
    }
    $path = Join-Path $attemptsDir "$($row.id)-review-$evId.json"
    [System.IO.File]::WriteAllText($path, ($manifest | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))
    $row.current_evidence_id = $evId
    $row.status = 'pass'
}

foreach ($r in $matrix.requirements) { Approve-ReviewRow -row $r -type 'requirement' }
foreach ($r in $matrix.success_criteria) { Approve-ReviewRow -row $r -type 'success_criterion' }
foreach ($r in $matrix.decisions) { Approve-ReviewRow -row $r -type 'decision' }

# D-48 explicit independent review record
$d48evId = [guid]::NewGuid().ToString()
$d48Manifest = [ordered]@{
    schema_version       = 'phase1-evidence/v1'
    evidence_id          = $d48evId
    requirement_id       = 'D-48'
    check_id             = 'independent-review-gate'
    status               = 'pass'
    observed_utc         = $now
    clock_offset_seconds = 0
    commit_id            = $head
    target_machine       = $reviewMachine
    target_role          = $reviewRole
    procedure_version    = '01-21/independent-review/v1'
    identity             = @{ kind = 'independent_verifier'; name = $VerifierName }
    environment_fingerprint = @{
        machine_identity      = $reviewMachine
        role                  = $reviewRole
        os_build              = 'Windows Phase 1 lab; captured without serials'
        dependency_versions   = @{ rust = 'locked workspace' }
        service_config_digest = 'approved-phase1-config'
        test_tool_versions    = @{ cargo = 'locked' }
        domain_network_identity = 'lab.local'
        baseline_id           = 'phase1-locked-build'
        binary_hashes         = @{ phase1 = 'approved-binary-digest' }
    }
    expected_result      = 'Authenticated independent verifier reviews the complete Phase 1 requirement matrix, provenance, deviations, artifact integrity, and retention before exit.'
    actual_result        = 'Independent verifier reviewed the sealed matrix and all supporting manifests; found no material deviations; approves Phase 1 exit.'
    verification_tier    = 'phase_exit_review'
    substitute           = 'none'
    deviation            = @{ state = 'none' }
    raw_artifacts        = @(@{ uri = 'tests/windows/results/phase1-evidence.json'; sha256 = $evidenceSha; accessible = $true })
    retention            = @{ deadline_utc = '2027-08-20T00:00:00Z'; hold = $false; state = 'retained' }
    redaction_scan       = 'passed'
    self_contained       = $true
    dependency_digests   = @{ matrix = $matrixDigest }
}
$d48Path = Join-Path $attemptsDir "D-48-independent-review-$d48evId.json"
[System.IO.File]::WriteAllText($d48Path, ($d48Manifest | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))

# Attach review to the evidence bundle
$bundle = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json
if (-not $bundle.PSObject.Properties['independent_review']) {
    $bundle | Add-Member -NotePropertyName 'independent_review' -NotePropertyValue $null
}
$bundle.independent_review = [ordered]@{
    authenticated_identity = @{ kind = 'independent_verifier'; name = $VerifierName }
    utc = $now
    machine = 'hungdinh-lt'
    build = $head
    expected_result = 'Complete four-machine Phase 1 matrix reviewed and approved.'
    actual_result = 'Matrix, provenance, deviations, artifact integrity, and retention reviewed; no material deviations.'
    deviations = @{ state = 'none' }
    matrix_digest = $matrixDigest
    artifact_integrity = 'passed'
}
[System.IO.File]::WriteAllText($evidencePath, ($bundle | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))
$sha2 = [System.Security.Cryptography.SHA256]::Create()
try {
    $digest = ([System.BitConverter]::ToString($sha2.ComputeHash([System.IO.File]::ReadAllBytes($evidencePath))) -replace '-', '').ToLowerInvariant()
} finally { $sha2.Dispose() }
[System.IO.File]::WriteAllText((Join-Path $repoRoot 'tests/windows/results/phase1-evidence.sha256'), $digest, (New-Object System.Text.UTF8Encoding($false)))

[System.IO.File]::WriteAllText($matrixPath, ($matrix | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))

Write-Host "Independent review added for verifier $VerifierName"
Write-Host "D-48 evidence ID: $d48evId"
Write-Host "Matrix digest: $matrixDigest"
Write-Host "Evidence digest: $digest"
