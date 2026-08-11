Set-StrictMode -Version Latest

$script:AllowedEvidenceFields = @(
    'schema_version', 'evidence_id', 'requirement_id', 'check_id', 'status', 'observed_utc', 'clock_offset_seconds',
    'commit_id', 'target_machine', 'target_role', 'procedure_version', 'identity', 'environment_fingerprint',
    'expected_result', 'actual_result', 'verification_tier', 'substitute', 'deviation', 'prior_attempt_id',
    'remediation_commit', 'supersedes_evidence_id', 'raw_artifacts', 'retention', 'redaction_scan', 'self_contained',
    'dependency_digests'
)
$script:RequiredEvidenceFields = @(
    'schema_version', 'evidence_id', 'requirement_id', 'check_id', 'status', 'observed_utc', 'clock_offset_seconds',
    'commit_id', 'target_machine', 'target_role', 'procedure_version', 'identity', 'environment_fingerprint',
    'expected_result', 'actual_result', 'verification_tier', 'substitute', 'deviation', 'raw_artifacts', 'retention',
    'redaction_scan', 'self_contained'
)
$script:MachineRoles = @{ 'hungdinh-lt' = 'developer_orchestrator'; 'LAB-SERVER01' = 'database_server'; 'LAB-DC01' = 'primary_directory_server'; 'LAB-DC02' = 'secondary_directory_server'; 'LAB-CLIENT01' = 'endpoint_runtime' }
$script:ForbiddenEvidencePattern = '(?i)(password\s*[:=]|private[ _-]?key|bearer\s+\S+|api[ _-]?key|secret\s*[:=]|protected\s+plaintext)'

function Get-Phase1RepositoryRoot {
    Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}

function Get-Phase1Sha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        ([System.BitConverter]::ToString($sha.ComputeHash([System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path))))).Replace('-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

function ConvertTo-Phase1Json {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Value)
    $Value | ConvertTo-Json -Depth 20
}

function Read-Phase1Json {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Get-Phase1Errors {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Evidence, [string]$ExecutionMachine, [string[]]$ExistingEvidencePaths = @())
    $errors = [System.Collections.Generic.List[string]]::new()
    $properties = @($Evidence.PSObject.Properties.Name)
    foreach ($property in $properties) { if ($property -notin $script:AllowedEvidenceFields) { $errors.Add("unknown field: $property") } }
    foreach ($property in $script:RequiredEvidenceFields) {
        $value = if ($properties -contains $property) { $Evidence.$property } else { $null }
        if ($null -eq $value -or ($value -is [string] -and [string]::IsNullOrWhiteSpace($value))) { $errors.Add("missing required field: $property") }
    }
    if ($Evidence.schema_version -ne 'phase1-evidence/v1') { $errors.Add('unsupported schema version') }
    $guid = [guid]::Empty
    if (-not [guid]::TryParse([string]$Evidence.evidence_id, [ref]$guid)) { $errors.Add('evidence_id is not a UUID') }
    if ([string]::IsNullOrWhiteSpace([string]$Evidence.requirement_id)) { $errors.Add('requirement_id is empty') }
    if (@('pass', 'fail', 'blocked') -notcontains [string]$Evidence.status) { $errors.Add('invalid status') }
    if ($ExecutionMachine -and $Evidence.target_machine -ne $ExecutionMachine) { $errors.Add('wrong execution machine') }
    if (-not $script:MachineRoles.ContainsKey([string]$Evidence.target_machine) -or $script:MachineRoles[[string]$Evidence.target_machine] -ne $Evidence.target_role) { $errors.Add('machine role violation') }
    if (@('portable_automation', 'focused_hyperv', 'signed_visual_checklist', 'phase_exit_review') -notcontains [string]$Evidence.verification_tier) { $errors.Add('unknown verification tier') }
    if ($Evidence.verification_tier -ne 'portable_automation' -and $Evidence.target_machine -eq 'hungdinh-lt') { $errors.Add('host cannot satisfy an infrastructure, visual, or exit tier') }
    if ($Evidence.verification_tier -ne 'portable_automation' -and $Evidence.substitute -ne 'none') { $errors.Add('substitute cannot satisfy a binding tier') }
    $utc = [datetime]::MinValue
    if (-not [datetime]::TryParse([string]$Evidence.observed_utc, [ref]$utc)) { $errors.Add('invalid observed UTC') }
    if ([math]::Abs([double]$Evidence.clock_offset_seconds) -gt 300) { $errors.Add('clock skew exceeds 300 seconds') }
    if ($Evidence.redaction_scan -ne 'passed') { $errors.Add('redaction scan did not pass') }
    if ((ConvertTo-Phase1Json $Evidence) -match $script:ForbiddenEvidencePattern) { $errors.Add('secret-bearing evidence content') }
    if ($Evidence.status -eq 'pass' -and $Evidence.deviation.state -ne 'none') { $errors.Add('deviation makes passing evidence non-passing') }
    foreach ($name in @('machine_identity', 'role', 'os_build', 'dependency_versions', 'service_config_digest', 'test_tool_versions', 'domain_network_identity', 'baseline_id', 'binary_hashes')) { if ($null -eq $Evidence.environment_fingerprint.$name -or [string]::IsNullOrWhiteSpace([string]$Evidence.environment_fingerprint.$name)) { $errors.Add("environment fingerprint missing $name") } }
    if ($null -eq $Evidence.retention -or [string]::IsNullOrWhiteSpace([string]$Evidence.retention.deadline_utc) -or $null -eq $Evidence.retention.hold -or @('retained', 'held', 'eligible_for_secure_deletion') -notcontains $Evidence.retention.state) { $errors.Add('invalid retention metadata') }
    if ($null -eq $Evidence.raw_artifacts -or $Evidence.raw_artifacts.Count -lt 1) { $errors.Add('raw artifact reference missing') }
    foreach ($artifact in @($Evidence.raw_artifacts)) {
        if ([string]::IsNullOrWhiteSpace([string]$artifact.sha256) -or $artifact.sha256 -notmatch '^[a-f0-9]{64}$') { $errors.Add('invalid raw artifact hash'); continue }
        if (-not [bool]$Evidence.self_contained) {
            if (-not [bool]$artifact.accessible -or -not (Test-Path -LiteralPath $artifact.uri)) { $errors.Add('raw artifact inaccessible'); continue }
            if ((Get-Phase1Sha256 $artifact.uri) -ne $artifact.sha256) { $errors.Add('raw artifact hash mismatch') }
        }
    }
    foreach ($path in $ExistingEvidencePaths) {
        if (Test-Path -LiteralPath $path) {
            $other = Read-Phase1Json $path
            if ($other.evidence_id -eq $Evidence.evidence_id) { $errors.Add('reused evidence ID'); break }
        }
    }
    return $errors
}

function Test-Phase1Evidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$EvidencePath, [string]$ExecutionMachine, [string[]]$ExistingEvidencePaths = @())
    if (-not (Test-Path -LiteralPath $EvidencePath)) { return [pscustomobject]@{ Valid = $false; Errors = @('evidence manifest is missing') } }
    try { $evidence = Read-Phase1Json $EvidencePath; $errors = @(Get-Phase1Errors -Evidence $evidence -ExecutionMachine $ExecutionMachine -ExistingEvidencePaths $ExistingEvidencePaths) }
    catch { return [pscustomobject]@{ Valid = $false; Errors = @($_.Exception.Message) } }
    [pscustomobject]@{ Valid = ($errors.Count -eq 0); Errors = $errors; Evidence = $evidence }
}

function New-Phase1Evidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Evidence, [Parameter(Mandatory)][string]$OutputPath)
    if (-not $Evidence.ContainsKey('evidence_id')) { $Evidence.evidence_id = [guid]::NewGuid().ToString() }
    if (-not $Evidence.ContainsKey('schema_version')) { $Evidence.schema_version = 'phase1-evidence/v1' }
    if (Test-Path -LiteralPath $OutputPath) { throw "Evidence output is immutable and already exists: $OutputPath" }
    $parent = Split-Path -Parent $OutputPath
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    [System.IO.File]::WriteAllText($OutputPath, ($Evidence | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))
    $result = Test-Phase1Evidence -EvidencePath $OutputPath
    if (-not $result.Valid) { Remove-Item -LiteralPath $OutputPath -Force; throw "Evidence validation failed: $($result.Errors -join '; ')" }
    return $result.Evidence
}

function Publish-Phase1Evidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$EvidencePath, [Parameter(Mandatory)][string]$MatrixPath, [Parameter(Mandatory)][string]$ExecutionMachine)
    $result = Test-Phase1Evidence -EvidencePath $EvidencePath -ExecutionMachine $ExecutionMachine
    if (-not $result.Valid) { throw "Evidence publication blocked: $($result.Errors -join '; ')" }
    $matrix = Read-Phase1Json $MatrixPath
    $row = @($matrix.requirements | Where-Object { $_.id -eq $result.Evidence.requirement_id })
    if ($row.Count -ne 1) { throw 'requirement matrix must contain exactly one matching requirement row' }
    $row[0].current_evidence_id = $result.Evidence.evidence_id
    $row[0].status = $result.Evidence.status
    [System.IO.File]::WriteAllText($MatrixPath, ($matrix | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))
    return $result.Evidence
}

function Resolve-Phase1EvidenceStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$EvidencePath, [hashtable]$CurrentDependencyDigests = @{})
    $result = Test-Phase1Evidence -EvidencePath $EvidencePath
    if (-not $result.Valid) { return [pscustomobject]@{ Status = 'invalid'; Reasons = $result.Errors } }
    foreach ($property in $result.Evidence.dependency_digests.PSObject.Properties) {
        if ($CurrentDependencyDigests.ContainsKey($property.Name) -and $CurrentDependencyDigests[$property.Name] -ne $property.Value) { return [pscustomobject]@{ Status = 'stale'; Reasons = @("dependency changed: $($property.Name)") } }
    }
    [pscustomobject]@{ Status = [string]$result.Evidence.status; Reasons = @() }
}

function Get-Phase1PrivilegeManifestDigest {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Manifest)
    $digestInput = [ordered]@{}
    foreach ($property in $Manifest.PSObject.Properties) {
        if ($property.Name -ne 'approval_digest') { $digestInput[$property.Name] = $property.Value }
    }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(($digestInput | ConvertTo-Json -Depth 20 -Compress))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
}

function Test-Phase1PrivilegeManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ConfigPath, [Parameter(Mandatory)][string]$PlanId)
    $config = Read-Phase1Json $ConfigPath
    $manifest = @($config.privilege_manifests | Where-Object { $_.plan_id -eq $PlanId })
    if ($manifest.Count -ne 1) { return [pscustomobject]@{ Valid = $false; Errors = @('exactly one privilege manifest is required') } }
    $manifest = $manifest[0]
    $required = @('plan_id', 'machine', 'role', 'changes', 'baseline', 'expected_state', 'apply', 'verify', 'remove', 'cleanup_on_failure', 'persistence', 'reboot_possible', 'version_or_hash', 'idempotence', 'approval_digest')
    $errors = [System.Collections.Generic.List[string]]::new()
    foreach ($field in $required) { if ($null -eq $manifest.$field -or [string]::IsNullOrWhiteSpace([string]$manifest.$field)) { $errors.Add("missing privilege field: $field") } }
    if (-not $script:MachineRoles.ContainsKey([string]$manifest.machine) -or $script:MachineRoles[[string]$manifest.machine] -ne $manifest.role) { $errors.Add('privilege manifest role violation') }
    if ((Get-Phase1PrivilegeManifestDigest $manifest) -ne $manifest.approval_digest) { $errors.Add('manifest drift: fresh approval digest required') }
    [pscustomobject]@{ Valid = ($errors.Count -eq 0); Errors = $errors; Manifest = $manifest }
}

function Test-Phase1VisualReview {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Record, [ValidateSet('visual', 'independent_review')][string]$Kind = 'visual')
    $required = @('authenticated_identity', 'utc', 'machine', 'build', 'expected_result', 'actual_result', 'deviations', 'matrix_digest', 'artifact_integrity')
    $errors = [System.Collections.Generic.List[string]]::new()
    foreach ($field in $required) {
        $value = $Record.$field
        if ($null -eq $value -or ($value -is [string] -and [string]::IsNullOrWhiteSpace($value))) { $errors.Add("missing review field: $field") }
    }
    $utc = [datetime]::MinValue
    if (-not [datetime]::TryParse([string]$Record.utc, [ref]$utc)) { $errors.Add('invalid review UTC') }
    if ($Kind -eq 'visual' -and $Record.machine -ne 'LAB-CLIENT01') { $errors.Add('visual review must run on LAB-CLIENT01') }
    if ($Record.authenticated_identity.kind -ne 'authenticated_domain_operator' -and $Record.authenticated_identity.kind -ne 'independent_verifier') { $errors.Add('review identity is not authenticated') }
    if ($Kind -eq 'independent_review' -and $Record.authenticated_identity.kind -ne 'independent_verifier') { $errors.Add('phase exit requires an independent verifier') }
    if ($Record.actual_result -eq 'pass' -and $Record.deviations.state -ne 'none') { $errors.Add('a deviation cannot be promoted to pass') }
    if ($Record.artifact_integrity -ne 'passed') { $errors.Add('artifact integrity did not pass') }
    [pscustomobject]@{ Valid = ($errors.Count -eq 0); Errors = $errors }
}

Export-ModuleMember -Function New-Phase1Evidence, Test-Phase1Evidence, Publish-Phase1Evidence, Test-Phase1PrivilegeManifest, Test-Phase1VisualReview, Resolve-Phase1EvidenceStatus, Get-Phase1PrivilegeManifestDigest, Get-Phase1Sha256
