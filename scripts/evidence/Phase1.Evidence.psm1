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
    if (($Evidence.verification_tier -eq 'signed_visual_checklist' -or $Evidence.verification_tier -eq 'phase_exit_review') -and $Evidence.target_machine -eq 'hungdinh-lt') { $errors.Add('host cannot satisfy a visual or exit tier') }
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

function ConvertTo-Phase1CanonicalBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Value)
    [System.Text.UTF8Encoding]::new($false).GetBytes((($Value | ConvertTo-Json -Depth 40 -Compress) -replace "`r`n", "`n"))
}

function Get-Phase1ReviewCommitment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$ReviewerPolicyPath,
        [Parameter(Mandatory)][string]$ReviewerRootPath,
        [Parameter(Mandatory)][string]$ArchivalPolicyPath,
        [Parameter(Mandatory)]$Signer,
        [string]$PreviousGenerationDigest = ''
    )
    $paths = [ordered]@{
        security_closure = 'evidence/phase1/security-closure.yaml'
        archival_policy = (Resolve-Path $ArchivalPolicyPath).Path
        reviewer_policy = (Resolve-Path $ReviewerPolicyPath).Path
        reviewer_root = (Resolve-Path $ReviewerRootPath).Path
        security_review = '.planning/phases/01-first-encrypted-drive-vertical-slice/01-SECURITY.md'
        code_review = '.planning/phases/01-first-encrypted-drive-vertical-slice/01-REVIEW.md'
        requirement_matrix = 'evidence/phase1/requirement-matrix.yaml'
        evidence_bundle = 'tests/windows/results/phase1-evidence.json'
        evidence_digest = 'tests/windows/results/phase1-evidence.sha256'
    }
    $artifacts = @()
    foreach ($entry in $paths.GetEnumerator()) {
        $path = if ([IO.Path]::IsPathRooted([string]$entry.Value)) { [string]$entry.Value } else { Join-Path $RepositoryRoot ([string]$entry.Value) }
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "d48_frozen_artifact_missing:$($entry.Key)" }
        $artifacts += [ordered]@{ name = $entry.Key; sha256 = Get-Phase1Sha256 $path; accessible = $true }
    }
    $matrix = Read-Phase1Json (Join-Path $RepositoryRoot 'evidence/phase1/requirement-matrix.yaml')
    $d49 = @($matrix.decisions | Where-Object id -eq 'D-49')
    if ($d49.Count -ne 1) { throw 'd48_d49_disposition_missing' }
    [ordered]@{
        schema_version = 'phase1-independent-review-commitment/v1'
        procedure_version = '01-37/d48/v1'
        created_utc = [DateTime]::UtcNow.ToString('o')
        clock_offset_seconds = 0
        commit_id = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
        signer = $Signer
        previous_generation_digest = $PreviousGenerationDigest
        d49_disposition = [ordered]@{ id = $d49[0].id; status = $d49[0].status; evidence_id = $d49[0].current_evidence_id }
        retention = [ordered]@{ evidence_retained = $true; legal_hold_observed = $false }
        artifacts = $artifacts
    }
}

function Test-Phase1IndependentReview {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RepositoryRoot, [Parameter(Mandatory)][string]$IndexPath, [Parameter(Mandatory)][string]$ReviewerPolicyPath, [Parameter(Mandatory)][string]$ReviewerRootPath, [Parameter(Mandatory)][string]$ArchivalPolicyPath)
    $errors = [Collections.Generic.List[string]]::new()
    if (-not (Test-Path $IndexPath)) { return [pscustomobject]@{ Present=$false; Valid=$false; Errors=@('independent_review_missing') } }
    try {
        try { Add-Type -AssemblyName System.Security -ErrorAction Stop } catch { throw 'd48_pkcs_assembly_missing' }
        $index = Read-Phase1Json $IndexPath
        if ($index.schema_version -ne 'phase1-independent-review-index/v1' -or @($index.generations).Count -lt 1) { throw 'independent_review_index_invalid' }
        $latest = @($index.generations)[-1]
        $generationPath = Join-Path (Split-Path $IndexPath -Parent) $latest.path
        $generation = Read-Phase1Json $generationPath
        $canonical = [Convert]::FromBase64String([string]$generation.commitment_base64)
        $cmsBytes = [Convert]::FromBase64String([string]$generation.signature_cms_base64)
        $cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($canonical), $true)
        $cms.Decode($cmsBytes); $cms.CheckSignature($true)
        if ($cms.SignerInfos.Count -ne 1) { throw 'independent_review_signer_count_invalid' }
        $commitment = [Text.Encoding]::UTF8.GetString($canonical) | ConvertFrom-Json
        if ($commitment.schema_version -ne 'phase1-independent-review-commitment/v1') { throw 'independent_review_commitment_invalid' }
        $policy = Read-Phase1Json $ReviewerPolicyPath; $archive = Read-Phase1Json $ArchivalPolicyPath
        $cert = $cms.SignerInfos[0].Certificate; $thumb = $cert.Thumbprint.Replace(' ','').ToUpperInvariant()
        $authorized = @($policy.reviewers | Where-Object { $_.thumbprint.Replace(' ','').ToUpperInvariant() -eq $thumb -and $_.identity -eq $commitment.signer.identity -and $_.machine_identity -eq $commitment.signer.machine })
        if ($authorized.Count -ne 1) { throw 'independent_review_policy_mismatch' }
        if ($archive.schema_version -ne 'phase1-reviewer-policy/v1') { throw 'independent_review_archival_policy_invalid' }
        foreach ($reviewer in @($archive.reviewers)) {
            $identityProperty = $reviewer.PSObject.Properties['identity']
            $thumbprintProperty = $reviewer.PSObject.Properties['thumbprint']
            $subjectProperty = $reviewer.PSObject.Properties['subject']
            if (-not $identityProperty -or [string]::IsNullOrWhiteSpace([string]$identityProperty.Value) -or
                -not $thumbprintProperty -or [string]::IsNullOrWhiteSpace([string]$thumbprintProperty.Value)) {
                throw 'independent_review_archival_subject_missing'
            }
            # phase1-reviewer-policy/v1 predates the optional subject field. Its
            # authenticated identity and thumbprint remain the compatibility keys.
            $subjectMatches = $subjectProperty -and -not [string]::IsNullOrWhiteSpace([string]$subjectProperty.Value) -and [string]$subjectProperty.Value -eq $cert.Subject
            if ([string]$identityProperty.Value -eq $commitment.signer.identity -or
                ([string]$thumbprintProperty.Value).Replace(' ','').ToUpperInvariant() -eq $thumb -or
                $subjectMatches) { throw 'independent_review_archival_signer_reuse' }
        }
        foreach ($artifact in @($commitment.artifacts)) {
            $map = @{ security_closure='evidence/phase1/security-closure.yaml'; security_review='.planning/phases/01-first-encrypted-drive-vertical-slice/01-SECURITY.md'; code_review='.planning/phases/01-first-encrypted-drive-vertical-slice/01-REVIEW.md'; requirement_matrix='evidence/phase1/requirement-matrix.yaml'; evidence_bundle='tests/windows/results/phase1-evidence.json'; evidence_digest='tests/windows/results/phase1-evidence.sha256' }
            $path = if ($map.ContainsKey([string]$artifact.name)) { Join-Path $RepositoryRoot $map[[string]$artifact.name] } elseif ($artifact.name -eq 'archival_policy') { $ArchivalPolicyPath } elseif ($artifact.name -eq 'reviewer_policy') { $ReviewerPolicyPath } else { $ReviewerRootPath }
            if (-not (Test-Path $path) -or (Get-Phase1Sha256 $path) -ne $artifact.sha256) { throw "independent_review_artifact_drift:$($artifact.name)" }
        }
        [pscustomobject]@{ Present=$true; Valid=$true; Errors=@(); Generation=$generation }
    } catch { [pscustomobject]@{ Present=$true; Valid=$false; Errors=@($_.Exception.Message) } }
}

Export-ModuleMember -Function New-Phase1Evidence, Test-Phase1Evidence, Publish-Phase1Evidence, Test-Phase1PrivilegeManifest, Test-Phase1VisualReview, Resolve-Phase1EvidenceStatus, Get-Phase1PrivilegeManifestDigest, Get-Phase1Sha256, ConvertTo-Phase1CanonicalBytes, Get-Phase1ReviewCommitment, Test-Phase1IndependentReview
