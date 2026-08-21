[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ClosurePath,
    [string]$SecurityPath,
    [string]$ThreatId,
    [switch]$RequireSignedOff
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $repoRoot 'scripts/evidence/Phase1.Evidence.psm1'
Import-Module $modulePath -Force

$matrixPath = Join-Path $repoRoot 'evidence/phase1/requirement-matrix.yaml'

$script:ExpectedClosureTargets = @(
    'T-01-15-01', 'T-01-15-02', 'T-01-15-03', 'T-01-15-04', 'T-01-15-06',
    'T-01-16-01', 'T-01-16-02', 'T-01-16-03', 'T-01-16-04', 'T-01-16-06',
    'T-01-18-SC',
    'T-01-20-01', 'T-01-20-02', 'T-01-20-05',
    'T-01-21-01', 'T-01-21-02', 'T-01-21-03', 'T-01-21-04', 'T-01-21-05'
)

$script:MachineRoles = @{
    'hungdinh-lt' = 'developer_orchestrator'
    'LAB-SERVER01' = 'database_server'
    'LAB-DC01' = 'primary_directory_server'
    'LAB-DC02' = 'secondary_directory_server'
    'LAB-CLIENT01' = 'endpoint_runtime'
}

$script:ForbiddenPattern = '(?i)(password\s*[:=]|private[ _-]?key|bearer\s+\S+|api[ _-]?key|secret\s*[:=]|protected\s+plaintext)'

function Get-Phase1Sha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { ([System.BitConverter]::ToString($sha.ComputeHash([System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path))))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Test-Phase1Redaction {
    param([Parameter(Mandatory)][string]$Text)
    return ($Text -notmatch $script:ForbiddenPattern)
}

function Test-Phase1SensitiveArtifactPath {
    param([Parameter(Mandatory)][string]$Path)
    # Redaction scan applies only to runtime-generated evidence artifacts, not to
    # source code or verifier scripts that legitimately name secret-handling fields.
    $relative = $Path -replace '\\', '/'
    return ($relative.StartsWith('tests/windows/results/') -or $relative.StartsWith('evidence/'))
}

function Read-SimpleYaml {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $lines = Get-Content -LiteralPath $Path
    $root = [ordered]@{}
    $stack = [System.Collections.Generic.Stack[object]]::new()
    $stack.Push(@{ Object = $root; Indent = -1; List = $null; Key = $null })

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $raw = $lines[$i]
        $line = $raw -replace '\r$', ''
        if ([string]::IsNullOrWhiteSpace($line) -or $line.Trim().StartsWith('#')) { continue }
        $indent = $line.Length - $line.TrimStart().Length
        $trimmed = $line.TrimStart()

        while ($stack.Count -gt 1 -and $indent -le $stack.Peek().Indent) { $stack.Pop() | Out-Null }
        $parent = $stack.Peek()

        if ($trimmed.StartsWith('- ')) {
            $value = $trimmed.Substring(2).Trim()
            if ($value -match '^(\w+):\s*(.*)$') {
                $newObj = [ordered]@{}
                $newObj[$Matches[1]] = Convert-SimpleYamlValue $Matches[2]
                [void]$parent.List.Add($newObj)
                $stack.Push(@{ Object = $newObj; Indent = $indent; List = $null; Key = $null })
            } else {
                [void]$parent.List.Add((Convert-SimpleYamlValue $value))
            }
        } elseif ($trimmed -match '^(\w+):\s*(.*)$') {
            $key = $Matches[1]
            $value = $Matches[2].Trim()
            if ($value -eq '') {
                $isList = $false
                for ($j = $i + 1; $j -lt $lines.Count; $j++) {
                    $peek = $lines[$j] -replace '\r$', ''
                    if ([string]::IsNullOrWhiteSpace($peek) -or $peek.Trim().StartsWith('#')) { continue }
                    $peekIndent = $peek.Length - $peek.TrimStart().Length
                    if ($peekIndent -le $indent) { break }
                    if ($peek.TrimStart().StartsWith('- ')) { $isList = $true; break }
                    if ($peek -match '^\s*\w+:\s*') { $isList = $false; break }
                }
                if ($isList) {
                    $newListOrObj = [System.Collections.Generic.List[object]]::new()
                    $parent.Object[$key] = $newListOrObj
                    $stack.Push(@{ Object = $parent.Object; Indent = $indent; List = $newListOrObj; Key = $key })
                } else {
                    $newObj = [ordered]@{}
                    $parent.Object[$key] = $newObj
                    $stack.Push(@{ Object = $newObj; Indent = $indent; List = $null; Key = $key })
                }
            } else {
                $parent.Object[$key] = Convert-SimpleYamlValue $value
            }
        }
    }
    return $root
}

function Convert-SimpleYamlValue {
    param([string]$Value)
    $Value = $Value.Trim()
    if ($Value.StartsWith('"') -and $Value.EndsWith('"')) { return $Value.Substring(1, $Value.Length - 2) }
    if ($Value -eq 'true') { return $true }
    if ($Value -eq 'false') { return $false }
    return $Value
}

function Assert-Security {
    param([Parameter(Mandatory)][bool]$Condition, [Parameter(Mandatory)][string]$Message)
    if (-not $Condition) {
        Write-Host "SECURITY CLOSURE FAILED: $Message"
        exit 1
    }
}

# Load and validate closure manifest.
Assert-Security (Test-Path -LiteralPath $ClosurePath) "closure manifest is missing: $ClosurePath"
$closure = Read-SimpleYaml -Path $ClosurePath
Assert-Security ($closure.schema_version -eq 'phase1-security-closure/v1') 'unsupported closure schema version'

$allowedTop = @('schema_version', 'matrix_digest', 'closure_targets', 'records')
foreach ($key in $closure.Keys) { Assert-Security ($key -in $allowedTop) "unknown top-level field: $key" }

# Validate matrix digest.
Assert-Security (Test-Path -LiteralPath $matrixPath) 'requirement matrix is missing'
$actualMatrixDigest = Get-Phase1Sha256 -Path $matrixPath
Assert-Security ($closure.matrix_digest -eq $actualMatrixDigest) "matrix digest mismatch: closure claims $($closure.matrix_digest), actual $actualMatrixDigest"

$matrix = Get-Content -LiteralPath $matrixPath -Raw | ConvertFrom-Json
$matrixById = @{}
foreach ($r in $matrix.requirements) { $matrixById[$r.id] = $r }
foreach ($sc in $matrix.success_criteria) { $matrixById[$sc.id] = $sc }
foreach ($d in $matrix.decisions) { $matrixById[$d.id] = $d }

# Validate immutable target set.
$actualTargets = @($closure.closure_targets | Sort-Object)
$expectedTargets = @($script:ExpectedClosureTargets | Sort-Object)
Assert-Security ($actualTargets.Count -eq $expectedTargets.Count) "closure target count mismatch: $($actualTargets.Count) vs $($expectedTargets.Count)"
for ($i = 0; $i -lt $actualTargets.Count; $i++) {
    Assert-Security ($actualTargets[$i] -eq $expectedTargets[$i]) "closure target mismatch at position $i`: $($actualTargets[$i]) vs $($expectedTargets[$i])"
}

# Validate records.
Assert-Security ($closure.records -is [System.Collections.Generic.List[object]] -or $closure.records -is [array]) 'records must be a list'
$recordsById = @{}
foreach ($record in $closure.records) {
    if ($record -isnot [System.Collections.Specialized.OrderedDictionary] -and $record -isnot [hashtable]) {
        Assert-Security $false 'each record must be a map'
    }
    $tid = [string]$record.threat_id
    Assert-Security (-not [string]::IsNullOrWhiteSpace($tid)) 'record missing threat_id'
    Assert-Security (-not $recordsById.ContainsKey($tid)) "duplicate record for $tid"
    $recordsById[$tid] = $record
}

$allowedRecordFields = @('threat_id', 'disposition', 'severity', 'mitigation_assertion', 'implementation_refs', 'evidence_attempt_ids', 'required_machine_roles', 'artifact_refs', 'reviewer_identity', 'review_utc', 'procedure_version', 'environment_fingerprint')

function Validate-Record {
    param([Parameter(Mandatory)]$Record)
    $tid = [string]$Record.threat_id
    Assert-Security ($tid -in $script:ExpectedClosureTargets) "record threat_id $tid is not in closure_targets"
    Assert-Security ($Record.disposition -eq 'mitigate') "$tid disposition must be mitigate"
    Assert-Security ($Record.severity -eq 'high') "$tid severity must be high"
    Assert-Security (-not [string]::IsNullOrWhiteSpace($Record.mitigation_assertion)) "$tid missing mitigation_assertion"
    Assert-Security (Test-Phase1Redaction -Text ($Record.mitigation_assertion | ConvertTo-Json -Depth 5)) "$tid mitigation_assertion contains forbidden pattern"
    Assert-Security (-not [string]::IsNullOrWhiteSpace($Record.procedure_version)) "$tid missing procedure_version"
    Assert-Security (-not [string]::IsNullOrWhiteSpace($Record.review_utc)) "$tid missing review_utc"
    $utc = [datetime]::MinValue
    Assert-Security ([datetime]::TryParse([string]$Record.review_utc, [ref]$utc)) "$tid invalid review_utc"

    Assert-Security ($Record.reviewer_identity -is [System.Collections.Specialized.OrderedDictionary] -or $Record.reviewer_identity -is [hashtable]) "$tid reviewer_identity must be a map"
    Assert-Security ($Record.reviewer_identity.kind -in @('independent_verifier', 'authenticated_domain_operator')) "$tid reviewer_identity.kind invalid"
    Assert-Security (-not [string]::IsNullOrWhiteSpace($Record.reviewer_identity.name)) "$tid reviewer_identity.name missing"

    Assert-Security ($Record.environment_fingerprint -is [System.Collections.Specialized.OrderedDictionary] -or $Record.environment_fingerprint -is [hashtable]) "$tid environment_fingerprint must be a map"
    foreach ($name in @('machine_identity', 'role', 'os_build', 'dependency_versions', 'service_config_digest', 'test_tool_versions', 'domain_network_identity', 'baseline_id', 'binary_hashes')) {
        Assert-Security (-not [string]::IsNullOrWhiteSpace([string]$Record.environment_fingerprint.$name)) "$tid environment_fingerprint missing $name"
    }

    Assert-Security ($Record.implementation_refs -is [System.Collections.Generic.List[object]] -or $Record.implementation_refs -is [array]) "$tid implementation_refs must be a list"
    Assert-Security ($Record.implementation_refs.Count -gt 0) "$tid implementation_refs must not be empty"
    foreach ($ref in $Record.implementation_refs) {
        Assert-Security (-not [string]::IsNullOrWhiteSpace($ref.path)) "$tid implementation_ref missing path"
        Assert-Security ($ref.sha256 -match '^[a-f0-9]{64}$') "$tid implementation_ref invalid sha256"
        $fullPath = Join-Path $repoRoot $ref.path
        Assert-Security (Test-Path -LiteralPath $fullPath) "$tid implementation_ref missing file: $($ref.path)"
        Assert-Security ((Get-Phase1Sha256 -Path $fullPath) -eq $ref.sha256) "$tid implementation_ref hash mismatch: $($ref.path)"
    }

    Assert-Security ($Record.evidence_attempt_ids -is [System.Collections.Generic.List[object]] -or $Record.evidence_attempt_ids -is [array]) "$tid evidence_attempt_ids must be a list"
    Assert-Security ($Record.evidence_attempt_ids.Count -gt 0) "$tid evidence_attempt_ids must not be empty"
    foreach ($evId in $Record.evidence_attempt_ids) {
        $found = $false
        foreach ($row in ($matrix.requirements + $matrix.success_criteria + $matrix.decisions)) {
            if ([string]$row.current_evidence_id -eq [string]$evId) {
                $found = $true
                Assert-Security ($row.status -eq 'pass') "$tid evidence $evId matrix status is $($row.status)"
            }
        }
        Assert-Security $found "$tid evidence_attempt_id $evId not found in matrix"
    }

    Assert-Security ($Record.required_machine_roles -is [System.Collections.Generic.List[object]] -or $Record.required_machine_roles -is [array]) "$tid required_machine_roles must be a list"
    Assert-Security ($Record.required_machine_roles.Count -gt 0) "$tid required_machine_roles must not be empty"
    $roleMap = @{}
    foreach ($rr in $Record.required_machine_roles) {
        Assert-Security ($rr -match '^([^:]+):(.+)$') "$tid invalid required_machine_role format: $rr"
        $machine = $Matches[1]
        $role = $Matches[2]
        Assert-Security ($script:MachineRoles.ContainsKey($machine) -and $script:MachineRoles[$machine] -eq $role) "$tid invalid machine role: $rr"
        $roleMap[$machine] = $role
    }

    Assert-Security ($Record.artifact_refs -is [System.Collections.Generic.List[object]] -or $Record.artifact_refs -is [array]) "$tid artifact_refs must be a list"
    Assert-Security ($Record.artifact_refs.Count -gt 0) "$tid artifact_refs must not be empty"
    $runtimeCovered = $false
    foreach ($artifact in $Record.artifact_refs) {
        Assert-Security (-not [string]::IsNullOrWhiteSpace($artifact.path)) "$tid artifact_ref missing path"
        Assert-Security ($artifact.sha256 -match '^[a-f0-9]{64}$') "$tid artifact_ref invalid sha256"
        Assert-Security ($artifact.role -match '^([^:]+):(.+)$') "$tid artifact_ref invalid role format"
        $machine = $Matches[1]
        $role = $Matches[2]
        Assert-Security ($script:MachineRoles.ContainsKey($machine) -and $script:MachineRoles[$machine] -eq $role) "$tid artifact_ref invalid role: $($artifact.role)"
        if ($machine -eq 'LAB-CLIENT01') { $runtimeCovered = $true }
        $fullPath = Join-Path $repoRoot $artifact.path
        Assert-Security (Test-Path -LiteralPath $fullPath) "$tid artifact_ref missing file: $($artifact.path)"
        Assert-Security ((Get-Phase1Sha256 -Path $fullPath) -eq $artifact.sha256) "$tid artifact_ref hash mismatch: $($artifact.path)"
        $artifactText = [System.IO.File]::ReadAllText($fullPath)
        if (Test-Phase1SensitiveArtifactPath -Path $artifact.path) {
            Assert-Security (Test-Phase1Redaction -Text $artifactText) "$tid artifact_ref contains forbidden pattern: $($artifact.path)"
        }
    }

    if ($tid -match '^T-01-1[56]-0[1234]$' -or $tid -match '^T-01-2[01]-0[12]$') {
        Assert-Security $runtimeCovered "$tid requires a LAB-CLIENT01 runtime artifact"
    }

    foreach ($key in $Record.Keys) { Assert-Security ($key -in $allowedRecordFields) "$tid unknown record field: $key" }
}

$recordsToValidate = if ($ThreatId) { @($ThreatId) } else { $script:ExpectedClosureTargets }
foreach ($tid in $recordsToValidate) {
    Assert-Security $recordsById.ContainsKey($tid) "missing closure record for $tid"
    Validate-Record -Record $recordsById[$tid]
}

if (-not $ThreatId) {
    Assert-Security ($recordsById.Count -eq $script:ExpectedClosureTargets.Count) "record count mismatch: $($recordsById.Count) records vs $($script:ExpectedClosureTargets.Count) targets"
}

# Optional security register cross-check.
if ($SecurityPath) {
    Assert-Security (Test-Path -LiteralPath $SecurityPath) 'security register is missing'
    $securityText = Get-Content -LiteralPath $SecurityPath -Raw
    $openMatches = [regex]::Matches($securityText, '\|\s*(T-01-\d{2}(?:-SC)?(?:-\d{2})?)\s*\|[^|]*\|[^|]*\|\s*high\s*\|\s*[^|]*\|\s*[^|]*\|\s*open\s*\|')
    $openHigh = $openMatches | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
    $manifested = @($recordsById.Keys | Sort-Object)
    foreach ($tid in $openHigh) {
        if ($tid -in $script:ExpectedClosureTargets) {
            Assert-Security ($tid -in $manifested) "open high threat $tid lacks closure record"
        }
    }
    if ($RequireSignedOff) {
        $blockingOpen = @($openHigh | Where-Object { $_ -in $script:ExpectedClosureTargets })
        Assert-Security ($blockingOpen.Count -eq 0) "signed-off mode still has open blocking threats: $($blockingOpen -join ', ')"
    }
}

if ($ThreatId) {
    Write-Host "Security closure verified for $ThreatId"
} elseif ($RequireSignedOff) {
    Write-Host "Security closure signed-off: all $($script:ExpectedClosureTargets.Count) blocking threats closed and verified"
} else {
    Write-Host "Security closure pre-sign-off: $($script:ExpectedClosureTargets.Count)/$($script:ExpectedClosureTargets.Count) target records valid"
}
exit 0
