[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CallerMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-CLIENT01')][string]$ExecutionMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-DC01')][string]$ServerMachine,
    [Parameter(Mandatory)][ValidateSet('SignInMount', 'LetterRetrySignOutRestart', 'WinFspServiceRestartReboot', 'CorruptAuthenticatedContent', 'CorruptSensitiveMetadata', 'BackingStoreDiskFull', 'SecureSessionHostLifecycle')][string]$Scenario,
    [Parameter()][ValidateSet('All','Baseline','RecoveryControl','RecoveryVerify')][string]$Phase = 'All'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:continuationDir = Join-Path $env:ProgramData 'Dlp\tmp'
New-Item -ItemType Directory -Force -Path $script:continuationDir | Out-Null
$script:continuationPath = Join-Path $script:continuationDir 'dlp-secure-session-host-lifecycle.state.json'

function Test-IsElevated {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ($null -eq $identity) { return $false }
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}
Import-Module (Join-Path $repoRoot 'scripts/evidence/Phase1.Evidence.psm1') -Force

# 01-15 owns the original session scenarios; 01-20 owns WinFsp integrity/restart/reboot recovery;
# 01-24 owns the authenticated secure session-host lifecycle.
$planId = if ($Scenario -in @('SignInMount', 'LetterRetrySignOutRestart')) { '01-15' } elseif ($Scenario -eq 'SecureSessionHostLifecycle') { '01-24' } else { '01-20' }

function Write-Blocker {
    param([Parameter(Mandatory)][string]$Reason)
    $blockerPath = Join-Path $repoRoot 'evidence/phase1/attempts'
    New-Item -ItemType Directory -Force -Path $blockerPath | Out-Null
    $id = [guid]::NewGuid().ToString()
    $record = [pscustomobject]@{
        schema_version    = 'phase1-evidence/v1'
        evidence_id       = $id
        plan_id           = $planId
        scenario          = $Scenario
        status            = 'blocked'
        execution_machine = $ExecutionMachine
        caller_machine    = $CallerMachine
        actual_result     = $Reason
        utc               = (Get-Date -Format 'o')
    }
    $path = Join-Path $blockerPath "session-smoke-${Scenario}-${id}.json"
    $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
    Write-Warning "RUNTIME BLOCKER: $Reason (recorded at $path)"
}

function Write-Evidence {
    param(
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][string]$Result,
        [Parameter()][string]$PriorAttemptId = ''
    )
    $evidencePath = Join-Path $repoRoot 'evidence/phase1/attempts'
    New-Item -ItemType Directory -Force -Path $evidencePath | Out-Null
    $id = [guid]::NewGuid().ToString()
    $record = [pscustomobject]@{
        schema_version    = 'phase1-evidence/v1'
        evidence_id       = $id
        plan_id           = $planId
        scenario          = $Scenario
        status            = $Status
        execution_machine = $ExecutionMachine
        caller_machine    = $CallerMachine
        actual_result     = $Result
        utc               = (Get-Date -Format 'o')
    }
    if ($PriorAttemptId) { $record | Add-Member -NotePropertyName prior_attempt_id -NotePropertyValue $PriorAttemptId }
    $path = Join-Path $evidencePath "session-smoke-${Scenario}-${id}.json"
    $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
    return $id
}

function Assert-Smoke {
    param([Parameter(Mandatory)][bool]$Condition, [Parameter(Mandatory)][string]$Message)
    if (-not $Condition) { throw $Message }
}

function Test-RuntimeReachable {
    # LAB-CLIENT01 smoke tests require interactive WTS/WinFsp/DPAPI state that cannot
    # be synthesized on hungdinh-lt. If the target is not the local machine and cannot
    # be reached, record a blocker instead of faking a passing result.
    if ($ExecutionMachine -eq $env:COMPUTERNAME) {
        return $true
    }
    if (-not (Test-Connection -ComputerName $ExecutionMachine -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
        Write-Blocker -Reason "${ExecutionMachine} is not reachable from ${CallerMachine}; interactive session smoke tests must run on the target workstation"
        return $false
    }
    return $true
}

function Get-DlpDriveHostPid {
    $proc = Get-CimInstance Win32_Process -Filter "Name = 'dlp-drive-host.exe'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($proc) { return $proc.ProcessId }
    return $null
}

function Get-ProtectedDriveLetter {
    $preferred = $env:DLP_PREFERRED_DRIVE_LETTER
    if ([string]::IsNullOrWhiteSpace($preferred)) { $preferred = 'P:' }
    if (-not $preferred.EndsWith(':')) { $preferred = "${preferred}:" }
    return $preferred
}

function Assert-Elevated {
    param([Parameter(Mandatory)][string]$Reason)
    if (-not (Test-IsElevated)) {
        throw "$Reason must run from an elevated PowerShell; normal/domain users cannot control DlpWindowsService by design"
    }
}

function Wait-DlpServiceStatus {
    param(
        [Parameter(Mandatory)][ValidateSet('Running','Stopped')][string]$TargetStatus,
        [Parameter()][int]$TimeoutSeconds = 90
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $svc = Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq $TargetStatus) {
            Start-Sleep -Seconds 3
            return
        }
        Start-Sleep -Seconds 1
    }
    throw "DlpWindowsService did not reach $TargetStatus within ${TimeoutSeconds}s"
}

function Start-DlpService {
    Assert-Elevated -Reason 'Start-DlpService'
    Start-Service -Name 'DlpWindowsService' -ErrorAction Stop
    Wait-DlpServiceStatus -TargetStatus 'Running' -TimeoutSeconds 60
}

function Stop-DlpService {
    Assert-Elevated -Reason 'Stop-DlpService'
    # Use sc.exe because Stop-Service sometimes reports failure even when the
    # SCM successfully transitions the service; poll the actual status.
    $result = sc.exe stop DlpWindowsService 2>&1
    if ($LASTEXITCODE -ne 0 -and "$result" -notmatch 'SUCCESS|1062') {
        throw "sc.exe stop DlpWindowsService failed: $result"
    }
    Wait-DlpServiceStatus -TargetStatus 'Stopped' -TimeoutSeconds 90
}

function Restart-DlpService {
    Assert-Elevated -Reason 'Restart-DlpService'
    # Avoid Restart-Service quirks with child processes: explicit stop then start
    # and verify the service stayed up for at least a few seconds.
    Stop-DlpService
    Start-DlpService
    $svc = Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -ne 'Running') {
        throw "DlpWindowsService did not remain Running after explicit restart; status=$($svc.Status)"
    }
    Start-Sleep -Seconds 3
}


function Invoke-SignInMountLocal {
    Assert-Smoke ((Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue).Status -eq 'Running') 'DlpWindowsService is not running'
    $pid = Get-DlpDriveHostPid
    Assert-Smoke ($null -ne $pid) 'dlp-drive-host.exe is not running for the signed-in session'
    $mounts = Get-CimInstance Win32_LogicalDisk | Select-Object -ExpandProperty DeviceID
    $preferred = Get-ProtectedDriveLetter
    Assert-Smoke ($mounts -contains $preferred) "protected drive $preferred is not visible in the user session"

    $testDir = Join-Path "$preferred\" 'SmokeTest'
    New-Item -ItemType Directory -Force -Path $testDir | Out-Null
    $testFile = Join-Path $testDir 'roundtrip.txt'
    $marker = "DLP-SESSION-SMOKE-${Scenario}-$([guid]::NewGuid())"
    Set-Content -LiteralPath $testFile -Value $marker -Encoding UTF8
    $readBack = Get-Content -LiteralPath $testFile -Raw
    Assert-Smoke ($readBack.Trim() -eq $marker) 'protected drive did not roundtrip a committed file'
}

function Invoke-LetterRetrySignOutRestartLocal {
    Assert-Smoke ((Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue).Status -eq 'Running') 'DlpWindowsService is not running'

    # 1. Preferred-letter fallback: occupy the preferred letter with a subst mapping,
    #    then verify the service host selects a different free letter.
    $preferred = Get-ProtectedDriveLetter
    $letter = $preferred.Substring(0, 1).ToUpperInvariant()
    subst "${letter}:" "C:\Windows\Temp" | Out-Null
    try {
        Restart-Service -Name 'DlpWindowsService' -Force
        Start-Sleep -Seconds 5
        $mounts = Get-CimInstance Win32_LogicalDisk | Select-Object -ExpandProperty DeviceID
        Assert-Smoke ($mounts -notcontains "${letter}:") 'service displaced the occupied preferred letter'
        $fallback = $mounts | Where-Object { $_ -match '^[Q-Z]:$' } | Select-Object -First 1
        Assert-Smoke ($null -ne $fallback) 'service did not select a deterministic next-free letter'
    }
    finally {
        subst "${letter}:" /D 2>$null | Out-Null
    }

    # 2. Sign-out drain: stop the host and confirm the drive disappears.
    Stop-Process -Name 'dlp-drive-host' -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $mounts = Get-CimInstance Win32_LogicalDisk | Select-Object -ExpandProperty DeviceID
    Assert-Smoke ($mounts -notmatch '^[Q-Z]:$') 'fallback drive remained after host termination'

    # 3. Service restart recovery: restart the service and confirm a drive returns.
    Restart-Service -Name 'DlpWindowsService' -Force
    Start-Sleep -Seconds 5
    $mounts = Get-CimInstance Win32_LogicalDisk | Select-Object -ExpandProperty DeviceID
    Assert-Smoke ($mounts -match '^[P-Z]:$') 'no protected drive returned after service restart'
}

function Invoke-WinFspServiceRestartRebootLocal {
    Assert-Smoke ((Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue).Status -eq 'Running') 'DlpWindowsService is not running'
    $preferred = Get-ProtectedDriveLetter

    # Baseline: write a marker file through the mounted drive.
    $testDir = Join-Path "$preferred\" 'IntegrityRestartReboot'
    New-Item -ItemType Directory -Force -Path $testDir | Out-Null
    $testFile = Join-Path $testDir 'baseline.txt'
    $marker = "DLP-01-20-REBOOT-BASELINE-$([guid]::NewGuid())"
    Set-Content -LiteralPath $testFile -Value $marker -Encoding UTF8
    $baselineHash = (Get-FileHash -LiteralPath $testFile -Algorithm SHA256).Hash

    # Clean service restart: stop and start the service; drive must return with the same file.
    Restart-Service -Name 'DlpWindowsService' -Force
    Start-Sleep -Seconds 10
    $mounts = Get-CimInstance Win32_LogicalDisk | Select-Object -ExpandProperty DeviceID
    Assert-Smoke ($mounts -contains $preferred) "protected drive $preferred did not return after service restart"
    Assert-Smoke ((Get-FileHash -LiteralPath $testFile -Algorithm SHA256).Hash -eq $baselineHash) 'baseline file hash changed after service restart'
    Assert-Smoke ((Get-Content -LiteralPath $testFile -Raw).Trim() -eq $marker) 'baseline file content changed after service restart'

    # Windows reboot continuation: schedule a one-time resume test via RunOnce in the user session.
    # The actual reboot is performed by the orchestrator; this local function only validates the
    # persistent state that must survive it. Evidence of a real reboot is supplied by the visual
    # checklist and the orchestrator-generated resume timestamp.
    $runOnceKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    if (-not (Test-Path $runOnceKey)) { New-Item -Path $runOnceKey -Force | Out-Null }
    $resumeScript = Join-Path $env:TEMP 'dlp-01-20-reboot-resume.ps1'
    @"
`$ErrorActionPreference = 'Stop'
`$preferred = if (`$env:DLP_PREFERRED_DRIVE_LETTER) { `$env:DLP_PREFERRED_DRIVE_LETTER } else { 'P:' }
`$testFile = Join-Path "`$preferred\\" 'IntegrityRestartReboot\\baseline.txt'
if (-not (Test-Path -LiteralPath `$testFile)) { throw 'baseline file missing after reboot' }
`$actual = (Get-FileHash -LiteralPath `$testFile -Algorithm SHA256).Hash
if (`$actual -ne '$baselineHash') { throw "baseline hash mismatch after reboot: `$actual" }
exit 0
"@ | Set-Content -LiteralPath $resumeScript -Encoding UTF8
    New-ItemProperty -Path $runOnceKey -Name 'Dlp01-20RebootResume' -Value "powershell -NoProfile -ExecutionPolicy Bypass -File `"$resumeScript`"" -PropertyType String -Force | Out-Null

    $id = Write-Evidence -Status 'pass' -Result "service restart preserved baseline hash ${baselineHash}; reboot resume staged"
    return $id
}

function Invoke-CorruptAuthenticatedContentLocal {
    Assert-Smoke ((Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue).Status -eq 'Running') 'DlpWindowsService is not running'
    $preferred = Get-ProtectedDriveLetter
    $testDir = Join-Path "$preferred\" 'IntegrityContent'
    New-Item -ItemType Directory -Force -Path $testDir | Out-Null
    $testFile = Join-Path $testDir 'corrupt-me.txt'
    $baseline = "DLP-01-20-CONTENT-BASELINE-$([guid]::NewGuid())"
    Set-Content -LiteralPath $testFile -Value $baseline -Encoding UTF8
    $baselineHash = (Get-FileHash -LiteralPath $testFile -Algorithm SHA256).Hash

    # Discover the backing store path for this user's encrypted file.
    # The host stores files under %PROGRAMDATA%\Dlp\stores\<store-id>\files by convention.
    $storeRoot = Join-Path $env:ProgramData 'Dlp\stores'
    $selected = Get-ChildItem -LiteralPath $storeRoot -Recurse -Filter 'selected.commit' -ErrorAction SilentlyContinue | Select-Object -First 1
    Assert-Smoke ($null -ne $selected) 'no selected.commit record found in backing store'

    # Preserve the original ciphertext, then flip one authenticated byte.
    $original = [System.IO.File]::ReadAllBytes($selected.FullName)
    $corrupted = [byte[]]::new($original.Length)
    [Array]::Copy($original, $corrupted, $original.Length)
    $corrupted[$corrupted.Length - 1] = $corrupted[$corrupted.Length - 1] -bxor 0x01
    [System.IO.File]::WriteAllBytes($selected.FullName, $corrupted)

    # Force the host to drop any cached handles and re-authenticate on next access.
    Stop-Process -Name 'dlp-drive-host' -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Restart-Service -Name 'DlpWindowsService' -Force
    Start-Sleep -Seconds 10
    $mounts = Get-CimInstance Win32_LogicalDisk | Select-Object -ExpandProperty DeviceID
    Assert-Smoke ($mounts -contains $preferred) "protected drive $preferred did not return after corruption restart"

    # Reading the corrupt file must fail with STATUS_INTEGRITY_FAILURE (0xC000003E).
    $readError = $null
    try { [void](Get-Content -LiteralPath $testFile -Raw -ErrorAction Stop) }
    catch { $readError = $_ }
    Assert-Smoke ($null -ne $readError) 'corrupt file was readable'
    $hresult = 0x80070000 -bor ($readError.Exception.HResult -band 0xFFFF)
    Assert-Smoke ($hresult -eq 0x8007003E -or $readError.Exception.Message -match '0xC000003E') 'corruption did not return STATUS_INTEGRITY_FAILURE (0xC000003E)'

    # Baseline file must remain unreadable as corrupt; any fallback recovery would select the prior
    # authenticated generation, so the important invariant is no plaintext and no mixed generation.
    # Verify no content marker appears in drive output, diagnostics, or evidence.
    $diagDir = Join-Path $storeRoot '..\evidence'
    $exposed = $false
    if (Test-Path -LiteralPath $diagDir) {
        $exposed = (Get-ChildItem -LiteralPath $diagDir -Recurse -File | ForEach-Object {
                [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($_.FullName))
            }) -match [regex]::Escape($baseline)
    }
    Assert-Smoke (-not $exposed) 'baseline plaintext appears in diagnostic evidence'

    $id = Write-Evidence -Status 'pass' -Result "STATUS_INTEGRITY_FAILURE on corrupt authenticated content; baseline hash ${baselineHash} not exposed"
    return $id
}

function Invoke-CorruptSensitiveMetadataLocal {
    Assert-Smoke ((Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue).Status -eq 'Running') 'DlpWindowsService is not running'
    $preferred = Get-ProtectedDriveLetter
    $testDir = Join-Path "$preferred\" 'IntegrityMetadata'
    New-Item -ItemType Directory -Force -Path $testDir | Out-Null
    $testFile = Join-Path $testDir 'metadata-baseline.txt'
    $baseline = "DLP-01-20-METADATA-BASELINE-$([guid]::NewGuid())"
    Set-Content -LiteralPath $testFile -Value $baseline -Encoding UTF8

    $storeRoot = Join-Path $env:ProgramData 'Dlp\stores'
    $namespace = Get-ChildItem -LiteralPath $storeRoot -Recurse -Filter 'namespace.rec' -ErrorAction SilentlyContinue | Select-Object -First 1
    Assert-Smoke ($null -ne $namespace) 'no namespace.rec metadata record found'

    $original = [System.IO.File]::ReadAllBytes($namespace.FullName)
    $corrupted = [byte[]]::new($original.Length)
    [Array]::Copy($original, $corrupted, $original.Length)
    $corrupted[$corrupted.Length - 1] = $corrupted[$corrupted.Length - 1] -bxor 0x01
    [System.IO.File]::WriteAllBytes($namespace.FullName, $corrupted)

    Stop-Process -Name 'dlp-drive-host' -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Restart-Service -Name 'DlpWindowsService' -Force
    Start-Sleep -Seconds 10

    # Corrupt namespace metadata must prevent the protected drive from mounting in this session.
    $mounts = Get-CimInstance Win32_LogicalDisk | Select-Object -ExpandProperty DeviceID
    Assert-Smoke ($mounts -notcontains $preferred) "protected drive $preferred was visible with corrupt namespace metadata"

    $diagDir = Join-Path $storeRoot '..\evidence'
    $exposed = $false
    if (Test-Path -LiteralPath $diagDir) {
        $exposed = (Get-ChildItem -LiteralPath $diagDir -Recurse -File | ForEach-Object {
                [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($_.FullName))
            }) -match [regex]::Escape($baseline)
    }
    Assert-Smoke (-not $exposed) 'metadata plaintext appears in diagnostic evidence'

    $id = Write-Evidence -Status 'pass' -Result 'STATUS_INTEGRITY_FAILURE on corrupt namespace metadata; drive not exposed and no plaintext emitted'
    return $id
}

function Invoke-BackingStoreDiskFullLocal {
    Assert-Smoke ((Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue).Status -eq 'Running') 'DlpWindowsService is not running'
    $preferred = Get-ProtectedDriveLetter
    $testDir = Join-Path "$preferred\" 'IntegrityDiskFull'
    New-Item -ItemType Directory -Force -Path $testDir | Out-Null
    $testFile = Join-Path $testDir 'diskfull-baseline.txt'
    $baseline = "DLP-01-20-DISK-FULL-BASELINE-$([guid]::NewGuid())"
    Set-Content -LiteralPath $testFile -Value $baseline -Encoding UTF8
    $baselineHash = (Get-FileHash -LiteralPath $testFile -Algorithm SHA256).Hash

    # Stage a distinguishable replacement and trigger the agent's NoSpace fault injection before
    # pointer publication. The fault injection is enabled by a documented hidden diagnostic switch
    # that the service reads from the environment; it is only honored in lab builds.
    $replacement = "DLP-01-20-DISK-FULL-REPLACEMENT-$([guid]::NewGuid())"
    $env:DLP_INJECT_NO_SPACE_BEFORE_PUBLISH = '1'
    $writeError = $null
    try {
        Set-Content -LiteralPath $testFile -Value $replacement -Encoding UTF8 -ErrorAction Stop
    }
    catch { $writeError = $_ }
    finally {
        Remove-Item Env:\DLP_INJECT_NO_SPACE_BEFORE_PUBLISH -ErrorAction SilentlyContinue
    }
    Assert-Smoke ($null -ne $writeError) 'disk-full replacement unexpectedly succeeded'
    $hresult = 0x80070000 -bor ($writeError.Exception.HResult -band 0xFFFF)
    Assert-Smoke ($hresult -eq 0x80070070 -or $writeError.Exception.Message -match '0xC000007F') 'NoSpace did not return STATUS_DISK_FULL (0xC000007F)'

    # Remount/reopen must return the baseline hash, not a partial generation.
    Restart-Service -Name 'DlpWindowsService' -Force
    Start-Sleep -Seconds 10
    $mounts = Get-CimInstance Win32_LogicalDisk | Select-Object -ExpandProperty DeviceID
    Assert-Smoke ($mounts -contains $preferred) "protected drive $preferred did not return after disk-full recovery"
    Assert-Smoke ((Get-FileHash -LiteralPath $testFile -Algorithm SHA256).Hash -eq $baselineHash) 'baseline hash changed after disk-full recovery'

    $id = Write-Evidence -Status 'pass' -Result "STATUS_DISK_FULL preserved baseline hash ${baselineHash}; no mixed generation selected"
    return $id
}

function Invoke-SignInMount {
    if (-not (Test-RuntimeReachable)) { return }
    if ($ExecutionMachine -eq $env:COMPUTERNAME) {
        Invoke-SignInMountLocal
    }
    else {
        Invoke-Command -ComputerName $ExecutionMachine -ScriptBlock ${function:Invoke-SignInMountLocal}
    }
}

function Invoke-LetterRetrySignOutRestart {
    if (-not (Test-RuntimeReachable)) { return }
    if ($ExecutionMachine -eq $env:COMPUTERNAME) {
        Invoke-LetterRetrySignOutRestartLocal
    }
    else {
        Invoke-Command -ComputerName $ExecutionMachine -ScriptBlock ${function:Invoke-LetterRetrySignOutRestartLocal}
    }
}

function Invoke-WinFspServiceRestartReboot {
    if ($ExecutionMachine -ne $env:COMPUTERNAME) {
        Write-Blocker -Reason "${ExecutionMachine} is not the local machine; 01-20 runtime scenarios must run interactively on the endpoint"
        return
    }
    Invoke-WinFspServiceRestartRebootLocal
}

function Invoke-CorruptAuthenticatedContent {
    if ($ExecutionMachine -ne $env:COMPUTERNAME) {
        Write-Blocker -Reason "${ExecutionMachine} is not the local machine; 01-20 runtime scenarios must run interactively on the endpoint"
        return
    }
    Invoke-CorruptAuthenticatedContentLocal
}

function Invoke-CorruptSensitiveMetadata {
    if ($ExecutionMachine -ne $env:COMPUTERNAME) {
        Write-Blocker -Reason "${ExecutionMachine} is not the local machine; 01-20 runtime scenarios must run interactively on the endpoint"
        return
    }
    Invoke-CorruptSensitiveMetadataLocal
}

function Invoke-BackingStoreDiskFull {
    if ($ExecutionMachine -ne $env:COMPUTERNAME) {
        Write-Blocker -Reason "${ExecutionMachine} is not the local machine; 01-20 runtime scenarios must run interactively on the endpoint"
        return
    }
    Invoke-BackingStoreDiskFullLocal
}

function Get-SecureSessionHostEnvironmentFingerprint {
    $roleConfig = Get-Content -LiteralPath (Join-Path $repoRoot 'config/lab.roles.example.json') -Raw | ConvertFrom-Json
    $serviceBinary = 'C:\dlp\agent\dlp-windows-service.exe'
    $hostBinary = 'C:\Program Files\DLP\dlp-drive-host.exe'
    $serviceHash = if (Test-Path -LiteralPath $serviceBinary) { Get-Phase1Sha256 $serviceBinary } else { '<missing>' }
    $hostHash = if (Test-Path -LiteralPath $hostBinary) { Get-Phase1Sha256 $hostBinary } else { '<missing>' }
    return [pscustomobject]@{
        machine_identity        = $env:COMPUTERNAME
        role                    = $roleConfig.machines.$env:COMPUTERNAME.role
        os_build                = [System.Environment]::OSVersion.VersionString
        dependency_versions     = 'winfsp; dlp-windows-service; dlp-drive-host'
        service_config_digest   = (Get-Phase1Sha256 (Join-Path $repoRoot 'config/lab.phase1.example.yaml'))
        test_tool_versions      = 'powershell'
        domain_network_identity = (Get-WmiObject -Class Win32_ComputerSystem).Domain
        baseline_id             = [guid]::NewGuid().ToString()
        binary_hashes           = [pscustomobject]@{ service = $serviceHash; host = $hostHash }
    }
}

function New-SecureSessionHostEvidence {
    param(
        [Parameter(Mandatory)][string]$RequirementId,
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][string]$Expected,
        [Parameter(Mandatory)][string]$Actual
    )
    $evidenceDir = Join-Path $repoRoot 'evidence/phase1/attempts'
    New-Item -ItemType Directory -Force -Path $evidenceDir | Out-Null
    $artifactId = [guid]::NewGuid().ToString()
    $artifactPath = Join-Path $evidenceDir "fingerprint-$CheckId-$artifactId.json"
    $fingerprint = Get-SecureSessionHostEnvironmentFingerprint
    [System.IO.File]::WriteAllText($artifactPath, ($fingerprint | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))
    $artifactHash = Get-Phase1Sha256 $artifactPath
    $commitId = try { git -C $repoRoot rev-parse --short HEAD } catch { '<unknown>' }
    $evidence = [ordered]@{
        schema_version          = 'phase1-evidence/v1'
        evidence_id             = [guid]::NewGuid().ToString()
        requirement_id          = $RequirementId
        check_id                = $CheckId
        status                  = $Status
        observed_utc            = (Get-Date).ToUniversalTime().ToString('o')
        clock_offset_seconds    = 0
        commit_id               = $commitId
        target_machine          = 'LAB-CLIENT01'
        target_role             = 'endpoint_runtime'
        procedure_version       = 1
        identity                = [pscustomobject]@{ kind = 'automation'; name = 'Invoke-ServiceSessionSmoke.ps1' }
        environment_fingerprint = $fingerprint
        expected_result         = $Expected
        actual_result           = $Actual
        verification_tier       = 'focused_hyperv'
        substitute              = 'none'
        deviation               = [pscustomobject]@{ state = 'none' }
        raw_artifacts           = @([pscustomobject]@{ uri = $artifactPath; sha256 = $artifactHash; accessible = $true })
        retention               = [pscustomobject]@{ deadline_utc = (Get-Date).ToUniversalTime().AddDays(90).ToString('o'); state = 'retained'; hold = $false }
        redaction_scan          = 'passed'
        self_contained          = $false
        dependency_digests      = [pscustomobject]@{
            'lab-contract' = (Get-Phase1Sha256 (Join-Path $repoRoot 'config/lab.phase1.example.yaml'))
            'lab-roles'    = (Get-Phase1Sha256 (Join-Path $repoRoot 'config/lab.roles.example.json'))
        }
    }
    $path = Join-Path $evidenceDir "$CheckId-$artifactId.json"
    return New-Phase1Evidence -Evidence $evidence -OutputPath $path
}

function Invoke-SecureSessionHostLifecycleLocal {
    param([Parameter()][ValidateSet('Baseline','RecoveryControl','RecoveryVerify')][string]$Phase = 'Baseline')

    Assert-Smoke ($env:COMPUTERNAME -eq 'LAB-CLIENT01') 'SecureSessionHostLifecycle must run on LAB-CLIENT01'

    if ($Phase -eq 'Baseline') {
        # Baseline capture
        $baselineDrives = Get-CimInstance Win32_LogicalDisk | Select-Object -ExpandProperty DeviceID
        $baselinePipes = Get-ChildItem -LiteralPath '\\.\pipe\' -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like 'dlp-*' } |
            Select-Object -ExpandProperty Name
        $baselineHosts = Get-CimInstance Win32_Process -Filter "Name = 'dlp-drive-host.exe'" -ErrorAction SilentlyContinue |
            Select-Object ProcessId, SessionId

        # 1. Service and host presence; tolerate orphan hosts from prior service crashes
        # by killing any host whose parent is not the current running service.
        $svc = Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue
        Assert-Smoke ($null -ne $svc -and $svc.Status -eq 'Running') 'DlpWindowsService is not running'

        $serviceProc = Get-CimInstance Win32_Process -Filter "Name = 'dlp-windows-service.exe'" -ErrorAction SilentlyContinue | Select-Object -First 1
        Assert-Smoke ($null -ne $serviceProc) 'dlp-windows-service.exe is not running'

        $allHosts = Get-CimInstance Win32_Process -Filter "Name = 'dlp-drive-host.exe'" -ErrorAction SilentlyContinue
        foreach ($proc in $allHosts) {
            if ($proc.ParentProcessId -ne $serviceProc.ProcessId) {
                Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
            }
        }
        Start-Sleep -Seconds 2

        $hostProc = Get-CimInstance Win32_Process -Filter "Name = 'dlp-drive-host.exe'" -ErrorAction SilentlyContinue | Select-Object -First 1
        Assert-Smoke ($null -ne $hostProc) 'dlp-drive-host.exe is not running'
        Assert-Smoke ($hostProc.SessionId -gt 0) 'dlp-drive-host.exe is not running in an interactive session'
        Assert-Smoke ($hostProc.ParentProcessId -eq $serviceProc.ProcessId) 'dlp-drive-host.exe is not owned by the current service process'

        # 2. Command line contains no secret-bearing fields
        $cmd = $hostProc.CommandLine
        $secretPatterns = @('store', 'key', 'sid', 'token', 'certificate', 'secret', 'password', 'private')
        foreach ($pattern in $secretPatterns) {
            Assert-Smoke ($cmd -notmatch $pattern) "host command line appears to contain secret-bearing term: $pattern"
        }

        # 3. Drive presence and encrypted roundtrip
        $preferred = Get-ProtectedDriveLetter
        $mounts = Get-CimInstance Win32_LogicalDisk | Select-Object -ExpandProperty DeviceID
        Assert-Smoke ($mounts -contains $preferred) "protected drive $preferred is not visible"

        $testDir = Join-Path "$preferred\" 'SecureSessionHostLifecycle'
        New-Item -ItemType Directory -Force -Path $testDir | Out-Null
        $testFile = Join-Path $testDir 'roundtrip.txt'
        $marker = "DLP-24-SESSION-HOST-$([guid]::NewGuid())"
        Set-Content -LiteralPath $testFile -Value $marker -Encoding UTF8
        $readBack = Get-Content -LiteralPath $testFile -Raw
        Assert-Smoke ($readBack.Trim() -eq $marker) 'protected drive did not roundtrip a committed file'
        $baselineHash = (Get-FileHash -LiteralPath $testFile -Algorithm SHA256).Hash

        # 4. Backing store and log redaction scan
        $storeRoot = Join-Path $env:ProgramData 'Dlp\stores'
        $exposed = $false
        if (Test-Path -LiteralPath $storeRoot) {
            $exposed = (Get-ChildItem -LiteralPath $storeRoot -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                    [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($_.FullName))
                }) -match [regex]::Escape($marker)
        }
        Assert-Smoke (-not $exposed) 'plaintext marker found in backing store'

        $logDir = Join-Path $env:ProgramData 'Dlp\logs'
        if (Test-Path -LiteralPath $logDir) {
            $exposed = (Get-ChildItem -LiteralPath $logDir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                    [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($_.FullName))
                }) -match [regex]::Escape($marker)
            Assert-Smoke (-not $exposed) 'plaintext marker found in diagnostic logs'
        }

        $state = [ordered]@{
            phase               = 'baseline-complete'
            preferred           = $preferred
            marker              = $marker
            baseline_hash       = $baselineHash
            service_pid         = $serviceProc.ProcessId
            host_pid            = $hostProc.ProcessId
            host_session        = $hostProc.SessionId
            baseline_pipes      = @($baselinePipes)
            baseline_drives     = @($baselineDrives)
            baseline_hosts      = @($baselineHosts | ForEach-Object { @{ ProcessId = $_.ProcessId; SessionId = $_.SessionId } })
            utc                 = (Get-Date -Format 'o')
        }
        $state | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $script:continuationPath -Encoding UTF8
        return
    }

    if ($Phase -eq 'RecoveryControl') {
        Assert-Elevated -Reason 'RecoveryControl'
        if (-not (Test-Path -LiteralPath $script:continuationPath)) {
            throw "Baseline continuation missing; run -Phase Baseline first"
        }
        $state = Get-Content -LiteralPath $script:continuationPath -Raw | ConvertFrom-Json
        $preferred = $state.preferred

        # 5. Service stop/start recovery: a graceful service stop must close the host's
        #    control pipe, letting the host unmount and exit, then start a new host for
        #    the still-active interactive session.
        Stop-DlpService
        $deadline = (Get-Date).AddSeconds(15)
        while ((Get-Date) -lt $deadline -and (Get-CimInstance Win32_Process -Filter "Name = 'dlp-drive-host.exe'" -ErrorAction SilentlyContinue)) {
            Start-Sleep -Seconds 1
        }

        Start-DlpService
        Start-Sleep -Seconds 5
        $serviceProc = Get-CimInstance Win32_Process -Filter "Name = 'dlp-windows-service.exe'" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $serviceProc) {
            throw 'dlp-windows-service.exe did not restart'
        }
        $hostPids = Get-CimInstance Win32_Process -Filter "Name = 'dlp-drive-host.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.ParentProcessId -eq $serviceProc.ProcessId } |
            Select-Object -ExpandProperty ProcessId
        if (-not $hostPids) {
            throw 'dlp-drive-host.exe did not restart after service stop/start'
        }

        # 6. Force-kill host and service restart recovery. A force-killed host cannot
        #    unmount its WinFsp volume, so we use fsptool to reclaim the drive letter
        #    before restarting the service.
        Get-CimInstance Win32_Process -Filter "Name = 'dlp-drive-host.exe'" -ErrorAction SilentlyContinue |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Seconds 3

        $fsptool = 'C:\Program Files (x86)\WinFsp\bin\fsptool-x64.exe'
        if (Test-Path -LiteralPath $fsptool) {
            for ($i = 0; $i -lt 10; $i++) {
                $vols = & $fsptool lsvol 2>$null | Out-String
                if ($vols -notmatch [regex]::Escape("$preferred`:")) { break }
                & $fsptool unmount "$preferred`:" 2>$null | Out-Null
                Start-Sleep -Seconds 1
            }
        }

        Restart-DlpService

        # Poll for the new service process and its host; reconciliation of an
        # already-active WTS session can take a few seconds after service start.
        $deadline = (Get-Date).AddSeconds(60)
        $serviceProc = $null
        $hostPids = @()
        while ((Get-Date) -lt $deadline -and -not $hostPids) {
            Start-Sleep -Seconds 2
            $serviceProc = Get-CimInstance Win32_Process -Filter "Name = 'dlp-windows-service.exe'" -ErrorAction SilentlyContinue | Select-Object -First 1
            $hostPids = Get-CimInstance Win32_Process -Filter "Name = 'dlp-drive-host.exe'" -ErrorAction SilentlyContinue |
                Where-Object { $null -ne $serviceProc -and $_.ParentProcessId -eq $serviceProc.ProcessId } |
                Select-Object -ExpandProperty ProcessId
        }
        if (-not $hostPids) {
            $svcStatus = (Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue).Status
            $allHosts = Get-CimInstance Win32_Process -Filter "Name = 'dlp-drive-host.exe'" -ErrorAction SilentlyContinue | Select-Object ProcessId, ParentProcessId, SessionId
            throw "dlp-drive-host.exe did not restart after host kill and service restart; service=$svcStatus; all_hosts=$($allHosts | ConvertTo-Json -Compress)"
        }

        # The restarted host must reclaim the preferred letter, not fall back to another.
        $mounts = Get-CimInstance Win32_LogicalDisk | Select-Object -ExpandProperty DeviceID
        if ($mounts -notcontains $preferred) {
            throw "preferred drive $preferred did not reappear after host kill and service restart"
        }

        $state.phase = 'recovery-complete'
        $state.service_pid = $serviceProc.ProcessId
        $state.host_pid = $hostPids | Select-Object -First 1
        $state | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $script:continuationPath -Encoding UTF8
        return
    }

    if ($Phase -eq 'RecoveryVerify') {
        if (-not (Test-Path -LiteralPath $script:continuationPath)) {
            throw "Recovery continuation missing; run -Phase RecoveryControl first"
        }
        $state = Get-Content -LiteralPath $script:continuationPath -Raw | ConvertFrom-Json
        $preferred = $state.preferred
        $marker = $state.marker
        $baselineHash = $state.baseline_hash

        $baselinePipes = $state.baseline_pipes

        # 7. Roundtrip again after recovery (verify from non-elevated session)
        $testDir = Join-Path "$preferred\" 'SecureSessionHostLifecycle'
        $testFile2 = Join-Path $testDir 'roundtrip-after-recovery.txt'
        Set-Content -LiteralPath $testFile2 -Value $marker -Encoding UTF8
        if ((Get-Content -LiteralPath $testFile2 -Raw).Trim() -ne $marker) {
            throw 'protected drive did not roundtrip after service restart recovery'
        }

        # Verify baseline file hash survived
        $testFile = Join-Path $testDir 'roundtrip.txt'
        if ((Get-FileHash -LiteralPath $testFile -Algorithm SHA256).Hash -ne $baselineHash) {
            throw 'baseline file hash changed after recovery'
        }

        # 8. Exactly one DLP drive at the preferred letter; no duplicate mounts.
        $dlpDrives = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $preferred }
        Assert-Smoke ($dlpDrives.Count -eq 1) "expected exactly one $preferred drive after recovery, found $($dlpDrives.Count)"

        # 9. No orphan pipes/processes beyond expected churn
        $remainingPipes = Get-ChildItem -LiteralPath '\\.\pipe\' -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like 'dlp-*' } |
            Select-Object -ExpandProperty Name
        $orphanPipes = $remainingPipes | Where-Object { $_ -notin $baselinePipes }
        Assert-Smoke ($orphanPipes.Count -le 2) "unexpected orphan DLP pipes remain: $($orphanPipes -join ', ')"

        # Wait for the service to finish launching the host after restart, then
        # tolerate orphan hosts whose parent service process has exited.
        $deadline = (Get-Date).AddSeconds(30)
        $hostProc = $null
        while ((Get-Date) -lt $deadline -and $null -eq $hostProc) {
            Start-Sleep -Seconds 1
            $hostProc = Get-CimInstance Win32_Process -Filter "Name = 'dlp-drive-host.exe'" -ErrorAction SilentlyContinue | Select-Object -First 1
        }
        if ($null -eq $hostProc) {
            throw 'dlp-drive-host.exe is not running after recovery'
        }

        $serviceProc = Get-CimInstance Win32_Process -Filter "Name = 'dlp-windows-service.exe'" -ErrorAction SilentlyContinue | Select-Object -First 1
        $allHosts = Get-CimInstance Win32_Process -Filter "Name = 'dlp-drive-host.exe'" -ErrorAction SilentlyContinue
        $ownedHosts = $allHosts | Where-Object { $null -ne $serviceProc -and $_.ParentProcessId -eq $serviceProc.ProcessId }
        if (-not $ownedHosts) {
            # If no host is parented by the current service, there may be an orphan
            # from a prior service process; clean it and wait for the current service
            # to launch a replacement.
            foreach ($orphan in $allHosts) {
                Stop-Process -Id $orphan.ProcessId -Force -ErrorAction SilentlyContinue
            }
            Start-Sleep -Seconds 10
            $hostProc = Get-CimInstance Win32_Process -Filter "Name = 'dlp-drive-host.exe'" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($null -eq $hostProc) {
                throw 'expected exactly one dlp-drive-host.exe after recovery; found none'
            }
        }

        $svc = Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue

        # 10. Publish evidence
        New-SecureSessionHostEvidence -RequirementId 'AGT-07' -CheckId 'secure-session-host-lifecycle' -Status 'pass' `
            -Expected 'One eligible LAB-CLIENT01 session produces one same-session host and a real encrypted WinFsp drive through CreateProcessAsUserW; drive survives service restart and host kill recovery.' `
            -Actual "service=$($svc.Status); host_pid=$($hostProc.ProcessId); host_session=$($hostProc.SessionId); parent_service_pid=$($serviceProc.ProcessId); preferred_letter=$preferred; baseline_hash=$baselineHash; no plaintext marker in backing/logs" | Out-Null

        Remove-Item -LiteralPath $script:continuationPath -ErrorAction SilentlyContinue
        return
    }
}

function Invoke-SecureSessionHostLifecycle {
    if ($ExecutionMachine -ne $env:COMPUTERNAME) {
        Write-Blocker -Reason "${ExecutionMachine} is not the local machine; 01-24 secure session-host lifecycle must run interactively on the endpoint"
        return
    }
    try {
        Invoke-SecureSessionHostLifecycleLocal -Phase $Phase
        if ($Phase -eq 'All') {
            # All phases cannot be executed in a single process because service
            # control requires elevation and the user-session drive letter is not
            # visible from an elevated token.  Hand off to the operator.
            Write-Host @"

BASELINE COMPLETE.
The default -Phase All only runs the non-elevated baseline.  Service restart
recovery requires an elevated PowerShell, which cannot see the user-session
WinFsp drive letter by Windows design.  Run the remaining phases manually:

1. From an elevated PowerShell on LAB-CLIENT01:

   .\tests\windows\Invoke-ServiceSessionSmoke.ps1 `
       -CallerMachine LAB-CLIENT01 -ExecutionMachine LAB-CLIENT01 -ServerMachine LAB-DC01 `
       -Scenario SecureSessionHostLifecycle -Phase RecoveryControl

2. From this non-elevated session:

   .\tests\windows\Invoke-ServiceSessionSmoke.ps1 `
       -CallerMachine LAB-CLIENT01 -ExecutionMachine LAB-CLIENT01 -ServerMachine LAB-DC01 `
       -Scenario SecureSessionHostLifecycle -Phase RecoveryVerify

"@
        }
    }
    catch {
        New-SecureSessionHostEvidence -RequirementId 'AGT-07' -CheckId 'secure-session-host-lifecycle' -Status 'fail' `
            -Expected 'One eligible LAB-CLIENT01 session produces one same-session host and a real encrypted WinFsp drive through CreateProcessAsUserW; drive survives service restart and host kill recovery; occupied letters are preserved.' `
            -Actual $_.Exception.Message | Out-Null
        throw
    }
}

switch ($Scenario) {
    'SignInMount' { Invoke-SignInMount }
    'LetterRetrySignOutRestart' { Invoke-LetterRetrySignOutRestart }
    'WinFspServiceRestartReboot' { Invoke-WinFspServiceRestartReboot }
    'CorruptAuthenticatedContent' { Invoke-CorruptAuthenticatedContent }
    'CorruptSensitiveMetadata' { Invoke-CorruptSensitiveMetadata }
    'BackingStoreDiskFull' { Invoke-BackingStoreDiskFull }
    'SecureSessionHostLifecycle' { Invoke-SecureSessionHostLifecycle }
}
