[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CallerMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-CLIENT01')][string]$ExecutionMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-DC01')][string]$ServerMachine,
    [Parameter(Mandatory)][ValidateSet('SignInMount', 'LetterRetrySignOutRestart', 'WinFspServiceRestartReboot', 'CorruptAuthenticatedContent', 'CorruptSensitiveMetadata', 'BackingStoreDiskFull')][string]$Scenario
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

# 01-15 owns the original session scenarios; 01-20 owns WinFsp integrity/restart/reboot recovery.
$planId = if ($Scenario -in @('SignInMount', 'LetterRetrySignOutRestart')) { '01-15' } else { '01-20' }

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
    if (-not (Test-RuntimeReachable)) { return }
    if ($ExecutionMachine -eq $env:COMPUTERNAME) {
        Invoke-WinFspServiceRestartRebootLocal
    }
    else {
        Invoke-Command -ComputerName $ExecutionMachine -ScriptBlock ${function:Invoke-WinFspServiceRestartRebootLocal}
    }
}

function Invoke-CorruptAuthenticatedContent {
    if (-not (Test-RuntimeReachable)) { return }
    if ($ExecutionMachine -eq $env:COMPUTERNAME) {
        Invoke-CorruptAuthenticatedContentLocal
    }
    else {
        Invoke-Command -ComputerName $ExecutionMachine -ScriptBlock ${function:Invoke-CorruptAuthenticatedContentLocal}
    }
}

function Invoke-CorruptSensitiveMetadata {
    if (-not (Test-RuntimeReachable)) { return }
    if ($ExecutionMachine -eq $env:COMPUTERNAME) {
        Invoke-CorruptSensitiveMetadataLocal
    }
    else {
        Invoke-Command -ComputerName $ExecutionMachine -ScriptBlock ${function:Invoke-CorruptSensitiveMetadataLocal}
    }
}

function Invoke-BackingStoreDiskFull {
    if (-not (Test-RuntimeReachable)) { return }
    if ($ExecutionMachine -eq $env:COMPUTERNAME) {
        Invoke-BackingStoreDiskFullLocal
    }
    else {
        Invoke-Command -ComputerName $ExecutionMachine -ScriptBlock ${function:Invoke-BackingStoreDiskFullLocal}
    }
}

switch ($Scenario) {
    'SignInMount' { Invoke-SignInMount }
    'LetterRetrySignOutRestart' { Invoke-LetterRetrySignOutRestart }
    'WinFspServiceRestartReboot' { Invoke-WinFspServiceRestartReboot }
    'CorruptAuthenticatedContent' { Invoke-CorruptAuthenticatedContent }
    'CorruptSensitiveMetadata' { Invoke-CorruptSensitiveMetadata }
    'BackingStoreDiskFull' { Invoke-BackingStoreDiskFull }
}
