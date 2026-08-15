[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CallerMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-CLIENT01')][string]$ExecutionMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-DC01')][string]$ServerMachine,
    [Parameter(Mandatory)][ValidateSet('SignInMount', 'LetterRetrySignOutRestart')][string]$Scenario
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

function Write-Blocker {
    param([Parameter(Mandatory)][string]$Reason)
    $blockerPath = Join-Path $repoRoot 'evidence/phase1/attempts'
    New-Item -ItemType Directory -Force -Path $blockerPath | Out-Null
    $id = [guid]::NewGuid().ToString()
    $record = [pscustomobject]@{
        schema_version = 'phase1-evidence/v1'
        evidence_id    = $id
        plan_id        = '01-15'
        scenario       = $Scenario
        status         = 'blocked'
        execution_machine = $ExecutionMachine
        caller_machine = $CallerMachine
        actual_result  = $Reason
        utc            = (Get-Date -Format 'o')
    }
    $path = Join-Path $blockerPath "session-smoke-${Scenario}-${id}.json"
    $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
    Write-Warning "RUNTIME BLOCKER: $Reason (recorded at $path)"
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

function Invoke-SignInMountLocal {
    Assert-Smoke ((Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue).Status -eq 'Running') 'DlpWindowsService is not running'
    $pid = Get-DlpDriveHostPid
    Assert-Smoke ($null -ne $pid) 'dlp-drive-host.exe is not running for the signed-in session'
    $mounts = Get-CimInstance Win32_LogicalDisk | Select-Object -ExpandProperty DeviceID
    $preferred = $env:DLP_PREFERRED_DRIVE_LETTER
    if ([string]::IsNullOrWhiteSpace($preferred)) { $preferred = 'P:' }
    if (-not $preferred.EndsWith(':')) { $preferred = "${preferred}:" }
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
    $preferred = $env:DLP_PREFERRED_DRIVE_LETTER
    if ([string]::IsNullOrWhiteSpace($preferred)) { $preferred = 'P' }
    $preferred = $preferred.Substring(0, 1).ToUpperInvariant()
    subst "${preferred}:" "C:\Windows\Temp" | Out-Null
    try {
        Restart-Service -Name 'DlpWindowsService' -Force
        Start-Sleep -Seconds 5
        $mounts = Get-CimInstance Win32_LogicalDisk | Select-Object -ExpandProperty DeviceID
        Assert-Smoke ($mounts -notcontains "${preferred}:") 'service displaced the occupied preferred letter'
        $fallback = $mounts | Where-Object { $_ -match '^[Q-Z]:$' } | Select-Object -First 1
        Assert-Smoke ($null -ne $fallback) 'service did not select a deterministic next-free letter'
    }
    finally {
        subst "${preferred}:" /D 2>$null | Out-Null
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

switch ($Scenario) {
    'SignInMount' { Invoke-SignInMount }
    'LetterRetrySignOutRestart' { Invoke-LetterRetrySignOutRestart }
}
