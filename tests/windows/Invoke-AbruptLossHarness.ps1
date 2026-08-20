[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('hungdinh-lt')][string]$CallerMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-DC01')][string]$ServerMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-CLIENT01')][string]$EndpointMachine,
    [Parameter()][ValidateSet('RunAll','CleanServiceRestart','WindowsReboot','ForcedTermination','AbruptLoss')][string]$Scenario = 'RunAll',
    [Parameter()][string]$TestUserPassword = $env:DLP_TEST_USER_PASSWORD,
    [Parameter()][string]$ResultsDir = '',
    [Parameter()][string]$DriveLetter = $env:DLP_WINFSP_SMOKE_LETTER
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# $PSScriptRoot can be empty in parameter defaults when invoked through certain
# callers (e.g., from WSL/bash), so resolve the results directory here.
if ([string]::IsNullOrWhiteSpace($ResultsDir)) {
    $ResultsDir = Join-Path $PSScriptRoot 'results'
}

if ([string]::IsNullOrWhiteSpace($DriveLetter)) { $DriveLetter = 'P' }
$DriveLetter = $DriveLetter.TrimEnd(':').ToUpperInvariant()

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$evidenceModulePath = Join-Path $repoRoot 'scripts/evidence/Phase1.Evidence.psm1'
$labConfigPath = Join-Path $repoRoot 'config/lab.phase1.example.yaml'
$serviceName = 'DlpWindowsService'
$hostProcessName = 'dlp-drive-host'
$markerDirName = 'AbruptLossMarkers'
# markerRoot is used only inside remote script blocks on the endpoint; construct it as a
# string so Join-Path does not try to resolve the drive letter on the caller machine.
$markerRoot = "$($DriveLetter):\$markerDirName"
$barrierPath = 'C:\dlp\abrupt-loss-barrier.signal'
$rebootResultPath = 'C:\dlp\abrupt-loss-reboot.result.json'

function Stop-AbruptLossHarness([string]$Code) { throw $Code }

function Assert-AbruptLossHarness([bool]$Condition, [string]$Code) {
    if (-not $Condition) { Stop-AbruptLossHarness $Code }
}

function Get-AdminCredential {
    $user = $env:DLP_VM_ADMIN_USER
    $pass = $env:DLP_VM_ADMIN_PASSWORD
    Assert-AbruptLossHarness (-not ([string]::IsNullOrWhiteSpace($user) -or [string]::IsNullOrWhiteSpace($pass))) 'vm_admin_credentials_required'
    $secure = New-Object System.Security.SecureString
    foreach ($c in $pass.ToCharArray()) { $secure.AppendChar($c) }
    return New-Object System.Management.Automation.PSCredential($user, $secure)
}

function Get-TestCredential([Parameter(Mandatory)][string]$UserName) {
    Assert-AbruptLossHarness (-not [string]::IsNullOrWhiteSpace($TestUserPassword)) 'test_user_password_required'
    $secure = New-Object System.Security.SecureString
    foreach ($c in $TestUserPassword.ToCharArray()) { $secure.AppendChar($c) }
    return New-Object System.Management.Automation.PSCredential($UserName, $secure)
}

function Invoke-AdminCommand {
    param(
        [Parameter(Mandatory)][string]$VMName,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [Parameter()][object[]]$ArgumentList = @()
    )
    $cred = Get-AdminCredential
    Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
}

function Invoke-TestCommand {
    param(
        [Parameter(Mandatory)][string]$VMName,
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [Parameter()][object[]]$ArgumentList = @()
    )
    $cred = Get-TestCredential -UserName $UserName
    Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
}

function Test-WindowsMachine([string]$Machine) {
    try { Test-WSMan -ComputerName $Machine -ErrorAction Stop | Out-Null; return $true } catch { return $false }
}

function Get-InteractiveSession {
    Invoke-AdminCommand -VMName $EndpointMachine -ScriptBlock {
        $lines = query user 2>$null
        if (-not $lines) { return $null }
        foreach ($line in $lines) {
            if ($line -match '^\s*(\S+)\s+(\S+)\s+(\d+)\s+(Active|Disc)\s+') {
                $user = $matches[1].Trim()
                $sessionName = $matches[2].Trim()
                $sessionId = [int]$matches[3]
                $state = $matches[4].Trim()
                if ($state -eq 'Active' -and $sessionName -eq 'console') {
                    $domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain
                    return [pscustomobject]@{ UserName = "$domain\$user"; SessionId = $sessionId }
                }
            }
        }
        return $null
    }
}

function Test-AutoLogon([Parameter(Mandatory)][string]$UserName) {
    Invoke-AdminCommand -VMName $EndpointMachine -ScriptBlock {
        param($UserName)
        $winlogon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
        if (-not $winlogon) { return $false }
        if ([string]$winlogon.AutoAdminLogon -ne '1') { return $false }
        $expectedUser = ($UserName -split '\\')[-1]
        $expectedDomain = ($UserName -split '\\')[0]
        if ([string]$winlogon.DefaultUserName -ne $expectedUser) { return $false }
        if ([string]$winlogon.DefaultDomainName -ne $expectedDomain) { return $false }
        return $true
    } -ArgumentList @($UserName)
}

function Wait-DlpServiceAndHost {
    param([Parameter(Mandatory)][int]$TimeoutSeconds = 120)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $ok = Invoke-AdminCommand -VMName $EndpointMachine -ScriptBlock {
            param($ServiceName, $HostName)
            $svc = try { (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue).Status } catch { 'missing' }
            $hostProc = Get-Process -Name $HostName -ErrorAction SilentlyContinue | Select-Object -First 1
            return ($svc -eq 'Running' -and $null -ne $hostProc)
        } -ArgumentList @($serviceName, $hostProcessName)
        if ($ok) { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

function Stop-DlpService {
    Invoke-AdminCommand -VMName $EndpointMachine -ScriptBlock {
        param($ServiceName)
        $svc = Get-Service -Name $ServiceName -ErrorAction Stop
        if ($svc.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            $svc.WaitForStatus('Stopped', '00:00:30')
        }
    } -ArgumentList @($serviceName)
}

function Start-DlpService {
    Invoke-AdminCommand -VMName $EndpointMachine -ScriptBlock {
        param($ServiceName)
        $svc = Get-Service -Name $ServiceName -ErrorAction Stop
        if ($svc.Status -ne 'Running') {
            Start-Service -Name $ServiceName -ErrorAction Stop
            $svc.WaitForStatus('Running', '00:00:30')
        }
    } -ArgumentList @($serviceName)
}

function Get-FileHashHex(
    [Parameter(Mandatory)][string]$UserName,
    [Parameter(Mandatory)][string]$Path
) {
    Invoke-TestCommand -VMName $EndpointMachine -UserName $UserName -ScriptBlock {
        param($Path)
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $bytes = [System.IO.File]::ReadAllBytes($Path)
            return ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
        } finally { $sha.Dispose() }
    } -ArgumentList @($Path)
}

function Initialize-MarkerDirectory([Parameter(Mandatory)][string]$UserName) {
    Invoke-TestCommand -VMName $EndpointMachine -UserName $UserName -ScriptBlock {
        param($MarkerRoot)
        if (-not (Test-Path -LiteralPath $MarkerRoot)) {
            New-Item -ItemType Directory -Force -Path $MarkerRoot | Out-Null
        }
    } -ArgumentList @($markerRoot)
}

function New-MarkerContent([int]$LengthBytes = 64) {
    $bytes = [System.Byte[]]::new($LengthBytes)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return [System.Convert]::ToBase64String($bytes)
}

function Write-MarkerFile {
    param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Content
    )
    $path = Join-Path $markerRoot $Name
    Invoke-TestCommand -VMName $EndpointMachine -UserName $UserName -ScriptBlock {
        param($Path, $Content)
        [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
    } -ArgumentList @($path, $Content)
    return $path
}

function Read-MarkerFile {
    param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$Name
    )
    $path = Join-Path $markerRoot $Name
    Invoke-TestCommand -VMName $EndpointMachine -UserName $UserName -ScriptBlock {
        param($Path)
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        return [System.IO.File]::ReadAllText($Path, (New-Object System.Text.UTF8Encoding($false)))
    } -ArgumentList @($path)
}

function Remove-MarkerFile {
    param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$Name
    )
    $path = Join-Path $markerRoot $Name
    Invoke-TestCommand -VMName $EndpointMachine -UserName $UserName -ScriptBlock {
        param($Path)
        if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    } -ArgumentList @($path)
}

function New-Case {
    param(
        [Parameter(Mandatory)][string]$Scenario,
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][string]$Rationale,
        [Parameter()][hashtable]$Details = @{}
    )
    $case = [ordered]@{
        scenario = $Scenario
        status = $Status
        rationale = $Rationale
        execution_machine = $EndpointMachine
        caller_machine = $CallerMachine
        observed_utc = (Get-Date).ToUniversalTime().ToString('o')
    }
    foreach ($k in $Details.Keys) { $case[$k] = $Details[$k] }
    return $case
}

function Update-EvidenceBundle {
    param([Parameter(Mandatory)][array]$NewCases)
    New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null
    $evidencePath = Join-Path $ResultsDir 'phase1-evidence.json'
    $bundle = $null
    if (Test-Path -LiteralPath $evidencePath) {
        $bundle = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json
    }
    if (-not $bundle -or -not $bundle.schema_version) {
        $bundle = [ordered]@{
            schema_version = 'phase1-evidence/v1'
            evidence_id = [guid]::NewGuid().ToString()
            plan_id = '01-21'
            execution_machine = $EndpointMachine
            caller_machine = $CallerMachine
            server_machine = $ServerMachine
            secondary_dc_machine = 'LAB-DC02'
            database_machine = 'LAB-SERVER01'
            observed_utc = (Get-Date).ToUniversalTime().ToString('o')
            cases = @()
            abrupt_loss_cases = @()
            environment = [ordered]@{}
            negative_trust_boundaries = @()
            visual_checklist_requirements = @()
            manifest_digest = ''
        }
    }
    $list = [System.Collections.Generic.List[object]]::new()
    if (-not $bundle.PSObject.Properties['abrupt_loss_cases']) {
        $bundle | Add-Member -NotePropertyName 'abrupt_loss_cases' -NotePropertyValue @() -Force
    }
    if ($bundle.abrupt_loss_cases) { foreach ($c in $bundle.abrupt_loss_cases) { $list.Add($c) } }
    foreach ($c in $NewCases) { $list.Add($c) }
    $bundle.abrupt_loss_cases = $list
    $bundle.observed_utc = (Get-Date).ToUniversalTime().ToString('o')

    [System.IO.File]::WriteAllText($evidencePath, ($bundle | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.IO.File]::ReadAllBytes($evidencePath)
        $digest = ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
    [System.IO.File]::WriteAllText((Join-Path $ResultsDir 'phase1-evidence.sha256'), $digest, (New-Object System.Text.UTF8Encoding($false)))
    return $digest
}

function Invoke-CleanServiceRestart {
    param([Parameter(Mandatory)][string]$UserName)
    $scenarioName = 'CleanServiceRestart'
    Initialize-MarkerDirectory -UserName $UserName
    $content = New-MarkerContent
    $markerName = 'clean-service-restart-marker.txt'
    Write-MarkerFile -UserName $UserName -Name $markerName -Content $content | Out-Null
    $oldHash = Get-FileHashHex -UserName $UserName -Path (Join-Path $markerRoot $markerName)

    Stop-DlpService
    Start-DlpService
    if (-not (Wait-DlpServiceAndHost -TimeoutSeconds 120)) {
        return New-Case -Scenario $scenarioName -Status 'fail' -Rationale 'service or host did not recover after restart'
    }

    $readContent = Read-MarkerFile -UserName $UserName -Name $markerName
    if ($null -eq $readContent) {
        return New-Case -Scenario $scenarioName -Status 'fail' -Rationale 'marker file unreadable after restart'
    }
    $newHash = Get-FileHashHex -UserName $UserName -Path (Join-Path $markerRoot $markerName)
    if ($readContent -ne $content -or $newHash -ne $oldHash) {
        return New-Case -Scenario $scenarioName -Status 'fail' -Rationale 'marker content or hash changed after restart' -Details @{ old_hash = $oldHash; new_hash = $newHash }
    }
    return New-Case -Scenario $scenarioName -Status 'pass' -Rationale 'old-complete marker preserved after clean service restart' -Details @{ hash = $newHash }
}

function Invoke-WindowsReboot {
    param([Parameter(Mandatory)][string]$UserName)
    $scenarioName = 'WindowsReboot'
    Initialize-MarkerDirectory -UserName $UserName
    $content = New-MarkerContent
    $markerName = 'windows-reboot-marker.txt'
    Write-MarkerFile -UserName $UserName -Name $markerName -Content $content | Out-Null

    # Plant a logon task that verifies the marker after reboot.
    $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>DLP Phase 1 abrupt-loss reboot verification</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$UserName</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -ExecutionPolicy Bypass -Command "&amp; { `$content = Get-Content -LiteralPath '$markerRoot\$markerName' -Raw; `$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath '$markerRoot\$markerName').Hash.ToLowerInvariant(); `$result = [ordered]@{ status = 'pass'; content_hash = `$hash; observed_utc = (Get-Date).ToUniversalTime().ToString('o') }; New-Item -ItemType Directory -Force -Path 'C:\dlp' | Out-Null; [System.IO.File]::WriteAllText('$rebootResultPath', (`$result | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding(`$false))) }"</Arguments>
    </Exec>
  </Actions>
</Task>
"@
    $taskPath = 'C:\dlp\abrupt-loss-reboot-task.xml'
    Invoke-AdminCommand -VMName $EndpointMachine -ScriptBlock {
        param($Xml, $Path)
        [System.IO.File]::WriteAllText($Path, $Xml, (New-Object System.Text.UTF8Encoding($false)))
        schtasks /Create /F /TN 'DLP_AbruptLoss_RebootVerify' /XML $Path | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'schtasks_create_failed' }
    } -ArgumentList @($taskXml, $taskPath)

    # Initiate in-guest reboot.
    $rebootUtc = (Get-Date).ToUniversalTime().ToString('o')
    Invoke-AdminCommand -VMName $EndpointMachine -ScriptBlock { Restart-Computer -Force }

    # Wait for the VM to come back and the result file to appear.
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $maxWait = [TimeSpan]::FromMinutes(10)
    $result = $null
    while ($sw.Elapsed -lt $maxWait) {
        Start-Sleep -Seconds 10
        try {
            $result = Invoke-AdminCommand -VMName $EndpointMachine -ScriptBlock {
                if (Test-Path -LiteralPath $using:rebootResultPath) {
                    return Get-Content -LiteralPath $using:rebootResultPath -Raw | ConvertFrom-Json
                }
                return $null
            }
        } catch { $result = $null }
        if ($result) { break }
    }

    Invoke-AdminCommand -VMName $EndpointMachine -ScriptBlock {
        schtasks /Delete /F /TN 'DLP_AbruptLoss_RebootVerify' | Out-Null
        if (Test-Path -LiteralPath 'C:\dlp\abrupt-loss-reboot-task.xml') { Remove-Item -LiteralPath 'C:\dlp\abrupt-loss-reboot-task.xml' -Force }
    }

    if (-not $result) {
        return New-Case -Scenario $scenarioName -Status 'fail' -Rationale 'reboot verification result did not appear' -Details @{ reboot_utc = $rebootUtc }
    }
    if ($result.status -ne 'pass') {
        return New-Case -Scenario $scenarioName -Status 'fail' -Rationale 'reboot verification reported failure' -Details @{ reboot_utc = $rebootUtc; result = $result }
    }
    return New-Case -Scenario $scenarioName -Status 'pass' -Rationale 'old-complete marker preserved after Windows reboot' -Details @{ reboot_utc = $rebootUtc; content_hash = $result.content_hash }
}

function Invoke-ForcedTermination {
    param([Parameter(Mandatory)][string]$UserName)
    $scenarioName = 'ForcedTerminationDuringActiveWrite'
    Initialize-MarkerDirectory -UserName $UserName
    $oldMarker = 'forced-term-old-marker.txt'
    $oldContent = New-MarkerContent
    Write-MarkerFile -UserName $UserName -Name $oldMarker -Content $oldContent | Out-Null
    $oldHash = Get-FileHashHex -UserName $UserName -Path (Join-Path $markerRoot $oldMarker)

    $newName = 'forced-term-new-large.bin'
    $newPath = Join-Path $markerRoot $newName
    $chunkSize = 1MB
    $targetSize = 100MB
    # Start a background writer in the user session and signal when mid-write.
    $writerJob = Invoke-TestCommand -VMName $EndpointMachine -UserName $UserName -ScriptBlock {
        param($Path, $Size, $Chunk, $Signal)
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $buffer = [System.Byte[]]::new($Chunk)
        $stream = [System.IO.File]::OpenWrite($Path)
        try {
            $written = 0
            while ($written -lt $Size) {
                $rng.GetBytes($buffer)
                $toWrite = [Math]::Min($Chunk, $Size - $written)
                $stream.Write($buffer, 0, $toWrite)
                $stream.Flush()
                $written += $toWrite
                if ($written -gt ($Size / 2) -and -not (Test-Path -LiteralPath $Signal)) {
                    New-Item -ItemType File -Path $Signal -Force | Out-Null
                }
            }
        } finally { $stream.Dispose(); $rng.Dispose() }
        return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    } -ArgumentList @($newPath, $targetSize, $chunkSize, $barrierPath)

    # Wait for the barrier signal from the writer.
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt 60) {
        $signaled = Invoke-AdminCommand -VMName $EndpointMachine -ScriptBlock {
            param($Path)
            return Test-Path -LiteralPath $Path
        } -ArgumentList @($barrierPath)
        if ($signaled) { break }
        Start-Sleep -Milliseconds 200
    }

    # Kill the drive host while the writer is active.
    Invoke-AdminCommand -VMName $EndpointMachine -ScriptBlock {
        param($HostName)
        $proc = Get-Process -Name $HostName -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($proc) { $proc.Kill(); $proc.WaitForExit(5000) }
    } -ArgumentList @($hostProcessName)

    # Clean up the barrier and wait for service to relaunch host.
    Invoke-AdminCommand -VMName $EndpointMachine -ScriptBlock {
        param($Path)
        if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    } -ArgumentList @($barrierPath)

    Start-Sleep -Seconds 2
    if (-not (Wait-DlpServiceAndHost -TimeoutSeconds 120)) {
        return New-Case -Scenario $scenarioName -Status 'fail' -Rationale 'service/host did not recover after forced termination'
    }

    # The writer job result may have completed or errored; we only care about filesystem state.
    $newHash = Get-FileHashHex -UserName $UserName -Path $newPath
    $oldReadHash = Get-FileHashHex -UserName $UserName -Path (Join-Path $markerRoot $oldMarker)
    $newExists = Invoke-TestCommand -VMName $EndpointMachine -UserName $UserName -ScriptBlock {
        param($Path)
        return Test-Path -LiteralPath $Path
    } -ArgumentList @($newPath)

    if ($oldReadHash -ne $oldHash) {
        return New-Case -Scenario $scenarioName -Status 'fail' -Rationale 'pre-existing marker was corrupted' -Details @{ old_hash_expected = $oldHash; old_hash_actual = $oldReadHash }
    }
    if ($newExists -and $null -ne $newHash -and $newHash -ne $oldHash) {
        return New-Case -Scenario $scenarioName -Status 'pass' -Rationale 'new-complete file present; old-complete marker preserved; no mixed/partial file observed' -Details @{ old_hash = $oldHash; new_hash = $newHash }
    }
    if (-not $newExists) {
        return New-Case -Scenario $scenarioName -Status 'pass' -Rationale 'new file was not committed; old-complete marker preserved' -Details @{ old_hash = $oldHash }
    }
    return New-Case -Scenario $scenarioName -Status 'fail' -Rationale 'unrecognized partial or mixed state' -Details @{ old_hash = $oldHash; new_hash = $newHash; new_exists = $newExists }
}

function Invoke-AbruptLoss {
    param([Parameter(Mandatory)][string]$UserName)
    $scenarioName = 'HostControlledAbruptLoss'
    Initialize-MarkerDirectory -UserName $UserName
    $oldMarker = 'abrupt-loss-old-marker.txt'
    $oldContent = New-MarkerContent
    Write-MarkerFile -UserName $UserName -Name $oldMarker -Content $oldContent | Out-Null
    $oldHash = Get-FileHashHex -UserName $UserName -Path (Join-Path $markerRoot $oldMarker)

    $newName = 'abrupt-loss-new-large.bin'
    $newPath = Join-Path $markerRoot $newName
    $chunkSize = 1MB
    $targetSize = 100MB

    # Launch a user-session writer that signals when mid-write.
    Invoke-TestCommand -VMName $EndpointMachine -UserName $UserName -ScriptBlock {
        param($Path, $Size, $Chunk, $Signal)
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $buffer = [System.Byte[]]::new($Chunk)
        $stream = [System.IO.File]::OpenWrite($Path)
        try {
            $written = 0
            while ($written -lt $Size) {
                $rng.GetBytes($buffer)
                $toWrite = [Math]::Min($Chunk, $Size - $written)
                $stream.Write($buffer, 0, $toWrite)
                $stream.Flush()
                $written += $toWrite
                if ($written -gt ($Size / 2) -and -not (Test-Path -LiteralPath $Signal)) {
                    New-Item -ItemType File -Path $Signal -Force | Out-Null
                }
            }
        } finally { $stream.Dispose(); $rng.Dispose() }
    } -ArgumentList @($newPath, $targetSize, $chunkSize, $barrierPath)

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt 60) {
        $signaled = Invoke-AdminCommand -VMName $EndpointMachine -ScriptBlock {
            param($Path)
            return Test-Path -LiteralPath $Path
        } -ArgumentList @($barrierPath)
        if ($signaled) { break }
        Start-Sleep -Milliseconds 200
    }
    Assert-AbruptLossHarness $signaled 'abrupt_loss_barrier_not_signaled'

    $hostCommandUtc = (Get-Date).ToUniversalTime().ToString('o')
    Stop-VM -Name $EndpointMachine -TurnOff -Force
    $hostCommand = "Stop-VM -Name $EndpointMachine -TurnOff -Force"

    # Wait for off and confirm no graceful shutdown event.
    $off = $false
    $graceful = $false
    $sw2 = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw2.Elapsed.TotalSeconds -lt 60) {
        $state = (Get-VM -Name $EndpointMachine).State
        if ($state -eq 'Off') { $off = $true; break }
        Start-Sleep -Seconds 1
    }

    if ($off) {
        $graceful = Invoke-AdminCommand -VMName $EndpointMachine -ScriptBlock {
            # This command will fail while VM is off; a graceful event would have been logged before power off.
            return $false
        } -ErrorAction SilentlyContinue
    }

    Start-VM -Name $EndpointMachine

    # Wait for VM to be reachable and for the active session to return (requires auto-logon).
    $reachable = $false
    $sw3 = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw3.Elapsed.TotalMinutes -lt 10) {
        try {
            $session = Get-InteractiveSession
            if ($session -and $session.UserName -eq $UserName) {
                $reachable = $true
                break
            }
        } catch { }
        Start-Sleep -Seconds 10
    }

    if (-not $reachable) {
        return New-Case -Scenario $scenarioName -Status 'fail' -Rationale 'VM did not resume an interactive session after abrupt loss; verify auto-logon' -Details @{ host_command = $hostCommand; host_command_utc = $hostCommandUtc; graceful_shutdown_observed = $graceful }
    }

    if (-not (Wait-DlpServiceAndHost -TimeoutSeconds 120)) {
        return New-Case -Scenario $scenarioName -Status 'fail' -Rationale 'service/host did not recover after abrupt loss' -Details @{ host_command = $hostCommand; host_command_utc = $hostCommandUtc }
    }

    $oldReadHash = Get-FileHashHex -UserName $UserName -Path (Join-Path $markerRoot $oldMarker)
    $newHash = Get-FileHashHex -UserName $UserName -Path $newPath
    $newExists = Invoke-TestCommand -VMName $EndpointMachine -UserName $UserName -ScriptBlock {
        param($Path)
        return Test-Path -LiteralPath $Path
    } -ArgumentList @($newPath)

    if ($oldReadHash -ne $oldHash) {
        return New-Case -Scenario $scenarioName -Status 'fail' -Rationale 'pre-existing marker was corrupted after abrupt loss' -Details @{ host_command = $hostCommand; host_command_utc = $hostCommandUtc; old_hash_expected = $oldHash; old_hash_actual = $oldReadHash }
    }
    if ($newExists -and $null -ne $newHash -and $newHash -ne $oldHash) {
        return New-Case -Scenario $scenarioName -Status 'pass' -Rationale 'host hard-off recovery preserved old-complete marker and exposed only new-complete file' -Details @{ host_command = $hostCommand; host_command_utc = $hostCommandUtc; graceful_shutdown_observed = $graceful; old_hash = $oldHash; new_hash = $newHash }
    }
    if (-not $newExists) {
        return New-Case -Scenario $scenarioName -Status 'pass' -Rationale 'host hard-off recovery preserved old-complete marker; new file was not committed' -Details @{ host_command = $hostCommand; host_command_utc = $hostCommandUtc; graceful_shutdown_observed = $graceful; old_hash = $oldHash }
    }
    return New-Case -Scenario $scenarioName -Status 'fail' -Rationale 'unrecognized partial or mixed state after abrupt loss' -Details @{ host_command = $hostCommand; host_command_utc = $hostCommandUtc; graceful_shutdown_observed = $graceful; old_hash = $oldHash; new_hash = $newHash; new_exists = $newExists }
}

# --- Preconditions and orchestration ---

Assert-AbruptLossHarness ($env:COMPUTERNAME -eq $CallerMachine -and $CallerMachine -eq 'hungdinh-lt') 'wrong_execution_machine'
Assert-AbruptLossHarness (Test-Path -LiteralPath $evidenceModulePath) 'evidence_module_missing'
Assert-AbruptLossHarness (Test-Path -LiteralPath $labConfigPath) 'lab_config_missing'

Import-Module $evidenceModulePath -Force

$manifest = Test-Phase1PrivilegeManifest -ConfigPath $labConfigPath -PlanId '01-21'
Assert-AbruptLossHarness $manifest.Valid "01-21_privilege_manifest_invalid: $($manifest.Errors -join '; ')"

$config = Get-Content -LiteralPath $labConfigPath -Raw | ConvertFrom-Json
$approval = @($config.privilege_approvals | Where-Object { $_.plan_id -eq '01-21' })
Assert-AbruptLossHarness ($approval.Count -eq 1) '01-21_privilege_approval_missing'
Assert-AbruptLossHarness ($approval[0].manifest_digest -eq $manifest.Manifest.approval_digest) '01-21_privilege_approval_digest_mismatch'

Assert-AbruptLossHarness (Test-WindowsMachine $ServerMachine) 'dc01_winrm_unavailable'
Assert-AbruptLossHarness (Test-WindowsMachine $EndpointMachine) 'client01_winrm_unavailable'

$sessionInfo = Get-InteractiveSession
if (-not $sessionInfo) {
    $cases = @(New-Case -Scenario 'Precondition' -Status 'blocked' -Rationale 'no active console session on LAB-CLIENT01; D-19 drive-level recovery cannot be verified')
    Update-EvidenceBundle -NewCases $cases | Out-Null
    throw 'no_active_console_session'
}

$testUserName = $sessionInfo.UserName
$autoLogonOk = Test-AutoLogon -UserName $testUserName
$hasTestPassword = -not [string]::IsNullOrWhiteSpace($TestUserPassword)

$cases = [System.Collections.Generic.List[object]]::new()

$runScenarios = @()
if ($Scenario -eq 'RunAll') { $runScenarios = @('CleanServiceRestart','WindowsReboot','ForcedTermination','AbruptLoss') }
else { $runScenarios = @($Scenario) }

foreach ($s in $runScenarios) {
    if ($s -eq 'CleanServiceRestart') {
        if (-not $hasTestPassword) {
            $cases.Add((New-Case -Scenario $s -Status 'blocked' -Rationale 'DLP_TEST_USER_PASSWORD not available; cannot run drive-level verification under the interactive session'))
        } else {
            $cases.Add((Invoke-CleanServiceRestart -UserName $testUserName))
        }
    }
    elseif ($s -eq 'WindowsReboot') {
        if (-not $hasTestPassword -or -not $autoLogonOk) {
            $cases.Add((New-Case -Scenario $s -Status 'blocked' -Rationale 'auto-logon and test user password required for post-boot drive-level verification'))
        } else {
            $cases.Add((Invoke-WindowsReboot -UserName $testUserName))
        }
    }
    elseif ($s -eq 'ForcedTermination') {
        if (-not $hasTestPassword) {
            $cases.Add((New-Case -Scenario $s -Status 'blocked' -Rationale 'DLP_TEST_USER_PASSWORD not available; cannot run drive-level active-write verification'))
        } else {
            $cases.Add((Invoke-ForcedTermination -UserName $testUserName))
        }
    }
    elseif ($s -eq 'AbruptLoss') {
        if (-not $hasTestPassword -or -not $autoLogonOk) {
            $cases.Add((New-Case -Scenario $s -Status 'blocked' -Rationale 'auto-logon and test user password required for host-controlled abrupt-loss recovery'))
        } else {
            $cases.Add((Invoke-AbruptLoss -UserName $testUserName))
        }
    }
}

$digest = Update-EvidenceBundle -NewCases $cases
Write-Host "AbruptLossHarness: wrote $($cases.Count) cases to $(Join-Path $ResultsDir 'phase1-evidence.json') with digest $digest"

$failed = @($cases | Where-Object { $_.status -eq 'fail' })
$blocked = @($cases | Where-Object { $_.status -eq 'blocked' })
if ($failed.Count -gt 0) { exit 1 }
if ($blocked.Count -gt 0) { exit 2 }
exit 0
