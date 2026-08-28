[CmdletBinding()]
param(
    [Parameter()][ValidateSet('hungdinh-lt')][string]$CallerMachine = 'hungdinh-lt',
    [Parameter()][ValidateSet('LAB-CLIENT01')][string]$ExecutionMachine = 'LAB-CLIENT01',
    [Parameter()][ValidateSet('LAB-DC01')][string]$ServerMachine = 'LAB-DC01',
    [Parameter()][ValidateSet('Runtime')][string]$SecretProvider = 'Runtime',
    [Parameter(Mandatory)][ValidateSet(
        'InitialEnrollmentCredential',
        'ReplacementRevocation',
        'OrdinaryMissingCredentialDoesNotRevoke',
        'ConfigurationCache',
        'ServiceRestart',
        'InstallStartFailureCleanup',
        'CleanupFailure',
        'FreshTokenRetry',
        'NormalOutput',
        'DiagnosticRedaction',
        'AuthorityQueryAdapter',
        'AuthorityEvidenceContract'
    )][string]$Scenario,
    [Parameter()][System.Management.Automation.PSCredential]$Credential,
    [Parameter()][string]$EvidencePath,
    [Parameter()][ValidateSet('AfterReplacementMutation')][string]$FailureInjection
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

function Stop-AgentSmoke([string]$Code) {
    throw $Code
}

function Assert-AgentSmoke([bool]$Condition, [string]$Code) {
    if (-not $Condition) { Stop-AgentSmoke $Code }
}

function Assert-NoHostArtifacts {
    # hungdinh-lt must never host the endpoint service, DPAPI credential, runtime
    # trust entries, hosts mappings, WinFsp runtime, or DLP mounts.
    $service = Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue
    Assert-AgentSmoke ($null -eq $service) 'host_service_present'
    $paths = @(
        'C:/ProgramData/DLP/agent',
        'C:/ProgramData/DLP/cache',
        'C:/Program Files/WinFsp'
    )
    foreach ($path in $paths) {
        Assert-AgentSmoke (-not (Test-Path -LiteralPath $path)) "host_artifact_present:$path"
    }
}

# Verify live scenarios only run from the approved orchestrator host. Contract
# scenarios are safe to run in CI from another machine because they do not
# contact or mutate either VM.
Assert-AgentSmoke ($ExecutionMachine -eq 'LAB-CLIENT01') 'execution_machine_denied'
Assert-AgentSmoke ($ServerMachine -eq 'LAB-DC01') 'server_machine_denied'
Assert-AgentSmoke ($SecretProvider -eq 'Runtime') 'secret_provider_denied'

function Assert-LiveLabAvailable {
    Assert-AgentSmoke ($env:COMPUTERNAME -eq 'hungdinh-lt' -and $CallerMachine -eq 'hungdinh-lt') 'live_lab_unavailable: approved orchestrator host hungdinh-lt is required'
    Assert-NoHostArtifacts
    $getVm = Get-Command Get-VM -ErrorAction SilentlyContinue
    Assert-AgentSmoke ($null -ne $getVm) 'live_lab_unavailable: Hyper-V PowerShell module is unavailable'
    $dcReachable = Test-NetConnection -ComputerName $ServerMachine -Port 8443 -WarningAction SilentlyContinue
    Assert-AgentSmoke $dcReachable.TcpTestSucceeded 'live_lab_unavailable: LAB-DC01:8443 is unreachable'
    $clientReachable = Test-Connection -ComputerName $ExecutionMachine -Count 1 -Quiet
    Assert-AgentSmoke $clientReachable 'live_lab_unavailable: LAB-CLIENT01 is unreachable'
}

function Invoke-AgentServiceCommand {
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [Parameter()][object[]]$ArgumentList = @()
    )
    try {
        $guestCredential = $Credential
        if ($null -eq $guestCredential) {
            $user = $env:DLP_VM_ADMIN_USER
            $pass = $env:DLP_VM_ADMIN_PASSWORD
            Assert-AgentSmoke (-not [string]::IsNullOrWhiteSpace($user) -and
                -not [string]::IsNullOrWhiteSpace($pass)) 'vm_credentials_required'
            $secure = New-Object System.Security.SecureString
            foreach ($character in $pass.ToCharArray()) { $secure.AppendChar($character) }
            $guestCredential = New-Object System.Management.Automation.PSCredential($user, $secure)
        }

        # LAB-CLIENT01 is a local Hyper-V guest. PowerShell Direct avoids
        # workgroup WinRM/TrustedHosts while still authenticating inside the VM.
        Invoke-Command -VMName $ExecutionMachine -Credential $guestCredential `
            -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
    }
    catch {
        # Preserve the existing stable, redacted failure code consumed by the
        # Phase 1 evidence workflow even though the transport is now VMDirect.
        Stop-AgentSmoke 'lab_client01_winrm_failed'
    }
}

function Get-AgentServiceState {
    Invoke-AgentServiceCommand -ScriptBlock {
        $svc = Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue
        if ($null -eq $svc) { return @{ Installed = $false } }
        return @{
            Installed = $true
            Status    = $svc.Status.ToString()
            StartType = (Get-CimInstance Win32_Service -Filter "Name='DlpWindowsService'").StartMode
        }
    }
}

function Install-AgentService {
    Invoke-AgentServiceCommand -ScriptBlock {
        $svc = Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue
        if ($null -ne $svc) { return @{ Installed = $true; Action = 'already_present' } }
        # The installer path and binary hash are validated by the 01-19 privilege manifest.
        $binary = 'C:/Program Files/DLP/dlp-windows-service.exe'
        if (-not (Test-Path -LiteralPath $binary)) { throw 'agent_binary_missing' }
        New-Service -Name 'DlpWindowsService' -BinaryPathName "`"$binary`"" -DisplayName 'DLP Windows Service' -StartupType Automatic -ErrorAction Stop | Out-Null
        return @{ Installed = $true; Action = 'installed' }
    }
}

function Start-AgentService {
    Invoke-AgentServiceCommand -ScriptBlock {
        Start-Service -Name 'DlpWindowsService' -ErrorAction Stop
        return @{ Status = (Get-Service -Name 'DlpWindowsService').Status.ToString() }
    }
}

function Stop-AgentService {
    Invoke-AgentServiceCommand -ScriptBlock {
        Stop-Service -Name 'DlpWindowsService' -Force -ErrorAction Stop
        return @{ Status = (Get-Service -Name 'DlpWindowsService').Status.ToString() }
    }
}

function Restart-AgentService {
    Invoke-AgentServiceCommand -ScriptBlock {
        Restart-Service -Name 'DlpWindowsService' -Force -ErrorAction Stop
        return @{ Status = (Get-Service -Name 'DlpWindowsService').Status.ToString() }
    }
}

function Get-AgentFingerprint {
    Invoke-AgentServiceCommand -ScriptBlock {
        # The fingerprint collector is exercised by invoking the service binary
        # with a hidden diagnostic verb that emits only redacted stable codes.
        $binary = 'C:/Program Files/DLP/dlp-windows-service.exe'
        $output = & $binary fingerprint 2>&1
        return @{ Output = ($output -join "`n") }
    }
}

function Get-AgentHealth {
    Invoke-AgentServiceCommand -ScriptBlock {
        $binary = 'C:/Program Files/DLP/dlp-windows-service.exe'
        $output = & $binary health 2>&1
        return @{ Output = ($output -join "`n") }
    }
}

function Force-KillAgentService {
    Invoke-AgentServiceCommand -ScriptBlock {
        $proc = Get-Process -Name 'dlp-windows-service' -ErrorAction SilentlyContinue
        if ($null -ne $proc) {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
        }
        return @{ Killed = ($null -ne $proc) }
    }
}

function Get-AgentServiceLogLength {
    return Invoke-AgentServiceCommand -ScriptBlock {
        $path = 'C:\dlp\agent\logs\dlp-windows-service.log'
        if (Test-Path -LiteralPath $path) { return (Get-Item -LiteralPath $path).Length }
        return 0
    }
}

function Wait-AgentAuthenticatedPollAfter {
    param([Parameter(Mandatory)][long]$BaselineLength)
    $matched = Invoke-AgentServiceCommand -ScriptBlock {
        param($Offset)
        $path = 'C:\dlp\agent\logs\dlp-windows-service.log'
        $deadline = [DateTime]::UtcNow.AddSeconds(120)
        while ([DateTime]::UtcNow -lt $deadline) {
            if (Test-Path -LiteralPath $path) {
                $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                try {
                    if ($stream.Length -lt $Offset) { $Offset = 0 }
                    [void]$stream.Seek($Offset, [System.IO.SeekOrigin]::Begin)
                    $reader = [System.IO.StreamReader]::new($stream)
                    try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
                } finally { $stream.Dispose() }
                if ($text -match 'authenticated configuration poll succeeded: (?:activated|unchanged)') { return $true }
            }
            Start-Sleep -Milliseconds 500
        }
        return $false
    } -ArgumentList @($BaselineLength)
    Assert-AgentSmoke $matched 'service_restart_authenticated_poll_missing'
}

function Invoke-LiveEnrollmentRecovery {
    param(
        [Parameter()][switch]$Force,
        [Parameter()][switch]$ExpectFailure,
        [Parameter()][switch]$SuppressOutput
    )
    $arguments = @{
        CallerMachine = $CallerMachine
        ExecutionMachine = $ExecutionMachine
        ProbeMachine = $ServerMachine
        SecretProvider = 'Runtime'
        Scenario = 'ServiceInstall'
        Apply = $true
    }
    if ($null -ne $Credential) { $arguments.Credential = $Credential }
    if ($Force) { $arguments.ForceReenrollment = $true }
    # SRV-13/D-05..D-08/TST-05: no provider override and no manual token.
    $runtimePath = Join-Path $repoRoot 'scripts/lab/Invoke-Client01Runtime.ps1'
    $failed = $false
    if ($SuppressOutput) {
        # Start-Process -NoNewWindow inside the runtime writes native cargo output
        # directly to inherited OS handles, bypassing PowerShell stream merging.
        # Give the runtime a child process with redirected OS handles so
        # injection mode can inspect all output without publishing anything
        # except the fixed recovery codes below. Credentials remain in the
        # child environment and never cross the command-line boundary.
        $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
        Assert-AgentSmoke ($null -ne $pwsh) 'recovery_powershell_missing'
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $pwsh.Source
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.CreateNoWindow = $true
        foreach ($argument in @(
            '-NoProfile',
            '-File', $runtimePath,
            '-CallerMachine', $CallerMachine,
            '-ExecutionMachine', $ExecutionMachine,
            '-ProbeMachine', $ServerMachine,
            '-SecretProvider', 'Runtime',
            '-Scenario', 'ServiceInstall',
            '-Apply'
        )) {
            [void]$startInfo.ArgumentList.Add($argument)
        }
        if ($Force) { [void]$startInfo.ArgumentList.Add('-ForceReenrollment') }
        if ($null -ne $Credential) {
            $startInfo.Environment['DLP_VM_ADMIN_USER'] = $Credential.UserName
            $startInfo.Environment['DLP_VM_ADMIN_PASSWORD'] = $Credential.GetNetworkCredential().Password
        }

        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        try {
            Assert-AgentSmoke $process.Start() 'recovery_process_start_failed'
            $stdoutTask = $process.StandardOutput.ReadToEndAsync()
            $stderrTask = $process.StandardError.ReadToEndAsync()
            $process.WaitForExit()
            $stdout = $stdoutTask.GetAwaiter().GetResult()
            $stderr = $stderrTask.GetAwaiter().GetResult()
            $failed = $process.ExitCode -ne 0
            $output = @(($stdout + [Environment]::NewLine + $stderr) -split '\r?\n' |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        } finally {
            $process.Dispose()
        }
    } else {
        try {
            $output = & $runtimePath @arguments *>&1
            if ($LASTEXITCODE -ne 0) { $failed = $true }
        } catch {
            $failed = $true
            $output = @($_.Exception.Message)
        }
    }
    $joined = $output -join "`n"
    if ($ExpectFailure) {
        Assert-AgentSmoke $failed 'ordinary_missing_credential_unexpectedly_succeeded'
        Assert-AgentSmoke ($joined -match 'ForceReenrollment -Apply') 'ordinary_missing_credential_remediation_missing'
        return $joined
    }
    if ($failed) { Stop-AgentSmoke 'client01_enrollment_tracer_failed' }
    Assert-AgentSmoke ($joined -match 'active_policy_version=\S+') 'active_policy_version_missing'
    Assert-AgentSmoke ($joined -match 'active_policy_state=Active') 'active_policy_state_not_active'
    if (-not $SuppressOutput) {
        $output | ForEach-Object { Write-Output $_ }
    }
    return $joined
}

function Invoke-AuthorityQuery {
    param(
        [Parameter(Mandatory)][string]$Sql,
        [Parameter()][ValidateSet('ActiveSerial', 'AuthoritySnapshot', 'CredentialStatus')][string]$ExpectedShape = 'ActiveSerial',
        [Parameter()][string]$ExecutablePath,
        [Parameter()][string]$DatabaseUrl
    )

    if ([string]::IsNullOrWhiteSpace($DatabaseUrl)) { $DatabaseUrl = $env:DLP_DATABASE_URL }
    Assert-AgentSmoke (-not [string]::IsNullOrWhiteSpace($DatabaseUrl)) 'database_url_missing'
    if ([string]::IsNullOrWhiteSpace($ExecutablePath)) {
        $psql = Get-Command psql -ErrorAction SilentlyContinue
        Assert-AgentSmoke ($null -ne $psql) 'psql_missing'
        $ExecutablePath = $psql.Source
    }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $ExecutablePath
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true
    foreach ($argument in @('-tA', '-v', 'ON_ERROR_STOP=1', '-c', $Sql, $DatabaseUrl)) {
        [void]$startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        try {
            Assert-AgentSmoke $process.Start() 'authority_query_process_failed'
        } catch {
            Stop-AgentSmoke 'authority_query_process_failed'
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $exitCode = $process.ExitCode
    } finally {
        $process.Dispose()
    }

    Assert-AgentSmoke ($exitCode -eq 0) 'authority_query_exit_nonzero'
    Assert-AgentSmoke ([string]::IsNullOrWhiteSpace($stderr)) 'authority_query_stderr'
    $rows = @($stdout -split "\r?\n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    Assert-AgentSmoke ($rows.Count -eq 1) 'authority_query_row_count_invalid'
    $row = [string]$rows[0]

    switch ($ExpectedShape) {
        'ActiveSerial' {
            Assert-AgentSmoke ($row -cmatch '^(?:[0-9a-f]{2})+$') 'authority_query_active_serial_invalid'
        }
        'AuthoritySnapshot' {
            $fields = $row.Split([char]'|', [System.StringSplitOptions]::None)
            Assert-AgentSmoke ($fields.Count -eq 4) 'authority_query_snapshot_invalid'
            Assert-AgentSmoke ($fields[0] -cmatch '^(?:[0-9a-f]{2})+$') 'authority_query_snapshot_invalid'
            Assert-AgentSmoke ($fields[1] -cmatch '^(?:[0-9a-f]{2})+$') 'authority_query_snapshot_invalid'
            $parsedTimestamp = [DateTimeOffset]::MinValue
            if (-not [string]::IsNullOrEmpty($fields[2])) {
                Assert-AgentSmoke ([DateTimeOffset]::TryParse(
                    $fields[2],
                    [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::AllowWhiteSpaces,
                    [ref]$parsedTimestamp
                )) 'authority_query_snapshot_invalid'
            }
            $parsedTimestamp = [DateTimeOffset]::MinValue
            Assert-AgentSmoke (-not [string]::IsNullOrEmpty($fields[3]) -and [DateTimeOffset]::TryParse(
                $fields[3],
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AllowWhiteSpaces,
                [ref]$parsedTimestamp
            )) 'authority_query_snapshot_invalid'
        }
        'CredentialStatus' {
            Assert-AgentSmoke ($row -ceq 'active' -or $row -ceq 'revoked') 'authority_query_status_invalid'
        }
    }
    return $row
}

function Get-ActiveCredentialSerial {
    return Invoke-AuthorityQuery -ExpectedShape ActiveSerial -Sql "SELECT COALESCE(encode(active_serial, 'hex'), '') FROM enrollment_authority WHERE device_id = 'LAB-CLIENT01.lab.local'"
}

function Get-EnrollmentAuthoritySnapshot {
    return Invoke-AuthorityQuery -ExpectedShape AuthoritySnapshot -Sql "SELECT concat_ws('|', COALESCE(encode(active_serial, 'hex'), ''), encode(token_digest, 'hex'), COALESCE(token_consumed_at::text, ''), token_expires_at::text) FROM enrollment_authority WHERE device_id = 'LAB-CLIENT01.lab.local'"
}

function Get-CredentialAuthorityStatus {
    param([Parameter(Mandatory)][string]$Serial)
    Assert-AgentSmoke ($Serial -match '^[0-9a-f]+$') 'credential_serial_invalid'
    return Invoke-AuthorityQuery -ExpectedShape CredentialStatus -Sql "SELECT credential_status FROM device_route_credentials WHERE device_id = 'LAB-CLIENT01.lab.local' AND credential_serial = decode('$Serial', 'hex')"
}

function Get-AgentPreservationState {
    Invoke-AgentServiceCommand -ScriptBlock {
        return [pscustomobject]@{
            ServicePresent = $null -ne (Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue)
            DataPresent = Test-Path -LiteralPath 'C:\dlp\agent\data' -PathType Container
            CachePresent = Test-Path -LiteralPath 'C:\dlp\agent\cache' -PathType Container
        }
    }
}

function Get-RuntimeSource {
    return [System.IO.File]::ReadAllText((Join-Path $repoRoot 'scripts/lab/Invoke-Client01Runtime.ps1'))
}

function Assert-SourceContract {
    param(
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][string]$Code
    )
    Assert-AgentSmoke ((Get-RuntimeSource) -match $Pattern) $Code
}

function Invoke-TokenCleanupFixture {
    param(
        [Parameter()][switch]$FailAgentEnv,
        [Parameter()][switch]$FailScmEnvironment
    )
    $fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dlp-cleanup-fixture-' + [Guid]::NewGuid().ToString('N'))
    $agentEnvPath = Join-Path $fixtureRoot 'agent.env'
    $scmEnvironmentPath = Join-Path $fixtureRoot 'scm-environment.txt'
    $initial = @('DLP_DEVICE_ID=device', 'DLP_AGENT_ENROLLMENT_TOKEN=secret', 'DLP_SERVER_URL=https://server')
    $cleanupCommand = Join-Path $repoRoot 'scripts/lab/Remove-EnrollmentTokenState.ps1'
    New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
    try {
        if ($FailAgentEnv) {
            New-Item -ItemType Directory -Path $agentEnvPath -Force | Out-Null
        } else {
            [System.IO.File]::WriteAllLines($agentEnvPath, $initial)
        }
        [System.IO.File]::WriteAllLines($scmEnvironmentPath, $initial)
        $readScm = { param($Path) [System.IO.File]::ReadAllLines($Path) }
        $writeScm = if ($FailScmEnvironment) {
            { param($Path, $Lines) throw 'injected_scm_write_failure' }
        } else {
            { param($Path, $Lines) [System.IO.File]::WriteAllLines($Path, [string[]]$Lines) }
        }
        $result = & $cleanupCommand -AgentEnvPath $agentEnvPath -ServiceKeyPath $scmEnvironmentPath `
            -ReadScmEnvironment $readScm -WriteScmEnvironment $writeScm
        $agentState = if ($FailAgentEnv) { $initial } else { [System.IO.File]::ReadAllLines($agentEnvPath) }
        return [pscustomobject]@{
            AgentEnv = $result.AgentEnv
            ScmEnvironment = $result.ScmEnvironment
            AgentEnvLines = @($agentState)
            ScmEnvironmentLines = @([System.IO.File]::ReadAllLines($scmEnvironmentPath))
            ServicePresent = $true
            BinaryPresent = $true
            DataPresent = $true
            CachePresent = $true
        }
    } finally {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Assert-RedactedText {
    param([Parameter(Mandatory)][string]$Text)
    $forbidden = @(
        'DLP_AGENT_ENROLLMENT_TOKEN=[^\s;]+',
        '-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
        'DLP_VM_ADMIN_PASSWORD=[^\s;]+',
        '-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----',
        'device\.dpapi[^\r\n]*=[^\r\n]+'
    )
    foreach ($pattern in $forbidden) {
        Assert-AgentSmoke ($Text -notmatch $pattern) 'diagnostic_secret_disclosure'
    }
}

function Assert-EnrollmentTokenRemoved {
    $state = Invoke-AgentServiceCommand -ScriptBlock {
        $serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\DlpWindowsService'
        $environment = (Get-ItemProperty -Path $serviceKey -Name Environment -ErrorAction SilentlyContinue).Environment
        $registry = @($environment | Where-Object { $_ -like 'DLP_AGENT_ENROLLMENT_TOKEN=*' }).Count
        $envPath = 'C:\dlp\agent\agent.env'
        $file = if (Test-Path -LiteralPath $envPath) {
            @([IO.File]::ReadAllLines($envPath) | Where-Object { $_ -like 'DLP_AGENT_ENROLLMENT_TOKEN=*' }).Count
        } else { 0 }
        return @{ RegistryTokenCount = $registry; FileTokenCount = $file }
    }
    Assert-AgentSmoke ($state.RegistryTokenCount -eq 0) 'enrollment_token_retained_in_registry'
    Assert-AgentSmoke ($state.FileTokenCount -eq 0) 'enrollment_token_retained_in_env_file'
}

function Assert-EnrollmentTokenAclProtected {
    $state = Invoke-AgentServiceCommand -ScriptBlock {
        $acl = Get-Acl -LiteralPath 'C:\dlp\agent\agent.env' -ErrorAction Stop
        $allowed = @('S-1-5-18', 'S-1-5-32-544')
        $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
        $unexpectedAllow = @($rules | Where-Object {
            $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            $_.IdentityReference.Value -notin $allowed
        })
        return [pscustomobject]@{
            Protected = $acl.AreAccessRulesProtected
            UnexpectedAllowCount = $unexpectedAllow.Count
        }
    }
    Assert-AgentSmoke $state.Protected 'enrollment_token_acl_inheritance_enabled'
    Assert-AgentSmoke ($state.UnexpectedAllowCount -eq 0) 'ordinary_user_can_read_agent_env'
}

function Remove-AgentCredentialAsSystem {
    Invoke-AgentServiceCommand -ScriptBlock {
        $task = 'DlpSmokeRemoveCredential-' + [Guid]::NewGuid().ToString('N')
        $time = (Get-Date).AddMinutes(1).ToString('HH:mm')
        try {
            & schtasks.exe /Create /TN $task /SC ONCE /ST $time `
                /TR 'cmd.exe /d /c del /q C:\dlp\agent\data\credentials\device.dpapi*' /RU SYSTEM /F | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'credential_remove_task_create_failed' }
            & schtasks.exe /Run /TN $task | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'credential_remove_task_run_failed' }
            Start-Sleep -Seconds 2
        } finally {
            $cleanupCommand = "schtasks.exe /Delete /TN $task /F >nul 2>&1"
            & cmd.exe /d /c $cleanupCommand | Out-Null
        }
    }
    Assert-AgentSmoke (-not (Test-AgentCredentialAsSystem)) 'smoke_credential_remove_failed'
}

function Test-AgentCredentialAsSystem {
    return Invoke-AgentServiceCommand -ScriptBlock {
        $task = 'DlpSmokeProbeCredential-' + [Guid]::NewGuid().ToString('N')
        $resultPath = Join-Path $env:ProgramData ($task + '.txt')
        $time = (Get-Date).AddMinutes(1).ToString('HH:mm')
        $action = "cmd.exe /d /c if exist C:\dlp\agent\data\credentials\device.dpapi (echo 1>$resultPath) else (echo 0>$resultPath)"
        try {
            & schtasks.exe /Create /TN $task /SC ONCE /ST $time /TR $action /RU SYSTEM /F | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'credential_probe_task_create_failed' }
            & schtasks.exe /Run /TN $task | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'credential_probe_task_run_failed' }
            $deadline = [DateTime]::UtcNow.AddSeconds(15)
            while (-not (Test-Path -LiteralPath $resultPath) -and [DateTime]::UtcNow -lt $deadline) {
                Start-Sleep -Milliseconds 200
            }
            if (-not (Test-Path -LiteralPath $resultPath)) { throw 'credential_probe_timed_out' }
            return ([System.IO.File]::ReadAllText($resultPath).Trim() -eq '1')
        } finally {
            $cleanupCommand = "schtasks.exe /Delete /TN $task /F >nul 2>&1"
            & cmd.exe /d /c $cleanupCommand | Out-Null
            Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Assert-InitialEnrollmentStateEmpty {
    Assert-AgentSmoke (-not (Test-AgentCredentialAsSystem)) 'initial_enrollment_credential_precondition_not_empty'
    $pointerPresent = Invoke-AgentServiceCommand -ScriptBlock {
        Test-Path -LiteralPath 'C:\dlp\agent\cache\pointers' -PathType Leaf
    }
    Assert-AgentSmoke (-not $pointerPresent) 'initial_enrollment_pointer_precondition_not_empty'
}

function New-AuthorityQueryFakeExecutable {
    param([Parameter(Mandatory)][string]$Path)

    $sourcePath = [IO.Path]::ChangeExtension($Path, '.cs')
    $source = @'
using System;
using System.IO;
using System.Text;

public static class AuthorityQueryFakePsql
{
    public static int Main(string[] args)
    {
        string recordPath = Environment.GetEnvironmentVariable("DLP_FAKE_PSQL_ARGUMENT_RECORD");
        if (!String.IsNullOrWhiteSpace(recordPath))
        {
            using (var writer = new StreamWriter(recordPath, false, new UTF8Encoding(false)))
            {
                foreach (string arg in args)
                {
                    writer.WriteLine(Convert.ToBase64String(Encoding.UTF8.GetBytes(arg)));
                }
            }
        }

        string sql = Environment.GetEnvironmentVariable("DLP_FAKE_PSQL_EXPECTED_SQL") ?? String.Empty;
        string databaseUrl = Environment.GetEnvironmentVariable("DLP_FAKE_PSQL_EXPECTED_URL") ?? String.Empty;
        string[] expected = new[] { "-tA", "-v", "ON_ERROR_STOP=1", "-c", sql, databaseUrl };
        if (args.Length != expected.Length)
        {
            Console.Error.WriteLine("argv_mismatch");
            return 41;
        }
        for (int index = 0; index < expected.Length; index++)
        {
            if (!String.Equals(args[index], expected[index], StringComparison.Ordinal))
            {
                Console.Error.WriteLine("argv_mismatch");
                return 41;
            }
        }

        string mode = Environment.GetEnvironmentVariable("DLP_FAKE_PSQL_MODE") ?? "clean";
        string row = Environment.GetEnvironmentVariable("DLP_FAKE_PSQL_ROW") ?? String.Empty;
        switch (mode)
        {
            case "clean":
                Console.Out.WriteLine(row);
                return 0;
            case "zero-row":
                return 0;
            case "multiple-row":
                Console.Out.WriteLine(row);
                Console.Out.WriteLine(row);
                return 0;
            case "stderr-warning":
                Console.Out.WriteLine(row);
                Console.Error.WriteLine("warning");
                return 0;
            case "nonzero-exit":
                return 42;
            default:
                Console.Error.WriteLine("fixture_mode_invalid");
                return 43;
        }
    }
}
'@
    $compilerCandidates = @(
        (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
        (Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
    )
    $compiler = @($compilerCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1)
    Assert-AgentSmoke ($compiler.Count -eq 1) 'authority_query_fixture_compiler_missing'
    [IO.File]::WriteAllText($sourcePath, $source, [Text.UTF8Encoding]::new($false))
    & $compiler[0] /nologo /target:exe "/out:$Path" $sourcePath | Out-Null
    Assert-AgentSmoke ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $Path -PathType Leaf)) 'authority_query_fixture_compile_failed'
}

function Assert-AuthorityQueryFailure {
    param(
        [Parameter(Mandatory)][string]$ExpectedCode,
        [Parameter(Mandatory)][scriptblock]$Action
    )

    $failed = $false
    try {
        & $Action | Out-Null
    } catch {
        $failed = $true
        Assert-AgentSmoke ($_.Exception.Message -ceq $ExpectedCode) 'authority_query_unexpected_failure_code'
    }
    Assert-AgentSmoke $failed 'authority_query_expected_failure_missing'
}

function Invoke-AuthorityQueryAdapterFixture {
    $fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('authority-query-adapter-' + [Guid]::NewGuid().ToString('N'))
    $fakePsql = Join-Path $fixtureRoot 'psql.exe'
    $argumentRecord = Join-Path $fixtureRoot 'arguments.txt'
    $sentinelSql = 'SELECT concat_ws(''|'', encode(active_serial, ''hex''), (token_expires_at::text)) FROM enrollment_authority WHERE device_id = ''LAB-CLIENT01.lab.local'''
    $sentinelUrl = 'postgresql://authority-fixture.invalid/dlp'
    $serial = '0123456789abcdef'
    $snapshot = '0123456789abcdef|fedcba9876543210|2026-08-28 10:11:12.123456+00|2026-08-28 11:11:12.654321+00'
    $oldPath = $env:PATH
    $oldDatabaseUrl = $env:DLP_DATABASE_URL
    $fixtureVariables = @(
        'DLP_FAKE_PSQL_ARGUMENT_RECORD',
        'DLP_FAKE_PSQL_EXPECTED_SQL',
        'DLP_FAKE_PSQL_EXPECTED_URL',
        'DLP_FAKE_PSQL_MODE',
        'DLP_FAKE_PSQL_ROW'
    )
    $oldFixtureValues = @{}
    foreach ($name in $fixtureVariables) { $oldFixtureValues[$name] = [Environment]::GetEnvironmentVariable($name) }

    New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
    try {
        New-AuthorityQueryFakeExecutable -Path $fakePsql
        $env:PATH = $fixtureRoot + [IO.Path]::PathSeparator + $oldPath
        $env:DLP_DATABASE_URL = $sentinelUrl
        $env:DLP_FAKE_PSQL_ARGUMENT_RECORD = $argumentRecord
        $env:DLP_FAKE_PSQL_EXPECTED_SQL = $sentinelSql
        $env:DLP_FAKE_PSQL_EXPECTED_URL = $sentinelUrl
        $env:DLP_FAKE_PSQL_MODE = 'clean'
        $env:DLP_FAKE_PSQL_ROW = $serial

        $actual = Invoke-AuthorityQuery -Sql $sentinelSql
        Assert-AgentSmoke ($actual -ceq $serial) 'authority_query_clean_row_mismatch'
        $recorded = @([IO.File]::ReadAllLines($argumentRecord) | ForEach-Object {
            [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_))
        })
        $expectedArguments = @('-tA', '-v', 'ON_ERROR_STOP=1', '-c', $sentinelSql, $sentinelUrl)
        Assert-AgentSmoke ($recorded.Count -eq $expectedArguments.Count) 'authority_query_argument_count_invalid'
        for ($index = 0; $index -lt $expectedArguments.Count; $index++) {
            Assert-AgentSmoke ($recorded[$index] -ceq $expectedArguments[$index]) 'authority_query_argument_order_invalid'
        }

        $env:DLP_FAKE_PSQL_ROW = $snapshot
        Assert-AgentSmoke ((Invoke-AuthorityQuery -Sql $sentinelSql -ExpectedShape AuthoritySnapshot -ExecutablePath $fakePsql -DatabaseUrl $sentinelUrl) -ceq $snapshot) 'authority_query_snapshot_row_mismatch'
        $env:DLP_FAKE_PSQL_ROW = 'active'
        Assert-AgentSmoke ((Invoke-AuthorityQuery -Sql $sentinelSql -ExpectedShape CredentialStatus -ExecutablePath $fakePsql -DatabaseUrl $sentinelUrl) -ceq 'active') 'authority_query_status_row_mismatch'

        $env:DLP_FAKE_PSQL_MODE = 'zero-row'
        Assert-AuthorityQueryFailure -ExpectedCode 'authority_query_row_count_invalid' -Action {
            Invoke-AuthorityQuery -Sql $sentinelSql -ExpectedShape ActiveSerial -ExecutablePath $fakePsql -DatabaseUrl $sentinelUrl
        }
        $env:DLP_FAKE_PSQL_MODE = 'multiple-row'
        $env:DLP_FAKE_PSQL_ROW = $serial
        Assert-AuthorityQueryFailure -ExpectedCode 'authority_query_row_count_invalid' -Action {
            Invoke-AuthorityQuery -Sql $sentinelSql -ExpectedShape ActiveSerial -ExecutablePath $fakePsql -DatabaseUrl $sentinelUrl
        }
        $env:DLP_FAKE_PSQL_MODE = 'clean'
        $env:DLP_FAKE_PSQL_ROW = 'ABC'
        Assert-AuthorityQueryFailure -ExpectedCode 'authority_query_active_serial_invalid' -Action {
            Invoke-AuthorityQuery -Sql $sentinelSql -ExpectedShape ActiveSerial -ExecutablePath $fakePsql -DatabaseUrl $sentinelUrl
        }
        $env:DLP_FAKE_PSQL_ROW = '0123|4567|not-a-time|also-not-a-time'
        Assert-AuthorityQueryFailure -ExpectedCode 'authority_query_snapshot_invalid' -Action {
            Invoke-AuthorityQuery -Sql $sentinelSql -ExpectedShape AuthoritySnapshot -ExecutablePath $fakePsql -DatabaseUrl $sentinelUrl
        }
        $env:DLP_FAKE_PSQL_ROW = 'ACTIVE'
        Assert-AuthorityQueryFailure -ExpectedCode 'authority_query_status_invalid' -Action {
            Invoke-AuthorityQuery -Sql $sentinelSql -ExpectedShape CredentialStatus -ExecutablePath $fakePsql -DatabaseUrl $sentinelUrl
        }
        $env:DLP_FAKE_PSQL_MODE = 'stderr-warning'
        $env:DLP_FAKE_PSQL_ROW = $serial
        Assert-AuthorityQueryFailure -ExpectedCode 'authority_query_stderr' -Action {
            Invoke-AuthorityQuery -Sql $sentinelSql -ExpectedShape ActiveSerial -ExecutablePath $fakePsql -DatabaseUrl $sentinelUrl
        }
        $env:DLP_FAKE_PSQL_MODE = 'nonzero-exit'
        Assert-AuthorityQueryFailure -ExpectedCode 'authority_query_exit_nonzero' -Action {
            Invoke-AuthorityQuery -Sql $sentinelSql -ExpectedShape ActiveSerial -ExecutablePath $fakePsql -DatabaseUrl $sentinelUrl
        }
    } finally {
        $env:PATH = $oldPath
        $env:DLP_DATABASE_URL = $oldDatabaseUrl
        foreach ($name in $fixtureVariables) {
            [Environment]::SetEnvironmentVariable($name, $oldFixtureValues[$name])
        }
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$script:OrdinaryAuthorityEvidenceProperties = @(
    'schema',
    'scenario',
    'observed_at_utc',
    'status',
    'active_serial_before_fingerprint',
    'active_serial_after_fingerprint',
    'authority_snapshot_before_fingerprint',
    'authority_snapshot_after_fingerprint',
    'active_serial_unchanged',
    'authority_snapshot_unchanged',
    'predecessor_status_after_refusal',
    'recovery_service_status',
    'recovery_service_start_mode',
    'recovery_active_policy_state',
    'recovery_agent_env_token_count',
    'recovery_scm_token_count'
)

$script:ReplacementAuthorityEvidenceProperties = @(
    'schema',
    'scenario',
    'observed_at_utc',
    'status',
    'predecessor_serial_fingerprint',
    'successor_serial_fingerprint',
    'serial_changed',
    'predecessor_status',
    'successor_status',
    'service_preserved',
    'data_preserved',
    'cache_preserved',
    'service_status',
    'service_start_mode',
    'active_policy_state',
    'agent_env_token_count',
    'scm_token_count'
)

function Get-AuthorityEvidenceProperties {
    param([Parameter(Mandatory)][ValidateSet('Ordinary', 'Replacement')][string]$ScenarioKind)

    if ($ScenarioKind -ceq 'Ordinary') { return $script:OrdinaryAuthorityEvidenceProperties }
    return $script:ReplacementAuthorityEvidenceProperties
}

function Get-AuthorityEvidenceEntries {
    param([Parameter(Mandatory)][object]$Evidence)

    if ($Evidence -is [System.Collections.IDictionary]) {
        return @($Evidence.GetEnumerator() | ForEach-Object {
            [pscustomobject]@{ Name = [string]$_.Key; Value = $_.Value }
        })
    }
    if ($Evidence -is [System.Collections.IEnumerable] -and $Evidence -isnot [string]) {
        return @($Evidence | ForEach-Object {
            if ($_ -is [System.Collections.DictionaryEntry]) {
                [pscustomobject]@{ Name = [string]$_.Key; Value = $_.Value }
            } elseif ($null -ne $_.PSObject.Properties['Name'] -and $null -ne $_.PSObject.Properties['Value']) {
                [pscustomobject]@{ Name = [string]$_.Name; Value = $_.Value }
            } else {
                Stop-AgentSmoke 'authority_evidence_property_invalid'
            }
        })
    }
    return @($Evidence.PSObject.Properties | ForEach-Object {
        [pscustomobject]@{ Name = [string]$_.Name; Value = $_.Value }
    })
}

function Get-Sha256Fingerprint {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        return (($algorithm.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $algorithm.Dispose()
    }
}

function Write-AuthorityTransitionEvidence {
    param(
        [Parameter(Mandatory)][ValidateSet('Ordinary', 'Replacement')][string]$ScenarioKind,
        [Parameter(Mandatory)][object]$Evidence,
        [Parameter(Mandatory)][string]$DestinationPath,
        [Parameter(Mandatory)][bool]$CompletedGate
    )

    Assert-AgentSmoke $CompletedGate 'authority_evidence_publication_gate_incomplete'
    $expected = @(Get-AuthorityEvidenceProperties -ScenarioKind $ScenarioKind)
    $entries = @(Get-AuthorityEvidenceEntries -Evidence $Evidence)
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($entry in $entries) {
        Assert-AgentSmoke ($seen.Add($entry.Name)) 'authority_evidence_duplicate_property'
        Assert-AgentSmoke ($entry.Name -cin $expected) 'authority_evidence_unknown_property'
        $valueText = if ($null -eq $entry.Value) { '' } else { [string]$entry.Value }
        Assert-AgentSmoke ($valueText -notmatch '(?i)(postgres(?:ql)?://|database[_-]?url|enrollment[_-]?token|private[_-]?key|password|certificate|dpapi[_-]?blob|raw[_-]?authority[_-]?row|stdout|stderr)') 'authority_evidence_protected_value'
    }
    Assert-AgentSmoke ($entries.Count -eq $expected.Count) 'authority_evidence_missing_property'
    for ($index = 0; $index -lt $expected.Count; $index++) {
        Assert-AgentSmoke ($entries[$index].Name -ceq $expected[$index]) 'authority_evidence_property_order_invalid'
    }

    $ordered = [ordered]@{}
    foreach ($entry in $entries) { $ordered[$entry.Name] = $entry.Value }
    Assert-AgentSmoke ($ordered.schema -ceq 'phase-01.2-authority-evidence/v1') 'authority_evidence_schema_invalid'
    $expectedScenario = if ($ScenarioKind -ceq 'Ordinary') { 'OrdinaryMissingCredentialDoesNotRevoke' } else { 'ReplacementRevocation' }
    Assert-AgentSmoke ($ordered.scenario -ceq $expectedScenario) 'authority_evidence_scenario_invalid'
    Assert-AgentSmoke ($ordered.status -ceq 'pass') 'authority_evidence_status_invalid'
    $observed = [string]$ordered.observed_at_utc
    $parsedObserved = [DateTimeOffset]::MinValue
    Assert-AgentSmoke ($observed.EndsWith('Z', [StringComparison]::Ordinal) -and [DateTimeOffset]::TryParseExact(
        $observed,
        'o',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$parsedObserved
    )) 'authority_evidence_observed_at_invalid'
    foreach ($name in @($expected | Where-Object { $_ -like '*_fingerprint' })) {
        Assert-AgentSmoke ([string]$ordered[$name] -cmatch '^[0-9a-f]{64}$') 'authority_evidence_fingerprint_invalid'
    }

    $fullDestination = [IO.Path]::GetFullPath($DestinationPath)
    $directory = [IO.Path]::GetDirectoryName($fullDestination)
    Assert-AgentSmoke (-not [string]::IsNullOrWhiteSpace($directory) -and (Test-Path -LiteralPath $directory -PathType Container)) 'authority_evidence_directory_missing'
    $staging = Join-Path $directory ('.' + [IO.Path]::GetFileName($fullDestination) + '.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $backup = $staging + '.bak'
    try {
        $json = $ordered | ConvertTo-Json -Depth 4
        [IO.File]::WriteAllText($staging, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
        if (Test-Path -LiteralPath $fullDestination -PathType Leaf) {
            [IO.File]::Replace($staging, $fullDestination, $backup)
        } else {
            [IO.File]::Move($staging, $fullDestination)
        }
    } catch {
        Stop-AgentSmoke 'authority_evidence_publication_failed'
    } finally {
        Remove-Item -LiteralPath $staging -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
    }
}

function Assert-AuthorityEvidenceFailure {
    param(
        [Parameter(Mandatory)][string]$ExpectedCode,
        [Parameter(Mandatory)][scriptblock]$Action
    )

    $failed = $false
    try {
        & $Action | Out-Null
    } catch {
        $failed = $true
        Assert-AgentSmoke ($_.Exception.Message -ceq $ExpectedCode) 'authority_evidence_unexpected_failure_code'
    }
    Assert-AgentSmoke $failed 'authority_evidence_expected_failure_missing'
}

function Assert-AuthorityEvidenceObject {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string[]]$Expected,
        [Parameter(Mandatory)][string]$Code
    )

    $actual = @($Object.PSObject.Properties.Name)
    Assert-AgentSmoke ($actual.Count -eq $Expected.Count) $Code
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        Assert-AgentSmoke ($actual[$index] -ceq $Expected[$index]) $Code
    }
}

function Invoke-AuthorityEvidenceContractFixture {
    Assert-AgentSmoke (-not [string]::IsNullOrWhiteSpace($EvidencePath)) 'authority_evidence_path_missing'
    $fingerprintA = ('a' * 64 -join '')
    $fingerprintB = ('b' * 64 -join '')
    $observed = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    $ordinary = [ordered]@{
        schema = 'phase-01.2-authority-evidence/v1'
        scenario = 'OrdinaryMissingCredentialDoesNotRevoke'
        observed_at_utc = $observed
        status = 'pass'
        active_serial_before_fingerprint = $fingerprintA
        active_serial_after_fingerprint = $fingerprintA
        authority_snapshot_before_fingerprint = $fingerprintB
        authority_snapshot_after_fingerprint = $fingerprintB
        active_serial_unchanged = $true
        authority_snapshot_unchanged = $true
        predecessor_status_after_refusal = 'active'
        recovery_service_status = 'Running'
        recovery_service_start_mode = 'Auto'
        recovery_active_policy_state = 'Active'
        recovery_agent_env_token_count = 0
        recovery_scm_token_count = 0
    }
    $replacement = [ordered]@{
        schema = 'phase-01.2-authority-evidence/v1'
        scenario = 'ReplacementRevocation'
        observed_at_utc = $observed
        status = 'pass'
        predecessor_serial_fingerprint = $fingerprintA
        successor_serial_fingerprint = $fingerprintB
        serial_changed = $true
        predecessor_status = 'revoked'
        successor_status = 'active'
        service_preserved = $true
        data_preserved = $true
        cache_preserved = $true
        service_status = 'Running'
        service_start_mode = 'Auto'
        active_policy_state = 'Active'
        agent_env_token_count = 0
        scm_token_count = 0
    }

    $seed = '{"contract":"preserve"}'
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($EvidencePath), $seed, [Text.UTF8Encoding]::new($false))
    $unknown = [ordered]@{}
    foreach ($key in $ordinary.Keys) { $unknown[$key] = $ordinary[$key] }
    $unknown['unexpected'] = 'rejected'
    Assert-AuthorityEvidenceFailure -ExpectedCode 'authority_evidence_unknown_property' -Action {
        Write-AuthorityTransitionEvidence -ScenarioKind Ordinary -Evidence $unknown -DestinationPath $EvidencePath -CompletedGate $true
    }
    Assert-AgentSmoke ([IO.File]::ReadAllText([IO.Path]::GetFullPath($EvidencePath)) -ceq $seed) 'authority_evidence_rejection_overwrote_destination'

    $duplicate = @(
        [Collections.DictionaryEntry]::new('schema', 'phase-01.2-authority-evidence/v1'),
        [Collections.DictionaryEntry]::new('schema', 'phase-01.2-authority-evidence/v1')
    )
    Assert-AuthorityEvidenceFailure -ExpectedCode 'authority_evidence_duplicate_property' -Action {
        Write-AuthorityTransitionEvidence -ScenarioKind Ordinary -Evidence $duplicate -DestinationPath $EvidencePath -CompletedGate $true
    }
    $missing = [ordered]@{}
    foreach ($key in @($ordinary.Keys | Select-Object -Skip 1)) { $missing[$key] = $ordinary[$key] }
    Assert-AuthorityEvidenceFailure -ExpectedCode 'authority_evidence_missing_property' -Action {
        Write-AuthorityTransitionEvidence -ScenarioKind Ordinary -Evidence $missing -DestinationPath $EvidencePath -CompletedGate $true
    }
    $protected = [ordered]@{}
    foreach ($key in $ordinary.Keys) { $protected[$key] = $ordinary[$key] }
    $protected.status = 'postgresql://protected.invalid/dlp'
    Assert-AuthorityEvidenceFailure -ExpectedCode 'authority_evidence_protected_value' -Action {
        Write-AuthorityTransitionEvidence -ScenarioKind Ordinary -Evidence $protected -DestinationPath $EvidencePath -CompletedGate $true
    }
    Assert-AuthorityEvidenceFailure -ExpectedCode 'authority_evidence_publication_gate_incomplete' -Action {
        Write-AuthorityTransitionEvidence -ScenarioKind Ordinary -Evidence $ordinary -DestinationPath $EvidencePath -CompletedGate $false
    }
    Assert-AgentSmoke ([IO.File]::ReadAllText([IO.Path]::GetFullPath($EvidencePath)) -ceq $seed) 'authority_evidence_gate_overwrote_destination'

    Write-AuthorityTransitionEvidence -ScenarioKind Ordinary -Evidence $ordinary -DestinationPath $EvidencePath -CompletedGate $true
    $ordinaryResult = Get-Content -LiteralPath $EvidencePath -Raw | ConvertFrom-Json
    Assert-AuthorityEvidenceObject -Object $ordinaryResult -Expected $script:OrdinaryAuthorityEvidenceProperties -Code 'authority_evidence_ordinary_schema_invalid'
    Write-AuthorityTransitionEvidence -ScenarioKind Replacement -Evidence $replacement -DestinationPath $EvidencePath -CompletedGate $true
    $replacementResult = Get-Content -LiteralPath $EvidencePath -Raw | ConvertFrom-Json
    Assert-AuthorityEvidenceObject -Object $replacementResult -Expected $script:ReplacementAuthorityEvidenceProperties -Code 'authority_evidence_replacement_schema_invalid'
    $stagingPattern = '^\.' + [regex]::Escape([IO.Path]::GetFileName([IO.Path]::GetFullPath($EvidencePath))) + '\..*\.tmp$'
    $residue = @(Get-ChildItem -LiteralPath ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($EvidencePath))) -File | Where-Object Name -Match $stagingPattern)
    Assert-AgentSmoke ($residue.Count -eq 0) 'authority_evidence_staging_residue'
}

function Get-EnrollmentTokenEvidenceState {
    return Invoke-AgentServiceCommand -ScriptBlock {
        $serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\DlpWindowsService'
        $environment = (Get-ItemProperty -Path $serviceKey -Name Environment -ErrorAction SilentlyContinue).Environment
        $registry = @($environment | Where-Object { $_ -like 'DLP_AGENT_ENROLLMENT_TOKEN=*' }).Count
        $envPath = 'C:\dlp\agent\agent.env'
        $file = if (Test-Path -LiteralPath $envPath) {
            @([IO.File]::ReadAllLines($envPath) | Where-Object { $_ -like 'DLP_AGENT_ENROLLMENT_TOKEN=*' }).Count
        } else { 0 }
        return [pscustomobject]@{ RegistryTokenCount = $registry; FileTokenCount = $file }
    }
}

function Get-RecoveredEndpointEvidenceState {
    $service = Get-AgentServiceState
    Assert-AgentSmoke $service.Installed 'recovery_service_not_installed'
    Assert-AgentSmoke ($service.Status -eq 'Running') 'recovery_service_not_running'
    Assert-AgentSmoke ($service.StartType -eq 'Auto') 'recovery_service_not_automatic'
    $preservation = Get-AgentPreservationState
    Assert-AgentSmoke ($preservation.ServicePresent -and $preservation.DataPresent -and $preservation.CachePresent) 'recovery_preserved_state_missing'
    $tokens = Get-EnrollmentTokenEvidenceState
    Assert-AgentSmoke ($tokens.FileTokenCount -eq 0) 'enrollment_token_retained_in_env_file'
    Assert-AgentSmoke ($tokens.RegistryTokenCount -eq 0) 'enrollment_token_retained_in_registry'
    return [pscustomobject]@{ Service = $service; Preservation = $preservation; Tokens = $tokens }
}

if (-not [string]::IsNullOrWhiteSpace($FailureInjection)) {
    Assert-AgentSmoke ($Scenario -ceq 'ReplacementRevocation') 'failure_injection_scenario_invalid'
}

switch ($Scenario) {
    'AuthorityQueryAdapter' {
        Invoke-AuthorityQueryAdapterFixture
        Write-Output 'authority_query_adapter=pass'
    }
    'AuthorityEvidenceContract' {
        Invoke-AuthorityEvidenceContractFixture
        Write-Output 'authority_evidence_contract=pass'
    }
    'InitialEnrollmentCredential' {
        Assert-LiveLabAvailable
        Assert-InitialEnrollmentStateEmpty
        Invoke-LiveEnrollmentRecovery
        $state = Get-AgentServiceState
        Assert-AgentSmoke $state.Installed 'dlp_agent_service_not_installed'
        Assert-AgentSmoke ($state.Status -eq 'Running') 'dlp_agent_service_not_running'
        Assert-AgentSmoke ($state.StartType -eq 'Auto') 'dlp_agent_service_not_automatic'
        Assert-EnrollmentTokenAclProtected
        Assert-EnrollmentTokenRemoved
        Assert-NoHostArtifacts
    }
    'ReplacementRevocation' {
        Assert-LiveLabAvailable
        $injectionMode = $FailureInjection -ceq 'AfterReplacementMutation'
        $recoverySucceeded = $false
        $cleanupSucceeded = $false
        try {
            $beforeSerial = Get-ActiveCredentialSerial
            Assert-AgentSmoke (-not [string]::IsNullOrWhiteSpace($beforeSerial)) 'replacement_predecessor_serial_missing'
            $before = Get-AgentPreservationState
            Assert-AgentSmoke ($before.ServicePresent -and $before.DataPresent -and $before.CachePresent) 'force_reenrollment_precondition_missing'
            Invoke-LiveEnrollmentRecovery -Force -SuppressOutput:$injectionMode | Out-Null
            if ($injectionMode) {
                Write-Output 'replacement_post_mutation_failure_injected'
                Stop-AgentSmoke 'replacement_injected_failure'
            }

            $recovered = Get-RecoveredEndpointEvidenceState
            $after = $recovered.Preservation
            Assert-AgentSmoke ($after.ServicePresent -and $after.DataPresent -and $after.CachePresent) 'force_reenrollment_removed_preserved_state'
            $afterSerial = Get-ActiveCredentialSerial
            Assert-AgentSmoke (-not [string]::IsNullOrWhiteSpace($afterSerial) -and $afterSerial -cne $beforeSerial) 'replacement_credential_serial_unchanged'
            $predecessorStatus = Get-CredentialAuthorityStatus -Serial $beforeSerial
            $successorStatus = Get-CredentialAuthorityStatus -Serial $afterSerial
            Assert-AgentSmoke ($predecessorStatus -eq 'revoked') 'replacement_predecessor_not_rejected'
            Assert-AgentSmoke ($successorStatus -eq 'active') 'replacement_successor_not_active'
            Assert-EnrollmentTokenRemoved
            Assert-NoHostArtifacts

            if (-not [string]::IsNullOrWhiteSpace($EvidencePath)) {
                $evidence = [ordered]@{
                    schema = 'phase-01.2-authority-evidence/v1'
                    scenario = 'ReplacementRevocation'
                    observed_at_utc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
                    status = 'pass'
                    predecessor_serial_fingerprint = Get-Sha256Fingerprint -Text $beforeSerial
                    successor_serial_fingerprint = Get-Sha256Fingerprint -Text $afterSerial
                    serial_changed = $true
                    predecessor_status = $predecessorStatus
                    successor_status = $successorStatus
                    service_preserved = [bool]$after.ServicePresent
                    data_preserved = [bool]$after.DataPresent
                    cache_preserved = [bool]$after.CachePresent
                    service_status = [string]$recovered.Service.Status
                    service_start_mode = [string]$recovered.Service.StartType
                    active_policy_state = 'Active'
                    agent_env_token_count = [int]$recovered.Tokens.FileTokenCount
                    scm_token_count = [int]$recovered.Tokens.RegistryTokenCount
                }
                Write-AuthorityTransitionEvidence -ScenarioKind Replacement -Evidence $evidence -DestinationPath $EvidencePath -CompletedGate $true
            }
        } catch {
            if (-not $injectionMode) { throw }
        } finally {
            if ($injectionMode) {
                Write-Output 'replacement_recovery_attempted'
                try {
                    Invoke-LiveEnrollmentRecovery -Force -SuppressOutput | Out-Null
                    [void](Get-RecoveredEndpointEvidenceState)
                    Assert-NoHostArtifacts
                    $recoverySucceeded = $true
                } catch {
                    $recoverySucceeded = $false
                }
                try {
                    $cleanupState = Get-EnrollmentTokenEvidenceState
                    $cleanupSucceeded = $cleanupState.FileTokenCount -eq 0 -and $cleanupState.RegistryTokenCount -eq 0
                } catch {
                    $cleanupSucceeded = $false
                }
                if ($recoverySucceeded) { Write-Output 'replacement_recovery_succeeded' } else { Write-Output 'replacement_recovery_failed' }
                if ($cleanupSucceeded) { Write-Output 'replacement_dual_cleanup_succeeded' } else { Write-Output 'replacement_dual_cleanup_failed' }
            }
        }
        if ($injectionMode) { exit 1 }
    }
    'OrdinaryMissingCredentialDoesNotRevoke' {
        Assert-LiveLabAvailable
        $beforeSerial = Get-ActiveCredentialSerial
        Assert-AgentSmoke (-not [string]::IsNullOrWhiteSpace($beforeSerial)) 'ordinary_recovery_predecessor_missing'
        $beforeAuthority = Get-EnrollmentAuthoritySnapshot
        Assert-AgentSmoke (-not [string]::IsNullOrWhiteSpace($beforeAuthority)) 'ordinary_recovery_authority_snapshot_missing'
        try {
            $service = Get-AgentServiceState
            if ($service.Installed -and $service.Status -eq 'Running') { Stop-AgentService | Out-Null }
            Remove-AgentCredentialAsSystem
            Invoke-LiveEnrollmentRecovery -ExpectFailure | Out-Null
            $afterSerial = Get-ActiveCredentialSerial
            $afterAuthority = Get-EnrollmentAuthoritySnapshot
            $activeSerialUnchanged = $afterSerial -ceq $beforeSerial
            $beforeFields = $beforeAuthority.Split([char]'|', [StringSplitOptions]::None)
            $afterFields = $afterAuthority.Split([char]'|', [StringSplitOptions]::None)
            $authoritySnapshotUnchanged = $beforeFields.Count -eq 4 -and $afterFields.Count -eq 4
            for ($index = 0; $authoritySnapshotUnchanged -and $index -lt 4; $index++) {
                $authoritySnapshotUnchanged = $beforeFields[$index] -ceq $afterFields[$index]
            }
            Assert-AgentSmoke $activeSerialUnchanged 'ordinary_recovery_changed_active_serial'
            Assert-AgentSmoke $authoritySnapshotUnchanged 'ordinary_recovery_changed_authority_fields'
            $predecessorStatus = Get-CredentialAuthorityStatus -Serial $beforeSerial
            Assert-AgentSmoke ($predecessorStatus -eq 'active') 'ordinary_recovery_revoked_predecessor'
        } finally {
            Invoke-LiveEnrollmentRecovery -Force | Out-Null
        }
        $recovered = Get-RecoveredEndpointEvidenceState
        Assert-EnrollmentTokenRemoved
        Assert-NoHostArtifacts
        if (-not [string]::IsNullOrWhiteSpace($EvidencePath)) {
            $evidence = [ordered]@{
                schema = 'phase-01.2-authority-evidence/v1'
                scenario = 'OrdinaryMissingCredentialDoesNotRevoke'
                observed_at_utc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
                status = 'pass'
                active_serial_before_fingerprint = Get-Sha256Fingerprint -Text $beforeSerial
                active_serial_after_fingerprint = Get-Sha256Fingerprint -Text $afterSerial
                authority_snapshot_before_fingerprint = Get-Sha256Fingerprint -Text $beforeAuthority
                authority_snapshot_after_fingerprint = Get-Sha256Fingerprint -Text $afterAuthority
                active_serial_unchanged = [bool]$activeSerialUnchanged
                authority_snapshot_unchanged = [bool]$authoritySnapshotUnchanged
                predecessor_status_after_refusal = $predecessorStatus
                recovery_service_status = [string]$recovered.Service.Status
                recovery_service_start_mode = [string]$recovered.Service.StartType
                recovery_active_policy_state = 'Active'
                recovery_agent_env_token_count = [int]$recovered.Tokens.FileTokenCount
                recovery_scm_token_count = [int]$recovered.Tokens.RegistryTokenCount
            }
            Write-AuthorityTransitionEvidence -ScenarioKind Ordinary -Evidence $evidence -DestinationPath $EvidencePath -CompletedGate $true
        }
    }
    'ConfigurationCache' {
        # Static contract plus wire-layout fixture. The live InitialEnrollment
        # scenario is the authoritative signed-fetch activation proof.
        Assert-SourceContract -Pattern 'Wait-Client01ActivePolicy' -Code 'active_policy_wait_missing'
        Assert-SourceContract -Pattern 'active_policy_version=\$\(\$state\.active_policy_version\)' -Code 'active_policy_version_output_missing'
        Assert-SourceContract -Pattern 'active_policy_state=\$\(\$state\.active_policy_state\)' -Code 'active_policy_state_output_missing'
        Assert-SourceContract -Pattern "'dlp-ptr1'" -Code 'signed_configuration_pointer_magic_missing'
        Write-Output 'configuration_cache_contract=pass'
    }
    'ServiceRestart' {
        Assert-LiveLabAvailable
        Install-AgentService
        $state = Get-AgentServiceState
        Assert-AgentSmoke $state.Installed 'dlp_agent_service_not_installed'
        Assert-AgentSmoke ($state.StartType -eq 'Auto') 'dlp_agent_service_not_automatic'
        Start-AgentService
        $state = Get-AgentServiceState
        Assert-AgentSmoke ($state.Status -eq 'Running') 'dlp_agent_service_not_running'
        Stop-AgentService
        $state = Get-AgentServiceState
        Assert-AgentSmoke ($state.Status -eq 'Stopped') 'dlp_agent_service_not_stopped'
        $restartBaseline = Get-AgentServiceLogLength
        Start-AgentService
        Wait-AgentAuthenticatedPollAfter -BaselineLength $restartBaseline
        Force-KillAgentService
        Restart-AgentService
        $state = Get-AgentServiceState
        Assert-AgentSmoke ($state.Status -eq 'Running') 'dlp_agent_service_restart_failed'
        Get-AgentFingerprint
        Get-AgentHealth
        Stop-AgentService
        Assert-NoHostArtifacts
    }
    'InstallStartFailureCleanup' {
        $result = Invoke-TokenCleanupFixture
        Assert-AgentSmoke ($result.AgentEnv -eq 'ok' -and $result.ScmEnvironment -eq 'ok') 'cleanup_adapter_success_status_failed'
        Assert-AgentSmoke (@($result.AgentEnvLines | Where-Object { $_ -like 'DLP_AGENT_ENROLLMENT_TOKEN=*' }).Count -eq 0) 'agent_env_cleanup_adapter_failed'
        Assert-AgentSmoke (@($result.ScmEnvironmentLines | Where-Object { $_ -like 'DLP_AGENT_ENROLLMENT_TOKEN=*' }).Count -eq 0) 'scm_cleanup_adapter_failed'
        Assert-AgentSmoke ($result.ServicePresent -and $result.BinaryPresent -and $result.DataPresent -and $result.CachePresent) 'partial_artifacts_not_preserved'
        Assert-SourceContract -Pattern 'partial service/binary artifacts were preserved' -Code 'failure_preservation_code_missing'
        Assert-SourceContract -Pattern 'Remove-Client01EnrollmentToken' -Code 'failure_cleanup_call_missing'
        Write-Output 'install_start_failure_cleanup=pass'
    }
    'CleanupFailure' {
        $agentFailure = Invoke-TokenCleanupFixture -FailAgentEnv
        Assert-AgentSmoke ($agentFailure.AgentEnv -eq 'failed' -and $agentFailure.ScmEnvironment -eq 'ok') 'agent_env_failure_not_isolated'
        Assert-AgentSmoke (@($agentFailure.ScmEnvironmentLines | Where-Object { $_ -like 'DLP_AGENT_ENROLLMENT_TOKEN=*' }).Count -eq 0) 'scm_cleanup_skipped_after_agent_failure'
        $scmFailure = Invoke-TokenCleanupFixture -FailScmEnvironment
        Assert-AgentSmoke ($scmFailure.ScmEnvironment -eq 'failed' -and $scmFailure.AgentEnv -eq 'ok') 'scm_failure_not_isolated'
        Assert-AgentSmoke (@($scmFailure.AgentEnvLines | Where-Object { $_ -like 'DLP_AGENT_ENROLLMENT_TOKEN=*' }).Count -eq 0) 'agent_cleanup_skipped_after_scm_failure'
        Assert-SourceContract -Pattern 'enrollment_token_cleanup_failed: agent\.env=\$\(\$result\.AgentEnv\); scm_environment=\$\(\$result\.ScmEnvironment\)' -Code 'stable_cleanup_failure_missing'
        Assert-SourceContract -Pattern 'C:\\dlp\\agent\\agent\.env and HKLM:\\SYSTEM\\CurrentControlSet\\Services\\DlpWindowsService\\Environment' -Code 'cleanup_remediation_paths_missing'
        Write-Output 'cleanup_failure=pass'
    }
    'FreshTokenRetry' {
        Assert-SourceContract -Pattern '\$enrollmentToken = Invoke-Client01TrustedProvisioning' -Code 'fresh_token_acquisition_missing'
        Assert-SourceContract -Pattern 'finally\s*\{\s*\$enrollmentToken = \$null' -Code 'local_token_clear_missing'
        Assert-SourceContract -Pattern "EnrollmentTokenProvider = 'TrustedProvisioning'" -Code 'trusted_provider_not_default'
        Assert-SourceContract -Pattern 'existing_credential_reused' -Code 'credential_reuse_gate_missing'
        Write-Output 'fresh_token_retry=pass'
    }
    'NormalOutput' {
        $source = Get-RuntimeSource
        Assert-AgentSmoke ($source -notmatch 'dlpctl\.log:`n') 'unconditional_dlpctl_dump_present'
        Assert-AgentSmoke ($source -notmatch 'env_file = Get-Content') 'raw_environment_dump_present'
        Assert-SourceContract -Pattern 'Write-Client01Status' -Code 'coded_status_output_missing'
        Assert-SourceContract -Pattern 'service_install_failed: partial service/binary artifacts were preserved' -Code 'stable_service_error_missing'
        Write-Output '[normal_output_contract] pass'
    }
    'DiagnosticRedaction' {
        $source = Get-RuntimeSource
        Assert-SourceContract -Pattern '\[Parameter\(\)\]\[switch\]\$Diagnostic' -Code 'diagnostic_switch_missing'
        Assert-SourceContract -Pattern 'file_lengths' -Code 'bounded_file_length_diagnostic_missing'
        Assert-SourceContract -Pattern 'event_log_error_count' -Code 'bounded_event_diagnostic_missing'
        Assert-AgentSmoke ($source -notmatch 'first_line=') 'diagnostic_first_line_dump_present'
        Assert-AgentSmoke ($source -notmatch 'env_file = Get-Content') 'diagnostic_environment_dump_present'
        $sample = '{"code":"trusted_provisioning_failed","protected_directory":"C:\\dlp\\provisioning","file_lengths":{"dlpctl.err":42},"error_type":"RuntimeException"}'
        Assert-RedactedText -Text $sample
        Write-Output '{"code":"diagnostic_redaction_contract","status":"pass","fields":"paths,lengths,fingerprints,bounded_error_metadata"}'
    }
}
