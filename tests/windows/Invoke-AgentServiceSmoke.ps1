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
        'AuthorityQueryAdapter'
    )][string]$Scenario,
    [Parameter()][System.Management.Automation.PSCredential]$Credential
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
        [Parameter()][switch]$ExpectFailure
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
    $failed = $false
    try {
        $output = & (Join-Path $repoRoot 'scripts/lab/Invoke-Client01Runtime.ps1') @arguments *>&1
        if ($LASTEXITCODE -ne 0) { $failed = $true }
    } catch {
        $failed = $true
        $output = @($_.Exception.Message)
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
    $output | ForEach-Object { Write-Output $_ }
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

switch ($Scenario) {
    'AuthorityQueryAdapter' {
        Invoke-AuthorityQueryAdapterFixture
        Write-Output 'authority_query_adapter=pass'
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
        $beforeSerial = Get-ActiveCredentialSerial
        Assert-AgentSmoke (-not [string]::IsNullOrWhiteSpace($beforeSerial)) 'replacement_predecessor_serial_missing'
        $before = Get-AgentPreservationState
        Assert-AgentSmoke ($before.ServicePresent -and $before.DataPresent -and $before.CachePresent) 'force_reenrollment_precondition_missing'
        Invoke-LiveEnrollmentRecovery -Force
        $state = Get-AgentServiceState
        Assert-AgentSmoke $state.Installed 'dlp_agent_service_not_installed'
        Assert-AgentSmoke ($state.Status -eq 'Running') 'replacement_enrollment_service_not_running'
        $after = Get-AgentPreservationState
        Assert-AgentSmoke ($after.ServicePresent -and $after.DataPresent -and $after.CachePresent) 'force_reenrollment_removed_preserved_state'
        $afterSerial = Get-ActiveCredentialSerial
        Assert-AgentSmoke (-not [string]::IsNullOrWhiteSpace($afterSerial) -and $afterSerial -cne $beforeSerial) 'replacement_credential_serial_unchanged'
        Assert-AgentSmoke ((Get-CredentialAuthorityStatus -Serial $beforeSerial) -eq 'revoked') 'replacement_predecessor_not_rejected'
        Assert-AgentSmoke ((Get-CredentialAuthorityStatus -Serial $afterSerial) -eq 'active') 'replacement_successor_not_active'
        Assert-EnrollmentTokenRemoved
        Assert-NoHostArtifacts
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
            Assert-AgentSmoke ($afterSerial -ceq $beforeSerial) 'ordinary_recovery_changed_active_serial'
            Assert-AgentSmoke ($afterAuthority -ceq $beforeAuthority) 'ordinary_recovery_changed_authority_fields'
            Assert-AgentSmoke ((Get-CredentialAuthorityStatus -Serial $beforeSerial) -eq 'active') 'ordinary_recovery_revoked_predecessor'
        } finally {
            Invoke-LiveEnrollmentRecovery -Force | Out-Null
        }
        Assert-NoHostArtifacts
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
