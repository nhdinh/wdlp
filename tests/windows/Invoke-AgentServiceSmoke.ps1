[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('hungdinh-lt')][string]$CallerMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-CLIENT01')][string]$ExecutionMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-DC01')][string]$ServerMachine,
    [Parameter(Mandatory)][ValidateSet('Runtime')][string]$SecretProvider,
    [Parameter(Mandatory)][ValidateSet('InitialEnrollmentCredential', 'ReplacementRevocation', 'ConfigurationCache', 'ServiceRestart')][string]$Scenario,
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

# Verify this script only runs from the approved orchestrator host.
Assert-AgentSmoke ($env:COMPUTERNAME -eq 'hungdinh-lt' -and $CallerMachine -eq 'hungdinh-lt') 'caller_machine_denied'
Assert-AgentSmoke ($ExecutionMachine -eq 'LAB-CLIENT01') 'execution_machine_denied'
Assert-AgentSmoke ($ServerMachine -eq 'LAB-DC01') 'server_machine_denied'
Assert-AgentSmoke ($SecretProvider -eq 'Runtime') 'secret_provider_denied'
Assert-NoHostArtifacts

# Runtime secret provider: the token is delivered through an out-of-band
# secret-handoff mechanism and is never logged or persisted by this script.
$token = $null
switch ($SecretProvider) {
    'Runtime' {
        $token = $env:DLP_AGENT_ENROLLMENT_TOKEN
        Assert-AgentSmoke (-not [string]::IsNullOrWhiteSpace($token)) 'runtime_token_missing'
        Assert-AgentSmoke ($token.Length -le 512 -and $token -match '^[A-Za-z0-9]+$') 'runtime_token_format_invalid'
    }
}

# Reachability checks only; no credentials or mutations are sent yet.
$dcReachable = Test-NetConnection -ComputerName $ServerMachine -Port 8443 -WarningAction SilentlyContinue
Assert-AgentSmoke ($dcReachable.TcpTestSucceeded) 'lab_dc01_enrollment_unreachable'

$clientReachable = Test-Connection -ComputerName $ExecutionMachine -Count 1 -Quiet
Assert-AgentSmoke $clientReachable 'lab_client01_unreachable'

function Invoke-AgentServiceCommand {
    param([Parameter(Mandatory)][scriptblock]$ScriptBlock)
    try {
        if ($null -ne $Credential) {
            return Invoke-Command -VMName $ExecutionMachine -Credential $Credential `
                -ScriptBlock $ScriptBlock -ErrorAction Stop
        }

        # LAB-CLIENT01 is a local Hyper-V guest. PowerShell Direct avoids
        # workgroup WinRM/TrustedHosts. The current Hyper-V session is sufficient
        # unless the caller explicitly supplies alternate guest credentials.
        Invoke-Command -VMName $ExecutionMachine -ScriptBlock $ScriptBlock -ErrorAction Stop
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

function Invoke-LiveEnrollmentRecovery {
    & (Join-Path $repoRoot 'scripts/lab/Invoke-Client01Runtime.ps1') `
        -CallerMachine $CallerMachine -ExecutionMachine $ExecutionMachine `
        -ProbeMachine $ServerMachine -SecretProvider Runtime -Scenario Tracer `
        -EnrollmentTokenProvider TrustedProvisioning -Apply
    if ($LASTEXITCODE -ne 0) { Stop-AgentSmoke 'client01_enrollment_tracer_failed' }
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
            & schtasks.exe /Delete /TN $task /F 2>$null | Out-Null
        }
    }
}

function Assert-EnrollmentTokenRemoved {
    $state = Invoke-AgentServiceCommand -ScriptBlock {
        $serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\DlpWindowsService'
        $registry = @((Get-ItemPropertyValue $serviceKey -Name Environment) |
            Where-Object { $_ -like 'DLP_AGENT_ENROLLMENT_TOKEN=*' }).Count
        $file = @([IO.File]::ReadAllLines('C:\dlp\agent\agent.env') |
            Where-Object { $_ -like 'DLP_AGENT_ENROLLMENT_TOKEN=*' }).Count
        return @{ RegistryTokenCount = $registry; FileTokenCount = $file }
    }
    Assert-AgentSmoke ($state.RegistryTokenCount -eq 0) 'enrollment_token_retained_in_registry'
    Assert-AgentSmoke ($state.FileTokenCount -eq 0) 'enrollment_token_retained_in_env_file'
}

switch ($Scenario) {
    'InitialEnrollmentCredential' {
        Invoke-LiveEnrollmentRecovery
        $state = Get-AgentServiceState
        Assert-AgentSmoke $state.Installed 'dlp_agent_service_not_installed'
        Assert-AgentSmoke ($state.Status -eq 'Running') 'dlp_agent_service_not_running'
        Assert-AgentSmoke ($state.StartType -eq 'Auto') 'dlp_agent_service_not_automatic'
        Assert-EnrollmentTokenRemoved
        Assert-NoHostArtifacts
    }
    'ReplacementRevocation' {
        Stop-AgentService
        Remove-AgentCredentialAsSystem
        Invoke-LiveEnrollmentRecovery
        $state = Get-AgentServiceState
        Assert-AgentSmoke $state.Installed 'dlp_agent_service_not_installed'
        Assert-AgentSmoke ($state.Status -eq 'Running') 'replacement_enrollment_service_not_running'
        Assert-EnrollmentTokenRemoved
        Assert-NoHostArtifacts
    }
    'ConfigurationCache' {
        $state = Get-AgentServiceState
        Assert-AgentSmoke $state.Installed 'dlp_agent_service_not_installed'
        # Once reachable, this scenario would stop the service, stage a signed
        # bundle, restart, and assert current/LKG pointer state.
        Stop-AgentSmoke 'configuration_cache_runtime_blocked'
    }
    'ServiceRestart' {
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
        Start-AgentService
        Force-KillAgentService
        Restart-AgentService
        $state = Get-AgentServiceState
        Assert-AgentSmoke ($state.Status -eq 'Running') 'dlp_agent_service_restart_failed'
        Get-AgentFingerprint
        Get-AgentHealth
        Stop-AgentService
        Assert-NoHostArtifacts
    }
}
