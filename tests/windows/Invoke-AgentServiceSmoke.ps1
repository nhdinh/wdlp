[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('hungdinh-lt')][string]$CallerMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-CLIENT01')][string]$ExecutionMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-DC01')][string]$ServerMachine,
    [Parameter(Mandatory)][ValidateSet('Runtime')][string]$SecretProvider,
    [Parameter(Mandatory)][ValidateSet('InitialEnrollmentCredential', 'ReplacementRevocation', 'ConfigurationCache', 'ServiceRestart')][string]$Scenario
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
    $service = Get-Service -Name 'dlp-agent' -ErrorAction SilentlyContinue
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
        Invoke-Command -ComputerName $ExecutionMachine -ScriptBlock $ScriptBlock -ErrorAction Stop
    }
    catch {
        Stop-AgentSmoke 'lab_client01_winrm_failed'
    }
}

function Get-AgentServiceState {
    Invoke-AgentServiceCommand -ScriptBlock {
        $svc = Get-Service -Name 'dlp-agent' -ErrorAction SilentlyContinue
        if ($null -eq $svc) { return @{ Installed = $false } }
        return @{
            Installed = $true
            Status    = $svc.Status.ToString()
            StartType = (Get-CimInstance Win32_Service -Filter "Name='dlp-agent'").StartMode
        }
    }
}

function Install-AgentService {
    Invoke-AgentServiceCommand -ScriptBlock {
        $svc = Get-Service -Name 'dlp-agent' -ErrorAction SilentlyContinue
        if ($null -ne $svc) { return @{ Installed = $true; Action = 'already_present' } }
        # The installer path and binary hash are validated by the 01-19 privilege manifest.
        $binary = 'C:/Program Files/DLP/dlp-windows-service.exe'
        if (-not (Test-Path -LiteralPath $binary)) { throw 'agent_binary_missing' }
        New-Service -Name 'dlp-agent' -BinaryPathName "`"$binary`"" -DisplayName 'DLP Agent' -StartupType Automatic -ErrorAction Stop | Out-Null
        return @{ Installed = $true; Action = 'installed' }
    }
}

function Start-AgentService {
    Invoke-AgentServiceCommand -ScriptBlock {
        Start-Service -Name 'dlp-agent' -ErrorAction Stop
        return @{ Status = (Get-Service -Name 'dlp-agent').Status.ToString() }
    }
}

function Stop-AgentService {
    Invoke-AgentServiceCommand -ScriptBlock {
        Stop-Service -Name 'dlp-agent' -Force -ErrorAction Stop
        return @{ Status = (Get-Service -Name 'dlp-agent').Status.ToString() }
    }
}

function Restart-AgentService {
    Invoke-AgentServiceCommand -ScriptBlock {
        Restart-Service -Name 'dlp-agent' -Force -ErrorAction Stop
        return @{ Status = (Get-Service -Name 'dlp-agent').Status.ToString() }
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

switch ($Scenario) {
    'InitialEnrollmentCredential' {
        $state = Get-AgentServiceState
        Assert-AgentSmoke $state.Installed 'dlp_agent_service_not_installed'
        Stop-AgentSmoke 'enrollment_endpoint_stub_503'
    }
    'ReplacementRevocation' {
        $state = Get-AgentServiceState
        Assert-AgentSmoke $state.Installed 'dlp_agent_service_not_installed'
        Stop-AgentSmoke 'enrollment_endpoint_stub_503'
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
