[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('hungdinh-lt')][string]$CallerMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-CLIENT01')][string]$ExecutionMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-DC01')][string]$ServerMachine,
    [Parameter(Mandatory)][ValidateSet('Runtime')][string]$SecretProvider,
    [Parameter(Mandatory)][ValidateSet('InitialEnrollmentCredential', 'ReplacementRevocation')][string]$Scenario
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

# Verify this script only runs from the approved orchestrator host.
Assert-AgentSmoke ($env:COMPUTERNAME -eq 'hungdinh-lt' -and $CallerMachine -eq 'hungdinh-lt') 'caller_machine_denied'
Assert-AgentSmoke ($ExecutionMachine -eq 'LAB-CLIENT01') 'execution_machine_denied'
Assert-AgentSmoke ($ServerMachine -eq 'LAB-DC01') 'server_machine_denied'
Assert-AgentSmoke ($SecretProvider -eq 'Runtime') 'secret_provider_denied'

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

# Verify the agent service is registered on LAB-CLIENT01 before attempting
# enrollment.  This requires WinRM HTTPS/Kerberos from hungdinh-lt.
try {
    $service = Invoke-Command -ComputerName $ExecutionMachine -ScriptBlock {
        Get-Service -Name 'dlp-agent' -ErrorAction SilentlyContinue
    } -ErrorAction Stop
    Assert-AgentSmoke ($null -ne $service) 'dlp_agent_service_not_installed'
}
catch {
    Stop-AgentSmoke 'lab_client01_winrm_failed'
}

# The actual enrollment call is intentionally not attempted here because the
# LAB-DC01 /api/v1/enrollment route is a known Plan 01-22/01-23 stub that
# returns 503 until that server work is wired.  Reaching this point proves the
# endpoint runtime preconditions are satisfied.
Stop-AgentSmoke 'enrollment_endpoint_stub_503'
