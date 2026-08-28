[CmdletBinding()]
param(
    [Parameter()][string]$AgentEnvPath = 'C:\dlp\agent\agent.env',
    [Parameter()][string]$ServiceKeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\DlpWindowsService',
    [Parameter()][scriptblock]$ReadScmEnvironment,
    [Parameter()][scriptblock]$WriteScmEnvironment
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$status = [ordered]@{ AgentEnv = 'ok'; ScmEnvironment = 'ok' }

try {
    $existing = if ($null -ne $ReadScmEnvironment) {
        @(& $ReadScmEnvironment $ServiceKeyPath)
    } else {
        $value = Get-ItemProperty -Path $ServiceKeyPath -Name 'Environment' -ErrorAction SilentlyContinue
        if ($null -eq $value -or $null -eq $value.Environment) { @() } else { @($value.Environment) }
    }
    $cleaned = @($existing | Where-Object { $_ -notlike 'DLP_AGENT_ENROLLMENT_TOKEN=*' })
    if ($null -ne $WriteScmEnvironment) {
        & $WriteScmEnvironment $ServiceKeyPath $cleaned
    } elseif ($existing.Count -gt 0) {
        Set-ItemProperty -Path $ServiceKeyPath -Name 'Environment' -Value $cleaned -Type MultiString -Force
    }
    $remaining = if ($null -ne $ReadScmEnvironment) {
        @(& $ReadScmEnvironment $ServiceKeyPath)
    } else {
        $value = Get-ItemProperty -Path $ServiceKeyPath -Name 'Environment' -ErrorAction SilentlyContinue
        if ($null -eq $value -or $null -eq $value.Environment) { @() } else { @($value.Environment) }
    }
    if (@($remaining | Where-Object { $_ -like 'DLP_AGENT_ENROLLMENT_TOKEN=*' }).Count -ne 0) {
        throw 'token_entry_remains'
    }
} catch {
    $status.ScmEnvironment = 'failed'
}

try {
    if (Test-Path -LiteralPath $AgentEnvPath) {
        $lines = [System.IO.File]::ReadAllLines($AgentEnvPath)
        $cleaned = @($lines | Where-Object { $_ -notlike 'DLP_AGENT_ENROLLMENT_TOKEN=*' })
        $temporaryPath = $AgentEnvPath + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
        try {
            [System.IO.File]::WriteAllLines($temporaryPath, $cleaned, (New-Object System.Text.UTF8Encoding($false)))
            Move-Item -LiteralPath $temporaryPath -Destination $AgentEnvPath -Force -ErrorAction Stop
        } finally {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
        $remaining = @([System.IO.File]::ReadAllLines($AgentEnvPath) |
            Where-Object { $_ -like 'DLP_AGENT_ENROLLMENT_TOKEN=*' }).Count
        if ($remaining -ne 0) { throw 'token_entry_remains' }
    }
} catch {
    $status.AgentEnv = 'failed'
}

return [pscustomobject]$status
