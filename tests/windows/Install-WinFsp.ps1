[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CallerMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-CLIENT01')][string]$ExecutionMachine
)

$ErrorActionPreference = 'Stop'

function Write-Blocker {
    param([Parameter(Mandatory)][string]$Reason)
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $blockerPath = Join-Path $repoRoot 'evidence/phase1/attempts'
    New-Item -ItemType Directory -Force -Path $blockerPath | Out-Null
    $id = [guid]::NewGuid().ToString()
    $record = [pscustomobject]@{
        schema_version    = 'phase1-evidence/v1'
        evidence_id       = $id
        plan_id           = '01-20'
        scenario          = 'InstallWinFsp'
        status            = 'blocked'
        execution_machine = $ExecutionMachine
        caller_machine    = $CallerMachine
        actual_result     = $Reason
        utc               = (Get-Date -Format 'o')
    }
    $path = Join-Path $blockerPath "winfsp-install-${id}.json"
    $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
    Write-Warning "RUNTIME BLOCKER: $Reason (recorded at $path)"
}

if ($ExecutionMachine -ne $env:COMPUTERNAME) {
    if (-not (Test-Connection -ComputerName $ExecutionMachine -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
        Write-Blocker -Reason "${ExecutionMachine} is not reachable from ${CallerMachine}; WinFsp installation must run on the endpoint"
        return
    }
    Invoke-Command -ComputerName $ExecutionMachine -FilePath $PSCommandPath -ArgumentList $CallerMachine, $ExecutionMachine
    return
}

$installerUrl = 'https://github.com/winfsp/winfsp/releases/download/v2.1/winfsp-2.1.25156.msi'
$expectedSha256 = '073a70e00f77423e34bed98b86e600def93393ba5822204fac57a29324db9f7a'
$installer = Join-Path $env:TEMP 'winfsp-2.1.25156-x64.msi'

Invoke-WebRequest -Uri $installerUrl -OutFile $installer -UseBasicParsing
$actualSha256 = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha256 -ne $expectedSha256) {
    throw "WinFsp MSI SHA-256 mismatch; refusing installation."
}

$signature = Get-AuthenticodeSignature -LiteralPath $installer
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Navimatics') {
    throw "WinFsp MSI Authenticode verification failed; refusing installation."
}

Write-Host "Verified WinFsp MSI signer: $($signature.SignerCertificate.Subject)"
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process msiexec.exe -Verb RunAs -Wait -ArgumentList @('/i', "`"$installer`"", '/qn', '/norestart')
} else {
    Start-Process msiexec.exe -Wait -ArgumentList @('/i', "`"$installer`"", '/qn', '/norestart')
}
