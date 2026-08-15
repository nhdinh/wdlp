[CmdletBinding()]
param(
    [ValidateSet('Scripts', 'Docs', 'All')]
    [string]$Suite = 'All'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Initializer = Join-Path $RepoRoot 'scripts/lab/Initialize-DlpEnvironment.ps1'
$ClientRunner = Join-Path $RepoRoot 'scripts/lab/Invoke-Client01Runtime.ps1'
$DocsRoot = Join-Path $RepoRoot '.planning/docs'
$Failures = [System.Collections.Generic.List[string]]::new()

function Assert-True {
    param([Parameter(Mandatory)][bool]$Condition, [Parameter(Mandatory)][string]$Message)
    if (-not $Condition) { $script:Failures.Add($Message) }
}

function Assert-Contains {
    param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)][string]$Pattern, [Parameter(Mandatory)][string]$Message)
    Assert-True -Condition ($Text -match $Pattern) -Message $Message
}

function Assert-Parses {
    param([Parameter(Mandatory)][string]$Path)
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    $errorText = if ($null -ne $errors -and $errors.Count -gt 0) { $errors | ForEach-Object { $_.Message } } else { '' }
    Assert-True -Condition ($null -eq $errors -or $errors.Count -eq 0) -Message "PowerShell parser errors in ${Path}: $($errorText -join '; ')"
}

function Invoke-ScriptsSuite {
    $initializerSource = Get-Content -LiteralPath $Initializer -Raw
    $runnerSource = Get-Content -LiteralPath $ClientRunner -Raw
    Assert-Parses -Path $Initializer
    Assert-Parses -Path $ClientRunner

    Assert-Contains -Text $initializerSource -Pattern '\[switch\]\$NonInteractive' -Message 'Initializer must expose -NonInteractive.'
    Assert-Contains -Text $initializerSource -Pattern 'REPLACE_' -Message 'Initializer must reject replacement markers embedded in values.'
    Assert-Contains -Text $initializerSource -Pattern 'ShouldProcess\(' -Message 'Initializer clear workflow must honor ShouldProcess/WhatIf.'
    Assert-Contains -Text $initializerSource -Pattern 'Clear cannot be combined' -Message 'Initializer must reject incompatible -Clear setup switches.'
    Assert-Contains -Text $initializerSource -Pattern 'Env file.*duplicate|Duplicate.*env' -Message 'Initializer must reject duplicate environment-file keys.'
    Assert-Contains -Text $initializerSource -Pattern 'OutEnvFile.*exists|already exists' -Message 'Initializer must protect existing output files.'

    Assert-Contains -Text $runnerSource -Pattern "'phase1-root-ca\.pem'\s*=\s*Get-Client01SecretValue" -Message 'Client deployment must resolve DLP_ROOT_CA_PEM before writing it.'
    Assert-Contains -Text $runnerSource -Pattern 'BEGIN CERTIFICATE' -Message 'Client deployment must reject non-certificate root-CA input.'
    Assert-Contains -Text $runnerSource -Pattern 'DLP_ROOT_CA_PEM=C:\\dlp\\secrets\\phase1-root-ca\.pem' -Message 'Service environment must keep the deployed root-CA path.'

    $escapedInitializer = $Initializer.Replace("'", "''")
    $clearProbe = @"
`$env:DLP_ENV_GUIDANCE_TEST = 'remove-me'
`$env:ENV_GUIDANCE_SENTINEL = 'keep-me'
& '$escapedInitializer' -Clear -WhatIf | Out-Null
if (`$env:DLP_ENV_GUIDANCE_TEST -ne 'remove-me') { throw 'WhatIf changed a DLP value.' }
if (`$env:ENV_GUIDANCE_SENTINEL -ne 'keep-me') { throw 'WhatIf changed a non-DLP value.' }
& '$escapedInitializer' -Clear | Out-Null
if (`$null -ne `$env:DLP_ENV_GUIDANCE_TEST) { throw 'Clear did not remove its DLP value.' }
if (`$env:ENV_GUIDANCE_SENTINEL -ne 'keep-me') { throw 'Clear removed a non-DLP value.' }
try { & '$escapedInitializer' -Clear -NonInteractive 2>`$null; throw 'Clear accepted an incompatible switch.' } catch { if (`$_.Exception.Message -notmatch 'Clear cannot be combined') { throw } }
Write-Output 'clear-contract-ok'
"@
    $encodedProbe = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($clearProbe))
    $probeOutput = & powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedProbe 2>&1
    Assert-True -Condition ($LASTEXITCODE -eq 0) -Message "Clear contract probe failed: $($probeOutput -join '; ')"
    Assert-True -Condition ([bool]($probeOutput -match 'clear-contract-ok')) -Message 'Clear contract probe did not complete.'
}

function Invoke-DocsSuite {
    $envGuide = Get-Content -LiteralPath (Join-Path $DocsRoot 'ENV-VARS.md') -Raw
    $pkiGuide = Get-Content -LiteralPath (Join-Path $DocsRoot 'PEM-KEY-GUIDE.md') -Raw

    foreach ($name in @('DATABASE_URL', 'DLP_DATABASE_URL', 'DLP_ROOT_CA_PEM', 'DLP_AGENT_ENROLLMENT_TOKEN', 'DLP_ADMIN_PROVISIONING_KEY')) {
        Assert-Contains -Text $envGuide -Pattern ([regex]::Escape($name)) -Message "ENV-VARS.md must classify $name."
    }
    foreach ($pattern in @('0\.0\.0\.0:8080', '0\.0\.0\.0:8443', 'phase1-config-signer', 'phase1-config-signing-key-v1', '300/60/60/10')) {
        Assert-Contains -Text $envGuide -Pattern $pattern -Message "ENV-VARS.md must document $pattern."
    }
    foreach ($pattern in @('separate trust roles', 'basicConstraints = critical, CA:true', 'CA:false', 'serverAuth', 'clientAuth', 'Verify-DlpLabCertificates\.ps1')) {
        Assert-Contains -Text $pkiGuide -Pattern $pattern -Message "PEM-KEY-GUIDE.md must document $pattern."
    }
}

function Invoke-SetupGuideSuite {
    $setupGuide = Get-Content -LiteralPath (Join-Path $DocsRoot 'LAB-SETUP-GUIDE.md') -Raw
    foreach ($link in @('ENV-VARS.md', 'PEM-KEY-GUIDE.md')) {
        Assert-Contains -Text $setupGuide -Pattern ([regex]::Escape($link)) -Message "LAB-SETUP-GUIDE.md must link to $link."
    }
    Assert-Contains -Text $setupGuide -Pattern 'edition 2024' -Message 'LAB-SETUP-GUIDE.md must state Rust edition 2024.'
    Assert-Contains -Text $setupGuide -Pattern 'curl\.exe --cacert' -Message 'LAB-SETUP-GUIDE.md must use a validating TLS health check.'
    Assert-True -Condition ($setupGuide -notmatch 'TrustAllCertsPolicy|CertificatePolicy') -Message 'LAB-SETUP-GUIDE.md must not recommend a trust-all certificate callback.'
}

if ($Suite -in @('Scripts', 'All')) { Invoke-ScriptsSuite }
if ($Suite -in @('Docs', 'All')) { Invoke-DocsSuite }
if ($Suite -eq 'All') { Invoke-SetupGuideSuite }

if ($Failures.Count -gt 0) {
    $Failures | ForEach-Object { Write-Error "FAIL: $_" }
    exit 1
}

Write-Host "EnvironmentGuidance $Suite suite passed."
