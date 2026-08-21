[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$modulePath = Join-Path $repoRoot 'scripts/evidence/Phase1.Evidence.psm1'
Import-Module $modulePath -Force

$global:ClosurePath = Join-Path $repoRoot 'evidence/phase1/security-closure.yaml'
$global:VerifierPath = Join-Path $repoRoot 'scripts/verify-phase1-security.ps1'
$global:SecurityPath = Join-Path $repoRoot '.planning/phases/01-first-encrypted-drive-vertical-slice/01-SECURITY.md'
$global:MatrixPath = Join-Path $repoRoot 'evidence/phase1/requirement-matrix.yaml'

function Get-Phase1Sha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { ([System.BitConverter]::ToString($sha.ComputeHash([System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path))))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function New-TempClosureWorkspace {
    [CmdletBinding()]
    param([switch]$IncludeSecurity)
    $temp = Join-Path $env:TEMP ('security-closure-' + [guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $temp | Out-Null
    Copy-Item -LiteralPath $global:ClosurePath -Destination (Join-Path $temp 'security-closure.yaml')
    if ($IncludeSecurity) { Copy-Item -LiteralPath $global:SecurityPath -Destination (Join-Path $temp '01-SECURITY.md') }
    return $temp
}

function Invoke-SecurityVerifier {
    [CmdletBinding()]
    param([string]$ClosurePath, [string]$SecurityPath, [switch]$RequireSignedOff, [string]$ThreatId)
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $global:VerifierPath, '-ClosurePath', $ClosurePath)
    if ($SecurityPath) { $argList += @('-SecurityPath', $SecurityPath) }
    if ($RequireSignedOff) { $argList += '-RequireSignedOff' }
    if ($ThreatId) { $argList += @('-ThreatId', $ThreatId) }
    $outFile = Join-Path $env:TEMP ('security-verifier-stdout-' + [guid]::NewGuid().ToString() + '.txt')
    $errFile = Join-Path $env:TEMP ('security-verifier-stderr-' + [guid]::NewGuid().ToString() + '.txt')
    try {
        $proc = Start-Process -FilePath powershell -ArgumentList $argList -NoNewWindow -Wait -PassThru -RedirectStandardOutput $outFile -RedirectStandardError $errFile
        $output = ((Get-Content -LiteralPath $outFile -Raw) + [Environment]::NewLine + (Get-Content -LiteralPath $errFile -Raw)).Trim()
        if ($proc.ExitCode -ne 0) { Write-Host "Verifier output: $output" }
        return $proc.ExitCode
    }
    finally {
        Remove-Item -LiteralPath $outFile -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $errFile -ErrorAction SilentlyContinue
    }
}

BeforeAll {
    if (-not (Test-Path -LiteralPath $global:ClosurePath)) { throw "Canonical closure manifest is missing: $global:ClosurePath" }
    if (-not (Test-Path -LiteralPath $global:VerifierPath)) { throw "Security verifier is missing: $global:VerifierPath" }
    if (-not (Test-Path -LiteralPath $global:MatrixPath)) { throw "Requirement matrix is missing: $global:MatrixPath" }
    $global:CanonicalClosureHash = Get-Phase1Sha256 -Path $global:ClosurePath
    $global:CanonicalSecurityHash = if (Test-Path -LiteralPath $global:SecurityPath) { Get-Phase1Sha256 -Path $global:SecurityPath } else { $null }
    $global:CanonicalMatrixHash = Get-Phase1Sha256 -Path $global:MatrixPath
}

Describe 'Phase 1 Security Closure Tracer (T-01-15-01)' {
    It 'T-01-15-01 passes with implemented mitigation, current passing attempt, LAB-CLIENT01 role, and matching artifact hashes' {
        $exit = Invoke-SecurityVerifier -ClosurePath $global:ClosurePath -ThreatId T-01-15-01
        $exit | Should -Be 0
    }

    It 'rejects a tampered threat ID in a closure record' {
        $temp = New-TempClosureWorkspace
        try {
            $path = Join-Path $temp 'security-closure.yaml'
            $yaml = Get-Content -LiteralPath $path -Raw
            $tampered = $yaml -replace 'threat_id: T-01-15-01', 'threat_id: T-01-15-99'
            [System.IO.File]::WriteAllText($path, $tampered, (New-Object System.Text.UTF8Encoding($false)))
            $exit = Invoke-SecurityVerifier -ClosurePath $path -ThreatId T-01-15-99
            $exit | Should -Not -Be 0
        }
        finally { Remove-Item -LiteralPath $temp -Recurse -Force }
    }

    It 'rejects a non-mitigate disposition in a closure record' {
        $temp = New-TempClosureWorkspace
        try {
            $path = Join-Path $temp 'security-closure.yaml'
            $yaml = Get-Content -LiteralPath $path -Raw
            $tampered = $yaml -replace 'disposition: mitigate', 'disposition: accept_risk'
            [System.IO.File]::WriteAllText($path, $tampered, (New-Object System.Text.UTF8Encoding($false)))
            $exit = Invoke-SecurityVerifier -ClosurePath $path -ThreatId T-01-15-01
            $exit | Should -Not -Be 0
        }
        finally { Remove-Item -LiteralPath $temp -Recurse -Force }
    }

    It 'rejects a wrong machine role for a session/IPC/store-key closure' {
        $temp = New-TempClosureWorkspace
        try {
            $path = Join-Path $temp 'security-closure.yaml'
            $yaml = Get-Content -LiteralPath $path -Raw
            $tampered = $yaml -replace 'LAB-CLIENT01:endpoint_runtime', 'hungdinh-lt:developer_orchestrator'
            [System.IO.File]::WriteAllText($path, $tampered, (New-Object System.Text.UTF8Encoding($false)))
            $exit = Invoke-SecurityVerifier -ClosurePath $path -ThreatId T-01-15-01
            $exit | Should -Not -Be 0
        }
        finally { Remove-Item -LiteralPath $temp -Recurse -Force }
    }

    It 'rejects a mismatched artifact hash' {
        $temp = New-TempClosureWorkspace
        try {
            $path = Join-Path $temp 'security-closure.yaml'
            $yaml = Get-Content -LiteralPath $path -Raw
            $tampered = $yaml -replace 'sha256: [a-f0-9]{64}', 'sha256: 0000000000000000000000000000000000000000000000000000000000000000'
            [System.IO.File]::WriteAllText($path, $tampered, (New-Object System.Text.UTF8Encoding($false)))
            $exit = Invoke-SecurityVerifier -ClosurePath $path -ThreatId T-01-15-01
            $exit | Should -Not -Be 0
        }
        finally { Remove-Item -LiteralPath $temp -Recurse -Force }
    }

    It 'rejects a missing artifact path' {
        $temp = New-TempClosureWorkspace
        try {
            $path = Join-Path $temp 'security-closure.yaml'
            $yaml = Get-Content -LiteralPath $path -Raw
            $tampered = $yaml -replace 'path: crates/dlp-windows-service/src/session.rs', 'path: crates/dlp-windows-service/src/nonexistent.rs'
            [System.IO.File]::WriteAllText($path, $tampered, (New-Object System.Text.UTF8Encoding($false)))
            $exit = Invoke-SecurityVerifier -ClosurePath $path -ThreatId T-01-15-01
            $exit | Should -Not -Be 0
        }
        finally { Remove-Item -LiteralPath $temp -Recurse -Force }
    }

    It 'rejects a closure record containing a token pattern' {
        $temp = New-TempClosureWorkspace
        try {
            $path = Join-Path $temp 'security-closure.yaml'
            $yaml = Get-Content -LiteralPath $path -Raw
            $tampered = $yaml -replace 'mitigation_assertion:', "mitigation_assertion: 'api_key=secret123 '"
            [System.IO.File]::WriteAllText($path, $tampered, (New-Object System.Text.UTF8Encoding($false)))
            $exit = Invoke-SecurityVerifier -ClosurePath $path -ThreatId T-01-15-01
            $exit | Should -Not -Be 0
        }
        finally { Remove-Item -LiteralPath $temp -Recurse -Force }
    }

    It 'rejects a closure record containing a private key pattern' {
        $temp = New-TempClosureWorkspace
        try {
            $path = Join-Path $temp 'security-closure.yaml'
            $yaml = Get-Content -LiteralPath $path -Raw
            $tampered = $yaml -replace 'mitigation_assertion:', "mitigation_assertion: 'private_key=ABCD '"
            [System.IO.File]::WriteAllText($path, $tampered, (New-Object System.Text.UTF8Encoding($false)))
            $exit = Invoke-SecurityVerifier -ClosurePath $path -ThreatId T-01-15-01
            $exit | Should -Not -Be 0
        }
        finally { Remove-Item -LiteralPath $temp -Recurse -Force }
    }

    It 'rejects a closure record containing a protected plaintext pattern' {
        $temp = New-TempClosureWorkspace
        try {
            $path = Join-Path $temp 'security-closure.yaml'
            $yaml = Get-Content -LiteralPath $path -Raw
            $tampered = $yaml -replace 'mitigation_assertion:', "mitigation_assertion: 'protected plaintext leak '"
            [System.IO.File]::WriteAllText($path, $tampered, (New-Object System.Text.UTF8Encoding($false)))
            $exit = Invoke-SecurityVerifier -ClosurePath $path -ThreatId T-01-15-01
            $exit | Should -Not -Be 0
        }
        finally { Remove-Item -LiteralPath $temp -Recurse -Force }
    }

    It 'rejects a closure record containing an unnecessary sensitive path' {
        $temp = New-TempClosureWorkspace
        try {
            $path = Join-Path $temp 'security-closure.yaml'
            $yaml = Get-Content -LiteralPath $path -Raw
            $tampered = $yaml -replace 'mitigation_assertion:', "mitigation_assertion: 'path C:\\Users\\secret-user\\data contains protected plaintext'"
            [System.IO.File]::WriteAllText($path, $tampered, (New-Object System.Text.UTF8Encoding($false)))
            $exit = Invoke-SecurityVerifier -ClosurePath $path -ThreatId T-01-15-01
            $exit | Should -Not -Be 0
        }
        finally { Remove-Item -LiteralPath $temp -Recurse -Force }
    }
}

AfterAll {
    $closureHash = Get-Phase1Sha256 -Path $global:ClosurePath
    $closureHash | Should -Be $global:CanonicalClosureHash
    $matrixHash = Get-Phase1Sha256 -Path $global:MatrixPath
    $matrixHash | Should -Be $global:CanonicalMatrixHash
    if ($global:CanonicalSecurityHash) {
        $securityHash = Get-Phase1Sha256 -Path $global:SecurityPath
        $securityHash | Should -Be $global:CanonicalSecurityHash
    }
}
