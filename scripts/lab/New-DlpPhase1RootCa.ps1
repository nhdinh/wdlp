[CmdletBinding()]
param(
    [Parameter()][string]$OutputDirectory = 'C:\dlp\secrets',
    [Parameter()][switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Stop-Generation([string]$Code, [string]$Detail) {
    Write-Host "FAIL: $Code" -ForegroundColor Red
    if ($Detail) { Write-Host $Detail -ForegroundColor Gray }
    exit 1
}

function Invoke-Openssl([string]$Arguments) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo('openssl', $Arguments)
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    if ($proc.ExitCode -ne 0) {
        Stop-Generation 'openssl_failed' "openssl $Arguments`n$stderr"
    }
    return $stdout
}

Write-Host '=== Generate DLP Phase 1 Root CA ===' -ForegroundColor Cyan
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$certPath = Join-Path $OutputDirectory 'phase1-root-ca.pem'
$keyPath = Join-Path $OutputDirectory 'phase1-root-ca-key.pem'
if (((Test-Path -LiteralPath $certPath) -or (Test-Path -LiteralPath $keyPath)) -and -not $Force) {
    Stop-Generation 'phase1_root_ca_already_exists' "Use -Force only when intentionally replacing $certPath and $keyPath. Replacing this root requires redeploying the server certificate and endpoint trust anchor."
}

Invoke-Openssl "genrsa -out `"$keyPath`" 4096" | Out-Null
$extensions = @'
[v3_ca]
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
'@
$extensionsPath = Join-Path $OutputDirectory 'phase1-root-ca-ext.cnf'
[System.IO.File]::WriteAllText($extensionsPath, $extensions, (New-Object System.Text.UTF8Encoding($false)))
try {
    Invoke-Openssl "req -x509 -new -nodes -key `"$keyPath`" -sha256 -days 3650 -subj `"/CN=phase1-root-ca/O=DLP Lab`" -config `"$extensionsPath`" -extensions v3_ca -out `"$certPath`"" | Out-Null
} finally {
    Remove-Item -LiteralPath $extensionsPath -Force -ErrorAction SilentlyContinue
}

Write-Host '=== Phase 1 root CA generated ===' -ForegroundColor Green
Write-Host "Public root certificate: $certPath" -ForegroundColor Gray
Write-Host "Offline root private key: $keyPath" -ForegroundColor Gray
