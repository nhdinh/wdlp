[CmdletBinding()]
param(
    [Parameter()][string]$OutputDirectory = 'C:\dlp\secrets',
    [Parameter()][switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Stop-Rotate([string]$Code, [string]$Detail) {
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
        Stop-Rotate 'openssl_failed' "openssl $Arguments`n$stderr"
    }
    return $stdout
}

Write-Host '=== Rotate DLP Device-Issuing CA ===' -ForegroundColor Cyan

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$deviceCaCertPath = Join-Path $OutputDirectory 'device-issuing-ca.pem'
$deviceCaKeyPath  = Join-Path $OutputDirectory 'device-issuing-ca-key.pem'

if (((Test-Path -LiteralPath $deviceCaCertPath) -or (Test-Path -LiteralPath $deviceCaKeyPath)) -and -not $Force) {
    Stop-Rotate 'device_ca_already_exists' "Use -Force to overwrite $deviceCaCertPath and $deviceCaKeyPath"
}

Write-Host 'Generating 4096-bit RSA device-issuing CA key...' -ForegroundColor Gray
Invoke-Openssl "genrsa -out `"$deviceCaKeyPath`" 4096" | Out-Null

Write-Host 'Self-signing device-issuing CA certificate with v3_ca extensions...' -ForegroundColor Gray
$caConfig = @'
[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
'@
$caConfigPath = Join-Path $OutputDirectory 'device-issuing-ca-ext.cnf'
[System.IO.File]::WriteAllText($caConfigPath, $caConfig, (New-Object System.Text.UTF8Encoding($false)))
try {
    Invoke-Openssl "req -x509 -new -nodes -key `"$deviceCaKeyPath`" -sha256 -days 3650 -subj `"/CN=device-issuing-ca/O=DLP Lab`" -config `"$caConfigPath`" -extensions v3_ca -out `"$deviceCaCertPath`"" | Out-Null
} finally {
    Remove-Item -LiteralPath $caConfigPath -Force -ErrorAction SilentlyContinue
}

$subject = (Invoke-Openssl "x509 -in `"$deviceCaCertPath`" -noout -subject").Trim()
Write-Host "Device-issuing CA subject: $subject" -ForegroundColor Gray

Write-Host '=== Device-issuing CA rotated ===' -ForegroundColor Green
Write-Host "Device-issuing CA certificate: $deviceCaCertPath" -ForegroundColor Gray
Write-Host "Device-issuing CA private key: $deviceCaKeyPath" -ForegroundColor Gray
Write-Host ''
Write-Host 'Set these environment variables before running Invoke-Dc01Server.ps1 or Invoke-Client01Runtime.ps1:' -ForegroundColor Yellow
Write-Host "  `$env:DLP_DEVICE_ISSUING_CA_CERT_PEM = '$deviceCaCertPath'"
Write-Host "  `$env:DLP_DEVICE_ISSUING_CA_KEY_PEM = '$deviceCaKeyPath'"
