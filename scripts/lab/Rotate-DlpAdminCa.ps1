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

Write-Host '=== Rotate DLP Administrator CA ===' -ForegroundColor Cyan

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$adminCaCertPath = Join-Path $OutputDirectory 'admin-ca.pem'
$adminCaKeyPath = Join-Path $OutputDirectory 'admin-ca-key.pem'
$provAdminCertPath = Join-Path $OutputDirectory 'provisioning-admin-cert.pem'
$provAdminKeyPath = Join-Path $OutputDirectory 'provisioning-admin-key.pem'
$provAdminCsrPath = Join-Path $OutputDirectory 'provisioning-admin.csr'

if (((Test-Path -LiteralPath $adminCaCertPath) -or (Test-Path -LiteralPath $adminCaKeyPath)) -and -not $Force) {
    Stop-Rotate 'admin_ca_already_exists' "Use -Force to overwrite $adminCaCertPath and $adminCaKeyPath"
}

Write-Host 'Generating 4096-bit RSA administrator CA key...' -ForegroundColor Gray
Invoke-Openssl "genrsa -out `"$adminCaKeyPath`" 4096" | Out-Null

Write-Host 'Self-signing administrator CA certificate with v3_ca extensions...' -ForegroundColor Gray
$caConfig = @'
[v3_ca]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
'@
$caConfigPath = Join-Path $OutputDirectory 'admin-ca-ext.cnf'
[System.IO.File]::WriteAllText($caConfigPath, $caConfig, (New-Object System.Text.UTF8Encoding($false)))
try {
    Invoke-Openssl "req -x509 -new -nodes -key `"$adminCaKeyPath`" -sha256 -days 3650 -subj `"/CN=admin-ca/O=DLP Lab`" -config `"$caConfigPath`" -extensions v3_ca -out `"$adminCaCertPath`"" | Out-Null
} finally {
    Remove-Item -LiteralPath $caConfigPath -Force -ErrorAction SilentlyContinue
}

$adminCaSubject = (Invoke-Openssl "x509 -in `"$adminCaCertPath`" -noout -subject").Trim()
Write-Host "New admin CA subject: $adminCaSubject" -ForegroundColor Gray

# Preserve existing provisioning admin private key if present, otherwise generate a new one.
if (-not (Test-Path -LiteralPath $provAdminKeyPath)) {
    Write-Host 'Generating new 2048-bit provisioning admin private key...' -ForegroundColor Gray
    Invoke-Openssl "genrsa -out `"$provAdminKeyPath`" 2048" | Out-Null
} else {
    Write-Host 'Using existing provisioning admin private key.' -ForegroundColor Gray
}

Write-Host 'Creating provisioning admin certificate signing request...' -ForegroundColor Gray
$csrConfig = @'
[req]
distinguished_name = req_distinguished_name
prompt = no
[req_distinguished_name]
CN = dlp-provisioning-admin
O = DLP Lab
'@
$csrConfigPath = Join-Path $OutputDirectory 'provisioning-admin-req.cnf'
[System.IO.File]::WriteAllText($csrConfigPath, $csrConfig, (New-Object System.Text.UTF8Encoding($false)))
try {
    Invoke-Openssl "req -new -key `"$provAdminKeyPath`" -config `"$csrConfigPath`" -out `"$provAdminCsrPath`"" | Out-Null
} finally {
    Remove-Item -LiteralPath $csrConfigPath -Force -ErrorAction SilentlyContinue
}

Write-Host 'Signing provisioning admin certificate with new admin CA...' -ForegroundColor Gray
$extConfig = @'
[v3_client]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
'@
$extConfigPath = Join-Path $OutputDirectory 'provisioning-admin-ext.cnf'
[System.IO.File]::WriteAllText($extConfigPath, $extConfig, (New-Object System.Text.UTF8Encoding($false)))
$serial = [BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes([guid]::NewGuid().ToString()))).Replace('-', '').Substring(0, 16).ToLowerInvariant()
try {
    Invoke-Openssl "x509 -req -in `"$provAdminCsrPath`" -CA `"$adminCaCertPath`" -CAkey `"$adminCaKeyPath`" -set_serial 0x$serial -days 365 -sha256 -extfile `"$extConfigPath`" -extensions v3_client -out `"$provAdminCertPath`"" | Out-Null
} finally {
    Remove-Item -LiteralPath $extConfigPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $provAdminCsrPath -Force -ErrorAction SilentlyContinue
}

Write-Host 'Verifying provisioning admin certificate chains to new admin CA...' -ForegroundColor Gray
$verifyResult = (Invoke-Openssl "verify -CAfile `"$adminCaCertPath`" `"$provAdminCertPath`"").Trim()
if (-not ($verifyResult -match ': OK$')) {
    Stop-Rotate 'verification_failed' $verifyResult
}

Write-Host '=== Administrator CA and provisioning admin certificate rotated ===' -ForegroundColor Green
Write-Host "Admin CA certificate: $adminCaCertPath" -ForegroundColor Gray
Write-Host "Admin CA private key: $adminCaKeyPath" -ForegroundColor Gray
Write-Host "Provisioning admin certificate: $provAdminCertPath" -ForegroundColor Gray
Write-Host "Provisioning admin private key: $provAdminKeyPath" -ForegroundColor Gray
Write-Host ''
Write-Host 'Set these environment variables before running Invoke-Client01Runtime.ps1:' -ForegroundColor Yellow
Write-Host "  `$env:DLP_ADMIN_CA_CERT_PEM = '$adminCaCertPath'"
Write-Host "  `$env:DLP_ADMIN_CA_KEY_PEM = '$adminCaKeyPath'"
Write-Host "  `$env:DLP_PROVISIONING_ADMIN_CERT_PEM = '$provAdminCertPath'"
Write-Host "  `$env:DLP_PROVISIONING_ADMIN_KEY_PEM = '$provAdminKeyPath'"
Write-Host ''
Write-Host 'Then run Verify-DlpLabCertificates.ps1 and Invoke-Client01Runtime.ps1.' -ForegroundColor Yellow
