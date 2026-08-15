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

function Resolve-PemContent([string]$Name, [string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) {
        Stop-Rotate "missing_$Name" "Set $Name before running this script."
    }
    if ($Value -match '^-----BEGIN') { return $Value }
    if (Test-Path -LiteralPath $Value -PathType Leaf) {
        $content = Get-Content -Raw -LiteralPath $Value
        if ($content -match '^-----BEGIN') { return $content }
        Stop-Rotate "pem_file_invalid:$Name" "$Value does not contain PEM content."
    }
    Stop-Rotate "pem_unresolvable:$Name" "$Name is neither inline PEM nor an existing file path."
}

function Get-EnvOrFail([string]$Name) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        Stop-Rotate "env_missing_$Name" "Set $Name before running this script."
    }
    return $value
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
        Stop-Rotate "openssl_failed" "openssl $Arguments`n$stderr"
    }
    return $stdout
}

Write-Host '=== Rotate DLP Provisioning Administrator Certificate ===' -ForegroundColor Cyan

$adminCaCertPem = Resolve-PemContent 'DLP_ADMIN_CA_CERT_PEM' (Get-EnvOrFail 'DLP_ADMIN_CA_CERT_PEM')
$adminCaKeyPem = Resolve-PemContent 'DLP_ADMIN_CA_KEY_PEM' (Get-EnvOrFail 'DLP_ADMIN_CA_KEY_PEM')

$tempAdminCa = [System.IO.Path]::GetTempFileName()
try {
    [System.IO.File]::WriteAllText($tempAdminCa, $adminCaCertPem)
    $adminCaSubject = (Invoke-Openssl "x509 -in `"$tempAdminCa`" -noout -subject").Trim()
    Write-Host "Admin CA subject: $adminCaSubject" -ForegroundColor Gray
} finally {
    if (Test-Path -LiteralPath $tempAdminCa) { Remove-Item -LiteralPath $tempAdminCa -Force }
}

$existingKeyPem = $null
if (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable('DLP_PROVISIONING_ADMIN_KEY_PEM'))) {
    $existingKeyPem = Resolve-PemContent 'DLP_PROVISIONING_ADMIN_KEY_PEM' ([Environment]::GetEnvironmentVariable('DLP_PROVISIONING_ADMIN_KEY_PEM'))
} elseif (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable('DLP_PROVISIONING_ADMIN_KEY_PATH'))) {
    $existingKeyPem = Resolve-PemContent 'DLP_PROVISIONING_ADMIN_KEY_PATH' ([Environment]::GetEnvironmentVariable('DLP_PROVISIONING_ADMIN_KEY_PATH'))
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$keyPath = Join-Path $OutputDirectory 'provisioning-admin-key.pem'
$certPath = Join-Path $OutputDirectory 'provisioning-admin-cert.pem'
$csrPath = Join-Path $OutputDirectory 'provisioning-admin.csr'
$adminCaCertPath = Join-Path $OutputDirectory 'admin-ca.pem'
$adminCaKeyPath = Join-Path $OutputDirectory 'admin-ca-key.pem'

if ((Test-Path -LiteralPath $certPath) -and -not $Force) {
    Stop-Rotate 'cert_already_exists' "Use -Force to overwrite $certPath"
}

[System.IO.File]::WriteAllText($adminCaCertPath, $adminCaCertPem, (New-Object System.Text.UTF8Encoding($false)))
[System.IO.File]::WriteAllText($adminCaKeyPath, $adminCaKeyPem, (New-Object System.Text.UTF8Encoding($false)))

if ($existingKeyPem) {
    Write-Host 'Using existing provisioning admin private key.' -ForegroundColor Gray
    [System.IO.File]::WriteAllText($keyPath, $existingKeyPem, (New-Object System.Text.UTF8Encoding($false)))
} else {
    Write-Host 'Generating new 2048-bit RSA provisioning admin private key...' -ForegroundColor Gray
    Invoke-Openssl "genrsa -out `"$keyPath`" 2048" | Out-Null
}

Write-Host 'Creating certificate signing request...' -ForegroundColor Gray
$csrConfig = @'
[req]
distinguished_name = req_distinguished_name
prompt = no
[req_distinguished_name]
CN = dlp-provisioning-admin
O = DLP Lab
[v3_req]
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
'@
$csrConfigPath = Join-Path $OutputDirectory 'provisioning-admin-req.cnf'
[System.IO.File]::WriteAllText($csrConfigPath, $csrConfig, (New-Object System.Text.UTF8Encoding($false)))
Invoke-Openssl "req -new -key `"$keyPath`" -config `"$csrConfigPath`" -out `"$csrPath`"" | Out-Null

Write-Host 'Signing provisioning admin certificate with admin CA...' -ForegroundColor Gray
$extConfig = @'
[v3_client]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
'@
$extConfigPath = Join-Path $OutputDirectory 'provisioning-admin-ext.cnf'
[System.IO.File]::WriteAllText($extConfigPath, $extConfig, (New-Object System.Text.UTF8Encoding($false)))
$serial = [BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes([guid]::NewGuid().ToString()))).Replace('-', '').Substring(0, 16).ToLowerInvariant()
Invoke-Openssl "x509 -req -in `"$csrPath`" -CA `"$adminCaCertPath`" -CAkey `"$adminCaKeyPath`" -set_serial 0x$serial -days 365 -sha256 -extfile `"$extConfigPath`" -extensions v3_client -out `"$certPath`"" | Out-Null

# Clean up temporary config files.
Remove-Item -LiteralPath $csrConfigPath -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $extConfigPath -Force -ErrorAction SilentlyContinue

Write-Host 'Verifying new certificate chains to admin CA...' -ForegroundColor Gray
$verifyResult = (Invoke-Openssl "verify -CAfile `"$adminCaCertPath`" `"$certPath`"").Trim()
if (-not ($verifyResult -match ': OK$')) {
    Stop-Rotate 'verification_failed' $verifyResult
}

# Clean up temporary CA key material from the output directory to avoid leaking it.
Remove-Item -LiteralPath $adminCaKeyPath -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $csrPath -Force -ErrorAction SilentlyContinue

Write-Host '=== Provisioning admin certificate rotated ===' -ForegroundColor Green
Write-Host "Certificate: $certPath" -ForegroundColor Gray
Write-Host "Private key: $keyPath" -ForegroundColor Gray
Write-Host ''
Write-Host 'Set these environment variables before running Invoke-Client01Runtime.ps1:' -ForegroundColor Yellow
Write-Host "  `$env:DLP_PROVISIONING_ADMIN_CERT_PEM = '$certPath'"
Write-Host "  `$env:DLP_PROVISIONING_ADMIN_KEY_PEM = '$keyPath'"
