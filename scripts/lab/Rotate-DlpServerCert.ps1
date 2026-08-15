[CmdletBinding()]
param(
    [Parameter()][string]$OutputDirectory = 'C:\dlp\secrets',
    [Parameter()][string]$RootCaCertPath = 'C:\dlp\secrets\phase1-root-ca.pem',
    [Parameter()][string]$RootCaKeyPath = 'C:\dlp\secrets\phase1-root-ca-key.pem',
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

function Test-CertKeyMatch([string]$CertPem, [string]$KeyPem) {
    # Compare the public key represented by the certificate against the public
    # key derivable from the private key. This works for both RSA and EC
    # material and lets us fail fast with a clear message instead of an
    # opaque OpenSSL "key values mismatch" error during signing.
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    try {
        $certPath = Join-Path $tempDir 'cert.pem'
        $keyPath = Join-Path $tempDir 'key.pem'
        [System.IO.File]::WriteAllText($certPath, $CertPem, (New-Object System.Text.UTF8Encoding($false)))
        [System.IO.File]::WriteAllText($keyPath, $KeyPem, (New-Object System.Text.UTF8Encoding($false)))
        $certPub = (Invoke-Openssl "x509 -in `"$certPath`" -noout -pubkey").Trim()
        $keyPub = (Invoke-Openssl "pkey -in `"$keyPath`" -pubout").Trim()
        return ($certPub -eq $keyPub)
    } finally {
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
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
        Stop-Rotate 'openssl_failed' "openssl $Arguments`n$stderr"
    }
    return $stdout
}

Write-Host '=== Rotate DLP Server TLS Certificate ===' -ForegroundColor Cyan

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$rootCaCertEnv = [Environment]::GetEnvironmentVariable('DLP_PHASE1_ROOT_CA_CERT_PEM')
$rootCaKeyEnv  = [Environment]::GetEnvironmentVariable('DLP_PHASE1_ROOT_CA_KEY_PEM')

$rootCaCertPem = if (-not [string]::IsNullOrWhiteSpace($rootCaCertEnv)) {
    Resolve-PemContent 'DLP_PHASE1_ROOT_CA_CERT_PEM' $rootCaCertEnv
} else {
    if (-not (Test-Path -LiteralPath $RootCaCertPath -PathType Leaf)) {
        Stop-Rotate 'root_ca_cert_not_found' "Root CA certificate not found at $RootCaCertPath. Provide -RootCaCertPath or set `$env:DLP_PHASE1_ROOT_CA_CERT_PEM."
    }
    Get-Content -Raw -LiteralPath $RootCaCertPath
}

$rootCaKeyPem = if (-not [string]::IsNullOrWhiteSpace($rootCaKeyEnv)) {
    Resolve-PemContent 'DLP_PHASE1_ROOT_CA_KEY_PEM' $rootCaKeyEnv
} else {
    if (-not (Test-Path -LiteralPath $RootCaKeyPath -PathType Leaf)) {
        Stop-Rotate 'root_ca_key_not_found' "Root CA private key not found at $RootCaKeyPath. Provide -RootCaKeyPath or set `$env:DLP_PHASE1_ROOT_CA_KEY_PEM."
    }
    Get-Content -Raw -LiteralPath $RootCaKeyPath
}

# Fail fast if the resolved cert and key are not a matched pair. If they do
# not match, fall back to the canonical on-disk pair in the output directory
# when one exists, so a stale inline env-var cert does not block rotation.
if (-not (Test-CertKeyMatch $rootCaCertPem $rootCaKeyPem)) {
    $fallbackCertPath = Join-Path $OutputDirectory 'phase1-root-ca.pem'
    $fallbackKeyPath  = Join-Path $OutputDirectory 'phase1-root-ca-key.pem'
    if ((Test-Path -LiteralPath $fallbackCertPath -PathType Leaf) -and (Test-Path -LiteralPath $fallbackKeyPath -PathType Leaf)) {
        $fallbackCert = Get-Content -Raw -LiteralPath $fallbackCertPath
        $fallbackKey  = Get-Content -Raw -LiteralPath $fallbackKeyPath
        if (Test-CertKeyMatch $fallbackCert $fallbackKey) {
            Write-Warning "Resolved root CA cert/key do not match; using canonical pair $fallbackCertPath / $fallbackKeyPath"
            $rootCaCertPem = $fallbackCert
            $rootCaKeyPem  = $fallbackKey
        } else {
            Stop-Rotate 'root_ca_cert_key_mismatch' "The root CA cert and key resolved from environment/path do not match, and the canonical pair in $OutputDirectory also does not match."
        }
    } else {
        Stop-Rotate 'root_ca_cert_key_mismatch' "The root CA cert and key resolved from environment/path do not match, and no canonical pair was found in $OutputDirectory."
    }
}

$serverKeyPath   = Join-Path $OutputDirectory 'server-key.pem'
$serverCertPath  = Join-Path $OutputDirectory 'server-cert.pem'
$serverCsrPath   = Join-Path $OutputDirectory 'server.csr'

if (((Test-Path -LiteralPath $serverCertPath) -or (Test-Path -LiteralPath $serverKeyPath)) -and -not $Force) {
    Stop-Rotate 'server_cert_already_exists' "Use -Force to overwrite $serverCertPath and $serverKeyPath"
}

# Use a private temp directory for the root CA material so we never overwrite
# or delete the user's actual phase1-root-ca.pem / phase1-root-ca-key.pem.
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
$rootCaCertPath  = Join-Path $tempDir 'phase1-root-ca.pem'
$rootCaKeyPathTemp = Join-Path $tempDir 'phase1-root-ca-key.pem'

try {
    [System.IO.File]::WriteAllText($rootCaCertPath, $rootCaCertPem, (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText($rootCaKeyPathTemp, $rootCaKeyPem, (New-Object System.Text.UTF8Encoding($false)))

    Write-Host 'Generating 2048-bit RSA server key...' -ForegroundColor Gray
    Invoke-Openssl "genrsa -out `"$serverKeyPath`" 2048" | Out-Null

    Write-Host 'Creating server certificate signing request...' -ForegroundColor Gray
    $csrConfig = @'
[req]
distinguished_name = req_distinguished_name
prompt = no
[req_distinguished_name]
CN = LAB-DC01.lab.local
O = DLP Lab
'@
    $csrConfigPath = Join-Path $OutputDirectory 'server-req.cnf'
    [System.IO.File]::WriteAllText($csrConfigPath, $csrConfig, (New-Object System.Text.UTF8Encoding($false)))
    try {
        Invoke-Openssl "req -new -key `"$serverKeyPath`" -config `"$csrConfigPath`" -out `"$serverCsrPath`"" | Out-Null
    } finally {
        Remove-Item -LiteralPath $csrConfigPath -Force -ErrorAction SilentlyContinue
    }

    Write-Host 'Signing server certificate with Phase 1 root CA...' -ForegroundColor Gray
    $extConfig = @'
[v3_server]
basicConstraints = critical, CA:false
subjectAltName = DNS:LAB-DC01, DNS:LAB-DC01.lab.local, IP:192.168.50.10
extendedKeyUsage = serverAuth
keyUsage = critical, digitalSignature, keyEncipherment
'@
    $extConfigPath = Join-Path $OutputDirectory 'server-ext.cnf'
    [System.IO.File]::WriteAllText($extConfigPath, $extConfig, (New-Object System.Text.UTF8Encoding($false)))
    $serial = [BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes([guid]::NewGuid().ToString()))).Replace('-', '').Substring(0, 16).ToLowerInvariant()
    try {
        Invoke-Openssl "x509 -req -in `"$serverCsrPath`" -CA `"$rootCaCertPath`" -CAkey `"$rootCaKeyPathTemp`" -CAcreateserial -set_serial 0x$serial -days 365 -sha256 -extfile `"$extConfigPath`" -extensions v3_server -out `"$serverCertPath`"" | Out-Null
    } finally {
        Remove-Item -LiteralPath $extConfigPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $serverCsrPath -Force -ErrorAction SilentlyContinue
    }

    Write-Host 'Verifying server certificate chains to Phase 1 root CA...' -ForegroundColor Gray
    $verifyResult = (Invoke-Openssl "verify -CAfile `"$rootCaCertPath`" `"$serverCertPath`"").Trim()
    if (-not ($verifyResult -match ': OK$')) {
        Stop-Rotate 'verification_failed' $verifyResult
    }

    $subject = (Invoke-Openssl "x509 -in `"$serverCertPath`" -noout -subject").Trim()
    Write-Host "Server cert subject: $subject" -ForegroundColor Gray

    Write-Host '=== Server TLS certificate rotated ===' -ForegroundColor Green
    Write-Host "Server certificate: $serverCertPath" -ForegroundColor Gray
    Write-Host "Server private key: $serverKeyPath" -ForegroundColor Gray
    Write-Host ''
    Write-Host 'Set these environment variables before running Invoke-Dc01Server.ps1 or Invoke-Client01Runtime.ps1:' -ForegroundColor Yellow
    Write-Host "  `$env:DLP_SERVER_CERT_PEM = '$serverCertPath'"
    Write-Host "  `$env:DLP_SERVER_KEY_PEM = '$serverKeyPath'"
} finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}
