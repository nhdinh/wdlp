[CmdletBinding()]
param(
    [Parameter()][string]$ServerHostname = 'LAB-DC01.lab.local',
    [Parameter()][string]$SecretsDirectory = 'C:\dlp\secrets'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Stop-Verify([string]$Code, [string]$Detail) {
    Write-Host "FAIL: $Code" -ForegroundColor Red
    if ($Detail) { Write-Host $Detail -ForegroundColor Gray }
    exit 1
}

function Update-VerificationEnvFromRotatedFiles {
    $rotations = @(
        @{ Name='DLP_PHASE1_ROOT_CA_CERT_PEM'; File='phase1-root-ca.pem' },
        @{ Name='DLP_PROVISIONING_ROOT_CA_PEM'; File='phase1-root-ca.pem' },
        @{ Name='DLP_PROVISIONING_ROOT_CA_PATH'; File='phase1-root-ca.pem' },
        @{ Name='DLP_ADMIN_CA_CERT_PEM'; File='admin-ca.pem' },
        @{ Name='DLP_ADMIN_CA_KEY_PEM'; File='admin-ca-key.pem' },
        @{ Name='DLP_PROVISIONING_ADMIN_CERT_PEM'; File='provisioning-admin-cert.pem' },
        @{ Name='DLP_PROVISIONING_ADMIN_KEY_PEM'; File='provisioning-admin-key.pem' },
        @{ Name='DLP_SERVER_CERT_PEM'; File='server-cert.pem' },
        @{ Name='DLP_SERVER_KEY_PEM'; File='server-key.pem' },
        @{ Name='DLP_DEVICE_ISSUING_CA_CERT_PEM'; File='device-issuing-ca.pem' },
        @{ Name='DLP_DEVICE_ISSUING_CA_KEY_PEM'; File='device-issuing-ca-key.pem' }
    )
    foreach ($entry in $rotations) {
        $name = $entry.Name
        $rotatedPath = Join-Path $SecretsDirectory $entry.File
        if (-not (Test-Path -LiteralPath $rotatedPath)) { continue }
        $envValue = [Environment]::GetEnvironmentVariable($name)
        $currentPath = if (-not [string]::IsNullOrWhiteSpace($envValue) -and $envValue -notmatch '^-----BEGIN' -and (Test-Path -LiteralPath $envValue)) {
            $envValue
        } else {
            $null
        }
        if ($null -eq $currentPath) {
            Write-Host "Using rotated file for $name`: $rotatedPath" -ForegroundColor Yellow
            [Environment]::SetEnvironmentVariable($name, $rotatedPath, 'Process')
            continue
        }
        $currentFull = [System.IO.Path]::GetFullPath($currentPath)
        $rotatedFull = [System.IO.Path]::GetFullPath($rotatedPath)
        if ($currentFull -eq $rotatedFull) { continue }
        $rotatedTime = (Get-Item -LiteralPath $rotatedFull).LastWriteTimeUtc
        $currentTime = (Get-Item -LiteralPath $currentFull).LastWriteTimeUtc
        if ($rotatedTime -gt $currentTime) {
            Write-Host "WARN: $rotatedPath is newer than `$env:$name ($currentPath). Using rotated file." -ForegroundColor Yellow
            [Environment]::SetEnvironmentVariable($name, $rotatedPath, 'Process')
        }
    }
}

Update-VerificationEnvFromRotatedFiles

function Get-EnvOrFail([string]$Name) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) { Stop-Verify "env_missing_$Name" "Set $Name before running this verification." }
    return $value
}
function Resolve-PemContent([string]$Name, [string]$Value) {
    if ($Value -match '^-----BEGIN') { return $Value }
    if (Test-Path -LiteralPath $Value -PathType Leaf) {
        $content = Get-Content -Raw -LiteralPath $Value
        if ($content -match '^-----BEGIN') { return $content }
        Stop-Verify "pem_file_invalid:$Name" "$Value does not contain PEM content."
    }
    Stop-Verify "pem_unresolvable:$Name" "$Name is neither inline PEM nor an existing file path."
}
function Get-X509FromPem([string]$PemContent) {
    $base64 = ($PemContent -replace '-----BEGIN CERTIFICATE-----' -replace '-----END CERTIFICATE-----' -replace "`r?`n" -replace ' ')
    $bytes = [System.Convert]::FromBase64String($base64)
    return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
}
function Get-PemBytes([string]$PemContent, [string]$Label) {
    $lines = $PemContent -split "`r?`n"
    $inBlock = $false
    $base64Lines = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^-----BEGIN ') {
            $inBlock = $true
            continue
        }
        if ($trimmed -match '^-----END ') {
            $inBlock = $false
            continue
        }
        if ($inBlock -and -not [string]::IsNullOrWhiteSpace($trimmed)) {
            $base64Lines.Add($trimmed)
        }
    }
    if ($base64Lines.Count -eq 0) { Stop-Verify "pem_empty:$Label" }
    $base64 = $base64Lines -join ''
    return [System.Convert]::FromBase64String($base64)
}

function Get-AnyRsaFromPem([string]$PemContent, [string]$Label) {
    $header = ($PemContent -split "`r?`n" | Where-Object { $_.Trim().StartsWith('-----BEGIN ') } | Select-Object -First 1).Trim()
    Write-Host "  $Label key header: $header" -ForegroundColor Gray
    if ($header -match 'ENCRYPTED') {
        Stop-Verify "encrypted_private_key:$Label" "Remove encryption from $Label private key or provide the decrypted PEM."
    }
    $bytes = Get-PemBytes $PemContent $Label
    Write-Host "  $Label key decoded bytes: $($bytes.Length)" -ForegroundColor Gray
    $rsa = [System.Security.Cryptography.RSA]::Create()
    try {
        if ($header -eq '-----BEGIN PRIVATE KEY-----') {
            [void]$rsa.ImportPkcs8PrivateKey($bytes, [ref]$null)
        } elseif ($header -eq '-----BEGIN RSA PRIVATE KEY-----') {
            [void]$rsa.ImportRSAPrivateKey($bytes, [ref]$null)
        } else {
            Stop-Verify "unsupported_private_key_header:$Label" "Expected -----BEGIN PRIVATE KEY----- or -----BEGIN RSA PRIVATE KEY-----."
        }
        return $rsa
    } catch {
        $rsa.Dispose()
        Stop-Verify 'private_key_parse_failed' "Could not parse $Label private key: $_"
    }
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
        Stop-Verify "openssl_failed" "openssl $Arguments`n$stderr"
    }
    return $stdout
}

function Get-OpensslModulus([string]$PemContent, [string]$Label, [string]$Type) {
    $temp = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($temp, $PemContent)
        $arg = if ($Type -eq 'cert') { 'x509' } else { 'rsa' }
        $stdout = (Invoke-Openssl "$arg -in `"$temp`" -noout -modulus").Trim()
        if (-not ($stdout -match '^Modulus=([0-9A-Fa-f]+)$')) {
            Stop-Verify "openssl_modulus_unexpected:$Label" $stdout
        }
        return $Matches[1].ToLowerInvariant()
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    }
}

function Get-OpensslText([string]$PemContent) {
    $temp = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($temp, $PemContent)
        return Invoke-Openssl "x509 -in `"$temp`" -noout -text"
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    }
}

Write-Host '=== DLP Lab Certificate/Key Verification ===' -ForegroundColor Cyan

# --- Resolve all PEM material from environment ---
$serverCertPem     = Resolve-PemContent 'DLP_SERVER_CERT_PEM'     (Get-EnvOrFail 'DLP_SERVER_CERT_PEM')
$serverKeyPem      = Resolve-PemContent 'DLP_SERVER_KEY_PEM'      (Get-EnvOrFail 'DLP_SERVER_KEY_PEM')
$adminCaCertPem    = Resolve-PemContent 'DLP_ADMIN_CA_CERT_PEM'   (Get-EnvOrFail 'DLP_ADMIN_CA_CERT_PEM')
$phase1RootPem     = Resolve-PemContent 'DLP_PHASE1_ROOT_CA_CERT_PEM' (Get-EnvOrFail 'DLP_PHASE1_ROOT_CA_CERT_PEM')
$deviceCaCertPem   = Resolve-PemContent 'DLP_DEVICE_ISSUING_CA_CERT_PEM' (Get-EnvOrFail 'DLP_DEVICE_ISSUING_CA_CERT_PEM')
$deviceCaKeyPem    = Resolve-PemContent 'DLP_DEVICE_ISSUING_CA_KEY_PEM'  (Get-EnvOrFail 'DLP_DEVICE_ISSUING_CA_KEY_PEM')

$provisioningRootCaPem = if (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable('DLP_PROVISIONING_ROOT_CA_PEM'))) {
    Resolve-PemContent 'DLP_PROVISIONING_ROOT_CA_PEM' ([Environment]::GetEnvironmentVariable('DLP_PROVISIONING_ROOT_CA_PEM'))
} elseif (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable('DLP_PROVISIONING_ROOT_CA_PATH'))) {
    Resolve-PemContent 'DLP_PROVISIONING_ROOT_CA_PATH' ([Environment]::GetEnvironmentVariable('DLP_PROVISIONING_ROOT_CA_PATH'))
} else {
    Resolve-PemContent 'DLP_PHASE1_ROOT_CA_CERT_PEM' (Get-EnvOrFail 'DLP_PHASE1_ROOT_CA_CERT_PEM')
}

$provAdminCertPem = Resolve-PemContent 'DLP_PROVISIONING_ADMIN_CERT_PEM' (Get-EnvOrFail 'DLP_PROVISIONING_ADMIN_CERT_PEM')
$provAdminKeyPem  = Resolve-PemContent 'DLP_PROVISIONING_ADMIN_KEY_PEM'  (Get-EnvOrFail 'DLP_PROVISIONING_ADMIN_KEY_PEM')

# --- Sanity: every PEM that should be a certificate actually is ---
foreach ($entry in @(
    @{ Name='DLP_SERVER_CERT_PEM'; Pem=$serverCertPem },
    @{ Name='DLP_ADMIN_CA_CERT_PEM'; Pem=$adminCaCertPem },
    @{ Name='DLP_PHASE1_ROOT_CA_CERT_PEM'; Pem=$phase1RootPem },
    @{ Name='DLP_DEVICE_ISSUING_CA_CERT_PEM'; Pem=$deviceCaCertPem },
    @{ Name='DLP_PHASE1_ROOT_CA_CERT_PEM (provisioning root)'; Pem=$provisioningRootCaPem },
    @{ Name='DLP_PROVISIONING_ADMIN_CERT_PEM'; Pem=$provAdminCertPem }
)) {
    if (-not ($entry.Pem -match '^-----BEGIN CERTIFICATE-----')) {
        Stop-Verify "not_a_certificate:$($entry.Name)" "$($entry.Name) does not start with -----BEGIN CERTIFICATE-----."
    }
}
# --- Sanity: every PEM that should be a private key actually is ---
foreach ($entry in @(
    @{ Name='DLP_SERVER_KEY_PEM'; Pem=$serverKeyPem },
    @{ Name='DLP_DEVICE_ISSUING_CA_KEY_PEM'; Pem=$deviceCaKeyPem },
    @{ Name='DLP_PROVISIONING_ADMIN_KEY_PEM'; Pem=$provAdminKeyPem }
)) {
    if (-not ($entry.Pem -match '^-----BEGIN (RSA )?PRIVATE KEY-----')) {
        Stop-Verify "not_a_private_key:$($entry.Name)" "$($entry.Name) does not start with -----BEGIN PRIVATE KEY-----."
    }
}

# --- Parse certificates ---
$serverCert   = Get-X509FromPem $serverCertPem
$adminCaCert  = Get-X509FromPem $adminCaCertPem
$phase1Root   = Get-X509FromPem $phase1RootPem
$deviceCaCert = Get-X509FromPem $deviceCaCertPem
$provRootCa   = Get-X509FromPem $provisioningRootCaPem
$provAdminCert = Get-X509FromPem $provAdminCertPem

Write-Host "Server cert subject:           $($serverCert.Subject)" -ForegroundColor Gray
Write-Host "Server cert issuer:            $($serverCert.Issuer)" -ForegroundColor Gray
Write-Host "Server cert signature:         $($serverCert.SignatureAlgorithm.FriendlyName) / OID=$($serverCert.SignatureAlgorithm.Value)" -ForegroundColor Gray
Write-Host "Server cert public key:        $($serverCert.PublicKey.Oid.FriendlyName) / OID=$($serverCert.PublicKey.Oid.Value)" -ForegroundColor Gray
Write-Host "Admin CA subject:              $($adminCaCert.Subject)" -ForegroundColor Gray
Write-Host "Provisioning root subject:     $($provRootCa.Subject)" -ForegroundColor Gray
Write-Host "Provisioning root signature:   $($provRootCa.SignatureAlgorithm.FriendlyName) / OID=$($provRootCa.SignatureAlgorithm.Value)" -ForegroundColor Gray
Write-Host "Provisioning admin cert subject: $($provAdminCert.Subject)" -ForegroundColor Gray
Write-Host "Provisioning admin cert issuer:  $($provAdminCert.Issuer)" -ForegroundColor Gray

# --- CA certificate extensions required by rustls/webpki ---
function Assert-CaExtensions([string]$Label, [string]$CertPem, [switch]$OptionalKeyCertSign) {
    $text = Get-OpensslText $CertPem
    $hasCaTrue = $text -match 'CA:TRUE'
    $hasKeyCertSign = $text -match 'Certificate Sign'
    Write-Host "  $Label Basic Constraints CA: $hasCaTrue" -ForegroundColor Gray
    Write-Host "  $Label Key Usage keyCertSign: $hasKeyCertSign" -ForegroundColor Gray
    if (-not $hasCaTrue) {
        Stop-Verify "missing_ca_basic_constraints:$Label" "$Label must have Basic Constraints CA:TRUE for rustls/webpki. Regenerate with -extensions v3_ca."
    }
    if (-not $hasKeyCertSign) {
        if ($OptionalKeyCertSign) {
            Write-Host "WARN: $Label is missing Key Usage Certificate Sign. Device mTLS will fail until this CA is regenerated with -extensions v3_ca, but admin provisioning can continue." -ForegroundColor Yellow
        } else {
            Stop-Verify "missing_key_cert_sign:$Label" "$Label must have Key Usage Certificate Sign for rustls/webpki."
        }
    }
}

function Assert-ClientCertExtensions([string]$Label, [string]$CertPem) {
    $text = Get-OpensslText $CertPem
    $hasDigitalSignature = $text -match 'Digital Signature'
    $hasClientAuth = $text -match 'TLS Web Client Authentication'
    $hasCaFalse = $text -match 'CA:FALSE'
    Write-Host "  $Label Key Usage digitalSignature: $hasDigitalSignature" -ForegroundColor Gray
    Write-Host "  $Label EKU clientAuth: $hasClientAuth" -ForegroundColor Gray
    Write-Host "  $Label Basic Constraints CA:false: $hasCaFalse" -ForegroundColor Gray
    if (-not $hasCaFalse) {
        Stop-Verify "missing_non_ca_basic_constraints:$Label" "$Label must have critical Basic Constraints CA:FALSE."
    }
    if (-not $hasDigitalSignature) {
        Stop-Verify "missing_digital_signature:$Label" "$Label must have Key Usage Digital Signature for TLS client authentication."
    }
    if (-not $hasClientAuth) {
        Stop-Verify "missing_client_auth_eku:$Label" "$Label must have Extended Key Usage TLS Web Client Authentication."
    }
}

function Assert-ServerCertExtensions([string]$Label, [string]$CertPem) {
    $text = Get-OpensslText $CertPem
    if (-not ($text -match 'CA:FALSE')) {
        Stop-Verify "missing_non_ca_basic_constraints:$Label" "$Label must have critical Basic Constraints CA:FALSE."
    }
    if (-not ($text -match 'Digital Signature')) {
        Stop-Verify "missing_digital_signature:$Label" "$Label must allow Digital Signature."
    }
    if (-not ($text -match 'Key Encipherment')) {
        Stop-Verify "missing_key_encipherment:$Label" "$Label must allow Key Encipherment."
    }
    if (-not ($text -match 'TLS Web Server Authentication')) {
        Stop-Verify "missing_server_auth_eku:$Label" "$Label must have Extended Key Usage TLS Web Server Authentication."
    }
}

Assert-CaExtensions 'admin CA' $adminCaCertPem
Assert-CaExtensions 'device issuing CA' $deviceCaCertPem -OptionalKeyCertSign
Assert-ClientCertExtensions 'provisioning admin cert' $provAdminCertPem
Assert-ServerCertExtensions 'server cert' $serverCertPem

# --- Expiration ---
$now = Get-Date
foreach ($entry in @(
    @{ Name='server cert'; Cert=$serverCert },
    @{ Name='admin CA'; Cert=$adminCaCert },
    @{ Name='phase1 root'; Cert=$phase1Root },
    @{ Name='device issuing CA'; Cert=$deviceCaCert },
    @{ Name='provisioning root CA'; Cert=$provRootCa },
    @{ Name='provisioning admin cert'; Cert=$provAdminCert }
)) {
    if ($null -eq $entry.Cert) {
        Stop-Verify "certificate_parse_failed:$($entry.Name)"
    }
    if ($now -lt $entry.Cert.NotBefore -or $now -gt $entry.Cert.NotAfter) {
        Stop-Verify "certificate_expired_or_not_yet_valid:$($entry.Name)" "NotBefore=$($entry.Cert.NotBefore), NotAfter=$($entry.Cert.NotAfter)"
    }
}

# --- Server cert hostname ---
$serverDnsNames = $serverCert.Extensions |
    Where-Object { $_.Oid.Value -eq '2.5.29.17' } |
    ForEach-Object {
        $san = [System.Security.Cryptography.AsnEncodedData]::new($_.Oid, $_.RawData)
        $san.Format($true) -split "`r?`n" |
            Where-Object { $_ -match 'DNS Name=(.+)$' } |
            ForEach-Object { $Matches[1] }
    }
$dnsMatch = $serverDnsNames | Where-Object { $_ -ieq $ServerHostname }
if (-not $dnsMatch) {
    Stop-Verify "server_cert_hostname_san_mismatch" "Expected a DNS SAN for $ServerHostname; SANs=$($serverDnsNames -join ', '). CN fallback is not accepted."
}

# --- Key/cert pairs: public modulus must match ---
function Assert-KeyMatchesCert([string]$Label, [string]$KeyPem, [string]$CertPem) {
    $keyMod = Get-OpensslModulus $KeyPem $Label 'key'
    $certMod = Get-OpensslModulus $CertPem $Label 'cert'
    Write-Host "  $Label cert modulus: $certMod" -ForegroundColor Gray
    Write-Host "  $Label key modulus: $keyMod" -ForegroundColor Gray
    if ($keyMod -ne $certMod) {
        Stop-Verify "key_cert_mismatch:$Label" "The private key modulus does not match the certificate public key modulus."
    }
}

Assert-KeyMatchesCert 'server'           $serverKeyPem   $serverCertPem
Assert-KeyMatchesCert 'device CA'        $deviceCaKeyPem $deviceCaCertPem
Assert-KeyMatchesCert 'provisioning admin' $provAdminKeyPem $provAdminCertPem

# --- Issuer chain checks (by name) ---
if ($serverCert.Issuer -ne $provRootCa.Subject) {
    Stop-Verify "server_cert_not_issued_by_provisioning_root" "Server cert issuer: $($serverCert.Issuer); Provisioning root subject: $($provRootCa.Subject)"
}
if ($provAdminCert.Issuer -ne $adminCaCert.Subject) {
    Stop-Verify "admin_cert_not_issued_by_admin_ca" "Admin cert issuer: $($provAdminCert.Issuer); Admin CA subject: $($adminCaCert.Subject)"
}

# --- Verify signatures against the claimed issuer CAs ---
function Assert-CertSignedByCa([string]$Label, [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert, [System.Security.Cryptography.X509Certificates.X509Certificate2]$CaCert) {
    $chain = $null
    try {
        $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
        $chain.ChainPolicy.ExtraStore.Add($CaCert)
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
        $valid = $chain.Build($Cert)
        if (-not $valid) {
            $status = $chain.ChainStatus | ForEach-Object { $_.StatusInformation }
            $caSubject = $CaCert.Subject
            $certSubject = $Cert.Subject
            $certIssuer = $Cert.Issuer
            Stop-Verify "signature_verification_failed:$Label" "Could not verify $Label signature. Certificate subject: $certSubject; Issuer: $certIssuer; CA subject used for verification: $caSubject; Chain status: $($status -join '; ')"
        }
        Write-Host "  $Label signature verified against issuer CA" -ForegroundColor Gray
    } finally {
        if ($null -ne $chain) { $chain.Dispose() }
    }
}

Assert-CertSignedByCa 'server cert' $serverCert $provRootCa
Assert-CertSignedByCa 'provisioning admin cert' $provAdminCert $adminCaCert

# --- Rustls/ring compatibility checks ---
$unsupportedSigOids = @('1.2.840.113549.1.1.4', '1.2.840.113549.1.1.5') # md5RSA, sha1RSA
foreach ($entry in @(
    @{ Name='server cert'; Cert=$serverCert },
    @{ Name='provisioning root CA'; Cert=$provRootCa },
    @{ Name='admin CA'; Cert=$adminCaCert }
)) {
    $oid = $entry.Cert.SignatureAlgorithm.Value
    if ($unsupportedSigOids -contains $oid) {
        Stop-Verify "unsupported_signature_algorithm:$($entry.Name)" "$($entry.Name) uses $oid which rustls/ring rejects. Regenerate with sha256RSA or better."
    }
}

function Assert-RsaKeySize([string]$Label, [string]$KeyPem) {
    $temp = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($temp, $KeyPem)
        $psi = New-Object System.Diagnostics.ProcessStartInfo('openssl', "rsa -in `"$temp`" -text -noout")
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        $proc.WaitForExit()
        if ($proc.ExitCode -ne 0) { Stop-Verify "openssl_key_text_failed:$Label" $stderr }
        $match = [regex]::Match($stdout, 'Private-Key:\s*\((\d+)\s*bit')
        if (-not $match.Success) { Stop-Verify "openssl_key_size_unexpected:$Label" $stdout }
        $bits = [int]$match.Groups[1].Value
        Write-Host "  $Label key size: $bits bits" -ForegroundColor Gray
        if ($bits -lt 2048) { Stop-Verify "rsa_key_too_small:$Label" "rustls/ring requires at least 2048-bit RSA keys; found $bits bits." }
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    }
}

Assert-RsaKeySize 'server' $serverKeyPem
Assert-RsaKeySize 'device CA' $deviceCaKeyPem
Assert-RsaKeySize 'provisioning admin' $provAdminKeyPem

Write-Host '=== All certificate/key checks passed ===' -ForegroundColor Green
