[CmdletBinding()]
param(
    [Parameter()][switch]$RunReproduction
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Diagnostic collector for the trusted-provisioning TLS abort.
# Run this on LAB-DC01 immediately before (and optionally during) the failure.
# It produces a single JSON blob that can be pasted back into the debug session.

$provDir = 'C:\dlp\provisioning'
$secretsDir = 'C:\dlp\secrets'
$serverDir = 'C:\dlp\server'
$tlsLogPath = Join-Path $serverDir 'tls-events.log'

function Get-Sha256([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '<missing>' }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-FirstLine([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '<missing>' }
    return (Get-Content -LiteralPath $Path -TotalCount 1 -ErrorAction SilentlyContinue) -join ''
}

function Get-PemSubject([string]$PemContent) {
    $temp = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($temp, $PemContent)
        $psi = New-Object System.Diagnostics.ProcessStartInfo('openssl', "x509 -in `"$temp`" -noout -subject -issuer")
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdout = $proc.StandardOutput.ReadToEnd()
        $proc.WaitForExit()
        if ($proc.ExitCode -ne 0) { return '<parse-failed>' }
        return ($stdout -split "`r?`n" | Where-Object { $_.Trim() -ne '' }) -join '; '
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    }
}

function Get-X509Subject([string]$PemPath) {
    if (-not (Test-Path -LiteralPath $PemPath -PathType Leaf)) { return '<missing>' }
    $content = Get-Content -Raw -LiteralPath $PemPath
    return Get-PemSubject $content
}

$report = [ordered]@{
    collected_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    computer_name = $env:COMPUTERNAME
    env_vars = [ordered]@{
        DLP_PROVISIONING_ROOT_CA_PEM = if ($env:DLP_PROVISIONING_ROOT_CA_PEM) { '<set-' + $env:DLP_PROVISIONING_ROOT_CA_PEM.Length + '-chars>' } else { '<not-set>' }
        DLP_PROVISIONING_ROOT_CA_PATH = $env:DLP_PROVISIONING_ROOT_CA_PATH
        DLP_PROVISIONING_ADMIN_CERT_PATH = $env:DLP_PROVISIONING_ADMIN_CERT_PATH
        DLP_PROVISIONING_ADMIN_KEY_PATH = $env:DLP_PROVISIONING_ADMIN_KEY_PATH
        DLP_PROVISIONING_ENDPOINT = $env:DLP_PROVISIONING_ENDPOINT
        DLP_LAB_ALLOW_VIRTUAL_DISK_UNIQUE_ID = $env:DLP_LAB_ALLOW_VIRTUAL_DISK_UNIQUE_ID
    }
    provisioning_files = [ordered]@{}
    secrets_files = [ordered]@{}
}

foreach ($name in @('phase1-root-ca.pem', 'admin-ca.pem', 'provisioning-admin-cert.pem', 'provisioning-admin-key.pem')) {
    $path = Join-Path $provDir $name
    $report.provisioning_files[$name] = [ordered]@{
        path = $path
        exists = Test-Path -LiteralPath $path -PathType Leaf
        sha256 = Get-Sha256 $path
        first_line = Get-FirstLine $path
        looks_like_path = (Get-FirstLine $path) -match '^[A-Za-z]:\\'
        subject_issuer = Get-X509Subject $path
    }
}

foreach ($name in @('phase1-root-ca.pem', 'server-cert.pem', 'admin-ca.pem')) {
    $path = Join-Path $secretsDir $name
    $report.secrets_files[$name] = [ordered]@{
        path = $path
        exists = Test-Path -LiteralPath $path -PathType Leaf
        sha256 = Get-Sha256 $path
        first_line = Get-FirstLine $path
        looks_like_path = (Get-FirstLine $path) -match '^[A-Za-z]:\\'
        subject_issuer = Get-X509Subject $path
    }
}

# Compare the root CA dlpctl will trust against the root that signed the server cert.
$provRoot = Join-Path $provDir 'phase1-root-ca.pem'
$secretsRoot = Join-Path $secretsDir 'phase1-root-ca.pem'
$serverCert = Join-Path $secretsDir 'server-cert.pem'

$report.root_comparison = [ordered]@{
    provisioning_root_matches_secrets_root = ((Get-Sha256 $provRoot) -eq (Get-Sha256 $secretsRoot))
    provisioning_root_sha256 = Get-Sha256 $provRoot
    secrets_root_sha256 = Get-Sha256 $secretsRoot
}

function Get-X509Field([string]$PemPath, [string]$Field) {
    if (-not (Test-Path -LiteralPath $PemPath -PathType Leaf)) { return '<missing>' }
    $content = Get-Content -Raw -LiteralPath $PemPath
    $temp = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($temp, $content)
        $psi = New-Object System.Diagnostics.ProcessStartInfo('openssl', "x509 -in `"$temp`" -noout -$Field")
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $proc.WaitForExit()
        if ($proc.ExitCode -ne 0) { return '<parse-failed>' }
        return ($proc.StandardOutput.ReadToEnd() -split "`r?`n" | Where-Object { $_.Trim() -ne '' }) -join '; '
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    }
}

function Get-X509Text([string]$PemPath) {
    if (-not (Test-Path -LiteralPath $PemPath -PathType Leaf)) { return '<missing>' }
    $content = Get-Content -Raw -LiteralPath $PemPath
    $temp = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($temp, $content)
        $psi = New-Object System.Diagnostics.ProcessStartInfo('openssl', "x509 -in `"$temp`" -noout -text")
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $proc.WaitForExit()
        if ($proc.ExitCode -ne 0) { return '<parse-failed>' }
        return $proc.StandardOutput.ReadToEnd()
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    }
}

function Get-OpensslModulus([string]$PemPath) {
    if (-not (Test-Path -LiteralPath $PemPath -PathType Leaf)) { return '<missing>' }
    $content = Get-Content -Raw -LiteralPath $PemPath
    $temp = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($temp, $content)
        $psi = New-Object System.Diagnostics.ProcessStartInfo('openssl', "x509 -in `"$temp`" -noout -modulus")
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $proc.WaitForExit()
        if ($proc.ExitCode -ne 0) { return '<cert-modulus-failed>' }
        return ($proc.StandardOutput.ReadToEnd() -split "`r?`n" | Where-Object { $_.Trim() -ne '' } | Select-Object -First 1)
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    }
}

function Get-KeyModulus([string]$PemPath) {
    if (-not (Test-Path -LiteralPath $PemPath -PathType Leaf)) { return '<missing>' }
    $content = Get-Content -Raw -LiteralPath $PemPath
    $temp = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($temp, $content)
        $psi = New-Object System.Diagnostics.ProcessStartInfo('openssl', "rsa -in `"$temp`" -noout -modulus")
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $proc.WaitForExit()
        if ($proc.ExitCode -ne 0) { return '<key-modulus-failed>' }
        return ($proc.StandardOutput.ReadToEnd() -split "`r?`n" | Where-Object { $_.Trim() -ne '' } | Select-Object -First 1)
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    }
}

function Test-CertSignature([string]$CertPath, [string]$CaPath) {
    if (-not (Test-Path -LiteralPath $CertPath -PathType Leaf)) { return '<cert-missing>' }
    if (-not (Test-Path -LiteralPath $CaPath -PathType Leaf)) { return '<ca-missing>' }
    $psi = New-Object System.Diagnostics.ProcessStartInfo('openssl', "verify -CAfile `"$CaPath`" `"$CertPath`"")
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    $proc.WaitForExit()
    return [ordered]@{
        exit_code = $proc.ExitCode
        output = ($proc.StandardOutput.ReadToEnd() -split "`r?`n" | Where-Object { $_.Trim() -ne '' }) -join '; '
        error = ($proc.StandardError.ReadToEnd() -split "`r?`n" | Where-Object { $_.Trim() -ne '' }) -join '; '
    }
}

$provAdminCert = Join-Path $provDir 'provisioning-admin-cert.pem'
$provAdminKey = Join-Path $provDir 'provisioning-admin-key.pem'
$provAdminCa = Join-Path $provDir 'admin-ca.pem'
$secretsAdminCa = Join-Path $secretsDir 'admin-ca.pem'

$adminCertText = Get-X509Text $provAdminCert
$report.provisioning_admin_cert_analysis = [ordered]@{
    issuer = Get-X509Field $provAdminCert 'issuer'
    subject = Get-X509Field $provAdminCert 'subject'
    has_client_auth_eku = ($adminCertText -match 'TLS Web Client Authentication')
    has_digital_signature_ku = ($adminCertText -match 'Digital Signature')
    signature_against_prov_admin_ca = Test-CertSignature $provAdminCert $provAdminCa
    signature_against_secrets_admin_ca = Test-CertSignature $provAdminCert $secretsAdminCa
    cert_modulus = Get-OpensslModulus $provAdminCert
    key_modulus = Get-KeyModulus $provAdminKey
    key_cert_modulus_match = (Get-OpensslModulus $provAdminCert) -eq (Get-KeyModulus $provAdminKey)
}

$report.admin_ca_analysis = [ordered]@{
    provisioning_admin_ca_subject = Get-X509Field $provAdminCa 'subject'
    secrets_admin_ca_subject = Get-X509Field $secretsAdminCa 'subject'
    provisioning_admin_ca_issuer_matches_admin_cert_issuer = ((Get-X509Field $provAdminCa 'subject') -eq (Get-X509Field $provAdminCert 'issuer'))
    secrets_admin_ca_issuer_matches_admin_cert_issuer = ((Get-X509Field $secretsAdminCa 'subject') -eq (Get-X509Field $provAdminCert 'issuer'))
}

# Record how the endpoint hostname resolves and how the server is bound. A
# loopback resolution or a non-all-interfaces binding can explain why a client
# on the same host sees handshake EOFs from unexpected addresses.
$hostName = $hostPort.Split(':')[0]
$port = $hostPort.Split(':')[1]
$dnsHostEntry = try { ([System.Net.Dns]::GetHostEntry($hostName)).HostName } catch { "<failed: $($_)>" }
$dnsAddresses = try { @(([System.Net.Dns]::GetHostAddresses($hostName) | ForEach-Object { $_.IPAddressToString })) } catch { @("<failed: $($_)>") }
$report.dns_resolution = [ordered]@{
    hostname = $hostName
    host_entry = $dnsHostEntry
    addresses = $dnsAddresses
}
$serverTcpConnections = try {
    @(Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, State, OwningProcess |
        ForEach-Object { "$($_.LocalAddress):$($_.LocalPort) ($($_.State)) pid=$($_.OwningProcess)" })
} catch { @("<failed: $($_)>") }
$report.server_binding = [ordered]@{
    listen_address_env = $env:DLP_LISTEN_ADDRESS
    tcp_connections = $serverTcpConnections
}

# Use openssl s_client to see the live TLS handshake from the server's own
# perspective. We test both server-auth-only and mutually-authenticated paths.
$endpoint = $env:DLP_PROVISIONING_ENDPOINT
$hostPort = if ($endpoint -and $endpoint -match 'https://([^:/]+):(\d+)') {
    "$($Matches[1]):$($Matches[2])"
} else {
    'LAB-DC01.lab.local:8443'
}

function Get-AcceptableClientCaNames([string]$Text) {
    $lines = $Text -split "`r?`n"
    $names = [System.Collections.Generic.List[string]]::new()
    $inBlock = $false
    foreach ($line in $lines) {
        if ($line -match '^Acceptable client certificate CA names') {
            $inBlock = $true
            continue
        }
        if ($inBlock -and [string]::IsNullOrWhiteSpace($line)) {
            break
        }
        if ($inBlock) {
            $names.Add($line.Trim())
        }
    }
    if ($names.Count -eq 0) { return '<none>' }
    return ($names -join '; ')
}

function Get-VerifyReturnCode([string]$Text) {
    $line = $Text -split "`r?`n" | Where-Object { $_ -match '^Verify return code:' } | Select-Object -First 1
    if ($line) { return $line.Trim() }
    return '<not-found>'
}

function Invoke-OpensslSClient([string]$Arguments) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo('openssl', $Arguments)
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    # Give it a few seconds, then kill — we only need the handshake summary.
    if (-not $proc.WaitForExit(5000)) {
        $proc.Kill()
        $proc.WaitForExit()
    }
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    return [ordered]@{
        command = "openssl $Arguments"
        exit_code = $proc.ExitCode
        stdout_head = ($stdout -split "`r?`n" | Select-Object -First 60) -join "`n"
        stderr_head = ($stderr -split "`r?`n" | Select-Object -First 40) -join "`n"
        acceptable_client_ca_names = Get-AcceptableClientCaNames $stdout
        verify_return_code = Get-VerifyReturnCode $stdout
    }
}

$tempRoot = [System.IO.Path]::GetTempFileName()
$tempAdminCert = [System.IO.Path]::GetTempFileName()
$tempAdminKey = [System.IO.Path]::GetTempFileName()
try {
    Copy-Item -LiteralPath $provRoot -Destination $tempRoot -Force
    $report.openssl_s_client_server_auth = Invoke-OpensslSClient "s_client -connect $hostPort -CAfile `"$tempRoot`" -showcerts -verify_return_error"

    if ((Test-Path -LiteralPath (Join-Path $provDir 'provisioning-admin-cert.pem') -PathType Leaf) -and
        (Test-Path -LiteralPath (Join-Path $provDir 'provisioning-admin-key.pem') -PathType Leaf)) {
        Copy-Item -LiteralPath (Join-Path $provDir 'provisioning-admin-cert.pem') -Destination $tempAdminCert -Force
        Copy-Item -LiteralPath (Join-Path $provDir 'provisioning-admin-key.pem') -Destination $tempAdminKey -Force
        $report.openssl_s_client_mutual_tls = Invoke-OpensslSClient "s_client -connect $hostPort -CAfile `"$tempRoot`" -cert `"$tempAdminCert`" -key `"$tempAdminKey`" -verify_return_error"
    } else {
        $report.openssl_s_client_mutual_tls = '<provisioning-admin-cert-or-key-missing>'
    }
} finally {
    if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Force }
    if (Test-Path -LiteralPath $tempAdminCert) { Remove-Item -LiteralPath $tempAdminCert -Force }
    if (Test-Path -LiteralPath $tempAdminKey) { Remove-Item -LiteralPath $tempAdminKey -Force }
}

# Extract the served server certificate and inspect rustls/webpki-critical
# extensions. This catches a case where the server loads a different cert than
# the one Verify-DlpLabCertificates.ps1 checks.
function Get-ServedServerCertText([string]$HostPort, [string]$CaFile) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo('openssl', "s_client -connect $HostPort -CAfile `"$CaFile`" -showcerts < nul")
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    if (-not $proc.WaitForExit(5000)) {
        $proc.Kill()
        $proc.WaitForExit()
    }
    $stdout = $proc.StandardOutput.ReadToEnd()
    # Extract the first PEM block (the server leaf).
    $lines = $stdout -split "`r?`n"
    $inCert = $false
    $certLines = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $lines) {
        if ($line.Trim() -eq '-----BEGIN CERTIFICATE-----') {
            $inCert = $true
            $certLines.Add($line.Trim())
            continue
        }
        if ($inCert) {
            $certLines.Add($line.Trim())
            if ($line.Trim() -eq '-----END CERTIFICATE-----') { break }
        }
    }
    if ($certLines.Count -eq 0) { return '<no-cert-received>' }
    $temp = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllLines($temp, $certLines)
        $psi2 = New-Object System.Diagnostics.ProcessStartInfo('openssl', "x509 -in `"$temp`" -noout -text")
        $psi2.RedirectStandardOutput = $true
        $psi2.UseShellExecute = $false
        $psi2.CreateNoWindow = $true
        $proc2 = [System.Diagnostics.Process]::Start($psi2)
        $proc2.WaitForExit()
        return $proc2.StandardOutput.ReadToEnd()
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    }
}

$tempRoot2 = [System.IO.Path]::GetTempFileName()
try {
    Copy-Item -LiteralPath $provRoot -Destination $tempRoot2 -Force
    $servedText = Get-ServedServerCertText $hostPort $tempRoot2
    $report.served_server_cert = [ordered]@{
        text = $servedText
        has_subject_lab_dc01 = ($servedText -match 'Subject:.*CN\s*=\s*LAB-DC01\.lab\.local')
        has_san_lab_dc01 = ($servedText -match 'DNS:LAB-DC01\.lab\.local')
        has_eku_server_auth = ($servedText -match 'TLS Web Server Authentication')
        has_ku_digital_signature = ($servedText -match 'Digital Signature')
        has_ku_key_encipherment = ($servedText -match 'Key Encipherment')
        issuer_contains_phase1_root = ($servedText -match 'Issuer:.*CN\s*=\s*phase1-root-ca')
    }
} finally {
    if (Test-Path -LiteralPath $tempRoot2) { Remove-Item -LiteralPath $tempRoot2 -Force }
}

# If -RunReproduction is set, also run the full Invoke-Client01Runtime.ps1 path
# so the snapshot includes the fresh dlpctl failure in the same report.
if ($RunReproduction) {
    $report.reproduction_note = 'RunReproduction requested; trigger Invoke-Client01Runtime.ps1 separately and collect tls-events.log / dlpctl-rust.err afterwards.'
}

# Clear the TLS event log so the next run captures only fresh events.
if (Test-Path -LiteralPath $tlsLogPath) {
    Remove-Item -LiteralPath $tlsLogPath -Force
}
$report.tls_log_cleared = $true

Write-Host '=== Diagnostic snapshot collected ===' -ForegroundColor Cyan
Write-Host ($report | ConvertTo-Json -Depth 10)
Write-Host ''
Write-Host "Next: trigger the trusted-provisioning failure, then run:" -ForegroundColor Yellow
Write-Host "  Get-Content -LiteralPath '$tlsLogPath' -Raw" -ForegroundColor Yellow
Write-Host "  Get-Content -LiteralPath '$provDir\dlpctl-rust.err' -Raw" -ForegroundColor Yellow
Write-Host "  Get-Content -LiteralPath '$provDir\dlpctl.err' -Raw" -ForegroundColor Yellow
Write-Host "  Get-Content -LiteralPath '$provDir\dlpctl.log' -Raw" -ForegroundColor Yellow
