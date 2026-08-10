[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
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
