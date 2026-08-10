[CmdletBinding()]
param(
    [switch]$Extended
)

$ErrorActionPreference = 'Stop'
$runtime = Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\WinFsp' -ErrorAction Stop
if (-not (Test-Path (Join-Path $runtime.InstallDir 'bin\winfsp-x64.dll'))) {
    throw 'WinFsp x64 runtime DLL is not installed.'
}

$llvm = 'C:\Program Files\LLVM\bin'
if (-not (Test-Path (Join-Path $llvm 'libclang.dll'))) {
    throw 'LLVM libclang.dll is required by the approved WinFsp binding build.'
}

$env:LIBCLANG_PATH = $llvm
$env:WINFSP_DLL_OUTPUT_PATH = (Join-Path (Get-Location) 'target\debug\deps')
cargo test -p dlp-windows-drive --test mounted_smoke -- --nocapture
if ($LASTEXITCODE -ne 0) { throw 'WinFsp mounted smoke failed.' }

if ($Extended) {
    Write-Host 'Extended WinFsp callback coverage is supplied by callback_contract in Task 2.'
}
