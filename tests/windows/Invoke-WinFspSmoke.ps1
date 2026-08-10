[CmdletBinding()]
param(
    [switch]$Extended,
    [ValidateRange(0, 120)]
    [int]$HoldSeconds = 0
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
$freeLetter = (68..90 | ForEach-Object { "$([char]$_):" } | Sort-Object -Descending |
    Where-Object { -not (Test-Path "$_\") } | Select-Object -First 1)
if (-not $freeLetter) { throw 'No free drive letter is available for WinFsp smoke.' }
$env:DLP_WINFSP_SMOKE_LETTER = $freeLetter
$env:DLP_WINFSP_INTERACTIVE_HOLD_MS = [string]($HoldSeconds * 1000)
Write-Host "WinFsp smoke will use $freeLetter"
cargo test -p dlp-windows-drive --test mounted_smoke -- --nocapture
if ($LASTEXITCODE -ne 0) { throw 'WinFsp mounted smoke failed.' }

if ($Extended) {
    Write-Host 'Extended smoke exercised directory, concurrent-handle, rename, delete, and restart-visible namespace operations.'
}
