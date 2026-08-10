[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$verifier = Join-Path $repoRoot 'scripts/verify-phase1-evidence.ps1'

& $verifier -ExecutionMachine hungdinh-lt -Scenario PortableTracer
if (-not $?) {
    throw 'Portable tracer contract did not pass.'
}

& $verifier -ExecutionMachine hungdinh-lt -Scenario ContractFixtures
if (-not $?) {
    throw 'Evidence fail-closed fixtures did not pass.'
}
