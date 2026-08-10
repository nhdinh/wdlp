[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$verifier = Join-Path $repoRoot 'scripts/verify-phase1-evidence.ps1'

& $verifier -ExecutionMachine hungdinh-lt -Scenario VisualAndReviewFixtures
if (-not $?) {
    throw 'Visual and independent-review contract did not pass.'
}
