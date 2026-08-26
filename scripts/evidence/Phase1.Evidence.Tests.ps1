[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$verifier = Join-Path $repoRoot 'scripts/verify-phase1-evidence.ps1'
$module = Join-Path $repoRoot 'scripts/evidence/Phase1.Evidence.psm1'
$publisher = Join-Path $repoRoot 'scripts/add-independent-review.ps1'
Import-Module $module -Force

function Assert-D48 {
    param([bool]$Condition,[string]$Message)
    if (-not $Condition) { throw "D-48 FAILED: $Message" }
}

$missingStore = Join-Path $env:TEMP "d48-missing-$([guid]::NewGuid())"
$before = Test-Path $missingStore
$missing = Test-Phase1IndependentReview -RepositoryRoot $repoRoot -IndexPath (Join-Path $missingStore 'index.json') -ReviewerPolicyPath $publisher -ReviewerRootPath $publisher -ArchivalPolicyPath $publisher
Assert-D48 (-not $missing.Present -and -not $missing.Valid -and $missing.Errors[0] -eq 'independent_review_missing') 'missing generation did not fail closed'
Assert-D48 ((Test-Path $missingStore) -eq $before) 'verification mutated missing review store'

$publisherText = Get-Content -Raw $publisher
Assert-D48 ($publisherText -notmatch '\$VerifierName') 'free-form verifier name remains'
foreach ($parameter in @('ReviewerPolicyPath','ReviewerRootPath','ArchivalPolicyPath','SignerThumbprint')) {
    Assert-D48 ($publisherText -match ('\$' + $parameter)) "publisher parameter $parameter missing"
}
Assert-D48 ($publisherText -match 'WindowsIdentity.*GetCurrent' -and $publisherText -match 'COMPUTERNAME') 'publisher does not observe Windows context'
Assert-D48 ($publisherText -match 'Threading\.Mutex' -and $publisherText -match '\.staging-') 'publisher lacks serialized recoverable generation protocol'

& $verifier -ExecutionMachine hungdinh-lt -Scenario PortableTracer
if (-not $?) {
    throw 'Portable tracer contract did not pass.'
}

& $verifier -ExecutionMachine hungdinh-lt -Scenario ContractFixtures
if (-not $?) {
    throw 'Evidence fail-closed fixtures did not pass.'
}
