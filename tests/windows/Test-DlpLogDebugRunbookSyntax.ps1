[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$RunbookPath
)

$ErrorActionPreference = 'Stop'
$runbook = Get-Content -LiteralPath $RunbookPath -Raw -ErrorAction Stop
$blocks = [regex]::Matches($runbook, '(?ms)^```powershell\s*\r?\n(.*?)^```\s*$')
if ($blocks.Count -eq 0) { Write-Error 'No fenced powershell blocks found.'; exit 1 }
$requiredPreflightContracts = @(
    '[System.Management.Automation.PSCredential]$Credential',
    '[string]$DnsSuffix = ''lab.local''',
    '-Credential $Credential',
    '-Credential $labCredential'
)
foreach ($contract in $requiredPreflightContracts) {
    if (-not $runbook.Contains($contract)) {
        Write-Error ("Missing preflight contract: {0}" -f $contract)
        exit 1
    }
}
$failed = $false
for ($index = 0; $index -lt $blocks.Count; $index++) {
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($blocks[$index].Groups[1].Value, [ref]$tokens, [ref]$parseErrors)
    foreach ($parseError in $parseErrors) {
        $failed = $true
        Write-Error ("Block {0}: {1}" -f ($index + 1), $parseError.Message)
    }
}
if ($failed) { exit 1 }
exit 0
