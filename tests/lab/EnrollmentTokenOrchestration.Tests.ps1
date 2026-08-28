[CmdletBinding()]
param(
    [ValidateSet('CoreFlow', 'DocumentationAndDecisionCoverage', 'All')]
    [string]$TestCase = 'All'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$RuntimePath = Join-Path $RepoRoot 'scripts/lab/Invoke-Client01Runtime.ps1'
$Dc01RuntimePath = Join-Path $RepoRoot 'scripts/lab/Invoke-Dc01Server.ps1'
$SmokePath = Join-Path $RepoRoot 'tests/windows/Invoke-AgentServiceSmoke.ps1'
$Docs = [ordered]@{
    Startup = Join-Path $RepoRoot '.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md'
    Environment = Join-Path $RepoRoot '.planning/docs/ENV-VARS.md'
    Setup = Join-Path $RepoRoot '.planning/docs/LAB-SETUP-GUIDE.md'
    Scripts = Join-Path $RepoRoot 'scripts/lab/README.md'
}
$Failures = [System.Collections.Generic.List[string]]::new()

function Assert-Condition {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )
    if (-not $Condition) { $script:Failures.Add($Message) }
}

function Assert-Matches {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][string]$Message
    )
    Assert-Condition -Condition ($Text -match $Pattern) -Message $Message
}

function Assert-NotMatches {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][string]$Message
    )
    Assert-Condition -Condition ($Text -notmatch $Pattern) -Message $Message
}

function Get-UncommentedSource {
    param([Parameter(Mandatory)][string]$Path)

    $source = [System.IO.File]::ReadAllText($Path)
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
    Assert-Condition -Condition ($null -eq $errors -or $errors.Count -eq 0) -Message "PowerShell parser errors in $Path."
    return (@($tokens | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text }) -join ' ')
}

function Get-MarkdownSection {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Heading
    )

    $pattern = '(?ms)^#{1,6}\s+' + [regex]::Escape($Heading) + '\s*$.*?(?=^#{1,6}\s+|\z)'
    $match = [regex]::Match($Text, $pattern)
    if (-not $match.Success) { return '' }
    return $match.Value
}

function Assert-NoSecretBearingExamples {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Name
    )

    # D-09..D-12: examples may use visible placeholders and metadata, never
    # reusable secret contents or commands that print managed secret values.
    $pemBlocks = [regex]::Matches(
        $Text,
        '(?ms)-----BEGIN (?<label>(?:RSA |EC |OPENSSH )?PRIVATE KEY|CERTIFICATE)-----(?<body>.*?)-----END \k<label>-----'
    )
    foreach ($block in $pemBlocks) {
        $body = $block.Groups['body'].Value.Trim()
        $placeholder = $body -match '^(?:\.\.\.|<[^>]+>|\*{3}|REDACTED|PLACEHOLDER)$'
        if ($placeholder) { continue }

        $normalized = [regex]::Replace($body, '\s+', '')
        $decoded = $null
        try { $decoded = [Convert]::FromBase64String($normalized) } catch { }
        $kind = if ($block.Groups['label'].Value -eq 'CERTIFICATE') { 'certificate' } else { 'private-key' }
        Assert-Condition -Condition ($null -eq $decoded -or $decoded.Length -eq 0) -Message "$Name contains $kind contents."
        if ($null -eq $decoded -and -not [string]::IsNullOrWhiteSpace($normalized)) {
            Assert-Condition -Condition $false -Message "$Name contains a non-placeholder $kind block."
        }
    }
    Assert-NotMatches -Text $Text -Pattern '(?im)^\s*\$env:DLP_AGENT_ENROLLMENT_TOKEN\s*=\s*[''\"](?!\*\*\*|<FROM-RUNTIME-PROVIDER>)[^''\"]+[''\"]' -Message "$Name contains a runnable enrollment-token value."
    Assert-NotMatches -Text $Text -Pattern '(?im)^\s*\$env:[A-Z0-9_]*PASSWORD\s*=\s*[''\"](?!\*\*\*|<FROM-RUNTIME-PROVIDER>)[^''\"]+[''\"]' -Message "$Name contains a runnable password value."
    Assert-NotMatches -Text $Text -Pattern '(?im)Get-Content[^\r\n]*(?:agent\.env|device\.dpapi)(?![^\r\n]*(?:-replace|-match|Select-String|\.Count))' -Message "$Name contains an unredacted managed-secret diagnostic path."
}

function Assert-WrappedPemFixtureRejected {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Name
    )

    $before = $script:Failures.Count
    Assert-NoSecretBearingExamples -Text $Text -Name $Name
    $after = $script:Failures.Count
    while ($script:Failures.Count -gt $before) {
        $script:Failures.RemoveAt($script:Failures.Count - 1)
    }
    Assert-Condition -Condition ($after -gt $before) -Message "$Name wrapped PEM fixture was not rejected."
}

function Invoke-CoreFlowCoverage {
    $runtime = Get-UncommentedSource -Path $RuntimePath
    $dc01Runtime = Get-UncommentedSource -Path $Dc01RuntimePath
    $smoke = Get-UncommentedSource -Path $SmokePath

    # SRV-13 / D-05: the ordinary ServiceInstall path defaults to trusted
    # provisioning, contains no manual token copy, and reuses device.dpapi.
    Assert-Matches -Text $runtime -Pattern "EnrollmentTokenProvider\s*=\s*'TrustedProvisioning'" -Message 'SRV-13/D-05: TrustedProvisioning must be the default provider.'
    Assert-Matches -Text $runtime -Pattern "'ServiceInstall'\s*\{[^}]*Invoke-Client01Tracer" -Message 'SRV-13: ServiceInstall must execute the enrollment tracer.'
    Assert-Matches -Text $runtime -Pattern "credentialPresentBeforeStart\s*=\s*Test-Client01CredentialPresent[\s\S]*EnrollmentTokenProvider\s*-eq\s*'TrustedProvisioning'[\s\S]*existing_credential_reused" -Message 'D-05: existing usable credentials must skip provisioning.'
    Assert-Matches -Text $runtime -Pattern 'if\s*\(\s*\$ForceReenrollment\s*\)\s*\{\s*\$provisioningArguments\s*\.\s*RecoverCredential\s*=\s*\$true\s*\}' -Message 'Normal provisioning must not request server-side credential recovery.'
    Assert-Matches -Text $smoke -Pattern 'Scenario\s*=\s*''ServiceInstall''[\s\S]*Apply\s*=\s*\$true' -Message 'SRV-13: smoke coverage must invoke ordinary ServiceInstall with Apply.'
    $liveRecovery = [regex]::Match($smoke, '(?s)function\s+Invoke-LiveEnrollmentRecovery\b.*?(?=function\s+Get-AgentPreservationState)').Value
    Assert-NotMatches -Text $liveRecovery -Pattern 'EnrollmentTokenProvider|DLP_AGENT_ENROLLMENT_TOKEN' -Message 'SRV-13: normal smoke flow must not override the provider or copy a token.'

    # SRV-14 / D-01..D-04: admin mTLS remains on LAB-DC01, failure cleanup
    # names and verifies both managed locations, and retry token state is fresh.
    Assert-Matches -Text $runtime -Pattern "Invoke-LabCommand\s+-VMName\s+'LAB-DC01'" -Message 'SRV-14: trusted provisioning must execute on LAB-DC01.'
    Assert-Matches -Text $runtime -Pattern "admin_material_location\s*=\s*'LAB-DC01'" -Message 'SRV-14: diagnostics must preserve the LAB-DC01 admin boundary.'
    Assert-Matches -Text $runtime -Pattern 'Remove-Client01EnrollmentToken[\s\S]*C:\\dlp\\agent\\agent\.env[\s\S]*HKLM:\\SYSTEM\\CurrentControlSet\\Services\\DlpWindowsService\\Environment' -Message 'D-01/D-02: cleanup must cover agent.env and SCM Environment.'
    Assert-Matches -Text $runtime -Pattern 'Remove-EnrollmentTokenState\.ps1' -Message 'D-01/D-02: runtime cleanup must invoke the testable command adapter.'
    Assert-NotMatches -Text $smoke -Pattern 'Invoke-TokenCleanupModel' -Message 'Failure-path smoke coverage must not use a cleanup model.'
    Assert-Matches -Text $smoke -Pattern 'Invoke-TokenCleanupFixture[\s\S]*FailAgentEnv[\s\S]*FailScmEnvironment' -Message 'Failure-path smoke must invoke the real adapter with independent location failures.'
    Assert-Matches -Text $runtime -Pattern 'partial service/binary artifacts were preserved' -Message 'D-03: failed startup must preserve diagnosable artifacts.'
    Assert-Matches -Text $runtime -Pattern '\$enrollmentToken\s*=\s*Invoke-Client01TrustedProvisioning' -Message 'D-04: retries must obtain trusted-provisioning material afresh.'
    Assert-Matches -Text $runtime -Pattern 'finally\s*\{\s*\$enrollmentToken\s*=\s*\$null' -Message 'D-04/D-12: local token state must be cleared after every attempt.'

    # D-06..D-08: force replacement is explicit, Apply-gated, and preserves
    # the installed service plus data/cache directories.
    Assert-Matches -Text $runtime -Pattern '\[\s*switch\s*\]\s*\$ForceReenrollment' -Message 'D-06: -ForceReenrollment must be supported.'
    Assert-Matches -Text $runtime -Pattern '\$ForceReenrollment\s*-and\s*-not\s*\$Apply[\s\S]*force_reenrollment_preview[\s\S]*return' -Message 'D-07: force preview must be non-destructive without -Apply.'
    Assert-Matches -Text $runtime -Pattern 'Reset-Client01EnrollmentCredential[\s\S]*preserv(?:e|ing)[^\r\n]*(?:service|data)[^\r\n]*cache' -Message 'D-08: force replacement must preserve service, data, and cache.'
    Assert-Matches -Text $runtime -Pattern 'credential_files_remain[\s\S]*WriteAllText\(\$ResultPath, ''complete''\)[\s\S]*credential_reset_delete_failed[\s\S]*credential_reset_verification_failed' -Message 'Force reset must fail closed unless the SYSTEM deletion and absence checks succeed.'
    Assert-Matches -Text $smoke -Pattern 'force_reenrollment_removed_preserved_state' -Message 'D-08: smoke coverage must assert preservation after replacement.'
    foreach ($replacementMarker in @('replacement_credential_serial_unchanged', 'replacement_predecessor_not_rejected', 'ordinary_recovery_revoked_predecessor')) {
        Assert-Matches -Text $smoke -Pattern ([regex]::Escape($replacementMarker)) -Message "Credential replacement regression marker $replacementMarker is missing."
    }

    # TST-05 / AGT-01: success means Automatic + Running and a verified first
    # signed policy with a non-null version and Active state.
    Assert-Matches -Text $runtime -Pattern '-StartupType\s+Automatic' -Message 'AGT-01: new service installation must use Automatic startup.'
    Assert-Matches -Text $runtime -Pattern 'start=\s*auto' -Message 'AGT-01: existing service reconfiguration must retain automatic startup.'
    Assert-Matches -Text $smoke -Pattern "StartType\s*-eq\s*'Auto'" -Message 'AGT-01: smoke coverage must verify automatic startup.'
    Assert-Matches -Text $runtime -Pattern 'Wait-Client01ActivePolicy' -Message 'TST-05: ServiceInstall must wait for first signed policy activation.'
    Assert-Matches -Text $runtime -Pattern 'BaselineLogLength[\s\S]*authenticated configuration poll succeeded' -Message 'TST-05: policy acceptance must be bound to a post-start authenticated poll.'
    Assert-Matches -Text $runtime -Pattern 'initial_enrollment_precondition_failed' -Message 'Initial enrollment must reject stale pointer state when no credential exists.'
    Assert-Matches -Text $smoke -Pattern 'active_policy_version=\\S\+' -Message 'TST-05: smoke coverage must reject a null active-policy version.'
    Assert-Matches -Text $smoke -Pattern 'active_policy_state=Active' -Message 'TST-05: smoke coverage must require Active policy state.'
    foreach ($aclMarker in @('SetAccessRuleProtection', 'FileSecurity', 'CreateNew', 'AreAccessRulesProtected', 'enrollment_token_acl_unexpected_principal')) {
        Assert-Matches -Text $runtime -Pattern ([regex]::Escape($aclMarker)) -Message "Enrollment-token ACL contract marker $aclMarker is missing."
    }
    Assert-Matches -Text $smoke -Pattern 'ordinary_user_can_read_agent_env' -Message 'Live smoke must reject an agent.env ACL readable by an ordinary principal.'

    # Authenticated evidence must preserve both CA and hostname validation in
    # every executable lab runner. A trust-all callback can never publish pass.
    foreach ($runner in @($runtime, $dc01Runtime)) {
        Assert-NotMatches -Text $runner -Pattern 'TrustAllCertsPolicy|ServerCertificateValidationCallback\s*=\s*\{\s*\$true\s*\}|CertificatePolicy\s*=\s*New-Object' -Message 'Executable lab runner contains a trust-all TLS path.'
    }
    Assert-Matches -Text $dc01Runtime -Pattern 'LAB-DC01\.lab\.local[\s\S]*curl\.exe[\s\S]*--cacert[\s\S]*--resolve' -Message 'LAB-DC01 evidence probes must authenticate the explicit Phase 1 CA and DNS name.'
    Assert-Matches -Text $dc01Runtime -Pattern 'DLP_CONFIGURATION_KEY_ID[\s\S]*phase1-config-signing-key-v1[\s\S]*configuration_key_id_mismatch' -Message 'LAB-DC01 must propagate and verify the configuration key identifier.'

    # D-09..D-12: normal status is coded/sparse; detailed diagnostics are
    # explicit, bounded, and never contain raw managed secret material.
    Assert-Matches -Text $runtime -Pattern '\[\s*switch\s*\]\s*\$Diagnostic' -Message 'D-11: an explicit diagnostic switch must exist.'
    Assert-Matches -Text $runtime -Pattern 'if\s*\(\s*-not\s*\$Diagnostic\s*\)\s*\{\s*return\s*\}' -Message 'D-09/D-11: detailed diagnostics must be opt-in.'
    foreach ($marker in @('file_lengths', 'event_log_error_count', 'fingerprint')) {
        Assert-Matches -Text $runtime -Pattern ([regex]::Escape($marker)) -Message "D-10/D-12: bounded diagnostic marker $marker is missing."
    }
    Assert-NotMatches -Text $runtime -Pattern 'env_file\s*=\s*Get-Content|first_line\s*=|ConvertTo-Json[^\r\n]*enrollment_token' -Message 'D-12: runtime diagnostics include a raw secret-bearing path.'
    Assert-Matches -Text $smoke -Pattern "'InstallStartFailureCleanup'[\s\S]*'CleanupFailure'[\s\S]*'FreshTokenRetry'[\s\S]*'NormalOutput'[\s\S]*'DiagnosticRedaction'" -Message 'D-01..D-04/D-09..D-12: smoke scenarios are incomplete.'
}

function Invoke-DocumentationAndDecisionCoverage {
    $wrappedBody = ('QUFB' * 16) + "`n" + ('QkJC' * 16)
    Assert-WrappedPemFixtureRejected -Name 'wrapped-certificate' -Text "-----BEGIN CERTIFICATE-----`n$wrappedBody`n-----END CERTIFICATE-----"
    Assert-WrappedPemFixtureRejected -Name 'wrapped-private-key' -Text "-----BEGIN PRIVATE KEY-----`n$wrappedBody`n-----END PRIVATE KEY-----"

    foreach ($entry in $Docs.GetEnumerator()) {
        $name = $entry.Key
        $text = [System.IO.File]::ReadAllText($entry.Value)

        foreach ($pattern in @(
            'TrustedProvisioning',
            'Manual',
            '-ForceReenrollment',
            '-Apply',
            '-Diagnostic',
            'active_policy_version',
            'active_policy_state',
            'C:\\dlp\\agent\\agent\.env',
            'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\DlpWindowsService\\Environment',
            'fresh[^\r\n]*token',
            'LAB-DC01'
        )) {
            Assert-Matches -Text $text -Pattern $pattern -Message "$name documentation is missing required automatic-enrollment/recovery marker: $pattern"
        }

        Assert-Matches -Text $text -Pattern 'Manual[^\r\n]*(?:offline|fallback)|(?:offline|fallback)[^\r\n]*Manual' -Message "$name must describe Manual only as the explicit offline fallback."
        Assert-Matches -Text $text -Pattern 'ForceReenrollment[^\r\n]*Apply|Apply[^\r\n]*ForceReenrollment' -Message "$name must document -ForceReenrollment -Apply as the only replacement path."
        Assert-Matches -Text $text -Pattern 'service[^\r\n]*(?:data|cache)[^\r\n]*(?:cache|data)|(?:data|cache)[^\r\n]*(?:service|binary)' -Message "$name must document service/data/cache preservation."
        Assert-Matches -Text $text -Pattern 'administrator mTLS[^\r\n]*LAB-DC01|LAB-DC01[^\r\n]*administrator mTLS' -Message "$name must keep administrator mTLS material on LAB-DC01."
        Assert-Matches -Text $text -Pattern 'redact' -Message "$name must require redacted diagnostics."

        $powershellBlocks = @([regex]::Matches($text, '(?ms)```powershell\s*(.*?)```') | ForEach-Object { $_.Groups[1].Value })
        $ordinaryBlocks = @($powershellBlocks | Where-Object {
            $_ -match '-Scenario\s+ServiceInstall' -and
            $_ -notmatch '-EnrollmentTokenProvider' -and
            $_ -notmatch '\$env:DLP_AGENT_ENROLLMENT_TOKEN'
        })
        Assert-Condition -Condition ($ordinaryBlocks.Count -gt 0) -Message "$name must show the ordinary ServiceInstall command with the default TrustedProvisioning provider and no token copy."

        Assert-NoSecretBearingExamples -Text $text -Name $name
    }

    $startup = [System.IO.File]::ReadAllText($Docs.Startup)
    $enrollmentSection = Get-MarkdownSection -Text $startup -Heading '8. Enrollment Flow'
    Assert-NotMatches -Text $enrollmentSection -Pattern 'manual provider remains the default|omit -EnrollmentTokenProvider' -Message 'Startup enrollment guidance still describes Manual as the default.'
    Assert-NotMatches -Text $startup -Pattern 'TrustAllCertsPolicy|ServerCertificateValidationCallback\s*=\s*\{\s*\$true\s*\}' -Message 'Startup guide contains a trust-all diagnostic path.'

    $environment = [System.IO.File]::ReadAllText($Docs.Environment)
    Assert-Matches -Text $environment -Pattern 'conditional[^\r\n]*existing credential|existing credential[^\r\n]*conditional' -Message 'ENV-VARS.md must explain enrollment-token optionality when device.dpapi is usable.'
}

if ($TestCase -in @('CoreFlow', 'All')) { Invoke-CoreFlowCoverage }
if ($TestCase -in @('DocumentationAndDecisionCoverage', 'All')) { Invoke-DocumentationAndDecisionCoverage }

if ($Failures.Count -gt 0) {
    $Failures | ForEach-Object { [Console]::Error.WriteLine("FAIL: $_") }
    exit 1
}

Write-Host "EnrollmentTokenOrchestration $TestCase passed."
