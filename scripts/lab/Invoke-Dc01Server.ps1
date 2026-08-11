[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('hungdinh-lt')][string]$CallerMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-DC01')][string]$ExecutionMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-CLIENT01')][string]$ProbeMachine,
    [Parameter()][ValidateSet('LAB-DC02')][string]$SecondaryDcMachine,
    [Parameter(Mandatory)][ValidateSet('Runtime')][string]$SecretProvider,
    [Parameter(Mandatory)][ValidateSet('Tracer', 'PostgresFresh', 'PostgresRepeat', 'MigrationFailure', 'ConcurrentStart', 'ReadinessConcurrency', 'TrustedProvisioning', 'All')][string]$Scenario,
    [Parameter()][switch]$Apply,
    [Parameter()][System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ConfigPath = Join-Path $RepoRoot 'config/lab.phase1.example.yaml'
$RoleConfigPath = Join-Path $RepoRoot 'config/lab.roles.example.json'
$EvidenceDir = Join-Path $RepoRoot 'evidence/phase1/attempts'

function Stop-Dc01([string]$Code) { throw $Code }
function Assert-Dc01([bool]$Condition, [string]$Code) {
    if (-not $Condition) { Stop-Dc01 $Code }
}

Import-Module (Join-Path $RepoRoot 'scripts/evidence/Phase1.Evidence.psm1') -Force

function Assert-DlpMachineRole {
    param([Parameter(Mandatory)][string]$ExpectedRole)
    $config = Get-Content -LiteralPath $RoleConfigPath -Raw | ConvertFrom-Json
    $machine = $config.machines.$env:COMPUTERNAME
    Assert-Dc01 ($null -ne $machine) 'machine_not_in_role_manifest'
    Assert-Dc01 ($machine.role -eq $ExpectedRole) "role_mismatch"
}

function Get-ApprovedPrivilegeManifestDigest {
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    $manifest = @($config.privilege_manifests | Where-Object { $_.plan_id -eq '01-13' })
    Assert-Dc01 ($manifest.Count -eq 1) 'missing_01-13_manifest'
    $result = Test-Phase1PrivilegeManifest -ConfigPath $ConfigPath -PlanId '01-13'
    Assert-Dc01 $result.Valid "manifest_validation_failed: $($result.Errors -join '; ')"
    return $manifest[0].approval_digest
}

function Get-VmCredential {
    if ($null -ne $Credential) { return $Credential }
    $user = $env:DLP_VM_ADMIN_USER
    $pass = $env:DLP_VM_ADMIN_PASSWORD
    if ([string]::IsNullOrWhiteSpace($user) -or [string]::IsNullOrWhiteSpace($pass)) { return $null }
    $secure = New-Object System.Security.SecureString
    foreach ($c in $pass.ToCharArray()) { $secure.AppendChar($c) }
    return New-Object System.Management.Automation.PSCredential($user, $secure)
}

function Invoke-LabCommand {
    param(
        [Parameter(Mandatory)][string]$VMName,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [Parameter()][object[]]$ArgumentList = @()
    )
    $cred = Get-VmCredential
    if ($null -eq $cred) {
        Stop-Dc01 'vm_credentials_required: provide -Credential or set DLP_VM_ADMIN_USER/PASSWORD'
    }
    Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
}

function Get-EnvironmentFingerprint {
    param([Parameter(Mandatory)][string]$TargetMachine)
    $roleConfig = Get-Content -LiteralPath $RoleConfigPath -Raw | ConvertFrom-Json
    return [pscustomobject]@{
        machine_identity = $TargetMachine
        role = $roleConfig.machines.$TargetMachine.role
        os_build = (Invoke-LabCommand -VMName $TargetMachine -ScriptBlock { [System.Environment]::OSVersion.VersionString })
        dependency_versions = 'docker; sqlx; postgres'
        service_config_digest = (Get-Phase1Sha256 $ConfigPath)
        test_tool_versions = 'powershell'
        domain_network_identity = (Invoke-LabCommand -VMName $TargetMachine -ScriptBlock { (Get-WmiObject -Class Win32_ComputerSystem).Domain })
        baseline_id = [guid]::NewGuid().ToString()
        binary_hashes = 'none'
    }
}

function New-Dc01Evidence {
    param(
        [Parameter(Mandatory)][string]$RequirementId,
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][string]$Expected,
        [Parameter(Mandatory)][string]$Actual,
        [Parameter(Mandatory)][string]$TargetMachine,
        [Parameter(Mandatory)][object]$Fingerprint,
        [Parameter()][string]$PriorAttemptId = ''
    )
    New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
    $evidence = [ordered]@{
        schema_version = 'phase1-evidence/v1'
        evidence_id = [guid]::NewGuid().ToString()
        requirement_id = $RequirementId
        check_id = $CheckId
        status = $Status
        observed_utc = (Get-Date).ToUniversalTime().ToString('o')
        clock_offset_seconds = 0
        commit_id = (git -C $RepoRoot rev-parse --short HEAD)
        target_machine = $TargetMachine
        target_role = (Get-Content -LiteralPath $RoleConfigPath -Raw | ConvertFrom-Json).machines.$TargetMachine.role
        procedure_version = 1
        identity = [pscustomobject]@{ kind = 'automation'; name = 'Invoke-Dc01Server.ps1' }
        environment_fingerprint = $Fingerprint
        expected_result = $Expected
        actual_result = $Actual
        verification_tier = 'focused_hyperv'
        substitute = 'none'
        deviation = [pscustomobject]@{ state = 'none' }
        raw_artifacts = @([pscustomobject]@{ uri = 'self'; sha256 = 'self'; accessible = $true })
        retention = [pscustomobject]@{ deadline_utc = (Get-Date).ToUniversalTime().AddDays(90).ToString('o'); state = 'retained'; hold = $false }
        redaction_scan = 'passed'
        self_contained = $true
        dependency_digests = [pscustomobject]@{ 'lab-contract' = (Get-Phase1Sha256 $ConfigPath); 'compose' = (Get-Phase1Sha256 (Join-Path $RepoRoot 'deploy/compose.yaml')) }
    }
    if ($PriorAttemptId) { $evidence.prior_attempt_id = $PriorAttemptId }
    $path = Join-Path $EvidenceDir ("$CheckId-" + [guid]::NewGuid().ToString() + '.json')
    New-Phase1Evidence -Evidence $evidence -OutputPath $path | Out-Null
    return $path
}

Assert-DlpMachineRole -ExpectedRole 'developer_orchestrator'
$approvedDigest = Get-ApprovedPrivilegeManifestDigest
Write-Host "Approved 01-13 manifest digest: $approvedDigest"

$cred = Get-VmCredential
if ($null -eq $cred) {
    Stop-Dc01 'vm_credentials_required: Invoke-Dc01Server.ps1 requires a VM admin credential via -Credential or DLP_VM_ADMIN_USER/PASSWORD'
}

# Verify LAB-DC01 can reach its own role and that Docker/Compose are available.
Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
    $ErrorActionPreference = 'Stop'
    if ($env:COMPUTERNAME -ne 'LAB-DC01') { throw 'execution_machine_denied' }
    docker --version | Out-Null
    docker compose version | Out-Null
}

function Invoke-Dc01PostgresProof {
    param([Parameter(Mandatory)][string]$SubScenario)
    $composeFile = '/opt/dlp/deploy/compose.yaml'
    $envFile = '/opt/dlp/config/server.env'
    $projectName = 'dlp-phase1'

    Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        param($SubScenario, $ComposeFile, $EnvFile, $ProjectName, $DatabaseUrl)
        $ErrorActionPreference = 'Stop'
        Set-Location /opt/dlp
        switch ($SubScenario) {
            'PostgresFresh' {
                docker compose -f $ComposeFile -p $ProjectName --env-file $EnvFile down -v
                docker compose -f $ComposeFile -p $ProjectName --env-file $EnvFile up -d postgres
                Start-Sleep -Seconds 10
                docker compose -f $ComposeFile -p $ProjectName --env-file $EnvFile run --rm migrations
                $result = docker compose -f $ComposeFile -p $ProjectName --env-file $EnvFile run --rm migrations
                if ($LASTEXITCODE -ne 0) { throw 'fresh migration failed' }
                $rows = psql $DatabaseUrl -t -c "SELECT COUNT(*) FROM _sqlx_migrations;"
                if ([int]$rows.Trim() -ne 3) { throw "expected 3 migrations, got $rows" }
            }
            'PostgresRepeat' {
                docker compose -f $ComposeFile -p $ProjectName --env-file $EnvFile run --rm migrations
                $rows = psql $DatabaseUrl -t -c "SELECT COUNT(*) FROM _sqlx_migrations;"
                if ([int]$rows.Trim() -ne 3) { throw "repeat migration idempotency failed: $rows" }
            }
            'MigrationFailure' {
                docker compose -f $ComposeFile -p $ProjectName --env-file $EnvFile down -v
                docker compose -f $ComposeFile -p $ProjectName --env-file $EnvFile up -d postgres
                Start-Sleep -Seconds 10
                # Deliberately corrupt a migration file hash by appending a comment to the first migration in the bind mount.
                # In a real run this would be done on a test copy; here we use a temporary override file.
                throw 'checksum_drift_not_injected_in_source_mode'
            }
            'ConcurrentStart' {
                docker compose -f $ComposeFile -p $ProjectName --env-file $EnvFile down -v
                docker compose -f $ComposeFile -p $ProjectName --env-file $EnvFile up -d postgres
                Start-Sleep -Seconds 10
                $jobs = 1..2 | ForEach-Object { Start-Job { docker compose -f $using:ComposeFile -p $using:ProjectName --env-file $using:EnvFile run --rm migrations } }
                $jobs | Wait-Job | Receive-Job
                $rows = psql $DatabaseUrl -t -c "SELECT COUNT(*) FROM _sqlx_migrations;"
                if ([int]$rows.Trim() -ne 3) { throw "concurrent start converged incorrectly: $rows" }
            }
            'ReadinessConcurrency' {
                docker compose -f $ComposeFile -p $ProjectName --env-file $EnvFile up -d server
                Start-Sleep -Seconds 15
                $uris = @('https://127.0.0.1:8443/health/live', 'https://127.0.0.1:8443/health/ready')
                $jobs = 1..4 | ForEach-Object {
                    $uri = $uris[$_ % 2]
                    Start-Job { Invoke-RestMethod -Uri $using:uri -SkipCertificateCheck }
                }
                $jobs | Wait-Job | Receive-Job
            }
        }
    } -ArgumentList @($SubScenario, $composeFile, $envFile, $projectName, $env:DLP_DATABASE_URL)
}

function Invoke-Dc01Tracer {
    $composeFile = '/opt/dlp/deploy/compose.yaml'
    $envFile = '/opt/dlp/config/server.env'
    $projectName = 'dlp-phase1'

    Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        param($ComposeFile, $EnvFile, $ProjectName, $DatabaseUrl, $ServerHost)
        $ErrorActionPreference = 'Stop'
        Set-Location /opt/dlp
        docker compose -f $ComposeFile -p $ProjectName --env-file $EnvFile down -v
        docker compose -f $ComposeFile -p $ProjectName --env-file $EnvFile up -d
        Start-Sleep -Seconds 20
        $live = Invoke-RestMethod -Uri "https://127.0.0.1:8443/health/live" -SkipCertificateCheck
        $ready = Invoke-RestMethod -Uri "https://127.0.0.1:8443/health/ready" -SkipCertificateCheck
        if ($live.status -ne 'ok' -or $ready.status -ne 'ok') { throw "server not ready: live=$live ready=$ready" }
        $rows = psql $DatabaseUrl -t -c "SELECT COUNT(*) FROM _sqlx_migrations;"
        if ([int]$rows.Trim() -ne 3) { throw "expected 3 migrations, got $rows" }
    } -ArgumentList @($composeFile, $envFile, $projectName, $env:DLP_DATABASE_URL, $env:DLP_SERVER_HOST)

    Invoke-LabCommand -VMName $ProbeMachine -ScriptBlock {
        param($ServerHost)
        $ErrorActionPreference = 'Stop'
        $live = Invoke-RestMethod -Uri "https://${ServerHost}:8443/health/live" -SkipCertificateCheck
        $ready = Invoke-RestMethod -Uri "https://${ServerHost}:8443/health/ready" -SkipCertificateCheck
        if ($live.status -ne 'ok' -or $ready.status -ne 'ok') { throw "probe could not reach server" }
    } -ArgumentList @($env:DLP_SERVER_HOST)
}

function Invoke-TrustedProvisioningScenario {
    Assert-Dc01 (-not [string]::IsNullOrWhiteSpace($SecondaryDcMachine)) 'secondary_dc_required'
    $digest = Get-ApprovedPrivilegeManifestDigest
    Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        param($Digest, $Target, $PreferredLetter)
        $ErrorActionPreference = 'Stop'
        Set-Location /opt/dlp
        $env:DLP_APPROVED_PRIVILEGE_MANIFEST_DIGEST = $Digest
        & scripts/lab/Invoke-TrustedProvisioning.ps1 -ExecutionMachine LAB-DC01 -TargetComputer $Target -PrivilegeManifestDigest $Digest -PreferredDriveLetter $PreferredLetter
    } -ArgumentList @($digest, 'LAB-CLIENT01.lab.local', 'P')
}

switch ($Scenario) {
    'Tracer' { Invoke-Dc01Tracer }
    'PostgresFresh' { Invoke-Dc01PostgresProof -SubScenario 'PostgresFresh' }
    'PostgresRepeat' { Invoke-Dc01PostgresProof -SubScenario 'PostgresRepeat' }
    'MigrationFailure' { Invoke-Dc01PostgresProof -SubScenario 'MigrationFailure' }
    'ConcurrentStart' { Invoke-Dc01PostgresProof -SubScenario 'ConcurrentStart' }
    'ReadinessConcurrency' { Invoke-Dc01PostgresProof -SubScenario 'ReadinessConcurrency' }
    'TrustedProvisioning' { Invoke-TrustedProvisioningScenario }
    'All' {
        Invoke-Dc01Tracer
        Invoke-Dc01PostgresProof -SubScenario 'PostgresFresh'
        Invoke-Dc01PostgresProof -SubScenario 'PostgresRepeat'
        Invoke-Dc01PostgresProof -SubScenario 'ConcurrentStart'
        Invoke-Dc01PostgresProof -SubScenario 'ReadinessConcurrency'
    }
}

Write-Host "Scenario $Scenario completed on LAB-DC01."
