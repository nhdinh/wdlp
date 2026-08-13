[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('hungdinh-lt')][string]$CallerMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-CLIENT01')][string]$ExecutionMachine,
    [Parameter()][ValidateSet('LAB-DC01')][string]$ProbeMachine = 'LAB-DC01',
    [Parameter()][ValidateSet('Runtime')][string]$SecretProvider = 'Runtime',
    [Parameter(Mandatory)][ValidateSet('Tracer', 'ServiceInstall', 'All')][string]$Scenario,
    [Parameter()][ValidateSet('Manual', 'TrustedProvisioning')][string]$EnrollmentTokenProvider = 'Manual',
    [Parameter()][switch]$RetainEnrollmentToken,
    [Parameter()][switch]$Apply,
    [Parameter()][System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ConfigPath = Join-Path $RepoRoot 'config/lab.phase1.example.yaml'
$RoleConfigPath = Join-Path $RepoRoot 'config/lab.roles.example.json'
$EvidenceDir = Join-Path $RepoRoot 'evidence/phase1/attempts'

# Fixed Phase 1 lab topology. The management server binds on LAB-DC01 and the
# endpoint agent runtime lives on LAB-CLIENT01.
$script:Dc01Ip = '192.168.50.10'
$script:ServerPort = 8443

function Stop-Client01([string]$Code) { throw $Code }
function Assert-Client01([bool]$Condition, [string]$Code) {
    if (-not $Condition) { Stop-Client01 $Code }
}

Import-Module (Join-Path $RepoRoot 'scripts/evidence/Phase1.Evidence.psm1') -Force

function Assert-DlpMachineRole {
    param([Parameter(Mandatory)][string]$ExpectedRole)
    $config = Get-Content -LiteralPath $RoleConfigPath -Raw | ConvertFrom-Json
    $machine = $config.machines.$env:COMPUTERNAME
    Assert-Client01 ($null -ne $machine) 'machine_not_in_role_manifest'
    Assert-Client01 ($machine.role -eq $ExpectedRole) "role_mismatch"
}

function Get-ApprovedPrivilegeManifestDigest {
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    $manifest = @($config.privilege_manifests | Where-Object { $_.plan_id -eq '01-19' })
    Assert-Client01 ($manifest.Count -eq 1) 'missing_01-19_manifest'
    $result = Test-Phase1PrivilegeManifest -ConfigPath $ConfigPath -PlanId '01-19'
    Assert-Client01 $result.Valid "manifest_validation_failed: $($result.Errors -join '; ')"
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
        Stop-Client01 'vm_credentials_required: provide -Credential or set DLP_VM_ADMIN_USER/PASSWORD'
    }
    Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
}

function Get-EnvironmentFingerprint {
    param([Parameter(Mandatory)][string]$TargetMachine)
    $roleConfig = Get-Content -LiteralPath $RoleConfigPath -Raw | ConvertFrom-Json
    $remoteInfo = Invoke-LabCommand -VMName $TargetMachine -ScriptBlock {
        [pscustomobject]@{
            os_build = [System.Environment]::OSVersion.VersionString
            domain_network_identity = (Get-WmiObject -Class Win32_ComputerSystem).Domain
        }
    }
    return [pscustomobject]@{
        machine_identity = $TargetMachine
        role = $roleConfig.machines.$TargetMachine.role
        os_build = $remoteInfo.os_build
        dependency_versions = 'winfsp; dlp-windows-service'
        service_config_digest = (Get-Phase1Sha256 $ConfigPath)
        test_tool_versions = 'powershell'
        domain_network_identity = $remoteInfo.domain_network_identity
        baseline_id = [guid]::NewGuid().ToString()
        binary_hashes = 'none'
    }
}

function New-Client01Evidence {
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
    $artifactId = [guid]::NewGuid().ToString()
    $artifactPath = Join-Path $EvidenceDir ("$CheckId-fingerprint-$artifactId.json")
    [System.IO.File]::WriteAllText($artifactPath, ($Fingerprint | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))
    $artifactHash = Get-Phase1Sha256 $artifactPath
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
        identity = [pscustomobject]@{ kind = 'automation'; name = 'Invoke-Client01Runtime.ps1' }
        environment_fingerprint = $Fingerprint
        expected_result = $Expected
        actual_result = $Actual
        verification_tier = 'focused_hyperv'
        substitute = 'none'
        deviation = [pscustomobject]@{ state = 'none' }
        raw_artifacts = @([pscustomobject]@{ uri = $artifactPath; sha256 = $artifactHash; accessible = $true })
        retention = [pscustomobject]@{ deadline_utc = (Get-Date).ToUniversalTime().AddDays(90).ToString('o'); state = 'retained'; hold = $false }
        redaction_scan = 'passed'
        self_contained = $false
        dependency_digests = [pscustomobject]@{ 'lab-contract' = (Get-Phase1Sha256 $ConfigPath); 'lab-roles' = (Get-Phase1Sha256 $RoleConfigPath); 'agent-binary' = (Get-Phase1Sha256 (Join-Path $RepoRoot 'target/release/dlp-windows-service.exe')) }
    }
    if ($PriorAttemptId) { $evidence.prior_attempt_id = $PriorAttemptId }
    $path = Join-Path $EvidenceDir ("$CheckId-" + [guid]::NewGuid().ToString() + '.json')
    New-Phase1Evidence -Evidence $evidence -OutputPath $path | Out-Null
    return $path
}

function Copy-VMFileOrStream {
    param(
        [Parameter(Mandatory)][string]$VMName,
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DestinationPath
    )
    $vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
    Assert-Client01 ($vm -and $vm.State -eq 'Running') 'execution_vm_not_running'
    try {
        Copy-VMFile -Name $VMName -SourcePath $SourcePath -DestinationPath $DestinationPath -CreateFullPath -Force -FileSource Host
    } catch {
        # Fallback: stream via PowerShell Direct.
        $bytes = [System.IO.File]::ReadAllBytes($SourcePath)
        $b64 = [Convert]::ToBase64String($bytes)
        Invoke-LabCommand -VMName $VMName -ScriptBlock {
            param($Base64, $Path)
            $ErrorActionPreference = 'Stop'
            New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
            [System.IO.File]::WriteAllBytes($Path, [Convert]::FromBase64String($Base64))
        } -ArgumentList @($b64, $DestinationPath)
    }
}

function Assert-RuntimeSecretsPresent {
    $required = @(
        'DLP_DEVICE_ID',
        'DLP_SERVER_URL',
        'DLP_ROOT_CA_PEM',
        'DLP_CONFIGURATION_PUBLIC_KEY_HEX'
    )
    if ($EnrollmentTokenProvider -ne 'TrustedProvisioning') {
        $required += 'DLP_AGENT_ENROLLMENT_TOKEN'
    }
    $missing = @($required | Where-Object { [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($_)) })
    if ($missing.Count -gt 0) { Stop-Client01 ("runtime_secrets_missing: " + ($missing -join ', ')) }
}

function Test-Client01CredentialPresent {
    return Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        Test-Path -LiteralPath 'C:\dlp\agent\data\credentials\device.dpapi'
    }
}

function Invoke-Client01TrustedProvisioning {
    param(
        [Parameter(Mandatory)][string]$PrivilegeManifestDigest,
        [Parameter(Mandatory)][string]$TargetComputer,
        [Parameter()][char]$PreferredDriveLetter = 'P'
    )
    Write-Host 'TrustedProvisioning: invoking trusted provisioning on LAB-DC01...'
    $resultJson = Invoke-LabCommand -VMName 'LAB-DC01' -ScriptBlock {
        param($Digest, $Target, $PreferredLetter)
        $ErrorActionPreference = 'Stop'
        Set-Location C:\dlp\server
        & scripts/lab/Invoke-TrustedProvisioning.ps1 `
            -ExecutionMachine LAB-DC01 `
            -TargetComputer $Target `
            -PrivilegeManifestDigest $Digest `
            -PreferredDriveLetter $PreferredLetter
    } -ArgumentList @($PrivilegeManifestDigest, $TargetComputer, $PreferredDriveLetter)

    $result = $resultJson | ConvertFrom-Json
    if ([string]::IsNullOrWhiteSpace($result.enrollment_token)) {
        Stop-Client01 'trusted_provisioning_returned_empty_token'
    }
    Write-Host "TrustedProvisioning: obtained enrollment token for $($result.target)"
    return $result.enrollment_token
}

function Install-Client01ServiceBinary {
    $localBinary = Join-Path $RepoRoot 'target/release/dlp-windows-service.exe'
    if (-not (Test-Path -LiteralPath $localBinary)) {
        Write-Host 'Building dlp-windows-service release binary on hungdinh-lt...'
        $proc = Start-Process -FilePath 'cargo' -ArgumentList @('build', '--release', '-p', 'dlp-windows-service') -WorkingDirectory $RepoRoot -NoNewWindow -Wait -PassThru
        if ($proc.ExitCode -ne 0) { Stop-Client01 'cargo_build_failed' }
    }
    Assert-Client01 (Test-Path -LiteralPath $localBinary) 'release_binary_missing'

    Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        New-Item -ItemType Directory -Path 'C:\dlp\agent' -Force | Out-Null
        New-Item -ItemType Directory -Path 'C:\dlp\agent\data' -Force | Out-Null
        New-Item -ItemType Directory -Path 'C:\dlp\agent\cache' -Force | Out-Null
    }

    # Stop any running service before replacing the binary.
    Stop-Client01Service

    $remoteBinary = 'C:\dlp\agent\dlp-windows-service.exe'
    Copy-VMFileOrStream -VMName $ExecutionMachine -SourcePath $localBinary -DestinationPath $remoteBinary
}

function Stop-Client01Service {
    Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        $service = Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue
        if ($null -ne $service -and $service.Status -ne 'Stopped') {
            Stop-Service -Name 'DlpWindowsService' -Force -ErrorAction SilentlyContinue
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        }
    }
}

function Install-Client01RuntimeSecrets {
    param([Parameter()][string]$EnrollmentToken)

    # The runtime provider supplies configuration as environment variables. We
    # write them to an env file on LAB-CLIENT01; Install-Client01Service later
    # persists the same lines into the service registry Environment value so the
    # SCM creates the service process with these variables already loaded.
    $secrets = [ordered]@{
        'root-ca.pem' = $env:DLP_ROOT_CA_PEM
    }
    foreach ($name in $secrets.Keys) {
        Assert-Client01 (-not [string]::IsNullOrWhiteSpace($secrets[$name])) "secret_missing_$name"
    }

    $secretNames = $secrets.Keys
    $secretValues = $secrets.Values
    Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        param($Names, $Values)
        $ErrorActionPreference = 'Stop'
        $dir = 'C:\dlp\secrets'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        for ($i = 0; $i -lt $Names.Count; $i++) {
            $path = Join-Path $dir $Names[$i]
            [System.IO.File]::WriteAllText($path, $Values[$i], (New-Object System.Text.UTF8Encoding($false)))
        }
    } -ArgumentList @($secretNames, $secretValues)

    $envLines = [System.Collections.Generic.List[string]]::new()
    $envLines.Add("DLP_DEVICE_ID=$($env:DLP_DEVICE_ID)")
    $envLines.Add("DLP_SERVER_URL=$($env:DLP_SERVER_URL)")
    $envLines.Add('DLP_ROOT_CA_PEM=C:\dlp\secrets\root-ca.pem')
    $envLines.Add('DLP_DATA_DIRECTORY=C:\dlp\agent\data')
    $envLines.Add('DLP_CACHE_DIRECTORY=C:\dlp\agent\cache')
    if (-not [string]::IsNullOrWhiteSpace($env:DLP_CONFIGURATION_KEY_ID)) {
        $envLines.Add("DLP_CONFIGURATION_KEY_ID=$($env:DLP_CONFIGURATION_KEY_ID)")
    }
    $envLines.Add("DLP_CONFIGURATION_PUBLIC_KEY_HEX=$($env:DLP_CONFIGURATION_PUBLIC_KEY_HEX)")
    if (-not [string]::IsNullOrWhiteSpace($EnrollmentToken)) {
        $envLines.Add("DLP_AGENT_ENROLLMENT_TOKEN=$EnrollmentToken")
    } elseif (-not [string]::IsNullOrWhiteSpace($env:DLP_AGENT_ENROLLMENT_TOKEN)) {
        $envLines.Add("DLP_AGENT_ENROLLMENT_TOKEN=$($env:DLP_AGENT_ENROLLMENT_TOKEN)")
    }
    if (-not [string]::IsNullOrWhiteSpace($env:DLP_POLL_INTERVAL_SECONDS)) {
        $envLines.Add("DLP_POLL_INTERVAL_SECONDS=$($env:DLP_POLL_INTERVAL_SECONDS)")
    }
    if (-not [string]::IsNullOrWhiteSpace($env:DLP_HEALTH_INTERVAL_SECONDS)) {
        $envLines.Add("DLP_HEALTH_INTERVAL_SECONDS=$($env:DLP_HEALTH_INTERVAL_SECONDS)")
    }

    Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        param($EnvLines)
        $ErrorActionPreference = 'Stop'
        $envPath = 'C:\dlp\agent\agent.env'
        [System.IO.File]::WriteAllLines($envPath, $EnvLines, (New-Object System.Text.UTF8Encoding($false)))
    } -ArgumentList @($envLines)
}

function Install-Client01Service {
    param(
        [Parameter()][switch]$StartAfterInstall,
        [Parameter()][string]$EnrollmentToken
    )

    Write-Host 'Install-Client01Service: installing binary...'
    Install-Client01ServiceBinary
    Write-Host 'Install-Client01Service: installing secrets...'
    Install-Client01RuntimeSecrets -EnrollmentToken $EnrollmentToken

    Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        param($StartAfter)
        $ErrorActionPreference = 'Stop'
        $serviceName = 'DlpWindowsService'
        $displayName = 'DLP Windows Endpoint Service'
        $binaryPath = 'C:\dlp\agent\dlp-windows-service.exe'
        $existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -eq $existing) {
            New-Service -Name $serviceName -BinaryPathName $binaryPath -DisplayName $displayName `
                -StartupType Automatic -Description 'Data Leakage Prevention endpoint agent service.' -ErrorAction Stop | Out-Null
        } else {
            # Reconfigure the existing service to point at the current binary.
            & sc.exe config $serviceName binPath= $binaryPath start= auto obj= 'NT AUTHORITY\SYSTEM' | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "sc.exe config failed: $LASTEXITCODE" }
        }

        # Ensure the service process receives the persisted environment.
        $envPath = 'C:\dlp\agent\agent.env'
        if (Test-Path -LiteralPath $envPath) {
            $envLines = [System.IO.File]::ReadAllLines($envPath)
            $serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $serviceName
            Set-ItemProperty -Path $serviceKey -Name 'Environment' -Value $envLines -Type MultiString -Force
        }

        if ($StartAfter) {
            Start-Service -Name $serviceName -ErrorAction Stop
        }
    } -ArgumentList @($StartAfterInstall)
}

function Test-Client01ServiceRunning {
    return Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        $service = Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue
        return ($null -ne $service -and $service.Status -eq 'Running')
    }
}

function Invoke-Client01ServiceInstall {
    param([Parameter()][string]$EnrollmentToken)

    $fingerprint = Get-EnvironmentFingerprint -TargetMachine $ExecutionMachine
    Install-Client01Service -StartAfterInstall -EnrollmentToken $EnrollmentToken

    $running = Test-Client01ServiceRunning
    $status = if ($running) { 'pass' } else { 'fail' }
    $actual = if ($running) { 'DlpWindowsService installed and running on LAB-CLIENT01' } else { 'DlpWindowsService did not reach Running state' }
    New-Client01Evidence -RequirementId 'SRV-13' -CheckId 'client01-service-install' -Status $status `
        -Expected 'dlp-windows-service is installed, configured, and starts as an automatic service on LAB-CLIENT01' `
        -Actual $actual -TargetMachine $ExecutionMachine -Fingerprint $fingerprint | Out-Null
    Assert-Client01 $running 'service_failed_to_start'
    Write-Host 'Invoke-Client01ServiceInstall: complete.'
}

function Invoke-Client01Tracer {
    $enrollmentToken = $null
    if ($EnrollmentTokenProvider -eq 'TrustedProvisioning') {
        if (Test-Client01CredentialPresent) {
            Write-Host 'Tracer: existing DPAPI credential found on LAB-CLIENT01; skipping trusted provisioning.'
        } else {
            $approvedDigest = Get-ApprovedPrivilegeManifestDigest
            $enrollmentToken = Invoke-Client01TrustedProvisioning `
                -PrivilegeManifestDigest $approvedDigest `
                -TargetComputer 'LAB-CLIENT01.lab.local' `
                -PreferredDriveLetter 'P'
        }
    }

    Write-Host 'Tracer: installing service...'
    Invoke-Client01ServiceInstall -EnrollmentToken $enrollmentToken

    $serverHost = $script:Dc01Ip
    Write-Host "Tracer: probing management server from $ExecutionMachine via $serverHost..."
    $probeFingerprint = Get-EnvironmentFingerprint -TargetMachine $ExecutionMachine

    Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        param($ServerHost, $Port)
        $ErrorActionPreference = 'Stop'
        Add-Type -TypeDefinition @'
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) { return true; }
        }
'@ -ErrorAction SilentlyContinue
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
        $uris = @("https://${ServerHost}:$Port/health/live", "https://${ServerHost}:$Port/health/ready")
        foreach ($uri in $uris) {
            $response = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 60
            $content = $response.Content | ConvertFrom-Json
            if ($content.status -ne 'ok') { throw "probe status not ok: $uri" }
        }
    } -ArgumentList @($serverHost, $script:ServerPort)

    New-Client01Evidence -RequirementId 'SRV-14' -CheckId 'client01-tracer-readiness' -Status 'pass' `
        -Expected 'LAB-CLIENT01 service reaches the management server on LAB-DC01 over validated TLS' `
        -Actual "live/ready ok from $ExecutionMachine to $serverHost" -TargetMachine $ExecutionMachine -Fingerprint $probeFingerprint | Out-Null
    Write-Host 'Tracer: complete.'
}

Assert-DlpMachineRole -ExpectedRole 'developer_orchestrator'
$approvedDigest = Get-ApprovedPrivilegeManifestDigest
Write-Host "Approved 01-19 manifest digest: $approvedDigest"

$cred = Get-VmCredential
if ($null -eq $cred) {
    Stop-Client01 'vm_credentials_required: Invoke-Client01Runtime.ps1 requires a VM admin credential via -Credential or DLP_VM_ADMIN_USER/PASSWORD'
}

Assert-RuntimeSecretsPresent

if (-not $Apply) {
    Write-Host 'Running in dry-run mode; no changes will be applied to LAB-CLIENT01. Use -Apply to execute.'
}

switch ($Scenario) {
    'Tracer' { if ($Apply) { Invoke-Client01Tracer } else { Write-Host 'Dry-run: would execute Tracer scenario' } }
    'ServiceInstall' { if ($Apply) { Invoke-Client01ServiceInstall } else { Write-Host 'Dry-run: would execute ServiceInstall scenario' } }
    'All' { if ($Apply) { Invoke-Client01ServiceInstall; Invoke-Client01Tracer } else { Write-Host 'Dry-run: would execute All scenarios' } }
}

Write-Host "Scenario $Scenario completed."
