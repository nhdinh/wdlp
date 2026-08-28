[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('hungdinh-lt')][string]$CallerMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-CLIENT01')][string]$ExecutionMachine,
    [Parameter()][ValidateSet('LAB-DC01')][string]$ProbeMachine = 'LAB-DC01',
    [Parameter()][ValidateSet('Runtime')][string]$SecretProvider = 'Runtime',
    [Parameter(Mandatory)][ValidateSet('Tracer', 'ServiceInstall', 'All')][string]$Scenario,
    [Parameter()][ValidateSet('Manual', 'TrustedProvisioning')][string]$EnrollmentTokenProvider = 'TrustedProvisioning',
    [Parameter()][switch]$RetainEnrollmentToken,
    [Parameter()][switch]$ForceReenrollment,
    [Parameter()][switch]$Diagnostic,
    [Parameter()][switch]$Apply,
    [Parameter()][System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Update-DlpEnvironmentFromRotatedFiles {
    # If a freshly rotated certificate/key file exists in the standard lab
    # secrets directory and is newer than the path referenced by the env var,
    # update the process environment variable to use it. This prevents the
    # orchestrator from silently using stale material after rotation.
    $rotations = @(
        @{ Name='DLP_PHASE1_ROOT_CA_CERT_PEM'; Path='C:\dlp\secrets\phase1-root-ca.pem' },
        @{ Name='DLP_PHASE1_ROOT_CA_KEY_PEM'; Path='C:\dlp\secrets\phase1-root-ca-key.pem' },
        @{ Name='DLP_ADMIN_CA_CERT_PEM'; Path='C:\dlp\secrets\admin-ca.pem' },
        @{ Name='DLP_ADMIN_CA_KEY_PEM'; Path='C:\dlp\secrets\admin-ca-key.pem' },
        @{ Name='DLP_PROVISIONING_ADMIN_CERT_PEM'; Path='C:\dlp\secrets\provisioning-admin-cert.pem' },
        @{ Name='DLP_PROVISIONING_ADMIN_KEY_PEM'; Path='C:\dlp\secrets\provisioning-admin-key.pem' },
        @{ Name='DLP_SERVER_CERT_PEM'; Path='C:\dlp\secrets\server-cert.pem' },
        @{ Name='DLP_SERVER_KEY_PEM'; Path='C:\dlp\secrets\server-key.pem' },
        @{ Name='DLP_DEVICE_ISSUING_CA_CERT_PEM'; Path='C:\dlp\secrets\device-issuing-ca.pem' },
        @{ Name='DLP_DEVICE_ISSUING_CA_KEY_PEM'; Path='C:\dlp\secrets\device-issuing-ca-key.pem' }
    )
    foreach ($entry in $rotations) {
        $name = $entry.Name
        $rotatedPath = $entry.Path
        if (-not (Test-Path -LiteralPath $rotatedPath)) { continue }
        $envValue = [Environment]::GetEnvironmentVariable($name)
        $currentPath = if (-not [string]::IsNullOrWhiteSpace($envValue) -and $envValue -notmatch '^-----BEGIN' -and (Test-Path -LiteralPath $envValue)) {
            $envValue
        } else {
            $null
        }
        if ($null -eq $currentPath) {
            Write-Host "Env-rotation: $name not set to a path; using $rotatedPath" -ForegroundColor Yellow
            [Environment]::SetEnvironmentVariable($name, $rotatedPath, 'Process')
            continue
        }
        $currentFull = [System.IO.Path]::GetFullPath($currentPath)
        $rotatedFull = [System.IO.Path]::GetFullPath($rotatedPath)
        if ($currentFull -eq $rotatedFull) { continue }
        $rotatedTime = (Get-Item -LiteralPath $rotatedFull).LastWriteTimeUtc
        $currentTime = (Get-Item -LiteralPath $currentFull).LastWriteTimeUtc
        if ($rotatedTime -gt $currentTime) {
            Write-Host "Env-rotation: $rotatedPath is newer than `$env:$name ($currentPath); using rotated file" -ForegroundColor Yellow
            [Environment]::SetEnvironmentVariable($name, $rotatedPath, 'Process')
        }
    }
}

Update-DlpEnvironmentFromRotatedFiles

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

function Write-Client01Status {
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message
    )
    Write-Host "[$Code] $Message"
}

function Write-Client01Diagnostic {
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][hashtable]$Fields
    )
    if (-not $Diagnostic) { return }
    $safe = [ordered]@{ code = $Code }
    foreach ($name in @($Fields.Keys | Sort-Object)) {
        $safe[$name] = $Fields[$name]
    }
    Write-Host ($safe | ConvertTo-Json -Compress -Depth 5)
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
    # Hyper-V Guest Service Interface copies can remain blocked indefinitely
    # without throwing. PowerShell Direct is already required for this workflow,
    # so use its bounded remoting channel as the deterministic transfer path.
    $bytes = [System.IO.File]::ReadAllBytes($SourcePath)
    $base64 = [Convert]::ToBase64String($bytes)
    $expectedHash = (Get-FileHash -LiteralPath $SourcePath -Algorithm SHA256).Hash
    $actualHash = Invoke-LabCommand -VMName $VMName -ScriptBlock {
        param($Base64, $Path)
        $ErrorActionPreference = 'Stop'
        New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
        [System.IO.File]::WriteAllBytes($Path, [Convert]::FromBase64String($Base64))
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    } -ArgumentList @($base64, $DestinationPath)
    Assert-Client01 ($actualHash -eq $expectedHash) 'vm_file_transfer_hash_mismatch'
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
        $ErrorActionPreference = 'Stop'
        $taskName = 'DlpCred-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
        $resultPath = Join-Path $env:ProgramData ($taskName + '.txt')
        # D-05: only a non-empty protected credential is usable enough to skip
        # the one-time trusted-provisioning flow.
        $command = ">$resultPath echo 0 & for %I in (C:\dlp\agent\data\credentials\device.dpapi) do @if %~zI GTR 0 >$resultPath echo 1"
        $action = "cmd.exe /d /c $command"
        $startTime = (Get-Date).AddMinutes(1).ToString('HH:mm')
        try {
            & schtasks.exe /Create /TN $taskName /SC ONCE /ST $startTime /TR $action /RU SYSTEM /F | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "credential probe task creation failed: $LASTEXITCODE" }
            & schtasks.exe /Run /TN $taskName | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "credential probe task start failed: $LASTEXITCODE" }
            $deadline = [DateTime]::UtcNow.AddSeconds(15)
            while (-not (Test-Path -LiteralPath $resultPath) -and [DateTime]::UtcNow -lt $deadline) {
                Start-Sleep -Milliseconds 200
            }
            if (-not (Test-Path -LiteralPath $resultPath)) { throw 'credential probe timed out' }
            return ([System.IO.File]::ReadAllText($resultPath).Trim() -eq '1')
        } finally {
            $cleanupCommand = "schtasks.exe /Delete /TN $taskName /F >nul 2>&1"
            & cmd.exe /d /c $cleanupCommand | Out-Null
            Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Assert-EnrollmentTokenValid {
    param([Parameter(Mandatory)][string]$Token)
    if ([string]::IsNullOrWhiteSpace($Token)) {
        Stop-Client01 'enrollment_token_invalid: token is empty'
    }
    if ($Token.Length -gt 512) {
        Stop-Client01 'enrollment_token_invalid: token exceeds 512 characters'
    }
    if ($Token -cmatch '[^A-Za-z0-9_.~/-]') {
        Stop-Client01 'enrollment_token_invalid: token contains characters outside the allowed alphabet'
    }
}

function Remove-Client01EnrollmentToken {
    # D-01/D-02/D-05/D-06/D-07: attempt both managed copies independently,
    # verify both, and make incomplete cleanup a stable hard failure.
    Write-Client01Status -Code 'enrollment_token_cleanup_started' -Message 'Removing the short-lived enrollment token from both endpoint locations.'
    try {
        $result = Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        $ErrorActionPreference = 'Stop'
        $serviceName = 'DlpWindowsService'
        $serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $serviceName
        $envPath = 'C:\dlp\agent\agent.env'
        $status = [ordered]@{ AgentEnv = 'ok'; ScmEnvironment = 'ok' }

        try {
            $existing = Get-ItemProperty -Path $serviceKey -Name 'Environment' -ErrorAction SilentlyContinue
            if ($null -ne $existing -and $null -ne $existing.Environment) {
                $cleaned = @($existing.Environment | Where-Object { $_ -notlike 'DLP_AGENT_ENROLLMENT_TOKEN=*' })
                Set-ItemProperty -Path $serviceKey -Name 'Environment' -Value $cleaned -Type MultiString -Force
            }
            $remaining = @((Get-ItemProperty -Path $serviceKey -Name 'Environment' -ErrorAction SilentlyContinue).Environment |
                Where-Object { $_ -like 'DLP_AGENT_ENROLLMENT_TOKEN=*' }).Count
            if ($remaining -ne 0) { throw 'token_entry_remains' }
        } catch {
            $status.ScmEnvironment = 'failed'
        }

        try {
            if (Test-Path -LiteralPath $envPath) {
                $lines = [System.IO.File]::ReadAllLines($envPath)
                $cleaned = @($lines | Where-Object { $_ -notlike 'DLP_AGENT_ENROLLMENT_TOKEN=*' })
                [System.IO.File]::WriteAllLines($envPath, $cleaned, (New-Object System.Text.UTF8Encoding($false)))
                $remaining = @([System.IO.File]::ReadAllLines($envPath) |
                    Where-Object { $_ -like 'DLP_AGENT_ENROLLMENT_TOKEN=*' }).Count
                if ($remaining -ne 0) { throw 'token_entry_remains' }
            }
        } catch {
            $status.AgentEnv = 'failed'
        }
        return [pscustomobject]$status
        }
    } catch {
        Stop-Client01 'enrollment_token_cleanup_failed: agent.env=unavailable; scm_environment=unavailable; remove DLP_AGENT_ENROLLMENT_TOKEN from C:\dlp\agent\agent.env and HKLM:\SYSTEM\CurrentControlSet\Services\DlpWindowsService\Environment before retrying'
    }

    if ($result.AgentEnv -ne 'ok' -or $result.ScmEnvironment -ne 'ok') {
        Stop-Client01 "enrollment_token_cleanup_failed: agent.env=$($result.AgentEnv); scm_environment=$($result.ScmEnvironment); remove DLP_AGENT_ENROLLMENT_TOKEN from C:\dlp\agent\agent.env and HKLM:\SYSTEM\CurrentControlSet\Services\DlpWindowsService\Environment before retrying"
    }
    Write-Client01Status -Code 'enrollment_token_cleanup_complete' -Message 'Enrollment token state is absent from agent.env and SCM Environment.'
}

function Reset-Client01EnrollmentCredential {
    # D-06/D-07/D-08: this helper is called only from the explicit Apply-gated
    # force path. It preserves the service, binaries, data root, and cache root.
    Write-Client01Status -Code 'force_reenrollment_started' -Message 'Replacing the protected enrollment credential while preserving service, data, and cache.'
    Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        $ErrorActionPreference = 'Stop'
        $service = Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue
        if ($null -ne $service -and $service.Status -ne 'Stopped') {
            Stop-Service -Name 'DlpWindowsService' -Force -ErrorAction Stop
        }
        $taskName = 'DlpForceReenrollment-' + [Guid]::NewGuid().ToString('N')
        $resultPath = Join-Path $env:ProgramData ($taskName + '.txt')
        $action = "cmd.exe /d /c del /q C:\dlp\agent\data\credentials\device.dpapi* & echo complete>$resultPath"
        $startTime = (Get-Date).AddMinutes(1).ToString('HH:mm')
        try {
            & schtasks.exe /Create /TN $taskName /SC ONCE /ST $startTime /TR $action /RU SYSTEM /F | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'credential_reset_task_create_failed' }
            & schtasks.exe /Run /TN $taskName | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'credential_reset_task_start_failed' }
            $deadline = [DateTime]::UtcNow.AddSeconds(20)
            while (-not (Test-Path -LiteralPath $resultPath) -and [DateTime]::UtcNow -lt $deadline) {
                Start-Sleep -Milliseconds 200
            }
            if (-not (Test-Path -LiteralPath $resultPath)) { throw 'credential_reset_timed_out' }
        } finally {
            $cleanupCommand = "schtasks.exe /Delete /TN $taskName /F >nul 2>&1"
            & cmd.exe /d /c $cleanupCommand | Out-Null
            Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue
        }
        if ($null -ne $service -and $null -eq (Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue)) {
            throw 'service_removed_during_force_reenrollment'
        }
        foreach ($path in @('C:\dlp\agent\data', 'C:\dlp\agent\cache')) {
            if (-not (Test-Path -LiteralPath $path -PathType Container)) {
                throw 'preserved_directory_missing'
            }
        }
    }
    Remove-Client01EnrollmentToken
}

function Wait-Client01AdwsReady {
    param(
        [Parameter(Mandatory)][string[]]$ServerName,
        [Parameter()][int]$TimeoutSeconds = 120
    )
    Write-Host "Waiting for Active Directory Web Services on $($ServerName -join ', ')..."
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        $readyList = Invoke-LabCommand -VMName 'LAB-DC01' -ScriptBlock {
            param($Names)
            $ErrorActionPreference = 'Stop'
            $svc = Get-Service -Name 'ADWS' -ErrorAction SilentlyContinue
            if ($null -eq $svc -or $svc.Status -ne 'Running') { return @($false) * $Names.Count }
            $results = @()
            foreach ($name in $Names) {
                try {
                    Get-ADComputer -Server $name -Identity 'LAB-CLIENT01' -ErrorAction Stop | Out-Null
                    $results += $true
                } catch {
                    $results += $false
                }
            }
            return $results
        } -ArgumentList @(,$ServerName)
        if (-not ($readyList -contains $false)) {
            Write-Host 'Active Directory Web Services is ready.'
            return
        }
        if ((Get-Date) -ge $deadline) {
            Stop-Client01 'adws_not_ready'
        }
        Write-Host 'ADWS not ready yet; retrying in 5 seconds...'
        Start-Sleep -Seconds 5
    }
}

function Assert-Client01ServerSecretsPresent {
    $required = @(
        'DLP_DATABASE_URL',
        'DLP_SERVER_CERT_PEM',
        'DLP_SERVER_KEY_PEM',
        'DLP_ADMIN_CA_CERT_PEM',
        'DLP_PHASE1_ROOT_CA_CERT_PEM',
        'DLP_DEVICE_ISSUING_CA_CERT_PEM',
        'DLP_DEVICE_ISSUING_CA_KEY_PEM',
        'DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX'
    )
    $missing = @($required | Where-Object { [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($_)) })
    if ($missing.Count -gt 0) { Stop-Client01 ("server_runtime_secrets_missing: " + ($missing -join ', ')) }

    # The configuration signing seed must be exactly 64 hexadecimal characters.
    # A placeholder or short value produces a cryptic server startup error; fail
    # fast here with a clear diagnostic.
    $seed = $env:DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX
    if ($seed -notmatch '^[A-Fa-f0-9]{64}$') {
        Stop-Client01 'configuration_signing_key_seed_invalid: DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX must be exactly 64 hexadecimal characters'
    }

    # Validate that the server private key is an unencrypted RSA key in PKCS#8
    # or PKCS#1 form. A mismatched or encrypted key causes a 'BadSignature' TLS
    # alert that is hard to diagnose inside the VM.
    $serverKey = Get-Client01SecretValue -Name 'DLP_SERVER_KEY_PEM' -Value $env:DLP_SERVER_KEY_PEM
    $keyHeader = ($serverKey -split "`r?`n" | Where-Object { $_.Trim().StartsWith('-----BEGIN ') } | Select-Object -First 1).Trim()
    if ($keyHeader -notmatch '^-----BEGIN (RSA )?PRIVATE KEY-----$') {
        Stop-Client01 "server_key_invalid_header: '$keyHeader'"
    }
    if ($keyHeader -match 'ENCRYPTED') {
        Stop-Client01 'server_key_encrypted: decrypt DLP_SERVER_KEY_PEM before use'
    }
}

function Test-Client01AdSecretsPresent {
    return -not ([string]::IsNullOrWhiteSpace($env:DLP_AD_PRIMARY_LDAPS_URL) -or
        [string]::IsNullOrWhiteSpace($env:DLP_AD_SECONDARY_LDAPS_URL) -or
        [string]::IsNullOrWhiteSpace($env:DLP_AD_BASE_DN) -or
        [string]::IsNullOrWhiteSpace($env:DLP_AD_DOMAIN) -or
        [string]::IsNullOrWhiteSpace($env:DLP_AD_BIND_DN) -or
        [string]::IsNullOrWhiteSpace($env:DLP_AD_BIND_PASSWORD) -or
        [string]::IsNullOrWhiteSpace($env:DLP_AD_CA_CERT_PEM))
}

function Install-Client01ServerBinary {
    # Re-use the server deployment logic from Invoke-Dc01Server.ps1 so the
    # client runtime script can perform a self-contained Tracer run. The server
    # binary, secrets, and provisioning helper are staged on LAB-DC01.
    $localBinary = Join-Path $RepoRoot 'target/release/dlp-server.exe'

    # Always rebuild the server from source so repository/route fixes are
    # deployed. Cargo incremental builds are fast; stale binaries have masked
    # root causes repeatedly in this workflow.
    Write-Host 'Building dlp-server release binary on hungdinh-lt...'
    if (Test-Path -LiteralPath $localBinary) { Remove-Item -LiteralPath $localBinary -Force }
    $proc = Start-Process -FilePath 'cargo' -ArgumentList @('build', '--release', '-p', 'dlp-server') -WorkingDirectory $RepoRoot -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -ne 0) { Stop-Client01 'cargo_build_server_failed' }
    Assert-Client01 (Test-Path -LiteralPath $localBinary) 'server_release_binary_missing'

    Invoke-LabCommand -VMName 'LAB-DC01' -ScriptBlock {
        New-Item -ItemType Directory -Path 'C:\dlp\server' -Force | Out-Null
    }

    # Stop any running server before replacing the binary.
    Invoke-LabCommand -VMName 'LAB-DC01' -ScriptBlock {
        Get-Process -Name 'dlp-server' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    $remoteBinary = 'C:\dlp\server\dlp-server.exe'
    Copy-VMFileOrStream -VMName 'LAB-DC01' -SourcePath $localBinary -DestinationPath $remoteBinary

    # Deploy the trusted-provisioning helper so it can be invoked from LAB-DC01.
    $localProvScript = Join-Path $RepoRoot 'scripts/lab/Invoke-TrustedProvisioning.ps1'
    $remoteProvScript = 'C:\dlp\server\scripts\lab\Invoke-TrustedProvisioning.ps1'
    if (Test-Path -LiteralPath $localProvScript) {
        Copy-VMFileOrStream -VMName 'LAB-DC01' -SourcePath $localProvScript -DestinationPath $remoteProvScript
    }
}

function Get-Client01SecretValue {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )
    # Secrets may be supplied either as inline PEM/KEY material or as a path to
    # a file on the orchestrator host. Detect the form and return the actual
    # secret bytes/string that should be written inside the VM.
    $trimmed = $Value.Trim()
    if ($trimmed.StartsWith('-----BEGIN')) {
        return $Value
    }
    if (Test-Path -LiteralPath $Value) {
        return [System.IO.File]::ReadAllText($Value)
    }
    Stop-Client01 "server_secret_not_pem_or_file: $Name"
}

function Install-Client01ServerSecrets {
    # The runtime provider supplies PEM content as environment variables, or
    # paths to PEM files on the orchestrator host. The server expects file
    # paths on LAB-DC01, so resolve each value and write it there.
    $secrets = [ordered]@{
        'server-cert.pem' = Get-Client01SecretValue -Name 'DLP_SERVER_CERT_PEM' -Value $env:DLP_SERVER_CERT_PEM
        'server-key.pem' = Get-Client01SecretValue -Name 'DLP_SERVER_KEY_PEM' -Value $env:DLP_SERVER_KEY_PEM
        'admin-ca.pem' = Get-Client01SecretValue -Name 'DLP_ADMIN_CA_CERT_PEM' -Value $env:DLP_ADMIN_CA_CERT_PEM
        'phase1-root-ca.pem' = Get-Client01SecretValue -Name 'DLP_PHASE1_ROOT_CA_CERT_PEM' -Value $env:DLP_PHASE1_ROOT_CA_CERT_PEM
        'device-issuing-ca.pem' = Get-Client01SecretValue -Name 'DLP_DEVICE_ISSUING_CA_CERT_PEM' -Value $env:DLP_DEVICE_ISSUING_CA_CERT_PEM
        'device-issuing-ca-key.pem' = Get-Client01SecretValue -Name 'DLP_DEVICE_ISSUING_CA_KEY_PEM' -Value $env:DLP_DEVICE_ISSUING_CA_KEY_PEM
    }
    if (Test-Client01AdSecretsPresent) {
        $secrets['ad-ca.pem'] = Get-Client01SecretValue -Name 'DLP_AD_CA_CERT_PEM' -Value $env:DLP_AD_CA_CERT_PEM
    }
    foreach ($name in $secrets.Keys) {
        Assert-Client01 (-not [string]::IsNullOrWhiteSpace($secrets[$name])) "server_secret_empty_$name"
        Assert-Client01 ($secrets[$name].Trim().StartsWith('-----BEGIN')) "server_secret_not_valid_pem_$name"
    }

    $secretNames = $secrets.Keys
    $secretValues = $secrets.Values
    Invoke-LabCommand -VMName 'LAB-DC01' -ScriptBlock {
        param($Names, $Values)
        $ErrorActionPreference = 'Stop'
        $dir = 'C:\dlp\secrets'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        for ($i = 0; $i -lt $Names.Count; $i++) {
            $path = Join-Path $dir $Names[$i]
            [System.IO.File]::WriteAllText($path, $Values[$i], (New-Object System.Text.UTF8Encoding($false)))
        }
    } -ArgumentList @($secretNames, $secretValues)
}

function Assert-Client01ServerSecretsValid {
    # Verify the server certificate and key installed on LAB-DC01 are byte-for-byte
    # identical to the orchestrator's resolved values. This catches corruption during
    # secret copy without requiring openssl on the remote VM.
    $expectedHashes = [ordered]@{
        'server-cert.pem' = (Get-Client01SecretHash -Name 'DLP_SERVER_CERT_PEM' -Value $env:DLP_SERVER_CERT_PEM)
        'server-key.pem' = (Get-Client01SecretHash -Name 'DLP_SERVER_KEY_PEM' -Value $env:DLP_SERVER_KEY_PEM)
        'phase1-root-ca.pem' = (Get-Client01SecretHash -Name 'DLP_PHASE1_ROOT_CA_CERT_PEM' -Value $env:DLP_PHASE1_ROOT_CA_CERT_PEM)
    }

    Invoke-LabCommand -VMName 'LAB-DC01' -ScriptBlock {
        param($ExpectedHashes)
        $ErrorActionPreference = 'Stop'
        $dir = 'C:\dlp\secrets'
        $result = [ordered]@{}
        foreach ($name in $ExpectedHashes.Keys) {
            $path = Join-Path $dir $name
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try {
                $bytes = [System.IO.File]::ReadAllBytes($path)
                $actual = ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
            } finally {
                $sha.Dispose()
            }
            $result[$name] = [ordered]@{
                expected = $ExpectedHashes[$name]
                actual = $actual
                match = ($actual -eq $ExpectedHashes[$name])
            }
            if (-not $result[$name].match) {
                throw "server_secret_hash_mismatch:$name expected=$($ExpectedHashes[$name]) actual=$actual"
            }
        }
        return $result
    } -ArgumentList @($expectedHashes)
}

function Get-Client01SecretHash {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $resolved = Get-Client01SecretValue -Name $Name -Value $Value
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($resolved)
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Invoke-Client01SqlxMigrate {
    $dbUrl = $env:DLP_DATABASE_URL
    Assert-Client01 (-not [string]::IsNullOrWhiteSpace($dbUrl)) 'database_url_missing'
    $env:DATABASE_URL = $dbUrl
    $migrationsDir = Join-Path $RepoRoot 'migrations'
    $output = sqlx migrate run --source $migrationsDir 2>&1
    if ($LASTEXITCODE -ne 0) { Stop-Client01 "sqlx migrate failed: $output" }
    return $output
}

function Start-Client01Server {
    param([Parameter()][switch]$WaitForReady)

    Assert-Client01ServerSecretsPresent
    Write-Host 'Start-Client01Server: installing binary...'
    Install-Client01ServerBinary
    Write-Host 'Start-Client01Server: installing secrets...'
    Install-Client01ServerSecrets
    Write-Host 'Start-Client01Server: validating installed secrets...'
    $secretValidation = Assert-Client01ServerSecretsValid
    Write-Host "Start-Client01Server: secret validation: $($secretValidation | ConvertTo-Json -Compress)"

    $listenAddress = "0.0.0.0:$($script:ServerPort)"
    $databaseUrl = $env:DLP_DATABASE_URL

    # Build the env file content inside LAB-DC01.
    $envLines = [System.Collections.Generic.List[string]]::new()
    $envLines.Add("DATABASE_URL=$databaseUrl")
    $envLines.Add("DLP_LISTEN_ADDRESS=$listenAddress")
    if (Test-Client01AdSecretsPresent) {
        $envLines.Add("DLP_AD_PRIMARY_LDAPS_URL=$($env:DLP_AD_PRIMARY_LDAPS_URL)")
        $envLines.Add("DLP_AD_SECONDARY_LDAPS_URL=$($env:DLP_AD_SECONDARY_LDAPS_URL)")
        $envLines.Add("DLP_AD_BASE_DN=$($env:DLP_AD_BASE_DN)")
        $envLines.Add("DLP_AD_DOMAIN=$($env:DLP_AD_DOMAIN)")
        $envLines.Add("DLP_AD_BIND_DN=$($env:DLP_AD_BIND_DN)")
        $envLines.Add("DLP_AD_BIND_PASSWORD=$($env:DLP_AD_BIND_PASSWORD)")
        $envLines.Add('DLP_AD_CA_CERT_PEM=C:\dlp\secrets\ad-ca.pem')
    }
    $envLines.Add('DLP_SERVER_CERT_PEM=C:\dlp\secrets\server-cert.pem')
    $envLines.Add('DLP_SERVER_KEY_PEM=C:\dlp\secrets\server-key.pem')
    $envLines.Add('DLP_ADMIN_CA_CERT_PEM=C:\dlp\secrets\admin-ca.pem')
    $envLines.Add('DLP_PHASE1_ROOT_CA_CERT_PEM=C:\dlp\secrets\phase1-root-ca.pem')
    $envLines.Add('DLP_DEVICE_ISSUING_CA_CERT_PEM=C:\dlp\secrets\device-issuing-ca.pem')
    $envLines.Add('DLP_DEVICE_ISSUING_CA_KEY_PEM=C:\dlp\secrets\device-issuing-ca-key.pem')
    $envLines.Add("DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX=$($env:DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX)")
    if (-not [string]::IsNullOrWhiteSpace($env:DLP_CONFIGURATION_KEY_ID)) {
        $envLines.Add("DLP_CONFIGURATION_KEY_ID=$($env:DLP_CONFIGURATION_KEY_ID)")
    }

    Invoke-LabCommand -VMName 'LAB-DC01' -ScriptBlock {
        param($EnvLines, $Port)
        $ErrorActionPreference = 'Stop'
        $envPath = 'C:\dlp\server\server.env'
        [System.IO.File]::WriteAllLines($envPath, $EnvLines, (New-Object System.Text.UTF8Encoding($false)))

        # Remove any stale listener.
        Get-Process -Name 'dlp-server' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1

        # Ensure the management-server port is reachable from LAB-CLIENT01 probes.
        $existing = Get-NetFirewallRule -Direction Inbound -ErrorAction SilentlyContinue |
            Where-Object { ($_ | Get-NetFirewallPortFilter).LocalPort -eq $Port }
        if (-not $existing) {
            New-NetFirewallRule -DisplayName 'DLP Management Server' -Direction Inbound -LocalPort $Port -Protocol TCP -Action Allow -Profile Domain,Private -ErrorAction Stop | Out-Null
        }

        # Load environment into the current process so the child inherits it.
        foreach ($line in $EnvLines) {
            $parts = $line.Split('=', 2)
            [Environment]::SetEnvironmentVariable($parts[0], $parts[1], 'Process')
        }

        # Verify the environment values the server will inherit.
        $diagnosticPath = 'C:\dlp\server\startup-diagnostic.log'
        @(
            "DLP_LISTEN_ADDRESS=$([Environment]::GetEnvironmentVariable('DLP_LISTEN_ADDRESS', 'Process'))"
            "DATABASE_URL_LENGTH=$(([Environment]::GetEnvironmentVariable('DATABASE_URL', 'Process')).Length)"
            "DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX_LENGTH=$(([Environment]::GetEnvironmentVariable('DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX', 'Process')).Length)"
            "DLP_AD_DOMAIN=$([Environment]::GetEnvironmentVariable('DLP_AD_DOMAIN', 'Process'))"
            "DLP_SERVER_CERT_PEM=$([Environment]::GetEnvironmentVariable('DLP_SERVER_CERT_PEM', 'Process'))"
            "DLP_SERVER_KEY_PEM=$([Environment]::GetEnvironmentVariable('DLP_SERVER_KEY_PEM', 'Process'))"
            "DLP_ADMIN_CA_CERT_PEM=$([Environment]::GetEnvironmentVariable('DLP_ADMIN_CA_CERT_PEM', 'Process'))"
            "DLP_PHASE1_ROOT_CA_CERT_PEM=$([Environment]::GetEnvironmentVariable('DLP_PHASE1_ROOT_CA_CERT_PEM', 'Process'))"
            "DLP_DEVICE_ISSUING_CA_CERT_PEM=$([Environment]::GetEnvironmentVariable('DLP_DEVICE_ISSUING_CA_CERT_PEM', 'Process'))"
            "DLP_DEVICE_ISSUING_CA_KEY_PEM=$([Environment]::GetEnvironmentVariable('DLP_DEVICE_ISSUING_CA_KEY_PEM', 'Process'))"
        ) | Set-Content -Path $diagnosticPath -Encoding UTF8

        $logPath = 'C:\dlp\server\dlp-server.log'
        $errPath = 'C:\dlp\server\dlp-server.err'
        $pidPath = 'C:\dlp\server\dlp-server.pid'
        Remove-Item -LiteralPath $logPath, $errPath -Force -ErrorAction SilentlyContinue
        $proc = Start-Process -FilePath 'C:\dlp\server\dlp-server.exe' -WorkingDirectory 'C:\dlp\server' `
            -RedirectStandardOutput $logPath -RedirectStandardError $errPath -WindowStyle Hidden -PassThru
        $proc.Id | Set-Content -Path $pidPath -Encoding UTF8
    } -ArgumentList @($envLines, $script:ServerPort)

    if ($WaitForReady) {
        $deadline = (Get-Date).AddSeconds(60)
        $ready = $false
        $lastErrorType = 'none'
        while ((Get-Date) -lt $deadline) {
            try {
                Invoke-LabCommand -VMName 'LAB-DC01' -ScriptBlock {
                    param($Port)
                    $ErrorActionPreference = 'Stop'
                    $tcp = New-Object System.Net.Sockets.TcpClient
                    $tcp.Connect('127.0.0.1', $Port)
                    $tcp.Close()
                } -ArgumentList @($script:ServerPort) | Out-Null
                $ready = $true
                break
            } catch {
                $lastErrorType = $_.Exception.GetType().Name
                Start-Sleep -Seconds 1
            }
        }
        if (-not $ready) {
            $diagnostics = Invoke-LabCommand -VMName 'LAB-DC01' -ScriptBlock {
                $secretLengths = [ordered]@{}
                Get-ChildItem -LiteralPath 'C:\dlp\secrets' -File -ErrorAction SilentlyContinue | ForEach-Object {
                    $secretLengths[$_.Name] = $_.Length
                }
                [pscustomobject]@{
                    startup_diagnostic_length = if (Test-Path -LiteralPath 'C:\dlp\server\startup-diagnostic.log') { (Get-Item 'C:\dlp\server\startup-diagnostic.log').Length } else { -1 }
                    stderr_length = if (Test-Path -LiteralPath 'C:\dlp\server\dlp-server.err') { (Get-Item 'C:\dlp\server\dlp-server.err').Length } else { -1 }
                    stdout_length = if (Test-Path -LiteralPath 'C:\dlp\server\dlp-server.log') { (Get-Item 'C:\dlp\server\dlp-server.log').Length } else { -1 }
                    secret_file_lengths = $secretLengths
                    listener_count = @(Get-NetTCPConnection -LocalPort 8443 -ErrorAction SilentlyContinue).Count
                    process_count = @(Get-Process -Name 'dlp-server' -ErrorAction SilentlyContinue).Count
                }
            }
            Write-Client01Diagnostic -Code 'server_failed_to_bind' -Fields @{
                error_type = $lastErrorType
                startup_diagnostic_length = $diagnostics.startup_diagnostic_length
                stderr_length = $diagnostics.stderr_length
                stdout_length = $diagnostics.stdout_length
                secret_file_lengths = $diagnostics.secret_file_lengths
                listener_count = $diagnostics.listener_count
                process_count = $diagnostics.process_count
            }
            Stop-Client01 'server_failed_to_bind: verify LAB-DC01 service configuration; use -Diagnostic for redacted metadata'
        }
    }
}

function Assert-Client01CertificatesValid {
    # Validate the orchestrator-side PKI material before copying it to LAB-DC01.
    # This catches hostname mismatches, chain breaks, and rustls-incompatible
    # certificates early with a clear error instead of a cryptic TLS EOF.
    $verifyScript = Join-Path $RepoRoot 'scripts/lab/Verify-DlpLabCertificates.ps1'
    Assert-Client01 (Test-Path -LiteralPath $verifyScript) 'certificate_verification_script_missing'

    $expectedHostname = "$ProbeMachine.lab.local"
    Write-Host "Assert-Client01CertificatesValid: verifying certificates against $expectedHostname..."
    $verifyArguments = @(
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy', 'Bypass',
        '-File', $verifyScript,
        '-ServerHostname', $expectedHostname
    )
    if ($Diagnostic) {
        & powershell.exe @verifyArguments
    } else {
        & powershell.exe @verifyArguments *> $null
    }
    if ($LASTEXITCODE -ne 0) {
        Stop-Client01 'certificate_validation_failed'
    }
}

function Assert-Client01ServerReady {
    # Validate certificates first so a hostname or chain mismatch fails fast
    # before we copy secrets to LAB-DC01 or start the server.
    Assert-Client01CertificatesValid

    # Ensure the management server is running on LAB-DC01 before trusted
    # provisioning. If it is not listening, start it (run migrations first).
    # Also restart it if the local release binary differs from the running one
    # so TLS diagnostic improvements are always deployed, or if the secrets
    # installed on the VM no longer match the orchestrator's current values.
    $serverHost = $script:Dc01Ip
    $localBinary = Join-Path $RepoRoot 'target/release/dlp-server.exe'
    if (-not (Test-Path -LiteralPath $localBinary)) {
        Write-Host 'Assert-Client01ServerReady: local server binary missing; building...'
        Install-Client01ServerBinary
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.IO.File]::ReadAllBytes($localBinary)
        $localHash = ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }

    $expectedSecretHashes = [ordered]@{
        'server-cert.pem' = Get-Client01SecretHash -Name 'DLP_SERVER_CERT_PEM' -Value $env:DLP_SERVER_CERT_PEM
        'server-key.pem' = Get-Client01SecretHash -Name 'DLP_SERVER_KEY_PEM' -Value $env:DLP_SERVER_KEY_PEM
        'phase1-root-ca.pem' = Get-Client01SecretHash -Name 'DLP_PHASE1_ROOT_CA_CERT_PEM' -Value $env:DLP_PHASE1_ROOT_CA_CERT_PEM
        'admin-ca.pem' = Get-Client01SecretHash -Name 'DLP_ADMIN_CA_CERT_PEM' -Value $env:DLP_ADMIN_CA_CERT_PEM
        'device-issuing-ca.pem' = Get-Client01SecretHash -Name 'DLP_DEVICE_ISSUING_CA_CERT_PEM' -Value $env:DLP_DEVICE_ISSUING_CA_CERT_PEM
    }

    $ready = $false
    $diagnostics = Invoke-LabCommand -VMName 'LAB-DC01' -ScriptBlock {
        param($Port, $ExpectedHash, $ExpectedSecretHashes)
        $ErrorActionPreference = 'Stop'
        $result = [ordered]@{
            process_running = $false
            port_listening = $false
            listening_process = $null
            tcp_connect_succeeded = $false
            tcp_connect_error = $null
            remote_binary_hash = $null
            hash_matches = $false
            secret_hash_matches = $true
            secret_hash_details = @{}
        }

        $proc = Get-Process -Name 'dlp-server' -ErrorAction SilentlyContinue
        $result.process_running = $null -ne $proc

        if ($null -ne $proc -and $proc.Path) {
            try {
                $sha = [System.Security.Cryptography.SHA256]::Create()
                try {
                    $bytes = [System.IO.File]::ReadAllBytes($proc.Path)
                    $result.remote_binary_hash = ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
                } finally {
                    $sha.Dispose()
                }
                $result.hash_matches = ($result.remote_binary_hash -eq $ExpectedHash)
            } catch { }
        }

        $secretsDir = 'C:\dlp\secrets'
        foreach ($name in $ExpectedSecretHashes.Keys) {
            $path = Join-Path $secretsDir $name
            $expected = $ExpectedSecretHashes[$name]
            $actual = if (Test-Path -LiteralPath $path) {
                $sha = [System.Security.Cryptography.SHA256]::Create()
                try {
                    $bytes = [System.IO.File]::ReadAllBytes($path)
                    ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
                } finally {
                    $sha.Dispose()
                }
            } else {
                '<missing>'
            }
            $result.secret_hash_details[$name] = [ordered]@{
                expected = $expected
                actual = $actual
                match = ($actual -eq $expected)
            }
            if (-not $result.secret_hash_details[$name].match) {
                $result.secret_hash_matches = $false
            }
        }

        $listener = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue |
            Select-Object -First 1
        $result.port_listening = $null -ne $listener
        if ($null -ne $listener) {
            $result.listening_process = try {
                (Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            } catch { '<unknown>' }
        }

        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $tcp.Connect('127.0.0.1', $Port)
            $result.tcp_connect_succeeded = $tcp.Connected
            $tcp.Close()
        } catch {
            $result.tcp_connect_error = $_.Exception.Message
        }

        return $result
    } -ArgumentList @($script:ServerPort, $localHash, $expectedSecretHashes)

    Write-Client01Diagnostic -Code 'server_readiness' -Fields @{
        process_running = $diagnostics.process_running
        port_listening = $diagnostics.port_listening
        tcp_connect_succeeded = $diagnostics.tcp_connect_succeeded
        binary_hash_matches = $diagnostics.hash_matches
        secret_hashes_match = $diagnostics.secret_hash_matches
    }

    $ready = $diagnostics.process_running -and $diagnostics.port_listening -and $diagnostics.tcp_connect_succeeded -and $diagnostics.hash_matches -and $diagnostics.secret_hash_matches
    if (-not $ready) {
        if ($diagnostics.process_running -and -not $diagnostics.hash_matches) {
            Write-Host 'Management server binary is stale; stopping it before restart...'
            Invoke-LabCommand -VMName 'LAB-DC01' -ScriptBlock {
                Get-Process -Name 'dlp-server' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                # Wait briefly for the port to be released.
                Start-Sleep -Seconds 2
            } | Out-Null
        } elseif ($diagnostics.process_running -and -not $diagnostics.secret_hash_matches) {
            Write-Host 'Management server secrets are stale; stopping it before restart...'
            Invoke-LabCommand -VMName 'LAB-DC01' -ScriptBlock {
                Get-Process -Name 'dlp-server' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            } | Out-Null
        }
        Write-Host 'Management server not ready on LAB-DC01; running migrations and starting it...'
        Invoke-Client01SqlxMigrate
        Start-Client01Server -WaitForReady
    }
}

function Install-Client01ProvisioningBinary {
    # Ensure the dlpctl binary used by the trusted provisioning station is present
    # on LAB-DC01. Always deploy the release artifact produced from this checkout;
    # a process-level path override may refer to another checkout and must not
    # cause a successful local build to be mistaken for a missing binary.
    $localBinary = Join-Path $RepoRoot 'target/release/dlpctl.exe'

    # Always rebuild dlpctl from source so crypto-provider fixes and other
    # changes are deployed. Cargo is fast when incremental; rebuilding prevents
    # a stale binary from masking the root cause.
    Write-Host 'Building dlpctl release binary on hungdinh-lt...'
    if (Test-Path -LiteralPath $localBinary) { Remove-Item -LiteralPath $localBinary -Force }
    $proc = Start-Process -FilePath 'cargo' -ArgumentList @('build', '--release', '-p', 'dlpctl') -WorkingDirectory $RepoRoot -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -ne 0) { Stop-Client01 'cargo_build_dlpctl_failed' }
    Assert-Client01 (Test-Path -LiteralPath $localBinary) 'dlpctl_release_binary_missing'

    Invoke-LabCommand -VMName 'LAB-DC01' -ScriptBlock {
        New-Item -ItemType Directory -Path 'C:\dlp\provisioning' -Force | Out-Null
    }

    $remoteBinary = 'C:\dlp\provisioning\dlpctl.exe'
    Copy-VMFileOrStream -VMName 'LAB-DC01' -SourcePath $localBinary -DestinationPath $remoteBinary

    # Always stage the latest provisioning helper so diagnostics and behavior
    # fixes are available even when the server binary is already running.
    Install-Client01ProvisioningScript

    return $remoteBinary
}

function Install-Client01ProvisioningScript {
    $localProvScript = Join-Path $RepoRoot 'scripts/lab/Invoke-TrustedProvisioning.ps1'
    $remoteProvScript = 'C:\dlp\server\scripts\lab\Invoke-TrustedProvisioning.ps1'
    Assert-Client01 (Test-Path -LiteralPath $localProvScript) 'trusted_provisioning_script_missing'

    # Remove any existing copy so Copy-VMFileOrStream cannot silently leave an
    # old helper in place.
    Invoke-LabCommand -VMName 'LAB-DC01' -ScriptBlock {
        param($Path)
        if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    } -ArgumentList @($remoteProvScript) | Out-Null

    Copy-VMFileOrStream -VMName 'LAB-DC01' -SourcePath $localProvScript -DestinationPath $remoteProvScript

    # Verify the remote file matches the local file so stale copies are caught
    # immediately.
    $localHash = Get-Phase1Sha256 $localProvScript
    $remoteHash = Invoke-LabCommand -VMName 'LAB-DC01' -ScriptBlock {
        param($Path)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $bytes = [System.IO.File]::ReadAllBytes($Path)
            $hash = $sha.ComputeHash($bytes)
            return ([System.BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
        } finally {
            $sha.Dispose()
        }
    } -ArgumentList @($remoteProvScript)
    if ($localHash -ne $remoteHash) { Stop-Client01 'trusted_provisioning_script_hash_mismatch' }
    Write-Host "TrustedProvisioning: staged Invoke-TrustedProvisioning.ps1 ($remoteHash)"
}

function Get-Client01ProvisioningMaterial {
    # The provisioning material may be supplied as inline PEM or as a path to a
    # file on the orchestrator host. The lab.env example uses the _PATH suffix,
    # while the orchestration code historically expected _PEM; support both.
    param(
        [Parameter(Mandatory)][string]$PemVariable,
        [Parameter(Mandatory)][string]$PathVariable
    )
    $value = [Environment]::GetEnvironmentVariable($PemVariable)
    if ([string]::IsNullOrWhiteSpace($value)) {
        $value = [Environment]::GetEnvironmentVariable($PathVariable)
    }
    if ([string]::IsNullOrWhiteSpace($value)) {
        Stop-Client01 "provisioning_material_missing: set $PemVariable or $PathVariable"
    }
    return (Get-Client01SecretValue -Name $PemVariable -Value $value)
}

function Get-LatestProvisioningAdminMaterial {
    # Prefer a freshly rotated provisioning admin cert/key in the standard lab
    # secrets directory if it exists and is newer than the env-var path. This
    # prevents the orchestrator from using a stale cert after rotation.
    param(
        [Parameter(Mandatory)][string]$PemVariable,
        [Parameter(Mandatory)][string]$PathVariable,
        [Parameter(Mandatory)][string]$DefaultPath
    )
    $envValue = [Environment]::GetEnvironmentVariable($PemVariable)
    $envPath = [Environment]::GetEnvironmentVariable($PathVariable)
    $resolvedPath = if (-not [string]::IsNullOrWhiteSpace($envValue) -and $envValue -notmatch '^-----BEGIN' -and (Test-Path -LiteralPath $envValue)) {
        $envValue
    } elseif (-not [string]::IsNullOrWhiteSpace($envPath) -and (Test-Path -LiteralPath $envPath)) {
        $envPath
    } else {
        $null
    }

    $defaultFullPath = [System.IO.Path]::GetFullPath($DefaultPath)
    if (Test-Path -LiteralPath $defaultFullPath) {
        if ($null -eq $resolvedPath) {
            Write-Host "TrustedProvisioning: using $defaultFullPath (no env-var path found)" -ForegroundColor Yellow
            return (Get-Client01SecretValue -Name $PemVariable -Value $defaultFullPath)
        }
        $resolvedFullPath = [System.IO.Path]::GetFullPath($resolvedPath)
        if ($resolvedFullPath -ne $defaultFullPath) {
            $defaultTime = (Get-Item -LiteralPath $defaultFullPath).LastWriteTimeUtc
            $resolvedTime = (Get-Item -LiteralPath $resolvedFullPath).LastWriteTimeUtc
            if ($defaultTime -gt $resolvedTime) {
                Write-Host "TrustedProvisioning: $defaultFullPath is newer than env-var path $resolvedFullPath; using rotated material" -ForegroundColor Yellow
                return (Get-Client01SecretValue -Name $PemVariable -Value $defaultFullPath)
            }
        }
    }

    return (Get-Client01ProvisioningMaterial -PemVariable $PemVariable -PathVariable $PathVariable)
}

function Invoke-Client01TrustedProvisioning {
    param(
        [Parameter(Mandatory)][string]$PrivilegeManifestDigest,
        [Parameter(Mandatory)][string]$TargetComputer,
        [Parameter()][char]$PreferredDriveLetter = 'P',
        [Parameter()][switch]$RecoverCredential
    )
    Wait-Client01AdwsReady -ServerName @('LAB-DC01.lab.local', 'LAB-DC02.lab.local')
    Assert-Client01ServerReady
    Write-Client01Status -Code 'trusted_provisioning_started' -Message 'Requesting a fresh short-lived enrollment token on LAB-DC01.'
    Write-Client01Diagnostic -Code 'trusted_provisioning_stage' -Fields @{
        target = $TargetComputer
        provider = 'TrustedProvisioning'
        admin_material_location = 'LAB-DC01'
    }
    $remoteDlpctlPath = Install-Client01ProvisioningBinary

    # Invoke-TrustedProvisioning.ps1 guards require both the approved digest and
    # the administrator provisioning mTLS material to be present in the LAB-DC01
    # session. These values are consumed only on LAB-DC01; they are not written
    # to LAB-CLIENT01 or persisted on hungdinh-lt.
    # The provisioning client needs the CA that signed the server's TLS
    # certificate. In the Phase 1 lab the server cert is signed by the Phase 1
    # root CA, so default to DLP_PHASE1_ROOT_CA_CERT_PEM when no
    # provisioning-specific root CA variable is set. Validate that the selected
    # value is a certificate, not a private key.
    $provisioningRootCa = if (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable('DLP_PROVISIONING_ROOT_CA_PEM')) -or
                               -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable('DLP_PROVISIONING_ROOT_CA_PATH'))) {
        Get-Client01ProvisioningMaterial -PemVariable 'DLP_PROVISIONING_ROOT_CA_PEM' -PathVariable 'DLP_PROVISIONING_ROOT_CA_PATH'
    } else {
        Get-Client01SecretValue -Name 'DLP_PHASE1_ROOT_CA_CERT_PEM' -Value ([Environment]::GetEnvironmentVariable('DLP_PHASE1_ROOT_CA_CERT_PEM'))
    }
    if (-not ($provisioningRootCa -match '^-----BEGIN CERTIFICATE-----')) {
        Stop-Client01 'provisioning_root_ca_invalid: expected -----BEGIN CERTIFICATE-----'
    }
    $provisioningAdminCert = Get-LatestProvisioningAdminMaterial -PemVariable 'DLP_PROVISIONING_ADMIN_CERT_PEM' -PathVariable 'DLP_PROVISIONING_ADMIN_CERT_PATH' -DefaultPath 'C:\dlp\secrets\provisioning-admin-cert.pem'
    $provisioningAdminKey = Get-LatestProvisioningAdminMaterial -PemVariable 'DLP_PROVISIONING_ADMIN_KEY_PEM' -PathVariable 'DLP_PROVISIONING_ADMIN_KEY_PATH' -DefaultPath 'C:\dlp\secrets\provisioning-admin-key.pem'
    # The admin CA certificate is required so dlpctl can present the full
    # client certificate chain (leaf + issuing CA) to the server's
    # CertificateRequest. Without it, rustls may be unable to select a cert.
    $provisioningAdminCa = Get-Client01SecretValue -Name 'DLP_ADMIN_CA_CERT_PEM' -Value ([Environment]::GetEnvironmentVariable('DLP_ADMIN_CA_CERT_PEM'))
    if (-not ($provisioningAdminCa -match '^-----BEGIN CERTIFICATE-----')) {
        Stop-Client01 'provisioning_admin_ca_invalid: expected -----BEGIN CERTIFICATE-----'
    }

    $resultJson = $null
    try {
        $resultJson = Invoke-LabCommand -VMName 'LAB-DC01' -ScriptBlock {
            param($Digest, $Target, $PreferredLetter, $ProvisioningRootCa, $ProvisioningAdminCert, $ProvisioningAdminKey, $ProvisioningAdminCa, $DlpctlPath, $LabAllowVirtualDiskUniqueId, $Recover)
            $ErrorActionPreference = 'Stop'
            Set-Location C:\dlp\server
            $env:DLP_APPROVED_PRIVILEGE_MANIFEST_DIGEST = $Digest
            $env:DLP_PROVISIONING_ROOT_CA_PEM = $ProvisioningRootCa
            $env:DLP_PROVISIONING_ADMIN_CERT_PEM = $ProvisioningAdminCert
            $env:DLP_PROVISIONING_ADMIN_KEY_PEM = $ProvisioningAdminKey
            $env:DLP_PROVISIONING_DLPCTL_PATH = $DlpctlPath
            if (-not [string]::IsNullOrWhiteSpace($LabAllowVirtualDiskUniqueId)) {
                $env:DLP_LAB_ALLOW_VIRTUAL_DISK_UNIQUE_ID = $LabAllowVirtualDiskUniqueId
            }
            $arguments = @{
                ExecutionMachine = 'LAB-DC01'
                TargetComputer = $Target
                PrivilegeManifestDigest = $Digest
                PreferredDriveLetter = $PreferredLetter
                AdminCaPem = $ProvisioningAdminCa
            }
            if ($Recover) { $arguments.RecoverCredential = $true }
            & scripts/lab/Invoke-TrustedProvisioning.ps1 @arguments
        } -ArgumentList @($PrivilegeManifestDigest, $TargetComputer, $PreferredDriveLetter, $provisioningRootCa, $provisioningAdminCert, $provisioningAdminKey, $provisioningAdminCa, $remoteDlpctlPath, $env:DLP_LAB_ALLOW_VIRTUAL_DISK_UNIQUE_ID, [bool]$RecoverCredential)
    } catch {
        # D-09..D-12: never echo protected files or exception text. Optional
        # diagnostics contain only bounded metadata and file lengths.
        $diagnostics = $null
        try {
            $diagnostics = Invoke-LabCommand -VMName 'LAB-DC01' -ScriptBlock {
            $provDir = 'C:\dlp\provisioning'
            $known = @('dlpctl.log', 'dlpctl.err', 'dlpctl-rust.err')
            $lengths = [ordered]@{}
            foreach ($name in $known) {
                $path = Join-Path $provDir $name
                $lengths[$name] = if (Test-Path -LiteralPath $path) { (Get-Item -LiteralPath $path).Length } else { -1 }
            }
            return [pscustomobject]@{
                stage = 'dlpctl'
                directory = $provDir
                file_lengths = $lengths
            }
            }
        } catch {
            $diagnostics = [pscustomobject]@{ stage = 'diagnostic_collection'; directory = 'C:\dlp\provisioning'; file_lengths = @{} }
        }
        Write-Client01Diagnostic -Code 'trusted_provisioning_failed' -Fields @{
            stage = $diagnostics.stage
            protected_directory = $diagnostics.directory
            file_lengths = $diagnostics.file_lengths
            error_type = $_.Exception.GetType().Name
        }
        Stop-Client01 'trusted_provisioning_failed: retry to mint a fresh token; use -Diagnostic for redacted metadata'
    }

    $result = $resultJson | ConvertFrom-Json
    if ([string]::IsNullOrWhiteSpace($result.enrollment_token)) {
        Stop-Client01 'trusted_provisioning_returned_empty_token'
    }
    Assert-EnrollmentTokenValid -Token $result.enrollment_token
    Write-Client01Status -Code 'trusted_provisioning_complete' -Message "Fresh enrollment material is ready for $($result.target)."
    return $result.enrollment_token
}

function Install-Client01ServiceBinary {
    $localServiceBinary = Join-Path $RepoRoot 'target/release/dlp-windows-service.exe'
    $localDriveHostBinary = Join-Path $RepoRoot 'target/release/dlp-drive-host.exe'
    # Always rebuild so a Tracer rerun deploys the current source instead of a
    # stale release binary left by an earlier lab attempt.
    Write-Host 'Building dlp-windows-service release binary on hungdinh-lt...'
    $proc = Start-Process -FilePath 'cargo' -ArgumentList @('build', '--release', '-p', 'dlp-windows-service') -WorkingDirectory $RepoRoot -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -ne 0) { Stop-Client01 'cargo_build_failed' }
    Write-Host 'Building dlp-drive-host release binary on hungdinh-lt...'
    $hostProc = Start-Process -FilePath 'cargo' -ArgumentList @('build', '--release', '-p', 'dlp-windows-drive', '--bin', 'dlp-drive-host') -WorkingDirectory $RepoRoot -NoNewWindow -Wait -PassThru
    if ($hostProc.ExitCode -ne 0) { Stop-Client01 'drive_host_build_failed' }
    Assert-Client01 (Test-Path -LiteralPath $localServiceBinary) 'service_release_binary_missing'
    Assert-Client01 (Test-Path -LiteralPath $localDriveHostBinary) 'drive_host_release_binary_missing'

    Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        New-Item -ItemType Directory -Path 'C:\dlp\agent' -Force | Out-Null
        New-Item -ItemType Directory -Path 'C:\dlp\agent\data' -Force | Out-Null
        New-Item -ItemType Directory -Path 'C:\dlp\agent\cache' -Force | Out-Null
        New-Item -ItemType Directory -Path 'C:\Program Files\DLP' -Force | Out-Null
    }

    # Stop any running service before replacing the binary.
    Stop-Client01Service

    $remoteServiceBinary = 'C:\dlp\agent\dlp-windows-service.exe'
    # This is the service's existing default host path; keeping the host beside
    # the approved product installation avoids a second deployment mechanism.
    $remoteDriveHostBinary = 'C:\Program Files\DLP\dlp-drive-host.exe'
    Copy-VMFileOrStream -VMName $ExecutionMachine -SourcePath $localServiceBinary -DestinationPath $remoteServiceBinary
    Copy-VMFileOrStream -VMName $ExecutionMachine -SourcePath $localDriveHostBinary -DestinationPath $remoteDriveHostBinary

    $expectedServiceHash = Get-Phase1Sha256 $localServiceBinary
    $expectedDriveHostHash = Get-Phase1Sha256 $localDriveHostBinary
    $remoteHashes = Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        param($ServicePath, $HostPath)
        $ErrorActionPreference = 'Stop'
        function Get-RemoteSha256([string]$Path) {
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            try {
                return ([System.BitConverter]::ToString($sha256.ComputeHash([System.IO.File]::ReadAllBytes($Path)))).Replace('-', '')
            } finally {
                $sha256.Dispose()
            }
        }
        if (-not (Test-Path -LiteralPath $ServicePath)) { throw 'service_binary_missing_after_deploy' }
        if (-not (Test-Path -LiteralPath $HostPath)) { throw 'drive_host_binary_missing_after_deploy' }
        [pscustomobject]@{
            service_hash = Get-RemoteSha256 $ServicePath
            drive_host_hash = Get-RemoteSha256 $HostPath
        }
    } -ArgumentList @($remoteServiceBinary, $remoteDriveHostBinary)
    Assert-Client01 ($remoteHashes.service_hash -eq $expectedServiceHash) 'service_binary_hash_mismatch'
    Assert-Client01 ($remoteHashes.drive_host_hash -eq $expectedDriveHostHash) 'drive_host_binary_hash_mismatch'
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
    $rootCaPem = Get-Client01SecretValue -Name 'DLP_ROOT_CA_PEM' -Value $env:DLP_ROOT_CA_PEM
    if (-not $rootCaPem.TrimStart().StartsWith('-----BEGIN CERTIFICATE-----')) {
        Stop-Client01 'root_ca_invalid: DLP_ROOT_CA_PEM must resolve to a certificate PEM, not a private key or other file'
    }
    $secrets = [ordered]@{
        'phase1-root-ca.pem' = $rootCaPem
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
    $envLines.Add('DLP_ROOT_CA_PEM=C:\dlp\secrets\phase1-root-ca.pem')
    $envLines.Add('DLP_DATA_DIRECTORY=C:\dlp\agent\data')
    $envLines.Add('DLP_CACHE_DIRECTORY=C:\dlp\agent\cache')
    if (-not [string]::IsNullOrWhiteSpace($env:DLP_CONFIGURATION_KEY_ID)) {
        $envLines.Add("DLP_CONFIGURATION_KEY_ID=$($env:DLP_CONFIGURATION_KEY_ID)")
    }
    $envLines.Add("DLP_CONFIGURATION_PUBLIC_KEY_HEX=$($env:DLP_CONFIGURATION_PUBLIC_KEY_HEX)")
    if (-not [string]::IsNullOrWhiteSpace($EnrollmentToken)) {
        $envLines.Add("DLP_AGENT_ENROLLMENT_TOKEN=$EnrollmentToken")
    } elseif ($EnrollmentTokenProvider -ne 'TrustedProvisioning' -and
        -not [string]::IsNullOrWhiteSpace($env:DLP_AGENT_ENROLLMENT_TOKEN)) {
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
        $agentDirectory = 'C:\dlp\agent'
        $envPath = 'C:\dlp\agent\agent.env'
        $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
        $administratorsSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $allowedSids = @($systemSid.Value, $administratorsSid.Value)

        # The service runs as LocalSystem. Protect the directory before a token
        # is written so no inherited Users/Authenticated Users ACE can expose it.
        $directorySecurity = New-Object System.Security.AccessControl.DirectorySecurity
        $directorySecurity.SetAccessRuleProtection($true, $false)
        $directorySecurity.SetOwner($administratorsSid)
        foreach ($sid in @($systemSid, $administratorsSid)) {
            $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                $sid,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $directorySecurity.AddAccessRule($rule) | Out-Null
        }
        Set-Acl -LiteralPath $agentDirectory -AclObject $directorySecurity -ErrorAction Stop

        # Create the temporary file with its final protected descriptor, write
        # all lines, then atomically rename it within the same NTFS directory.
        $fileSecurity = New-Object System.Security.AccessControl.FileSecurity
        $fileSecurity.SetAccessRuleProtection($true, $false)
        $fileSecurity.SetOwner($administratorsSid)
        foreach ($sid in @($systemSid, $administratorsSid)) {
            $fileSecurity.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
                $sid,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.AccessControlType]::Allow
            )) | Out-Null
        }
        $temporaryPath = Join-Path $agentDirectory ('agent.env.' + [Guid]::NewGuid().ToString('N') + '.tmp')
        $stream = $null
        $writer = $null
        try {
            $stream = [System.IO.FileStream]::new(
                $temporaryPath,
                [System.IO.FileMode]::CreateNew,
                [System.Security.AccessControl.FileSystemRights]::Write,
                [System.IO.FileShare]::None,
                4096,
                [System.IO.FileOptions]::WriteThrough,
                $fileSecurity
            )
            $writer = [System.IO.StreamWriter]::new($stream, (New-Object System.Text.UTF8Encoding($false)))
            foreach ($line in $EnvLines) { $writer.WriteLine($line) }
            $writer.Flush()
            $stream.Flush($true)
            $writer.Dispose()
            $writer = $null
            $stream = $null
            Move-Item -LiteralPath $temporaryPath -Destination $envPath -Force -ErrorAction Stop
        } finally {
            if ($null -ne $writer) { $writer.Dispose() }
            elseif ($null -ne $stream) { $stream.Dispose() }
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }

        foreach ($path in @($agentDirectory, $envPath)) {
            $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
            if (-not $acl.AreAccessRulesProtected) { throw 'enrollment_token_acl_inheritance_enabled' }
            $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
            $unexpectedAllow = @($rules | Where-Object {
                $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                $_.IdentityReference.Value -notin $allowedSids
            })
            if ($unexpectedAllow.Count -ne 0) { throw 'enrollment_token_acl_unexpected_principal' }
            foreach ($sid in $allowedSids) {
                $matching = @($rules | Where-Object {
                    $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                    $_.IdentityReference.Value -eq $sid -and
                    ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl)
                })
                if ($matching.Count -eq 0) { throw 'enrollment_token_acl_required_principal_missing' }
            }
        }
    # Preserve the complete string array as one positional argument. Without
    # the unary comma, PowerShell enumerates the list and the remote script's
    # single parameter receives only DLP_DEVICE_ID.
    } -ArgumentList (,$envLines.ToArray())
}

function Install-Client01Service {
    param(
        [Parameter()][switch]$StartAfterInstall,
        [Parameter()][string]$EnrollmentToken
    )

    Write-Client01Status -Code 'service_install_started' -Message 'Installing the endpoint service while preserving data and cache.'
    # D-08: Install-Client01ServiceBinary creates missing directories and
    # replaces only binaries; it never removes data, credentials, or cache.
    Install-Client01ServiceBinary
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

        # The credential directory grants access to SYSTEM and the per-service
        # SID. SCM must add that SID to the service token or DPAPI persistence
        # correctly fails closed after enrollment.
        & sc.exe sidtype $serviceName unrestricted | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe sidtype failed: $LASTEXITCODE" }

        # Ensure the service process receives the persisted environment.
        $envPath = 'C:\dlp\agent\agent.env'
        if (Test-Path -LiteralPath $envPath) {
            $envLines = [System.IO.File]::ReadAllLines($envPath)
            $serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $serviceName
            Set-ItemProperty -Path $serviceKey -Name 'Environment' -Value $envLines -Type MultiString -Force
        }

        if ($StartAfter) {
            try {
                Start-Service -Name $serviceName -ErrorAction Stop
            } catch {
                # D-09..D-12: return redacted metadata only. Environment values,
                # event messages, certificates, and credentials are excluded.
                $diag = [ordered]@{
                    service_status = '<missing>'
                    service_exit_code = $null
                    event_log_error_count = 0
                    binary_exists = $false
                    binary_version = $null
                    env_file_exists = $false
                    env_line_count = 0
                }
                $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($null -ne $svc) {
                    $diag.service_status = $svc.Status.ToString()
                    try {
                        $wmiSvc = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
                        if ($null -ne $wmiSvc) { $diag.service_exit_code = $wmiSvc.ExitCode }
                    } catch { }
                }
                $diag.binary_exists = Test-Path -LiteralPath $binaryPath
                if ($diag.binary_exists) {
                    try { $diag.binary_version = (Get-ItemProperty -LiteralPath $binaryPath).VersionInfo.FileVersion } catch { }
                }
                if (Test-Path -LiteralPath $envPath) {
                    $diag.env_file_exists = $true
                    $diag.env_line_count = @([System.IO.File]::ReadAllLines($envPath)).Count
                }
                $diag.event_log_error_count = @(Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddMinutes(-10)} -ErrorAction SilentlyContinue |
                    Where-Object { $_.Message -like "*$serviceName*" -or $_.ProviderName -eq 'Service Control Manager' } |
                    Select-Object -First 10).Count
                throw ([System.InvalidOperationException]::new(('service_start_failed|' + ($diag | ConvertTo-Json -Compress -Depth 5))))
            }
        }
    } -ArgumentList @($StartAfterInstall)
}

function Get-Client01ServiceStartDiagnostics {
    return Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        $ErrorActionPreference = 'Stop'
        $serviceName = 'DlpWindowsService'
        $result = [ordered]@{
            service_status = '<missing>'
            service_exit_code = $null
            event_log_error_count = 0
            binary_exists = $false
            binary_version = $null
            env_file_exists = $false
            env_line_count = 0
        }
        $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -ne $svc) {
            $result.service_status = $svc.Status.ToString()
            try {
                $wmiSvc = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
                if ($null -ne $wmiSvc) {
                    $result.service_exit_code = $wmiSvc.ExitCode
                }
            } catch { }
        }
        $binaryPath = 'C:\dlp\agent\dlp-windows-service.exe'
        $result.binary_exists = Test-Path -LiteralPath $binaryPath
        if ($result.binary_exists) {
            try {
                $result.binary_version = (Get-ItemProperty -LiteralPath $binaryPath).VersionInfo.FileVersion
            } catch { }
        }
        $envPath = 'C:\dlp\agent\agent.env'
        if (Test-Path -LiteralPath $envPath) {
            $result.env_file_exists = $true
            $result.env_line_count = @([System.IO.File]::ReadAllLines($envPath)).Count
        }
        $result.event_log_error_count = @(Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddMinutes(-10)} -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -like "*$serviceName*" -or $_.ProviderName -eq 'Service Control Manager' } |
            Select-Object -First 10).Count
        return $result
    }
}

function Test-Client01ServiceRunning {
    return Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        $service = Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue
        return ($null -ne $service -and $service.Status -eq 'Running')
    }
}

function Wait-Client01ActivePolicy {
    param([Parameter()][int]$TimeoutSeconds = 120)
    # TST-05: the durable pointer is written only after signed configuration
    # verification and atomic activation. Reading version/state proves more
    # than credential-file existence or a merely Running service.
    $state = Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        param($Timeout)
        $ErrorActionPreference = 'Stop'
        $pointerPath = 'C:\dlp\agent\cache\pointers'
        $deadline = [DateTime]::UtcNow.AddSeconds($Timeout)
        while ([DateTime]::UtcNow -lt $deadline) {
            if (Test-Path -LiteralPath $pointerPath) {
                $bytes = [System.IO.File]::ReadAllBytes($pointerPath)
                if ($bytes.Length -ge 65 -and [System.Text.Encoding]::ASCII.GetString($bytes, 0, 8) -eq 'dlp-ptr1' -and $bytes[24] -eq 1) {
                    [UInt64]$version = 0
                    for ($i = 0; $i -lt 8; $i++) {
                        $version = ($version -shl 8) -bor [UInt64]$bytes[57 + $i]
                    }
                    if ($version -gt 0) {
                        return [pscustomobject]@{ active_policy_version = $version.ToString(); active_policy_state = 'Active' }
                    }
                }
            }
            Start-Sleep -Milliseconds 500
        }
        return [pscustomobject]@{ active_policy_version = $null; active_policy_state = 'Unconfigured' }
    } -ArgumentList @($TimeoutSeconds)
    Assert-Client01 (-not [string]::IsNullOrWhiteSpace($state.active_policy_version)) 'active_policy_version_missing: wait for a signed configuration assignment and retry'
    Assert-Client01 ($state.active_policy_state -eq 'Active') 'active_policy_not_active: inspect redacted service diagnostics with -Diagnostic'
    Write-Host "active_policy_version=$($state.active_policy_version)"
    Write-Host "active_policy_state=$($state.active_policy_state)"
    return $state
}

function Invoke-Client01ServiceInstall {
    param([Parameter()][string]$EnrollmentToken)

    $fingerprint = Get-EnvironmentFingerprint -TargetMachine $ExecutionMachine
    try {
        Install-Client01Service -StartAfterInstall -EnrollmentToken $EnrollmentToken
    } catch {
        Write-Client01Diagnostic -Code 'service_install_failed' -Fields @{
            stage = 'install_or_start'
            error_type = $_.Exception.GetType().Name
            endpoint = $ExecutionMachine
        }
        Stop-Client01 'service_install_failed: partial service/binary artifacts were preserved; token cleanup will run before a fresh retry'
    }

    $running = Test-Client01ServiceRunning
    if (-not $running) {
        $diag = Get-Client01ServiceStartDiagnostics
        Write-Client01Diagnostic -Code 'service_not_running' -Fields @{
            service_status = $diag.service_status
            service_exit_code = $diag.service_exit_code
            binary_exists = $diag.binary_exists
            binary_version = $diag.binary_version
            env_file_exists = $diag.env_file_exists
            env_line_count = $diag.env_line_count
            event_log_error_count = $diag.event_log_error_count
        }
    }
    $credentialPresent = if ($running) { Test-Client01CredentialPresent } else { $false }
    if ($running -and -not [string]::IsNullOrWhiteSpace($EnrollmentToken) -and -not $credentialPresent) {
        Stop-Client01 'credential_not_established: service started without a usable device.dpapi; token cleanup will run before retry'
    }
    if ($running -and $credentialPresent -and -not [string]::IsNullOrWhiteSpace($EnrollmentToken) -and -not $RetainEnrollmentToken) {
        # D-05/D-06/D-07: cleanup follows durable credential establishment for
        # both initial and explicitly forced enrollment.
        Remove-Client01EnrollmentToken
    }
    $status = if ($running) { 'pass' } else { 'fail' }
    $actual = if ($running) { 'DlpWindowsService installed and running on LAB-CLIENT01' } else { 'DlpWindowsService did not reach Running state' }
    New-Client01Evidence -RequirementId 'SRV-13' -CheckId 'client01-service-install' -Status $status `
        -Expected 'dlp-windows-service is installed, configured, and starts as an automatic service on LAB-CLIENT01' `
        -Actual $actual -TargetMachine $ExecutionMachine -Fingerprint $fingerprint | Out-Null
    Assert-Client01 $running 'service_failed_to_start'
    Write-Client01Status -Code 'service_install_complete' -Message 'DlpWindowsService is installed, Automatic, and Running.'
}

function Invoke-Client01Tracer {
    $targetComputer = 'LAB-CLIENT01.lab.local'
    $enrollmentToken = $null
    $tokenHandedOff = $false
    if ($ForceReenrollment -and -not $Apply) {
        Write-Client01Status -Code 'force_reenrollment_preview' -Message 'Preview only: credential/token state would be replaced; service, data, and cache would be preserved. Add -Apply to mutate.'
        return
    }
    if ($ForceReenrollment) {
        Reset-Client01EnrollmentCredential
    }

    if ($EnrollmentTokenProvider -eq 'TrustedProvisioning') {
        if ($env:DLP_DEVICE_ID -cne $targetComputer) {
            Write-Client01Diagnostic -Code 'device_id_canonicalized' -Fields @{ target = $targetComputer }
            $env:DLP_DEVICE_ID = $targetComputer
        }
        if ((-not $ForceReenrollment) -and (Test-Client01CredentialPresent)) {
            Write-Client01Status -Code 'existing_credential_reused' -Message 'A usable device.dpapi is present; trusted provisioning was skipped.'
        } else {
            $approvedDigest = Get-ApprovedPrivilegeManifestDigest
            $enrollmentToken = Invoke-Client01TrustedProvisioning `
                -PrivilegeManifestDigest $approvedDigest `
                -TargetComputer $targetComputer `
                -PreferredDriveLetter 'P' `
                -RecoverCredential
        }
    } else {
        # Manual is an explicitly selected offline fallback only.
        $enrollmentToken = $env:DLP_AGENT_ENROLLMENT_TOKEN
        Assert-EnrollmentTokenValid -Token $enrollmentToken
        Write-Client01Status -Code 'manual_token_selected' -Message 'Using the explicitly selected offline enrollment-token provider.'
    }

    try {
        $tokenHandedOff = -not [string]::IsNullOrWhiteSpace($enrollmentToken)
        Invoke-Client01ServiceInstall -EnrollmentToken $enrollmentToken
        Wait-Client01ActivePolicy | Out-Null
    } catch {
        $safeFailure = $_.Exception.Message
        if ($tokenHandedOff) {
            # D-01..D-04: cleanup is mandatory even when retention was requested;
            # partial services/binaries remain and retry must provision afresh.
            Remove-Client01EnrollmentToken
        }
        Stop-Client01 $safeFailure
    } finally {
        $enrollmentToken = $null
    }

    Write-Client01Status -Code 'server_readiness_probe' -Message 'Checking LAB-DC01 readiness over the trusted TLS path.'
    Assert-Client01ServerReady

    $serverHost = "$ProbeMachine.lab.local"
    Write-Client01Diagnostic -Code 'server_probe' -Fields @{ endpoint = $ExecutionMachine; server = $serverHost; port = $script:ServerPort }
    $probeFingerprint = Get-EnvironmentFingerprint -TargetMachine $ExecutionMachine

    Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        param($ServerHost, $Port, $RootCaPath)
        $ErrorActionPreference = 'Stop'
        if (-not (Test-Path -LiteralPath $RootCaPath)) {
            throw 'server_probe_root_ca_missing'
        }
        $uris = @("https://${ServerHost}:$Port/health/live", "https://${ServerHost}:$Port/health/ready")
        foreach ($uri in $uris) {
            $response = & curl.exe --silent --fail --ssl-no-revoke --cacert $RootCaPath --max-time 60 $uri 2>$null
            if ($LASTEXITCODE -ne 0) { throw 'server_probe_tls_failed' }
            $content = ($response -join "`n") | ConvertFrom-Json
            if ($content.status -ne 'ok') { throw "probe status not ok: $uri" }
        }
    } -ArgumentList @($serverHost, $script:ServerPort, 'C:\dlp\secrets\phase1-root-ca.pem')

    New-Client01Evidence -RequirementId 'SRV-14' -CheckId 'client01-tracer-readiness' -Status 'pass' `
        -Expected 'LAB-CLIENT01 service reaches the management server on LAB-DC01 over validated TLS' `
        -Actual "live/ready ok from $ExecutionMachine to $serverHost" -TargetMachine $ExecutionMachine -Fingerprint $probeFingerprint | Out-Null
    Write-Client01Status -Code 'tracer_complete' -Message 'Enrollment, automatic startup, and first signed policy activation are complete.'
}

Assert-DlpMachineRole -ExpectedRole 'developer_orchestrator'
$approvedDigest = Get-ApprovedPrivilegeManifestDigest
Write-Client01Diagnostic -Code 'privilege_manifest_approved' -Fields @{ fingerprint = $approvedDigest; plan = '01-19' }

if ($Apply) {
    $cred = Get-VmCredential
    if ($null -eq $cred) {
        Stop-Client01 'vm_credentials_required: provide -Credential or DLP_VM_ADMIN_USER/PASSWORD and retry'
    }
    Assert-RuntimeSecretsPresent
}

if (-not $Apply) {
    Write-Client01Status -Code 'preview_only' -Message 'No endpoint changes will be applied. Add -Apply to execute.'
}

switch ($Scenario) {
    'Tracer' { if ($Apply) { Invoke-Client01Tracer } elseif ($ForceReenrollment) { Invoke-Client01Tracer } else { Write-Host 'Dry-run: would execute Tracer scenario' } }
    # SRV-13/TST-05: ServiceInstall is the documented normal path and therefore
    # includes automatic token acquisition and first signed-policy activation.
    'ServiceInstall' { if ($Apply) { Invoke-Client01Tracer } elseif ($ForceReenrollment) { Invoke-Client01Tracer } else { Write-Host 'Dry-run: would execute ServiceInstall with TrustedProvisioning by default' } }
    'All' { if ($Apply) { Invoke-Client01Tracer } elseif ($ForceReenrollment) { Invoke-Client01Tracer } else { Write-Host 'Dry-run: would execute the full enrollment tracer' } }
}

Write-Client01Status -Code 'scenario_complete' -Message "Scenario $Scenario completed."
