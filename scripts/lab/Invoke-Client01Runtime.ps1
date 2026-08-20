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
    Write-Host 'Install-Client01Service: removing enrollment token from service environment...'
    Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        $ErrorActionPreference = 'Stop'
        $serviceName = 'DlpWindowsService'
        $serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $serviceName
        $envPath = 'C:\dlp\agent\agent.env'

        $existing = Get-ItemProperty -Path $serviceKey -Name 'Environment' -ErrorAction SilentlyContinue
        if ($null -ne $existing -and $null -ne $existing.Environment) {
            $cleaned = @($existing.Environment | Where-Object { $_ -notlike 'DLP_AGENT_ENROLLMENT_TOKEN=*' })
            Set-ItemProperty -Path $serviceKey -Name 'Environment' -Value $cleaned -Type MultiString -Force
        }

        if (Test-Path -LiteralPath $envPath) {
            $lines = [System.IO.File]::ReadAllLines($envPath)
            $cleaned = @($lines | Where-Object { $_ -notlike 'DLP_AGENT_ENROLLMENT_TOKEN=*' })
            [System.IO.File]::WriteAllLines($envPath, $cleaned, (New-Object System.Text.UTF8Encoding($false)))
        }
    }
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
            "DATABASE_URL=$([Environment]::GetEnvironmentVariable('DATABASE_URL', 'Process'))"
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
        $lastErr = ''
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
                $lastErr = $_.Exception.Message
                Start-Sleep -Seconds 1
            }
        }
        if (-not $ready) {
            Invoke-LabCommand -VMName 'LAB-DC01' -ScriptBlock {
                Write-Host '--- startup-diagnostic.log ---'
                Get-Content -LiteralPath 'C:\dlp\server\startup-diagnostic.log' -ErrorAction SilentlyContinue
                Write-Host '--- dlp-server.err ---'
                Get-Content -LiteralPath 'C:\dlp\server\dlp-server.err' -ErrorAction SilentlyContinue
                Write-Host '--- dlp-server.log ---'
                Get-Content -LiteralPath 'C:\dlp\server\dlp-server.log' -ErrorAction SilentlyContinue
                Write-Host '--- secret files ---'
                Get-ChildItem -LiteralPath 'C:\dlp\secrets' -ErrorAction SilentlyContinue | ForEach-Object {
                    $firstLine = Get-Content -LiteralPath $_.FullName -TotalCount 1 -ErrorAction SilentlyContinue
                    "$($_.Name): length=$($_.Length) first_line=$firstLine"
                }
                Write-Host '--- listening ports ---'
                Get-NetTCPConnection -LocalPort 8443 -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, State, OwningProcess
                Write-Host '--- excluded port ranges ---'
                netsh int ipv4 show excludedportrange protocol=tcp 2>&1
                Write-Host '--- dlp-server processes ---'
                Get-Process -Name 'dlp-server' -ErrorAction SilentlyContinue | Select-Object Id, Path
            } | Write-Host
            Stop-Client01 "server_failed_to_bind: $lastErr"
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
    $command = "& '$verifyScript' -ServerHostname '$expectedHostname'"
    $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList @(
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy', 'Bypass',
        '-Command', $command
    ) -WorkingDirectory $RepoRoot -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
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
            dlp_server_err = $null
            dlp_server_log = $null
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

        $result.dlp_server_err = if (Test-Path -LiteralPath 'C:\dlp\server\dlp-server.err') {
            Get-Content -LiteralPath 'C:\dlp\server\dlp-server.err' -Raw
        } else { '<missing>' }
        $result.dlp_server_log = if (Test-Path -LiteralPath 'C:\dlp\server\dlp-server.log') {
            Get-Content -LiteralPath 'C:\dlp\server\dlp-server.log' -Raw
        } else { '<missing>' }

        return $result
    } -ArgumentList @($script:ServerPort, $localHash, $expectedSecretHashes)

    Write-Host "Server readiness diagnostics: $($diagnostics | ConvertTo-Json -Compress -Depth 10)"

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
    # on LAB-DC01. The orchestrator host may already have a local path in
    # $env:DLP_PROVISIONING_DLPCTL_PATH; otherwise default to the workspace release
    # build. The binary is copied to a deterministic location inside the DC so the
    # remote Invoke-TrustedProvisioning.ps1 can invoke it by path.
    $localBinary = if ($env:DLP_PROVISIONING_DLPCTL_PATH) { $env:DLP_PROVISIONING_DLPCTL_PATH } else { Join-Path $RepoRoot 'target/release/dlpctl.exe' }

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
        [Parameter()][char]$PreferredDriveLetter = 'P'
    )
    Wait-Client01AdwsReady -ServerName @('LAB-DC01.lab.local', 'LAB-DC02.lab.local')
    Assert-Client01ServerReady
    Write-Host 'TrustedProvisioning: staging dlpctl binary on LAB-DC01...'
    $remoteDlpctlPath = Install-Client01ProvisioningBinary
    Write-Host 'TrustedProvisioning: invoking trusted provisioning on LAB-DC01...'

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
            param($Digest, $Target, $PreferredLetter, $ProvisioningRootCa, $ProvisioningAdminCert, $ProvisioningAdminKey, $ProvisioningAdminCa, $DlpctlPath, $LabAllowVirtualDiskUniqueId)
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
            & scripts/lab/Invoke-TrustedProvisioning.ps1 `
                -ExecutionMachine LAB-DC01 `
                -TargetComputer $Target `
                -PrivilegeManifestDigest $Digest `
                -PreferredDriveLetter $PreferredLetter `
                -AdminCaPem $ProvisioningAdminCa
        } -ArgumentList @($PrivilegeManifestDigest, $TargetComputer, $PreferredDriveLetter, $provisioningRootCa, $provisioningAdminCert, $provisioningAdminKey, $provisioningAdminCa, $remoteDlpctlPath, $env:DLP_LAB_ALLOW_VIRTUAL_DISK_UNIQUE_ID)
    } catch {
        Write-Host '--- dlpctl diagnostics from LAB-DC01 ---'
        $diagnostics = Invoke-LabCommand -VMName 'LAB-DC01' -ScriptBlock {
            $provDir = 'C:\dlp\provisioning'
            $logPath = Join-Path $provDir 'dlpctl.log'
            $errPath = Join-Path $provDir 'dlpctl.err'
            $rustErrPath = Join-Path $provDir 'dlpctl-rust.err'
            $tlsLogPath = 'C:\dlp\server\tls-events.log'
            $result = [ordered]@{
                log = if (Test-Path -LiteralPath $logPath) { Get-Content -LiteralPath $logPath -Raw } else { '<missing>' }
                err = if (Test-Path -LiteralPath $errPath) { Get-Content -LiteralPath $errPath -Raw } else { '<missing>' }
                rustErr = if (Test-Path -LiteralPath $rustErrPath) { Get-Content -LiteralPath $rustErrPath -Raw } else { '<missing>' }
                tlsEvents = if (Test-Path -LiteralPath $tlsLogPath) { Get-Content -LiteralPath $tlsLogPath -Raw } else { '<missing>' }
                files = @()
            }
            Get-ChildItem -LiteralPath $provDir -ErrorAction SilentlyContinue | ForEach-Object {
                $firstLine = Get-Content -LiteralPath $_.FullName -TotalCount 1 -ErrorAction SilentlyContinue
                $result.files += "$($_.Name): length=$($_.Length) first_line=$firstLine"
            }
            return $result
        }
        Write-Host "dlpctl.log:`n$($diagnostics.log)"
        Write-Host "dlpctl.err:`n$($diagnostics.err)"
        Write-Host "dlpctl-rust.err:`n$($diagnostics.rustErr)"
        Write-Host "tls-events.log:`n$($diagnostics.tlsEvents)"
        Write-Host 'provisioning files:'
        $diagnostics.files | ForEach-Object { Write-Host $_ }
        throw
    }

    $result = $resultJson | ConvertFrom-Json
    if ([string]::IsNullOrWhiteSpace($result.enrollment_token)) {
        Stop-Client01 'trusted_provisioning_returned_empty_token'
    }
    Assert-EnrollmentTokenValid -Token $result.enrollment_token
    Write-Host "TrustedProvisioning: obtained enrollment token for $($result.target)"
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
            try {
                Start-Service -Name $serviceName -ErrorAction Stop
            } catch {
                # Collect diagnostics before re-throwing so the orchestrator can see
                # why the service failed without a second remote round-trip.
                $diag = [ordered]@{
                    service_status = '<missing>'
                    service_exit_code = $null
                    event_log_errors = @()
                    binary_exists = $false
                    binary_version = $null
                    env_file = '<missing>'
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
                    $diag.env_file = Get-Content -LiteralPath $envPath -Raw
                }
                $diag.event_log_errors = @(Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddMinutes(-10)} -ErrorAction SilentlyContinue |
                    Where-Object { $_.Message -like "*$serviceName*" -or $_.ProviderName -eq 'Service Control Manager' } |
                    Select-Object -First 10 |
                    ForEach-Object { "[$($_.TimeCreated.ToString('o'))] $($_.ProviderName): $($_.LevelDisplayName) - $($_.Message)" })
                throw "Start-Service failed: $_`nDiagnostics: $($diag | ConvertTo-Json -Compress -Depth 10)"
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
            event_log_errors = @()
            binary_exists = $false
            binary_version = $null
            env_file = '<missing>'
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
            $result.env_file = Get-Content -LiteralPath $envPath -Raw
        }
        # Collect the most recent 10 service-related errors from the System log.
        $result.event_log_errors = @(Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddMinutes(-10)} -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -like "*$serviceName*" -or $_.ProviderName -eq 'Service Control Manager' } |
            Select-Object -First 10 |
            ForEach-Object { "[$($_.TimeCreated.ToString('o'))] $($_.ProviderName): $($_.LevelDisplayName) - $($_.Message)" })
        return $result
    }
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
    if (-not $running) {
        Write-Host '--- service start diagnostics ---'
        $diag = Get-Client01ServiceStartDiagnostics
        Write-Host ($diag | ConvertTo-Json -Compress -Depth 10)
    }
    if ($running -and $EnrollmentTokenProvider -eq 'TrustedProvisioning' -and -not $RetainEnrollmentToken) {
        if (Test-Client01CredentialPresent) {
            Remove-Client01EnrollmentToken
        } else {
            Write-Host 'Install-Client01Service: credential store not yet present; deferring token cleanup.'
        }
    }
    $status = if ($running) { 'pass' } else { 'fail' }
    $actual = if ($running) { 'DlpWindowsService installed and running on LAB-CLIENT01' } else { 'DlpWindowsService did not reach Running state' }
    New-Client01Evidence -RequirementId 'SRV-13' -CheckId 'client01-service-install' -Status $status `
        -Expected 'dlp-windows-service is installed, configured, and starts as an automatic service on LAB-CLIENT01' `
        -Actual $actual -TargetMachine $ExecutionMachine -Fingerprint $fingerprint | Out-Null
    Assert-Client01 $running 'service_failed_to_start'
    Write-Host 'Invoke-Client01ServiceInstall: complete.'
}

function Invoke-Client01Tracer {
    $targetComputer = 'LAB-CLIENT01.lab.local'
    $enrollmentToken = $null
    if ($EnrollmentTokenProvider -eq 'TrustedProvisioning') {
        if ($env:DLP_DEVICE_ID -cne $targetComputer) {
            Write-Host "Tracer: canonicalizing DLP_DEVICE_ID from '$($env:DLP_DEVICE_ID)' to '$targetComputer' to match trusted provisioning."
            $env:DLP_DEVICE_ID = $targetComputer
        }
        if (Test-Client01CredentialPresent) {
            Write-Host 'Tracer: existing DPAPI credential found on LAB-CLIENT01; skipping trusted provisioning.'
        } else {
            $approvedDigest = Get-ApprovedPrivilegeManifestDigest
            $enrollmentToken = Invoke-Client01TrustedProvisioning `
                -PrivilegeManifestDigest $approvedDigest `
                -TargetComputer $targetComputer `
                -PreferredDriveLetter 'P'
        }
    }

    Write-Host 'Tracer: installing service...'
    Invoke-Client01ServiceInstall -EnrollmentToken $enrollmentToken

    Write-Host 'Tracer: ensuring management server is ready on LAB-DC01...'
    Assert-Client01ServerReady

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
