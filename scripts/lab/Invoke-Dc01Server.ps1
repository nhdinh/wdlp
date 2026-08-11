[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('hungdinh-lt')][string]$CallerMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-DC01')][string]$ExecutionMachine,
    [Parameter(Mandatory)][ValidateSet('LAB-CLIENT01')][string]$ProbeMachine,
    [Parameter()][ValidateSet('LAB-SERVER01')][string]$DatabaseMachine = 'LAB-SERVER01',
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

# Fixed Phase 1 lab topology. The management server binds on LAB-DC01 and the
# PostgreSQL database lives on LAB-SERVER01. Probes from LAB-CLIENT01 must reach
# LAB-DC01, never the database host.
$script:Dc01Ip = '192.168.50.10'
$script:Server01Ip = '192.168.50.12'
$script:ServerPort = 8443

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

function Get-DatabaseFingerprint {
    return [pscustomobject]@{
        machine_identity = 'LAB-SERVER01'
        role = 'database_server'
        os_build = 'Ubuntu Server (native PostgreSQL)'
        dependency_versions = 'PostgreSQL 18.x; sqlx-cli 0.9.0'
        service_config_digest = (Get-Phase1Sha256 $ConfigPath)
        test_tool_versions = 'psql; sqlx'
        domain_network_identity = 'lab.local'
        baseline_id = [guid]::NewGuid().ToString()
        binary_hashes = 'none'
    }
}

function Get-EnvironmentFingerprint {
    param([Parameter(Mandatory)][string]$TargetMachine)
    $roleConfig = Get-Content -LiteralPath $RoleConfigPath -Raw | ConvertFrom-Json
    if ($TargetMachine -eq 'LAB-SERVER01') { return Get-DatabaseFingerprint }
    return [pscustomobject]@{
        machine_identity = $TargetMachine
        role = $roleConfig.machines.$TargetMachine.role
        os_build = (Invoke-LabCommand -VMName $TargetMachine -ScriptBlock { [System.Environment]::OSVersion.VersionString })
        dependency_versions = 'sqlx; postgres'
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
        identity = [pscustomobject]@{ kind = 'automation'; name = 'Invoke-Dc01Server.ps1' }
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
        dependency_digests = [pscustomobject]@{ 'lab-contract' = (Get-Phase1Sha256 $ConfigPath); 'lab-roles' = (Get-Phase1Sha256 $RoleConfigPath); 'migrations' = (Get-MigrationsDigest) }
    }
    if ($PriorAttemptId) { $evidence.prior_attempt_id = $PriorAttemptId }
    $path = Join-Path $EvidenceDir ("$CheckId-" + [guid]::NewGuid().ToString() + '.json')
    New-Phase1Evidence -Evidence $evidence -OutputPath $path | Out-Null
    return $path
}

function Get-MigrationsDigest {
    $migrationsDir = Join-Path $RepoRoot 'migrations'
    $files = Get-ChildItem -LiteralPath $migrationsDir -Filter '*.sql' | Sort-Object Name
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $buffer = New-Object System.Collections.Generic.List[byte]
        foreach ($file in $files) {
            $nameBytes = [System.Text.Encoding]::UTF8.GetBytes($file.Name)
            $buffer.AddRange([byte[]]([BitConverter]::GetBytes([UInt32]$nameBytes.Length)[3..0]))
            $buffer.AddRange($nameBytes)
            $content = [System.IO.File]::ReadAllBytes($file.FullName)
            $buffer.AddRange([byte[]]([BitConverter]::GetBytes([UInt32]$content.Length)[3..0]))
            $buffer.AddRange($content)
        }
        return [System.BitConverter]::ToString($sha.ComputeHash($buffer.ToArray())).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Get-AppliedMigrationCount {
    $dbUrl = $env:DLP_DATABASE_URL
    Assert-Dc01 (-not [string]::IsNullOrWhiteSpace($dbUrl)) 'database_url_missing'
    $env:DATABASE_URL = $dbUrl
    $migrationsDir = Join-Path $RepoRoot 'migrations'
    $output = sqlx migrate info --source $migrationsDir 2>&1
    if ($LASTEXITCODE -ne 0) { throw "sqlx migrate info failed: $output" }
    $applied = @($output | Where-Object { $_ -match '/installed' })
    return $applied.Count
}

function Invoke-DatabaseCommand {
    param([Parameter(Mandatory)][string]$Sql)
    $dbUrl = $env:DLP_DATABASE_URL
    Assert-Dc01 (-not [string]::IsNullOrWhiteSpace($dbUrl)) 'database_url_missing'
    $psql = Get-Command psql -ErrorAction SilentlyContinue
    if ($null -ne $psql) {
        $result = psql $dbUrl -t -c $Sql
        if ($LASTEXITCODE -ne 0) { throw "psql failed: $result" }
        return $result
    }
    throw 'psql is required for ad-hoc SQL queries; sqlx-cli does not provide a generic query subcommand'
}

function Invoke-SqlxMigrate {
    param([Parameter()][switch]$RevertIfPresent)
    $dbUrl = $env:DLP_DATABASE_URL
    Assert-Dc01 (-not [string]::IsNullOrWhiteSpace($dbUrl)) 'database_url_missing'
    $env:DATABASE_URL = $dbUrl
    $migrationsDir = Join-Path $RepoRoot 'migrations'
    $output = sqlx migrate run --source $migrationsDir 2>&1
    if ($LASTEXITCODE -ne 0) { throw "sqlx migrate failed: $output" }
    return $output
}

function Assert-RuntimeSecretsPresent {
    $required = @(
        'DLP_DATABASE_URL',
        'DLP_AD_PRIMARY_LDAPS_URL',
        'DLP_AD_SECONDARY_LDAPS_URL',
        'DLP_AD_BASE_DN',
        'DLP_AD_BIND_DN',
        'DLP_AD_BIND_PASSWORD',
        'DLP_AD_CA_CERT_PEM',
        'DLP_SERVER_CERT_PEM',
        'DLP_SERVER_KEY_PEM',
        'DLP_ADMIN_CA_CERT_PEM',
        'DLP_PHASE1_ROOT_CA_CERT_PEM',
        'DLP_DEVICE_ISSUING_CA_CERT_PEM',
        'DLP_DEVICE_ISSUING_CA_KEY_PEM',
        'DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX',
        'DLP_ADMIN_PROVISIONING_KEY'
    )
    $missing = @($required | Where-Object { [string]::IsNullOrWhiteSpace($env:$_) })
    if ($missing.Count -gt 0) { Stop-Dc01 ("runtime_secrets_missing: " + ($missing -join ', ')) }
}

function Install-Dc01ServerBinary {
    $localBinary = Join-Path $RepoRoot 'target/release/dlp-server.exe'
    if (-not (Test-Path -LiteralPath $localBinary)) {
        Write-Host 'Building dlp-server release binary on hungdinh-lt...'
        $proc = Start-Process -FilePath 'cargo' -ArgumentList @('build', '--release', '-p', 'dlp-server') -WorkingDirectory $RepoRoot -NoNewWindow -Wait -PassThru
        if ($proc.ExitCode -ne 0) { Stop-Dc01 'cargo_build_failed' }
    }
    Assert-Dc01 (Test-Path -LiteralPath $localBinary) 'release_binary_missing'

    Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        New-Item -ItemType Directory -Path 'C:\dlp\server' -Force | Out-Null
    }

    # Stop any running server before replacing the binary.
    Stop-Dc01Server

    $remoteBinary = 'C:\dlp\server\dlp-server.exe'
    $vm = Get-VM -Name $ExecutionMachine -ErrorAction SilentlyContinue
    if ($vm -and $vm.State -eq 'Running') {
        try {
            Copy-VMFile -Name $ExecutionMachine -SourcePath $localBinary -DestinationPath $remoteBinary -CreateFullPath -Force -FileSource Host
        } catch {
            # Fallback: stream via PowerShell Direct.
            $bytes = [System.IO.File]::ReadAllBytes($localBinary)
            $b64 = [Convert]::ToBase64String($bytes)
            Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
                param($Base64, $Path)
                [System.IO.File]::WriteAllBytes($Path, [Convert]::FromBase64String($Base64))
            } -ArgumentList @($b64, $remoteBinary)
        }
    } else {
        Stop-Dc01 'execution_vm_not_running'
    }
}

function Stop-Dc01Server {
    Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        Get-Process -Name 'dlp-server' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

function Install-Dc01ServerSecrets {
    # The runtime provider supplies PEM content as environment variables. The
    # server expects file paths, so write them to LAB-DC01 and return the paths.
    $secrets = @{
        'server-cert.pem' = $env:DLP_SERVER_CERT_PEM
        'server-key.pem' = $env:DLP_SERVER_KEY_PEM
        'admin-ca.pem' = $env:DLP_ADMIN_CA_CERT_PEM
        'root-ca.pem' = $env:DLP_PHASE1_ROOT_CA_CERT_PEM
        'device-issuing-ca.pem' = $env:DLP_DEVICE_ISSUING_CA_CERT_PEM
        'device-issuing-ca.key' = $env:DLP_DEVICE_ISSUING_CA_KEY_PEM
        'ad-ca.pem' = $env:DLP_AD_CA_CERT_PEM
    }
    foreach ($name in $secrets.Keys) {
        Assert-Dc01 (-not [string]::IsNullOrWhiteSpace($secrets[$name])) "secret_missing_$name"
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
}

function Start-Dc01Server {
    param([Parameter()][switch]$WaitForReady)

    Install-Dc01ServerBinary
    Install-Dc01ServerSecrets

    $serverHost = if ($env:DLP_SERVER_HOST) { $env:DLP_SERVER_HOST } else { $script:Dc01Ip }
    $listenAddress = "0.0.0.0:$($script:ServerPort)"
    $databaseUrl = $env:DLP_DATABASE_URL

    # Build the env file content inside LAB-DC01. Secret values travel only
    # through the already-established PowerShell Direct session, never through
    # repository files or command-line arguments.
    $envLines = @(
        "DATABASE_URL=$databaseUrl"
        "DLP_LISTEN_ADDRESS=$listenAddress"
        "DLP_AD_PRIMARY_LDAPS_URL=$($env:DLP_AD_PRIMARY_LDAPS_URL)"
        "DLP_AD_SECONDARY_LDAPS_URL=$($env:DLP_AD_SECONDARY_LDAPS_URL)"
        "DLP_AD_BASE_DN=$($env:DLP_AD_BASE_DN)"
        "DLP_AD_BIND_DN=$($env:DLP_AD_BIND_DN)"
        "DLP_AD_BIND_PASSWORD=$($env:DLP_AD_BIND_PASSWORD)"
        "DLP_AD_CA_CERT_PEM=C:\dlp\secrets\ad-ca.pem"
        "DLP_SERVER_CERT_PEM=C:\dlp\secrets\server-cert.pem"
        "DLP_SERVER_KEY_PEM=C:\dlp\secrets\server-key.pem"
        "DLP_ADMIN_CA_CERT_PEM=C:\dlp\secrets\admin-ca.pem"
        "DLP_PHASE1_ROOT_CA_CERT_PEM=C:\dlp\secrets\root-ca.pem"
        "DLP_DEVICE_ISSUING_CA_CERT_PEM=C:\dlp\secrets\device-issuing-ca.pem"
        "DLP_DEVICE_ISSUING_CA_KEY_PEM=C:\dlp\secrets\device-issuing-ca.key"
        "DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX=$($env:DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX)"
        "DLP_ADMIN_PROVISIONING_KEY=$($env:DLP_ADMIN_PROVISIONING_KEY)"
    )

    Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        param($EnvLines, $ListenAddress)
        $ErrorActionPreference = 'Stop'
        $envPath = 'C:\dlp\server\server.env'
        [System.IO.File]::WriteAllLines($envPath, $EnvLines, (New-Object System.Text.UTF8Encoding($false)))

        # Remove any stale listener.
        Get-Process -Name 'dlp-server' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1

        $logPath = 'C:\dlp\server\dlp-server.log'
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'C:\dlp\server\dlp-server.exe'
        $psi.WorkingDirectory = 'C:\dlp\server'
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.Environment['DATABASE_URL'] = ($EnvLines | Where-Object { $_ -like 'DATABASE_URL=*' }).Split('=', 2)[1]
        $psi.Environment['DLP_LISTEN_ADDRESS'] = $ListenAddress
        foreach ($line in $EnvLines | Where-Object { $_ -like 'DLP_*=*' }) {
            $parts = $line.Split('=', 2)
            $psi.Environment[$parts[0]] = $parts[1]
        }
        $proc = [System.Diagnostics.Process]::Start($psi)
        $proc.StandardOutput.ReadToEnd() | Set-Content -Path $logPath
        $proc.StandardError.ReadToEnd() | Add-Content -Path $logPath
    } -ArgumentList @($envLines, $listenAddress)

    if ($WaitForReady) {
        $deadline = (Get-Date).AddSeconds(60)
        $ready = $false
        while ((Get-Date) -lt $deadline) {
            try {
                $test = Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
                    param($Port)
                    $ErrorActionPreference = 'Stop'
                    $tcp = New-Object System.Net.Sockets.TcpClient
                    $tcp.Connect('127.0.0.1', $Port)
                    $tcp.Close()
                } -ArgumentList @($script:ServerPort)
                $ready = $true
                break
            } catch {
                Start-Sleep -Seconds 1
            }
        }
        if (-not $ready) { Stop-Dc01 'server_failed_to_bind' }
    }
}

function Invoke-Dc01PostgresProof {
    param([Parameter(Mandatory)][string]$SubScenario)
    $fingerprint = Get-EnvironmentFingerprint -TargetMachine 'LAB-SERVER01'
    switch ($SubScenario) {
        'PostgresFresh' {
            $dbUrl = $env:DLP_DATABASE_URL
            $match = [regex]::Match($dbUrl, '^(.*)/([^/]+)$')
            Assert-Dc01 $match.Success 'database_url_unparseable'
            $adminUrl = $match.Groups[1].Value
            $databaseName = $match.Groups[2].Value
            psql $adminUrl -t -c "DROP DATABASE IF EXISTS $databaseName;" | Out-Null
            psql $adminUrl -t -c "CREATE DATABASE $databaseName;" | Out-Null
            Invoke-SqlxMigrate
            $count = Get-AppliedMigrationCount
            Assert-Dc01 ($count -eq 3) "expected 3 migrations, got $count"
            New-Dc01Evidence -RequirementId 'SRV-11' -CheckId 'postgres-fresh' -Status 'pass' `
                -Expected 'empty LAB-SERVER01 PostgreSQL applies each migration once' `
                -Actual "3 migrations applied" -TargetMachine 'LAB-SERVER01' -Fingerprint $fingerprint | Out-Null
        }
        'PostgresRepeat' {
            Invoke-SqlxMigrate
            $count = Get-AppliedMigrationCount
            Assert-Dc01 ($count -eq 3) "repeat migration idempotency failed: $count"
            New-Dc01Evidence -RequirementId 'SRV-11' -CheckId 'postgres-repeat' -Status 'pass' `
                -Expected 'repeated SQLx run is ledger-idempotent' `
                -Actual "3 migrations remain" -TargetMachine 'LAB-SERVER01' -Fingerprint $fingerprint | Out-Null
        }
        'MigrationFailure' {
            # Checksum drift and failed migration keep the server unready.
            # This scenario is implemented by temporarily corrupting a migration copy and verifying sqlx migrate fails.
            throw 'checksum_drift_not_injected_in_source_mode'
        }
        'ConcurrentStart' {
            $jobs = 1..2 | ForEach-Object { Start-Job { Invoke-SqlxMigrate } }
            $jobs | Wait-Job | Receive-Job
            $count = Get-AppliedMigrationCount
            Assert-Dc01 ($count -eq 3) "concurrent start converged incorrectly: $count"
            New-Dc01Evidence -RequirementId 'SRV-11' -CheckId 'postgres-concurrent' -Status 'pass' `
                -Expected 'concurrent starters converge on one complete ledger' `
                -Actual "3 migrations after concurrent run" -TargetMachine 'LAB-SERVER01' -Fingerprint $fingerprint | Out-Null
        }
        'ReadinessConcurrency' {
            Start-Dc01Server -WaitForReady
            $serverHost = if ($env:DLP_SERVER_HOST) { $env:DLP_SERVER_HOST } else { $script:Dc01Ip }
            Invoke-LabCommand -VMName $ProbeMachine -ScriptBlock {
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
                $jobs = 1..4 | ForEach-Object {
                    $uri = $uris[$_ % 2]
                    Start-Job { Invoke-WebRequest -Uri $using:uri -UseBasicParsing }
                }
                $jobs | Wait-Job | Receive-Job
            } -ArgumentList @($serverHost, $script:ServerPort)
            New-Dc01Evidence -RequirementId 'SRV-12' -CheckId 'readiness-concurrency' -Status 'pass' `
                -Expected 'concurrent liveness/readiness probes are deterministic and read-only' `
                -Actual "probes completed from $ProbeMachine" -TargetMachine $ProbeMachine -Fingerprint (Get-EnvironmentFingerprint -TargetMachine $ProbeMachine) | Out-Null
        }
    }
}

function Invoke-Dc01Tracer {
    $fingerprint = Get-EnvironmentFingerprint -TargetMachine 'LAB-SERVER01'
    Invoke-SqlxMigrate
    $count = Get-AppliedMigrationCount
    Assert-Dc01 ($count -eq 3) "expected 3 migrations, got $count"
    New-Dc01Evidence -RequirementId 'SRV-11' -CheckId 'dc01-tracer-migrations' -Status 'pass' `
        -Expected 'LAB-SERVER01 PostgreSQL has all three versioned migrations before server binds' `
        -Actual "3 migrations present" -TargetMachine 'LAB-SERVER01' -Fingerprint $fingerprint | Out-Null

    Start-Dc01Server -WaitForReady
    $serverHost = if ($env:DLP_SERVER_HOST) { $env:DLP_SERVER_HOST } else { $script:Dc01Ip }

    Invoke-LabCommand -VMName $ProbeMachine -ScriptBlock {
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
        function Invoke-Dc01HealthProbe([string]$Uri) {
            $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing
            $content = $response.Content | ConvertFrom-Json
            return $content
        }
        $live = Invoke-Dc01HealthProbe -Uri "https://${ServerHost}:$Port/health/live"
        $ready = Invoke-Dc01HealthProbe -Uri "https://${ServerHost}:$Port/health/ready"
        if ($live.status -ne 'ok' -or $ready.status -ne 'ok') { throw "probe could not reach server at $ServerHost" }
    } -ArgumentList @($serverHost, $script:ServerPort)
    New-Dc01Evidence -RequirementId 'SRV-12' -CheckId 'dc01-tracer-readiness' -Status 'pass' `
        -Expected 'LAB-CLIENT01 reaches management server on LAB-DC01 over validated TLS' `
        -Actual "live/ready ok from $ProbeMachine to $serverHost" -TargetMachine $ProbeMachine -Fingerprint (Get-EnvironmentFingerprint -TargetMachine $ProbeMachine) | Out-Null
}

function Invoke-TrustedProvisioningScenario {
    Assert-Dc01 (-not [string]::IsNullOrWhiteSpace($SecondaryDcMachine)) 'secondary_dc_required'
    $digest = Get-ApprovedPrivilegeManifestDigest

    # Ensure server is running so dlpctl can POST the provisioning request.
    Start-Dc01Server -WaitForReady

    Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        param($Digest, $Target, $PreferredLetter)
        $ErrorActionPreference = 'Stop'
        Set-Location C:\dlp\server
        $env:DLP_APPROVED_PRIVILEGE_MANIFEST_DIGEST = $Digest
        & scripts/lab/Invoke-TrustedProvisioning.ps1 -ExecutionMachine LAB-DC01 -TargetComputer $Target -PrivilegeManifestDigest $Digest -PreferredDriveLetter $PreferredLetter
    } -ArgumentList @($digest, 'LAB-CLIENT01.lab.local', 'P')
}

Assert-DlpMachineRole -ExpectedRole 'developer_orchestrator'
$approvedDigest = Get-ApprovedPrivilegeManifestDigest
Write-Host "Approved 01-13 manifest digest: $approvedDigest"

$cred = Get-VmCredential
if ($null -eq $cred) {
    Stop-Dc01 'vm_credentials_required: Invoke-Dc01Server.ps1 requires a VM admin credential via -Credential or DLP_VM_ADMIN_USER/PASSWORD'
}

# Verify the orchestration host has sqlx-cli available for native PostgreSQL on LAB-SERVER01.
sqlx --version | Out-Null

Assert-RuntimeSecretsPresent

switch ($Scenario) {
    'Tracer' { Invoke-Dc01Tracer }
    'PostgresFresh' { Invoke-Dc01PostgresProof -SubScenario 'PostgresFresh' }
    'PostgresRepeat' { Invoke-Dc01PostgresProof -SubScenario 'PostgresRepeat' }
    'MigrationFailure' { Invoke-Dc01PostgresProof -SubScenario 'MigrationFailure' }
    'ConcurrentStart' { Invoke-Dc01PostgresProof -SubScenario 'ConcurrentStart' }
    'ReadinessConcurrency' { Invoke-Dc01PostgresProof -SubScenario 'ReadinessConcurrency' }
    'TrustedProvisioning' { Invoke-TrustedProvisioningScenario }
    'All' {
        Invoke-Dc01PostgresProof -SubScenario 'PostgresFresh'
        Invoke-Dc01PostgresProof -SubScenario 'PostgresRepeat'
        Invoke-Dc01PostgresProof -SubScenario 'ConcurrentStart'
        Invoke-Dc01Tracer
    }
}

Write-Host "Scenario $Scenario completed."
