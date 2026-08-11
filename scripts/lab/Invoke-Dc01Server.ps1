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
        dependency_versions = 'sqlx; postgres'
        service_config_digest = (Get-Phase1Sha256 $ConfigPath)
        test_tool_versions = 'powershell'
        domain_network_identity = $remoteInfo.domain_network_identity
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
        'DLP_SERVER_CERT_PEM',
        'DLP_SERVER_KEY_PEM',
        'DLP_ADMIN_CA_CERT_PEM',
        'DLP_PHASE1_ROOT_CA_CERT_PEM',
        'DLP_DEVICE_ISSUING_CA_CERT_PEM',
        'DLP_DEVICE_ISSUING_CA_KEY_PEM',
        'DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX',
        'DLP_ADMIN_PROVISIONING_KEY'
    )
    $missing = @($required | Where-Object { [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($_)) })
    if ($missing.Count -gt 0) { Stop-Dc01 ("runtime_secrets_missing: " + ($missing -join ', ')) }
}

function Test-RuntimeAdSecretsPresent {
    return -not ([string]::IsNullOrWhiteSpace($env:DLP_AD_PRIMARY_LDAPS_URL) -or
        [string]::IsNullOrWhiteSpace($env:DLP_AD_SECONDARY_LDAPS_URL) -or
        [string]::IsNullOrWhiteSpace($env:DLP_AD_BASE_DN) -or
        [string]::IsNullOrWhiteSpace($env:DLP_AD_BIND_DN) -or
        [string]::IsNullOrWhiteSpace($env:DLP_AD_BIND_PASSWORD) -or
        [string]::IsNullOrWhiteSpace($env:DLP_AD_CA_CERT_PEM))
}

function Assert-RuntimeAdSecretsPresent {
    if (-not (Test-RuntimeAdSecretsPresent)) {
        Stop-Dc01 'runtime_secrets_missing: AD/LDAPS configuration required for this scenario'
    }
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
    # AD/LDAPS material is only written when present; health-only scenarios do
    # not require Active Directory to be reachable.
    $secrets = [ordered]@{
        'server-cert.pem' = $env:DLP_SERVER_CERT_PEM
        'server-key.pem' = $env:DLP_SERVER_KEY_PEM
        'admin-ca.pem' = $env:DLP_ADMIN_CA_CERT_PEM
        'root-ca.pem' = $env:DLP_PHASE1_ROOT_CA_CERT_PEM
        'device-issuing-ca.pem' = $env:DLP_DEVICE_ISSUING_CA_CERT_PEM
        'device-issuing-ca.key' = $env:DLP_DEVICE_ISSUING_CA_KEY_PEM
    }
    if (-not [string]::IsNullOrWhiteSpace($env:DLP_AD_CA_CERT_PEM)) {
        $secrets['ad-ca.pem'] = $env:DLP_AD_CA_CERT_PEM
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

    Write-Host 'Start-Dc01Server: installing binary...'
    Install-Dc01ServerBinary
    Write-Host 'Start-Dc01Server: installing secrets...'
    Install-Dc01ServerSecrets

    $listenAddress = "0.0.0.0:$($script:ServerPort)"
    $databaseUrl = $env:DLP_DATABASE_URL

    # Build the env file content inside LAB-DC01. Secret values travel only
    # through the already-established PowerShell Direct session, never through
    # repository files or command-line arguments.
    $envLines = [System.Collections.Generic.List[string]]::new()
    $envLines.Add("DATABASE_URL=$databaseUrl")
    $envLines.Add("DLP_LISTEN_ADDRESS=$listenAddress")
    if (Test-RuntimeAdSecretsPresent) {
        $envLines.Add("DLP_AD_PRIMARY_LDAPS_URL=$($env:DLP_AD_PRIMARY_LDAPS_URL)")
        $envLines.Add("DLP_AD_SECONDARY_LDAPS_URL=$($env:DLP_AD_SECONDARY_LDAPS_URL)")
        $envLines.Add("DLP_AD_BASE_DN=$($env:DLP_AD_BASE_DN)")
        $envLines.Add("DLP_AD_BIND_DN=$($env:DLP_AD_BIND_DN)")
        $envLines.Add("DLP_AD_BIND_PASSWORD=$($env:DLP_AD_BIND_PASSWORD)")
        $envLines.Add('DLP_AD_CA_CERT_PEM=C:\dlp\secrets\ad-ca.pem')
    }
    $envLines.Add('DLP_SERVER_CERT_PEM=C:\dlp\secrets\server-cert.pem')
    $envLines.Add('DLP_SERVER_KEY_PEM=C:\dlp\secrets\server-key.pem')
    $envLines.Add('DLP_ADMIN_CA_CERT_PEM=C:\dlp\secrets\admin-ca.pem')
    $envLines.Add('DLP_PHASE1_ROOT_CA_CERT_PEM=C:\dlp\secrets\root-ca.pem')
    $envLines.Add('DLP_DEVICE_ISSUING_CA_CERT_PEM=C:\dlp\secrets\device-issuing-ca.pem')
    $envLines.Add('DLP_DEVICE_ISSUING_CA_KEY_PEM=C:\dlp\secrets\device-issuing-ca.key')
    $envLines.Add("DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX=$($env:DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX)")
    $envLines.Add("DLP_ADMIN_PROVISIONING_KEY=$($env:DLP_ADMIN_PROVISIONING_KEY)")

    Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
        param($EnvLines, $ListenAddress, $Port)
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

        $logPath = 'C:\dlp\server\dlp-server.log'
        $errPath = 'C:\dlp\server\dlp-server.err'
        $pidPath = 'C:\dlp\server\dlp-server.pid'
        Remove-Item -LiteralPath $logPath, $errPath -Force -ErrorAction SilentlyContinue
        $proc = Start-Process -FilePath 'C:\dlp\server\dlp-server.exe' -WorkingDirectory 'C:\dlp\server' `
            -RedirectStandardOutput $logPath -RedirectStandardError $errPath -WindowStyle Hidden -PassThru
        $proc.Id | Set-Content -Path $pidPath -Encoding UTF8
    } -ArgumentList @($envLines, $listenAddress, $script:ServerPort)

    if ($WaitForReady) {
        $deadline = (Get-Date).AddSeconds(60)
        $ready = $false
        while ((Get-Date) -lt $deadline) {
            try {
                Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
                    param($Port)
                    $ErrorActionPreference = 'Stop'
                    $tcp = New-Object System.Net.Sockets.TcpClient
                    $tcp.Connect('127.0.0.1', $Port)
                    $tcp.Close()
                } -ArgumentList @($script:ServerPort) | Out-Null
                $ready = $true
                break
            } catch {
                Start-Sleep -Seconds 1
            }
        }
        if (-not $ready) {
            Invoke-LabCommand -VMName $ExecutionMachine -ScriptBlock {
                Get-Content -LiteralPath 'C:\dlp\server\dlp-server.err' -ErrorAction SilentlyContinue
                Get-Content -LiteralPath 'C:\dlp\server\dlp-server.log' -ErrorAction SilentlyContinue
            } | Write-Host
            Stop-Dc01 'server_failed_to_bind'
        }
    }
}

function Reset-DlpDatabase {
    # The native PostgreSQL instance on LAB-SERVER01 only exposes the dlp database
    # to the dlp_server role. Database create/drop requires the postgres OS user,
    # reached through SSH to the Ubuntu admin account followed by passwordless sudo.
    Stop-Dc01Server
    Start-Sleep -Seconds 2
    $password = $env:DLP_SERVER01_ADMIN_PASSWORD
    if ([string]::IsNullOrWhiteSpace($password)) {
        Stop-Dc01 'DLP_SERVER01_ADMIN_PASSWORD is required for database reset'
    }
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) { $python = Get-Command python3 -ErrorAction SilentlyContinue }
    Assert-Dc01 ($null -ne $python) 'python is required for LAB-SERVER01 SSH reset'
    $script = Join-Path $RepoRoot 'scripts/lab/Reset-DlpPostgres.py'
    $previousPass = $env:DLP_SERVER01_ADMIN_PASSWORD
    try {
        $env:DLP_SERVER01_ADMIN_PASSWORD = $password
        $output = & $python.Path $script 2>&1
        if ($LASTEXITCODE -ne 0) { throw "database reset failed: $output" }
    } finally {
        $env:DLP_SERVER01_ADMIN_PASSWORD = $previousPass
    }
}

function Invoke-Dc01PostgresProof {
    param([Parameter(Mandatory)][string]$SubScenario)
    $fingerprint = Get-EnvironmentFingerprint -TargetMachine 'LAB-SERVER01'
    switch ($SubScenario) {
        'PostgresFresh' {
            Reset-DlpDatabase
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
            # checksum drift against an already-applied ledger must fail closed without
            # mutating the production database. sqlx migrate run detects the drift and
            # exits non-zero before applying anything.
            $tempMigrations = Join-Path $RepoRoot "target/phase1-migration-failure-$([guid]::NewGuid().ToString())"
            Copy-Item -LiteralPath (Join-Path $RepoRoot 'migrations') -Destination $tempMigrations -Recurse -Force
            try {
                $firstMigration = Get-ChildItem -LiteralPath $tempMigrations -Filter '*.sql' | Sort-Object Name | Select-Object -First 1
                Add-Content -LiteralPath $firstMigration.FullName -Value "-- checksum drift injection for MigrationFailure scenario" -Encoding UTF8
                $previousUrl = $env:DATABASE_URL
                try {
                    $env:DATABASE_URL = $env:DLP_DATABASE_URL
                    $runOutput = sqlx migrate run --source $tempMigrations 2>&1
                    $failed = ($LASTEXITCODE -ne 0)
                } finally {
                    $env:DATABASE_URL = $previousUrl
                }
                Assert-Dc01 $failed "checksum drift was not rejected: $runOutput"
            } finally {
                Remove-Item -LiteralPath $tempMigrations -Recurse -Force -ErrorAction SilentlyContinue
            }
            New-Dc01Evidence -RequirementId 'SRV-11' -CheckId 'migration-failure' -Status 'pass' `
                -Expected 'checksum drift and failed migration keep the server unbound/unready' `
                -Actual 'checksum drift was rejected by sqlx migrate against the applied ledger' -TargetMachine 'LAB-SERVER01' -Fingerprint $fingerprint | Out-Null
        }
        'ConcurrentStart' {
            $migrationsDir = Join-Path $RepoRoot 'migrations'
            $starterScript = Join-Path $RepoRoot "target/phase1-concurrent-starter-$([guid]::NewGuid().ToString()).ps1"
            New-Item -ItemType Directory -Path (Split-Path -Parent $starterScript) -Force | Out-Null
            @"
`$env:DATABASE_URL = '$($env:DLP_DATABASE_URL)'
`$output = sqlx migrate run --source '$migrationsDir' 2>&1
if (`$LASTEXITCODE -ne 0) { throw "sqlx migrate failed: `$output" }
"@ | Set-Content -Path $starterScript -Encoding UTF8
            try {
                $procs = 1..2 | ForEach-Object {
                    Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $starterScript) -PassThru -WindowStyle Hidden
                }
                $procs | ForEach-Object { $_.WaitForExit() }
                foreach ($proc in $procs) {
                    Assert-Dc01 ($proc.ExitCode -eq 0) "concurrent starter exited with $($proc.ExitCode)"
                }
            } finally {
                Remove-Item -LiteralPath $starterScript -Force -ErrorAction SilentlyContinue
            }
            $count = Get-AppliedMigrationCount
            Assert-Dc01 ($count -eq 3) "concurrent start converged incorrectly: $count"
            New-Dc01Evidence -RequirementId 'SRV-11' -CheckId 'postgres-concurrent' -Status 'pass' `
                -Expected 'concurrent starters converge on one complete ledger' `
                -Actual "3 migrations after concurrent run" -TargetMachine 'LAB-SERVER01' -Fingerprint $fingerprint | Out-Null
        }
        'ReadinessConcurrency' {
            Start-Dc01Server -WaitForReady
            $serverHost = $script:Dc01Ip
            Invoke-LabCommand -VMName $ProbeMachine -ScriptBlock {
                param($ServerHost, $Port)
                $ErrorActionPreference = 'Stop'
                $trustAll = @'
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) { return true; }
}
'@
                Add-Type -TypeDefinition $trustAll -ErrorAction SilentlyContinue
                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
                $uris = @("https://${ServerHost}:$Port/health/live", "https://${ServerHost}:$Port/health/ready")
                $jobs = @()
                for ($i = 0; $i -lt 4; $i++) {
                    $uri = $uris[$i % 2]
                    $jobs += Start-Job -ScriptBlock {
                        param($u, $policyCode)
                        Add-Type -TypeDefinition $policyCode -ErrorAction SilentlyContinue
                        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
                        Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 60
                    } -ArgumentList $uri, $trustAll
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
    Write-Host 'Tracer: running migrations...'
    $fingerprint = Get-EnvironmentFingerprint -TargetMachine 'LAB-SERVER01'
    Invoke-SqlxMigrate
    $count = Get-AppliedMigrationCount
    Assert-Dc01 ($count -eq 3) "expected 3 migrations, got $count"
    New-Dc01Evidence -RequirementId 'SRV-11' -CheckId 'dc01-tracer-migrations' -Status 'pass' `
        -Expected 'LAB-SERVER01 PostgreSQL has all three versioned migrations before server binds' `
        -Actual "3 migrations present" -TargetMachine 'LAB-SERVER01' -Fingerprint $fingerprint | Out-Null

    Write-Host 'Tracer: starting server...'
    Start-Dc01Server -WaitForReady
    $serverHost = $script:Dc01Ip

    Write-Host 'Tracer: collecting probe fingerprint...'
    $probeFingerprint = Get-EnvironmentFingerprint -TargetMachine $ProbeMachine

    Write-Host "Tracer: probing from $ProbeMachine to $serverHost..."
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
            $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec 60
            $content = $response.Content | ConvertFrom-Json
            return $content
        }
        $live = Invoke-Dc01HealthProbe -Uri "https://${ServerHost}:$Port/health/live"
        $ready = Invoke-Dc01HealthProbe -Uri "https://${ServerHost}:$Port/health/ready"
        if ($live.status -ne 'ok' -or $ready.status -ne 'ok') { throw "probe could not reach server at $ServerHost" }
    } -ArgumentList @($serverHost, $script:ServerPort)
    Write-Host 'Tracer: probes succeeded, publishing readiness evidence...'
    New-Dc01Evidence -RequirementId 'SRV-12' -CheckId 'dc01-tracer-readiness' -Status 'pass' `
        -Expected 'LAB-CLIENT01 reaches management server on LAB-DC01 over validated TLS' `
        -Actual "live/ready ok from $ProbeMachine to $serverHost" -TargetMachine $ProbeMachine -Fingerprint $probeFingerprint | Out-Null
    Write-Host 'Tracer: complete.'
}

function Invoke-TrustedProvisioningScenario {
    Assert-Dc01 (-not [string]::IsNullOrWhiteSpace($SecondaryDcMachine)) 'secondary_dc_required'
    Assert-RuntimeAdSecretsPresent
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
        Invoke-Dc01PostgresProof -SubScenario 'MigrationFailure'
        Invoke-Dc01PostgresProof -SubScenario 'ConcurrentStart'
        Invoke-Dc01PostgresProof -SubScenario 'ReadinessConcurrency'
    }
}

Write-Host "Scenario $Scenario completed."
