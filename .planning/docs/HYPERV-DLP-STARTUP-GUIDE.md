# DLP Lab Cold-Start and Service Startup Walkthrough

Step-by-step PowerShell commands for booting the Phase 1 DLP lab environment on Hyper-V VMs and bringing up the PostgreSQL database, management server, and endpoint agent service.

> **Lab topology:**
> - `hungdinh-lt` — developer orchestration host (where you run these commands).
> - `LAB-SERVER01` (`192.168.50.12`) — native PostgreSQL database server (Ubuntu Server; managed via SSH).
> - `LAB-DC01` (`192.168.50.10`) — management server / primary directory server (Windows; managed via PowerShell Direct/WinRM).
> - `LAB-CLIENT01` — endpoint runtime target (agent service, DPAPI, WinFsp).
> - `LAB-DC02` — secondary AD authority (used only by trusted-provisioning scenarios).

---

## 1. Prerequisites

Run PowerShell as **Administrator** on `hungdinh-lt` with the Hyper-V PowerShell module installed.

```powershell
# Install Hyper-V management tools if needed
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell

# Verify the module loads
Import-Module Hyper-V
Get-VM | Select-Object -First 5
```

Set the environment variables the lab scripts expect. Values come from your runtime secret provider; they are never committed.

For authoritative collection and creation instructions for each DLP Windows agent runtime variable, see [.planning/docs/ENV-VARS.md](ENV-VARS.md). For detailed instructions on generating or obtaining the PEM and KEY files used by the server and provisioning flows, see [.planning/docs/PEM-KEY-GUIDE.md](PEM-KEY-GUIDE.md). The lines below are a quick-reference reminder only.

```powershell
$env:DLP_VM_ADMIN_USER     = 'labadmin'
$env:DLP_VM_ADMIN_PASSWORD = '***from-runtime-provider***'
$env:DLP_DATABASE_URL      = 'postgres://dlp_server:***@192.168.50.12:5432/dlp'
$env:DLP_SERVER01_ADMIN_PASSWORD = '***from-runtime-provider***'
$env:DLP_SERVER01_SSH_USER = 'dlpadmin'   # Ubuntu account with passwordless sudo or postgres group membership

# Server runtime secrets (PEM content as multi-line strings)
$env:DLP_SERVER_CERT_PEM  = '-----BEGIN CERTIFICATE-----...'
$env:DLP_SERVER_KEY_PEM   = '-----BEGIN PRIVATE KEY-----...'
# ... remaining secrets per Invoke-Dc01Server.ps1

# Endpoint runtime secrets for LAB-CLIENT01 (required by Invoke-Client01Runtime.ps1).
# See ENV-VARS.md for how to collect or create each value.
$env:DLP_DEVICE_ID                     = 'device-id-from-runtime-provider'
$env:DLP_SERVER_URL                    = 'https://LAB-DC01:8443'
$env:DLP_ROOT_CA_PEM                   = '-----BEGIN CERTIFICATE-----...'
$env:DLP_CONFIGURATION_PUBLIC_KEY_HEX  = '0123...abcdef'   # 64 hex chars
$env:DLP_CONFIGURATION_KEY_ID          = 'phase1-config-signer'   # optional
```

---

## 2. Verify VM State

```powershell
# Show all lab VMs
Get-VM -Name 'LAB-SERVER01','LAB-DC01','LAB-CLIENT01' | Select-Object Name, State, Uptime, Status

# Expected cold-start state
Get-VM | Where-Object { $_.Name -match 'LAB-(SERVER|DC|CLIENT)' -and $_.State -ne 'Running' }
```

If any VM is `Saved` or `Paused`, decide whether you want to resume it or cold-start it.

---

## 3. Start the Lab VMs (Warm Start)

Boot order matters: database first, then directory/management server, then endpoint.

```powershell
$vms = @('LAB-SERVER01','LAB-DC01','LAB-CLIENT01')
foreach ($vm in $vms) {
    $state = (Get-VM -Name $vm).State
    if ($state -eq 'Off') {
        Write-Host "Starting $vm..."
        Start-VM -Name $vm
    }
}

# Wait for healthy heartbeats before moving on
foreach ($vm in $vms) {
    while ((Get-VM -Name $vm).Heartbeat -notin ('OkApplicationsHealthy','OkApplicationsUnknown')) {
        Write-Host "Waiting for $vm heartbeat..."
        Start-Sleep -Seconds 5
    }
    Write-Host "$vm is up."
}
```

---

## 4. Cold-Start the Whole Lab

Use this when VMs are hung, saved in a bad state, or you want a clean boot cycle.

```powershell
function Invoke-DlpLabColdStart {
    param([string[]]$VmNames = @('LAB-SERVER01','LAB-DC01','LAB-CLIENT01'))
    foreach ($vm in $VmNames) {
        $state = (Get-VM -Name $vm).State
        if ($state -ne 'Off') {
            Write-Host "Force-stopping $vm..."
            Stop-VM -Name $vm -TurnOff -Force
            Start-Sleep -Seconds 2
        }
    }
    foreach ($vm in $VmNames) {
        Write-Host "Starting $vm..."
        Start-VM -Name $vm
        while ((Get-VM -Name $vm).Heartbeat -notin ('OkApplicationsHealthy','OkApplicationsUnknown')) {
            Start-Sleep -Seconds 5
        }
        Write-Host "$vm cold-started."
    }
}

Invoke-DlpLabColdStart
```

---

## 5. Start the Database on LAB-SERVER01

`LAB-SERVER01` runs Ubuntu Server, so manage PostgreSQL over SSH rather than PowerShell Direct. Use the SSH user configured during server provisioning (see `.planning/docs/LAB-SERVER01-SETUP.md`).

### 5.1 Verify SSH connectivity

```powershell
# Interactive password authentication
ssh "${env:DLP_SERVER01_SSH_USER}@192.168.50.12" "uname -a"

# Or with a key
ssh -i "${env:USERPROFILE}\.ssh\lab-server01" "${env:DLP_SERVER01_SSH_USER}@192.168.50.12" "uname -a"
```

### 5.2 Check and start PostgreSQL

```bash
# Check service status
ssh "${env:DLP_SERVER01_SSH_USER}@192.168.50.12" "sudo systemctl status postgresql"

# Start if not running
ssh "${env:DLP_SERVER01_SSH_USER}@192.168.50.12" "sudo systemctl start postgresql"

# Enable autostart
ssh "${env:DLP_SERVER01_SSH_USER}@192.168.50.12" "sudo systemctl enable postgresql"
```

Run the same commands from PowerShell on `hungdinh-lt` by inlining the bash string:

```powershell
$serverUser = $env:DLP_SERVER01_SSH_USER
$serverIp   = '192.168.50.12'

ssh "${serverUser}@${serverIp}" "sudo systemctl is-active postgresql"
ssh "${serverUser}@${serverIp}" "sudo systemctl start postgresql"
```

### 5.3 Run SQLx migrations

Migrations are executed from the orchestration host against the live PostgreSQL instance:

```powershell
$env:DATABASE_URL = $env:DLP_DATABASE_URL
sqlx migrate run --source migrations/
```

### 5.4 Verify migrations

```powershell
# Via psql on hungdinh-lt
psql "$env:DLP_DATABASE_URL" -c "SELECT COUNT(*) FROM _sqlx_migrations;"

# Or query directly on the server
ssh "${env:DLP_SERVER01_SSH_USER}@192.168.50.12" "sudo -u postgres psql -d dlp -t -c 'SELECT COUNT(*) FROM _sqlx_migrations;'"
```

Expected result after Phase 1 migrations: `3`.

### 5.5 Cold-start the database VM specifically

If `LAB-SERVER01` is off or needs a clean boot, start it from Hyper-V and then bring PostgreSQL up:

```powershell
# From hungdinh-lt
Start-VM -Name 'LAB-SERVER01'
while ((Get-VM -Name 'LAB-SERVER01').Heartbeat -notin ('OkApplicationsHealthy','OkApplicationsUnknown')) {
    Start-Sleep -Seconds 5
}

# Wait a few seconds for the OS and SSH daemon, then start PostgreSQL
Start-Sleep -Seconds 15
ssh "${env:DLP_SERVER01_SSH_USER}@192.168.50.12" "sudo systemctl start postgresql"
ssh "${env:DLP_SERVER01_SSH_USER}@192.168.50.12" "sudo systemctl is-active postgresql"
```

---

## 6. Start the Management Server on LAB-DC01

Use the existing orchestration script. It builds the release binary, copies it to `LAB-DC01`, deploys secrets, writes `C:\dlp\server\server.env`, and starts `dlp-server.exe`.

```powershell
$cred = Get-Credential -Message "LAB-DC01 admin credential"

$repoRoot = 'C:\Users\nhdinh\dev\dleakprevention'
.\scripts\lab\Invoke-Dc01Server.ps1 `
    -CallerMachine      hungdinh-lt `
    -ExecutionMachine   LAB-DC01 `
    -ProbeMachine       LAB-CLIENT01 `
    -SecretProvider     Runtime `
    -Scenario           Tracer `
    -Credential         $cred
```

For a lighter health check without running the full tracer scenario:

```powershell
.\scripts\lab\Invoke-Dc01Server.ps1 `
    -CallerMachine      hungdinh-lt `
    -ExecutionMachine   LAB-DC01 `
    -ProbeMachine       LAB-CLIENT01 `
    -SecretProvider     Runtime `
    -Scenario           ReadinessConcurrency `
    -Credential         $cred
```

---

## 7. Verify the Management Server from LAB-CLIENT01

From `hungdinh-lt`, probe the health endpoints through `LAB-CLIENT01`.

```powershell
Invoke-Command -VMName 'LAB-CLIENT01' -Credential $cred -ScriptBlock {
    $ErrorActionPreference = 'Stop'
    $policy = @'
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) { return true; }
}
'@
    Add-Type -TypeDefinition $policy -ErrorAction SilentlyContinue
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13

    Invoke-WebRequest -Uri 'https://LAB-DC01:8443/health/live'  -UseBasicParsing -TimeoutSec 30
    Invoke-WebRequest -Uri 'https://LAB-DC01:8443/health/ready' -UseBasicParsing -TimeoutSec 30
}
```

---

> **Note:** `Invoke-Client01Runtime.ps1 -Scenario Tracer` performs the same health probes from `LAB-CLIENT01`, so the manual probe step below is optional if you run the tracer next.

## 8. Deploy and Start the Endpoint Agent Service on LAB-CLIENT01

Use the endpoint orchestration script. It builds the release binary, copies it to `LAB-CLIENT01`, deploys the root CA, writes `C:\dlp\agent\agent.env`, installs or reconfigures the `DlpWindowsService` Windows service, and starts it.

> **Enrollment token flow:** Use `-EnrollmentTokenProvider TrustedProvisioning` so `Invoke-Client01Runtime.ps1` obtains the short-lived enrollment token directly from LAB-DC01 trusted provisioning. The token is never written to disk on hungdinh-lt and is removed from the service registry after enrollment unless you add `-RetainEnrollmentToken` for troubleshooting.

### 8.1 Dry-run the deployment

```powershell
$cred = Get-Credential -Message "LAB-CLIENT01 admin credential"

$repoRoot = 'C:\Users\nhdinh\dev\dleakprevention'
Set-Location $repoRoot
.\scripts\lab\Invoke-Client01Runtime.ps1 `
    -CallerMachine    hungdinh-lt `
    -ExecutionMachine LAB-CLIENT01 `
    -ProbeMachine     LAB-DC01 `
    -SecretProvider   Runtime `
    -Scenario         ServiceInstall
```

### 8.2 Install and start the service

```powershell
.\scripts\lab\Invoke-Client01Runtime.ps1 `
    -CallerMachine    hungdinh-lt `
    -ExecutionMachine LAB-CLIENT01 `
    -ProbeMachine     LAB-DC01 `
    -SecretProvider   Runtime `
    -Scenario         ServiceInstall `
    -EnrollmentTokenProvider TrustedProvisioning `
    -Credential       $cred `
    -Apply
```

The script:

- Builds `target/release/dlp-windows-service.exe` if it is missing.
- Copies the binary to `C:\dlp\agent\dlp-windows-service.exe` on `LAB-CLIENT01`.
- Creates `C:\dlp\agent\data` and `C:\dlp\agent\cache`.
- Writes `C:\dlp\agent\agent.env` and persists the same values to the service registry `Environment` value.
- Installs or reconfigures the `DlpWindowsService` service as automatic, running as `NT AUTHORITY\SYSTEM`.
- Starts the service and verifies it reaches the `Running` state.

### 8.3 Run the endpoint tracer

The `Tracer` scenario installs the service and then probes `/health/live` and `/health/ready` on `LAB-DC01` from `LAB-CLIENT01`.

```powershell
.\scripts\lab\Invoke-Client01Runtime.ps1 `
    -CallerMachine    hungdinh-lt `
    -ExecutionMachine LAB-CLIENT01 `
    -ProbeMachine     LAB-DC01 `
    -SecretProvider   Runtime `
    -Scenario         Tracer `
    -EnrollmentTokenProvider TrustedProvisioning `
    -Credential       $cred `
    -Apply
```

### 8.4 Check service state manually

```powershell
Invoke-Command -VMName 'LAB-CLIENT01' -Credential $cred -ScriptBlock {
    $svc = Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue
    if ($svc) {
        [PSCustomObject]@{
            Name      = $svc.Name
            Status    = $svc.Status.ToString()
            StartType = (Get-CimInstance Win32_Service -Filter "Name='DlpWindowsService'").StartMode
        }
    } else {
        Write-Output 'DlpWindowsService is not installed'
    }
}
```

### 8.5 Stop, start, and restart the service

```powershell
# Stop
Invoke-Command -VMName 'LAB-CLIENT01' -Credential $cred -ScriptBlock { Stop-Service -Name 'DlpWindowsService' -Force }

# Start
Invoke-Command -VMName 'LAB-CLIENT01' -Credential $cred -ScriptBlock { Start-Service -Name 'DlpWindowsService' }

# Restart
Invoke-Command -VMName 'LAB-CLIENT01' -Credential $cred -ScriptBlock { Restart-Service -Name 'DlpWindowsService' -Force }
```

### 8.6 Force-kill the agent process

Use only when the service control manager cannot stop it.

```powershell
Invoke-Command -VMName 'LAB-CLIENT01' -Credential $cred -ScriptBlock {
    Get-Process -Name 'dlp-windows-service' -ErrorAction SilentlyContinue | Stop-Process -Force
}
```

---

## 9. Run Endpoint Service Smoke Tests

Use the existing smoke-test harness. The `ServiceRestart` scenario can run without a live enrollment endpoint.

```powershell
$env:DLP_AGENT_ENROLLMENT_TOKEN = '***from-runtime-provider***'

.\tests\windows\Invoke-AgentServiceSmoke.ps1 `
    -CallerMachine   hungdinh-lt `
    -ExecutionMachine LAB-CLIENT01 `
    -ServerMachine   LAB-DC01 `
    -SecretProvider  Runtime `
    -Scenario        ServiceRestart
```

Enrollment-dependent scenarios (`InitialEnrollmentCredential`, `ReplacementRevocation`, `ConfigurationCache`) currently stop at runtime gates when the enrollment endpoint is not reachable.

---

## 10. Full Environment Reconcile

If you need to clean the developer host after a test run:

```powershell
.\scripts\lab\Invoke-Phase1EnvironmentReconcile.ps1 `
    -ExecutionMachine hungdinh-lt `
    -ServerVm         LAB-DC01 `
    -SecondaryDcVm    LAB-DC02 `
    -EndpointVm       LAB-CLIENT01

# Actually apply cleanup (removes DLP services, directories, certs, hosts entries on hungdinh-lt)
.\scripts\lab\Invoke-Phase1EnvironmentReconcile.ps1 `
    -ExecutionMachine hungdinh-lt `
    -ServerVm         LAB-DC01 `
    -SecondaryDcVm    LAB-DC02 `
    -EndpointVm       LAB-CLIENT01 `
    -Apply
```

---

## 11. Troubleshooting Quick Reference

| Symptom | Check / Fix |
|---------|-------------|
| `Get-VM` access denied | Run PowerShell as Administrator. |
| VM stuck in `Starting` | `Stop-VM -Name <VM> -TurnOff -Force`, then `Start-VM`. |
| `sqlx migrate` fails | Verify `$env:DLP_DATABASE_URL`, SSH to `LAB-SERVER01`, and run `sudo systemctl status postgresql`. |
| Cannot SSH to `LAB-SERVER01` | Verify the VM IP, SSH key or password, and that `sshd` is installed and running. |
| `Invoke-Dc01Server.ps1` fails with `vm_credentials_required` | Set `$env:DLP_VM_ADMIN_USER`/`PASSWORD` or pass `-Credential`. |
| `Invoke-Client01Runtime.ps1` fails with `runtime_secrets_missing` | Set `DLP_DEVICE_ID`, `DLP_SERVER_URL`, `DLP_ROOT_CA_PEM`, and `DLP_CONFIGURATION_PUBLIC_KEY_HEX`. |
| `Invoke-Client01Runtime.ps1` fails with `service_failed_to_start` | Check `C:\dlp\agent\dlp-windows-service.err`, verify the env file, and confirm `DlpWindowsService` is configured. |
| `dlp-server` port not reachable from `LAB-CLIENT01` | Check firewall rule on `LAB-DC01`; verify VM network profile is Domain/Private. |
| `DlpWindowsService` service fails to start | Check `C:\dlp\agent` logs, verify WinFsp is installed, verify DPAPI identity. |
| `Invoke-AgentServiceSmoke` fails `host_service_present` | Run environment reconcile with `-Apply` on `hungdinh-lt` to remove leaked artifacts. |

---

## 12. Cheat Sheet

```powershell
# VM status
Get-VM -Name 'LAB-SERVER01','LAB-DC01','LAB-CLIENT01'

# Start VMs in order
Start-VM -Name 'LAB-SERVER01'; Start-VM -Name 'LAB-DC01'; Start-VM -Name 'LAB-CLIENT01'

# Cold start one VM
Stop-VM -Name 'LAB-DC01' -TurnOff -Force; Start-Sleep 2; Start-VM -Name 'LAB-DC01'

# Start PostgreSQL on LAB-SERVER01 via SSH
ssh "${env:DLP_SERVER01_SSH_USER}@192.168.50.12" "sudo systemctl start postgresql"

# Check migrations
psql "$env:DLP_DATABASE_URL" -c "SELECT COUNT(*) FROM _sqlx_migrations;"

# Start management server with tracer
.\scripts\lab\Invoke-Dc01Server.ps1 -CallerMachine hungdinh-lt -ExecutionMachine LAB-DC01 -ProbeMachine LAB-CLIENT01 -SecretProvider Runtime -Scenario Tracer -Credential $cred

# Deploy and start endpoint service
.\scripts\lab\Invoke-Client01Runtime.ps1 -CallerMachine hungdinh-lt -ExecutionMachine LAB-CLIENT01 -ProbeMachine LAB-DC01 -SecretProvider Runtime -Scenario Tracer -EnrollmentTokenProvider TrustedProvisioning -Credential $cred -Apply

# Stop endpoint service
Invoke-Command -VMName 'LAB-CLIENT01' -Credential $cred -ScriptBlock { Stop-Service -Name 'DlpWindowsService' -Force }

# Start endpoint service
Invoke-Command -VMName 'LAB-CLIENT01' -Credential $cred -ScriptBlock { Start-Service -Name 'DlpWindowsService' }

# Restart endpoint service
Invoke-Command -VMName 'LAB-CLIENT01' -Credential $cred -ScriptBlock { Restart-Service -Name 'DlpWindowsService' -Force }

# Health probe from endpoint
Invoke-Command -VMName 'LAB-CLIENT01' -Credential $cred -ScriptBlock {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    Invoke-RestMethod -Uri 'https://LAB-DC01:8443/health/ready' -TimeoutSec 30
}
```

---

## Related Docs

- `.planning/docs/ENV-VARS.md` — canonical reference for DLP Windows agent runtime environment variables.
- `.planning/docs/PEM-KEY-GUIDE.md` — how to obtain or generate the PEM/KEY files used by the lab.
- `.planning/docs/HYPERV-VM-START-GUIDE.md` — generic Hyper-V VM start/cold-start reference.
- `.planning/docs/LAB-SERVER01-SETUP.md` — PostgreSQL setup on `LAB-SERVER01`.
- `scripts/lab/Invoke-Dc01Server.ps1` — management-server orchestration.
- `scripts/lab/Invoke-Client01Runtime.ps1` — endpoint agent service deployment on `LAB-CLIENT01`.
- `scripts/lab/Invoke-Phase1EnvironmentReconcile.ps1` — developer-host cleanup.
- `tests/windows/Invoke-AgentServiceSmoke.ps1` — endpoint agent smoke tests.
- `.planning/STATE.md` — current lab environment status.
- `.planning/WINDOWS.md` — broken-windows ledger (open stubs / unrun verification).
