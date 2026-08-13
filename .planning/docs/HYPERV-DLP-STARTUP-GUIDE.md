# DLP Lab Cold-Start and Service Startup Walkthrough

Step-by-step PowerShell commands for booting the Phase 1 DLP lab environment on Hyper-V VMs and bringing up the PostgreSQL database, management server, and endpoint agent service.

> **Lab topology:**
> - `hungdinh-lt` — developer orchestration host (where you run these commands).
> - `LAB-SERVER01` (`192.168.50.12`) — native PostgreSQL database server.
> - `LAB-DC01` (`192.168.50.10`) — management server / primary directory server.
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

```powershell
$env:DLP_VM_ADMIN_USER     = 'labadmin'
$env:DLP_VM_ADMIN_PASSWORD = '***from-runtime-provider***'
$env:DLP_DATABASE_URL      = 'postgres://dlp_server:***@192.168.50.12:5432/dlp'
$env:DLP_SERVER01_ADMIN_PASSWORD = '***from-runtime-provider***'

# Server runtime secrets (PEM content as multi-line strings)
$env:DLP_SERVER_CERT_PEM  = '-----BEGIN CERTIFICATE-----...'
$env:DLP_SERVER_KEY_PEM   = '-----BEGIN PRIVATE KEY-----...'
# ... remaining secrets per Invoke-Dc01Server.ps1
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

The PostgreSQL service on `LAB-SERVER01` should start automatically, but verify it.

```powershell
$cred = Get-Credential -Message "LAB-SERVER01 admin credential"

Invoke-Command -VMName 'LAB-SERVER01' -Credential $cred -ScriptBlock {
    $svc = Get-Service -Name 'postgresql*' -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Running') {
        Start-Service -Name $svc.Name
    }
    Write-Output (Get-Service -Name $svc.Name | Select-Object Name, Status)
}
```

Run migrations from `hungdinh-lt`:

```powershell
$env:DATABASE_URL = $env:DLP_DATABASE_URL
sqlx migrate run --source migrations/

# Verify
psql "$env:DLP_DATABASE_URL" -c "SELECT COUNT(*) FROM _sqlx_migrations;"
```

Expected result after Phase 1 migrations: `3`.

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

## 8. Manage the Endpoint Agent Service on LAB-CLIENT01

### 8.1 Check service state

```powershell
Invoke-Command -VMName 'LAB-CLIENT01' -Credential $cred -ScriptBlock {
    $svc = Get-Service -Name 'dlp-agent' -ErrorAction SilentlyContinue
    if ($svc) {
        [PSCustomObject]@{
            Name      = $svc.Name
            Status    = $svc.Status.ToString()
            StartType = (Get-CimInstance Win32_Service -Filter "Name='dlp-agent'").StartMode
        }
    } else {
        Write-Output 'dlp-agent service is not installed'
    }
}
```

### 8.2 Install the service

```powershell
Invoke-Command -VMName 'LAB-CLIENT01' -Credential $cred -ScriptBlock {
    $binary = 'C:/Program Files/DLP/dlp-windows-service.exe'
    if (-not (Test-Path -LiteralPath $binary)) { throw 'agent_binary_missing' }
    New-Service -Name 'dlp-agent' -BinaryPathName "`"$binary`"" -DisplayName 'DLP Agent' -StartupType Automatic | Out-Null
}
```

### 8.3 Start, stop, and restart

```powershell
# Start
Invoke-Command -VMName 'LAB-CLIENT01' -Credential $cred -ScriptBlock { Start-Service -Name 'dlp-agent' }

# Stop
Invoke-Command -VMName 'LAB-CLIENT01' -Credential $cred -ScriptBlock { Stop-Service -Name 'dlp-agent' -Force }

# Restart
Invoke-Command -VMName 'LAB-CLIENT01' -Credential $cred -ScriptBlock { Restart-Service -Name 'dlp-agent' -Force }
```

### 8.4 Force-kill the agent process

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
| `sqlx migrate` fails | Verify `$env:DLP_DATABASE_URL` and PostgreSQL service state on `LAB-SERVER01`. |
| `Invoke-Dc01Server.ps1` fails with `vm_credentials_required` | Set `$env:DLP_VM_ADMIN_USER`/`PASSWORD` or pass `-Credential`. |
| `dlp-server` port not reachable from `LAB-CLIENT01` | Check firewall rule on `LAB-DC01`; verify VM network profile is Domain/Private. |
| `dlp-agent` service fails to start | Check `C:\ProgramData\DLP\logs`, verify WinFsp is installed, verify DPAPI identity. |
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

# Start management server with tracer
.\scripts\lab\Invoke-Dc01Server.ps1 -CallerMachine hungdinh-lt -ExecutionMachine LAB-DC01 -ProbeMachine LAB-CLIENT01 -SecretProvider Runtime -Scenario Tracer -Credential $cred

# Start agent service
Invoke-Command -VMName 'LAB-CLIENT01' -Credential $cred -ScriptBlock { Start-Service -Name 'dlp-agent' }

# Restart agent service
Invoke-Command -VMName 'LAB-CLIENT01' -Credential $cred -ScriptBlock { Restart-Service -Name 'dlp-agent' -Force }

# Health probe from endpoint
Invoke-Command -VMName 'LAB-CLIENT01' -Credential $cred -ScriptBlock {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    Invoke-RestMethod -Uri 'https://LAB-DC01:8443/health/ready' -TimeoutSec 30
}
```

---

## Related Docs

- `.planning/docs/HYPERV-VM-START-GUIDE.md` — generic Hyper-V VM start/cold-start reference.
- `.planning/docs/LAB-SERVER01-SETUP.md` — PostgreSQL setup on `LAB-SERVER01`.
- `scripts/lab/Invoke-Dc01Server.ps1` — management-server orchestration.
- `scripts/lab/Invoke-Phase1EnvironmentReconcile.ps1` — developer-host cleanup.
- `tests/windows/Invoke-AgentServiceSmoke.ps1` — endpoint agent smoke tests.
- `.planning/STATE.md` — current lab environment status.
- `.planning/WINDOWS.md` — broken-windows ledger (open stubs / unrun verification).
