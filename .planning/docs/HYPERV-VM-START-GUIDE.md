# Hyper-V VM Start / Cold-Start PowerShell Walkthrough

A copy-paste reference for managing Hyper-V virtual machines from PowerShell. Useful for lab cold-boot sequences, remote HV hosts, and automation scripts.

> **Scope:** Starting, stopping, and checking VM state. Does not cover VM creation, networking, or checkpoints.

---

## 1. Prerequisites

Run PowerShell as **Administrator** on a machine that has the Hyper-V management tools installed.

```powershell
# Install Hyper-V PowerShell module (Windows Server / Windows 10+ Pro/Enterprise)
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell

# Verify the module is available
Get-Module Hyper-V -ListAvailable
```

The commands below use `VMName` for the friendly VM name. You can also target a VM by `Id` (`(Get-VM).Id`) if names are not unique.

---

## 2. Discover VMs and Current State

```powershell
# List all VMs on the local Hyper-V host
Get-VM

# List a specific VM
Get-VM -Name "LAB-CLIENT01"

# Show only running VMs
Get-VM | Where-Object { $_.State -eq 'Running' }

# Show only off VMs (candidates for a cold start)
Get-VM | Where-Object { $_.State -eq 'Off' }

# Compact table of name, state, uptime, and status
Get-VM | Select-Object Name, State, Uptime, Status, @{N='CPU';E={$_.CPUUsage}}, MemoryAssigned
```

Common `State` values: `Off`, `Running`, `Saved`, `Paused`, `Starting`, `Stopping`, `Critical`.

---

## 3. Warm Start (Start a Stopped VM)

A *warm start* simply powers on a VM that is currently `Off` or `Saved`.

```powershell
# Start one VM
Start-VM -Name "LAB-CLIENT01"

# Start multiple VMs by name
Start-VM -Name "LAB-CLIENT01", "LAB-DC01"

# Start all VMs that are currently Off
Get-VM | Where-Object { $_.State -eq 'Off' } | Start-VM
```

Wait for a VM to finish booting before proceeding:

```powershell
# Wait until the VM reports Running and integration services are OK
$vmName = "LAB-CLIENT01"
Start-VM -Name $vmName
while ((Get-VM -Name $vmName).Heartbeat -notin ('OkApplicationsHealthy','OkApplicationsUnknown')) {
    Write-Host "Waiting for $vmName heartbeat..."
    Start-Sleep -Seconds 5
}
Write-Host "$vmName is up."
```

---

## 4. Cold Start (Force Off + Start)

A *cold start* is required when a VM is hung, stuck in `Saved`/`Paused`, or you want to power-cycle it as if the physical power button was pressed.

### 4.1 Graceful shutdown first

```powershell
$vmName = "LAB-CLIENT01"
Stop-VM -Name $vmName -Save
# or
Stop-VM -Name $vmName -Shutdown
```

- `-Save` — hibernates the VM to disk (fast to resume).
- `-Shutdown` — asks the guest OS to shut down cleanly via integration services. Fails if integration services are unavailable.

### 4.2 Force stop (pull the plug)

```powershell
# Hard power-off (data-loss risk for running apps)
Stop-VM -Name "LAB-CLIENT01" -TurnOff -Force

# Force-stop all running lab VMs
Get-VM | Where-Object { $_.State -eq 'Running' } | Stop-VM -TurnOff -Force
```

### 4.3 Full cold-start sequence

```powershell
$vmName = "LAB-CLIENT01"

# 1. Ensure it is off
$vm = Get-VM -Name $vmName
if ($vm.State -ne 'Off') {
    Write-Host "Force-stopping $vmName..."
    Stop-VM -Name $vmName -TurnOff -Force
}

# 2. Wait briefly for the lock files to release
Start-Sleep -Seconds 2

# 3. Start fresh
Start-VM -Name $vmName

# 4. Wait for healthy heartbeat
while ((Get-VM -Name $vmName).Heartbeat -notin ('OkApplicationsHealthy','OkApplicationsUnknown')) {
    Start-Sleep -Seconds 3
}
Write-Host "$vmName cold-started successfully."
```

---

## 5. Working with a Remote Hyper-V Host

If Hyper-V is on another machine, use `-ComputerName` with CredSSP or a cached credential. The remote host must have PowerShell remoting and Hyper-V management enabled.

```powershell
$hvHost = "HV-LAB01"
$cred   = Get-Credential -Message "Enter credentials for $hvHost"

# List VMs on the remote host
Get-VM -ComputerName $hvHost -Credential $cred

# Start a VM remotely
Start-VM -Name "LAB-CLIENT01" -ComputerName $hvHost -Credential $cred

# Cold start remotely
Stop-VM -Name "LAB-CLIENT01" -TurnOff -Force -ComputerName $hvHost -Credential $cred
Start-VM -Name "LAB-CLIENT01" -ComputerName $hvHost -Credential $cred
```

> **Note:** For `Stop-VM -Shutdown` to work remotely, the remote session usually needs CredSSP or constrained delegation so the shutdown command can reach the guest OS.

---

## 6. Batch Cold-Start a Lab Environment

Save this as `Start-Lab.ps1` and run it as Administrator.

```powershell
#Requires -RunAsAdministrator
param(
    [string]$ComputerName = $env:COMPUTERNAME,
    [string[]]$VmNames = @("LAB-DC01","LAB-SERVER01","LAB-CLIENT01"),
    [int]$BootDelaySeconds = 30,
    [switch]$Force
)

$cred = if ($ComputerName -ne $env:COMPUTERNAME) { Get-Credential -Message "Credentials for $ComputerName" } else { $null }

foreach ($name in $VmNames) {
    $vm = Get-VM -Name $name -ComputerName $ComputerName -Credential $cred -ErrorAction SilentlyContinue
    if (-not $vm) {
        Write-Warning "VM not found: $name"
        continue
    }

    if ($vm.State -eq 'Running' -and $Force) {
        Write-Host "Force-stopping $name..."
        Stop-VM -Name $name -TurnOff -Force -ComputerName $ComputerName -Credential $cred
        Start-Sleep -Seconds 2
    }
    elseif ($vm.State -eq 'Running') {
        Write-Host "$name is already running. Skipping."
        continue
    }

    Write-Host "Starting $name..."
    Start-VM -Name $name -ComputerName $ComputerName -Credential $cred

    # Wait for this VM to come up before booting the next (useful for DC-first labs)
    $timeout = (Get-Date).AddMinutes(5)
    while ((Get-VM -Name $name -ComputerName $ComputerName -Credential $cred).Heartbeat -notin ('OkApplicationsHealthy','OkApplicationsUnknown')) {
        if ((Get-Date) -gt $timeout) {
            Write-Warning "Timeout waiting for $name"
            break
        }
        Start-Sleep -Seconds 5
    }

    if ($BootDelaySeconds -gt 0) {
        Write-Host "Waiting $BootDelaySeconds`s before next VM..."
        Start-Sleep -Seconds $BootDelaySeconds
    }
}

Write-Host "Lab start sequence complete."
```

Example usage:

```powershell
.\Start-Lab.ps1 -ComputerName "HV-LAB01" -Force -BootDelaySeconds 60
```

---

## 7. Common Gotchas

| Symptom | Cause / Fix |
|---------|-------------|
| `Start-VM` fails with *access denied* | Run PowerShell as Administrator, or supply `-Credential` for remote hosts. |
| `Stop-VM -Shutdown` hangs | Guest integration services are stopped; use `-TurnOff` (data-loss risk). |
| VM stuck in `Starting` | Check `Get-VM | Select-Object Name, State, Status`; force-off and retry. |
| `Heartbeat` stays `Lost` | VM booted but integration services not running; guest OS may still be booting. |
| Remote commands fail with *CredSSP* | Enable CredSSP client/server or use a PS session with `-Authentication CredSSP`. |
| Saved-state restore is slow | Use `Stop-VM -TurnOff` then `Start-VM` for a true cold boot. |

---

## 8. Quick Reference Cheat Sheet

```powershell
# Status
Get-VM
Get-VM -Name "LAB-CLIENT01" | Select-Object *

# Warm start
Start-VM -Name "LAB-CLIENT01"

# Save state
Stop-VM -Name "LAB-CLIENT01" -Save

# Graceful shutdown
Stop-VM -Name "LAB-CLIENT01" -Shutdown

# Hard power-off
Stop-VM -Name "LAB-CLIENT01" -TurnOff -Force

# Cold start
Stop-VM -Name "LAB-CLIENT01" -TurnOff -Force; Start-Sleep 2; Start-VM -Name "LAB-CLIENT01"

# Remote
Start-VM -Name "LAB-CLIENT01" -ComputerName "HV-LAB01" -Credential (Get-Credential)
```

---

## Related Project Docs

- [README.md](README.md) — documentation front door and ownership map.
- [LAB-SETUP-GUIDE.md](LAB-SETUP-GUIDE.md) — first-time DLP lab provisioning.
- [HYPERV-DLP-STARTUP-GUIDE.md](HYPERV-DLP-STARTUP-GUIDE.md) — daily DLP service startup after the VMs are running.
- [LAB-SERVER01-SETUP.md](LAB-SERVER01-SETUP.md) — PostgreSQL host provisioning and migration verification.
- [STATE.md](../STATE.md) — current lab environment status.
