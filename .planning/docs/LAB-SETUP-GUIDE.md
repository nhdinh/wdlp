# DLP Lab Setup Guide

This guide walks through setting up the Phase 1 Windows Data Leakage Prevention (DLP) lab from scratch. It assumes the Hyper-V VMs already exist; if you need VM start/stop/cold-start commands, see [.planning/docs/HYPERV-VM-START-GUIDE.md](HYPERV-VM-START-GUIDE.md). For day-to-day boot and service startup after setup is complete, see [.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md](HYPERV-DLP-STARTUP-GUIDE.md).

> **Security note:** All secrets (certificates, private keys, passwords, enrollment tokens) are runtime-only. They must never be committed to source control. Use a password manager, HSM, or the interactive setup script to supply them.

## Lab Topology

| Machine | Role | OS | IP | Access |
|---------|------|----|-----|--------|
| `hungdinh-lt` | Developer orchestration host | Windows 10/11 Pro or Enterprise | — | PowerShell as Administrator |
| `LAB-SERVER01` | Native PostgreSQL database | Ubuntu Server LTS | `192.168.50.12` | SSH |
| `LAB-DC01` | Management server + primary AD + trusted provisioning | Windows Server | `192.168.50.10` | PowerShell Direct / WinRM |
| `LAB-DC02` | Secondary AD authority (trusted-provisioning corroboration) | Windows Server | lab subnet | PowerShell Direct / WinRM |
| `LAB-CLIENT01` | Endpoint agent runtime | Windows 10/11 Pro or Enterprise | lab subnet | PowerShell Direct / WinRM |

Network: all machines on `192.168.50.0/24` (adjust if your lab uses a different subnet). DNS resolves `lab.local` and the machine hostnames.

## 1. Prerequisites

### 1.1 Orchestration host (`hungdinh-lt`)

Install on `hungdinh-lt`:

- [Rust](https://rustup.rs/) (current stable; the repo uses edition 2021)
- [Git for Windows](https://git-scm.com/download/win)
- [OpenSSL](https://slproweb.com/products/Win32OpenSSL.html) or `openssl` via Git Bash / WSL / Chocolate
- [sqlx-cli](https://crates.io/crates/sqlx-cli) (`cargo install sqlx-cli --version 0.9.0`)
- PostgreSQL client tools (`psql`) for ad-hoc queries
- Hyper-V PowerShell module:
  ```powershell
  Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell
  ```
- Python 3 + [Paramiko](https://www.paramiko.org/) (for `Reset-DlpPostgres.py`)
  ```powershell
  python -m pip install paramiko
  ```

Clone the repository:

```powershell
Set-Location C:\Users\nhdinh\dev
# adjust to your checkout path
```

### 1.2 LAB-SERVER01 (PostgreSQL)

Install Ubuntu Server LTS and PostgreSQL from the official PostgreSQL APT repository. See [.planning/docs/LAB-SERVER01-SETUP.md](LAB-SERVER01-SETUP.md) for the exact PostgreSQL configuration, `pg_hba.conf`, and `postgresql.conf` settings.

Minimum requirements:

- PostgreSQL 18.x listening on `192.168.50.12:5432`
- Database `dlp` and role `dlp_server` with password authentication
- An OS admin account that can `sudo -u postgres` (used by `Reset-DlpPostgres.py`)

### 1.3 LAB-DC01 and LAB-DC02 (Active Directory)

- Both must be domain controllers for `lab.local`.
- LDAPS must be available on `ldaps://LAB-DC01.lab.local:636` and `ldaps://LAB-DC02.lab.local:636`.
- A service account for the DLP server to bind to AD, e.g. `CN=dlp-service,OU=Service Accounts,DC=lab,DC=local`.
- `LAB-CLIENT01` must be joined to the domain with a computer object visible from both DCs.
- AD CS or a lab CA must be exportable so you can obtain `ad-ca.pem` for LDAPS trust.

### 1.4 LAB-CLIENT01 (endpoint)

- Joined to `lab.local`.
- [WinFsp 2.1+](https://winfsp.dev/rel/) installed (required for the virtual drive).
- PowerShell remoting / PowerShell Direct enabled so `hungdinh-lt` can run remote commands.

## 2. Environment Setup

The lab uses many environment variables. The easiest way to set them is with the interactive setup script.

### 2.1 Interactive setup

```powershell
Set-Location C:\Users\nhdinh\dev\dleakprevention
.\scripts\lab\Initialize-DlpEnvironment.ps1
```

The script prompts for every variable, explains how to obtain each value, validates formats, and optionally writes the result to `config/lab.env.local`:

```powershell
.\scripts\lab\Initialize-DlpEnvironment.ps1 -OutEnvFile .\config\lab.env.local
```

### 2.2 Reload a saved environment

```powershell
.\scripts\lab\Set-DlpEnvironment.ps1 -EnvFile .\config\lab.env.local
```

### 2.3 Variable reference

For the full list of variables and how to collect or create each value, see [.planning/docs/ENV-VARS.md](ENV-VARS.md).

Key variables you must provide:

| Variable | Purpose |
|----------|---------|
| `DLP_DATABASE_URL` | PostgreSQL connection string |
| `DLP_SERVER_CERT_PEM` / `DLP_SERVER_KEY_PEM` | Management server TLS certificate and key |
| `DLP_ADMIN_CA_CERT_PEM` | CA that signs provisioning admin certs |
| `DLP_PHASE1_ROOT_CA_CERT_PEM` | Root CA that signs the server cert and is pinned by the agent |
| `DLP_DEVICE_ISSUING_CA_CERT_PEM` / `DLP_DEVICE_ISSUING_CA_KEY_PEM` | CA that issues device mTLS certs |
| `DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX` | 64-hex-char Ed25519 seed for signing config bundles |
| `DLP_AD_*` | Active Directory / LDAPS settings |
| `DLP_PROVISIONING_ADMIN_CERT_PEM` / `DLP_PROVISIONING_ADMIN_KEY_PEM` | Admin client cert/key for `dlpctl` trusted provisioning |
| `DLP_DEVICE_ID` | Stable endpoint identifier (e.g. `LAB-CLIENT01`) |
| `DLP_SERVER_URL` | Agent-facing URL of the management server |
| `DLP_ROOT_CA_PEM` | Same root CA, pinned by the agent |
| `DLP_CONFIGURATION_PUBLIC_KEY_HEX` | 64-hex-char Ed25519 public key matching the signing seed |

## 3. PKI Setup

All certificates and keys live in `C:\dlp\secrets\` on the relevant machines. For detailed OpenSSL commands, see [.planning/docs/PEM-KEY-GUIDE.md](PEM-KEY-GUIDE.md).

### 3.1 Required PKI files

| File | Machine | Purpose |
|------|---------|---------|
| `phase1-root-ca.pem` (public) | LAB-DC01, hungdinh-lt, LAB-CLIENT01 | Trust anchor for server TLS and agent pinning |
| `server-cert.pem` + `server-key.pem` | LAB-DC01 | Management server TLS listener |
| `admin-ca.pem` + `admin-ca-key.pem` | hungdinh-lt / LAB-DC01 | CA for provisioning admin certs |
| `provisioning-admin-cert.pem` + `provisioning-admin-key.pem` | hungdinh-lt / LAB-DC01 | mTLS client cert for `dlpctl` |
| `device-issuing-ca.pem` + `device-issuing-ca-key.pem` | LAB-DC01 | Issues device mTLS certs during enrollment |
| `ad-ca.pem` (public) | LAB-DC01 | Trust anchor for LDAPS to AD |

### 3.2 Generate or rotate lab PKI

Rotate the admin CA and provisioning admin certificate:

```powershell
.\scripts\lab\Rotate-DlpAdminCa.ps1 -OutputDirectory C:\dlp\secrets -Force
```

Rotate only the provisioning admin certificate (keeps the same admin CA):

```powershell
.\scripts\lab\Rotate-DlpProvisioningAdmin.ps1 -OutputDirectory C:\dlp\secrets -Force
```

### 3.3 Verify the PKI

```powershell
.\scripts\lab\Verify-DlpLabCertificates.ps1 -ServerHostname 'LAB-DC01.lab.local'
```

This checks certificate/key pairs, issuer chains, CA extensions, expiration, hostname SAN/CN, and rustls/ring compatibility.

### 3.4 Export the AD CA for LDAPS

If AD CS is deployed, run on `LAB-DC01` or export from `certlm.msc`:

```powershell
.\scripts\lab\Fetch-DC01Cert.ps1
```

Copy the exported `.cer` to `C:\dlp\secrets\ad-ca.pem` on `hungdinh-lt` and LAB-DC01.

## 4. Database Setup on LAB-SERVER01

See [.planning/docs/LAB-SERVER01-SETUP.md](LAB-SERVER01-SETUP.md) for native PostgreSQL installation.

After PostgreSQL is installed and reachable:

```powershell
$env:DATABASE_URL = $env:DLP_DATABASE_URL
sqlx migrate run --source migrations/
```

Verify:

```powershell
psql "$env:DLP_DATABASE_URL" -c "SELECT COUNT(*) FROM _sqlx_migrations;"
```

Expected result after Phase 1: `3`.

To reset the database during testing:

```powershell
$env:DLP_SERVER01_ADMIN_PASSWORD = '***from-runtime-provider***'
python .\scripts\lab\Reset-DlpPostgres.py
sqlx migrate run --source migrations/
```

## 5. Management Server Setup on LAB-DC01

The orchestration script builds `dlp-server.exe`, copies it to `LAB-DC01`, deploys secrets, writes `C:\dlp\server\server.env`, and starts the server.

```powershell
$cred = Get-Credential -Message "LAB-DC01 admin credential"

.\scripts\lab\Invoke-Dc01Server.ps1 `
    -CallerMachine    hungdinh-lt `
    -ExecutionMachine LAB-DC01 `
    -ProbeMachine     LAB-CLIENT01 `
    -SecretProvider   Runtime `
    -Scenario         Tracer `
    -Credential       $cred
```

Other scenarios:

- `PostgresFresh` — reset DB and apply migrations
- `PostgresRepeat` — verify migration idempotence
- `MigrationFailure` — verify checksum-drift rejection
- `ConcurrentStart` — verify concurrent migration runners converge
- `ReadinessConcurrency` — verify liveness/readiness probes
- `TrustedProvisioning` — obtain an enrollment token for `LAB-CLIENT01`
- `All` — run all PostgreSQL and readiness scenarios

The server listens on `https://LAB-DC01:8443`.

## 6. Enrollment and Trusted Provisioning

The recommended flow uses trusted provisioning to obtain the enrollment token automatically.

### 6.1 Prerequisites for trusted provisioning

- `DLP_PROVISIONING_ROOT_CA_PATH` (or `DLP_PROVISIONING_ROOT_CA_PEM`)
- `DLP_PROVISIONING_ADMIN_CERT_PATH` / `DLP_PROVISIONING_ADMIN_KEY_PATH`
- Approved privilege manifest digest (computed from `config/lab.phase1.example.yaml`)
- `LAB-DC02` reachable for dual-DC corroboration
- `LAB-CLIENT01` domain-joined with a computer object in AD

### 6.2 Deploy the endpoint service with automatic token acquisition

```powershell
$cred = Get-Credential -Message "LAB admin credential"

.\scripts\lab\Invoke-Client01Runtime.ps1 `
    -CallerMachine            hungdinh-lt `
    -ExecutionMachine         LAB-CLIENT01 `
    -ProbeMachine             LAB-DC01 `
    -SecretProvider           Runtime `
    -Scenario                 Tracer `
    -EnrollmentTokenProvider  TrustedProvisioning `
    -Credential               $cred `
    -Apply
```

What happens:

1. If no DPAPI credential exists, `Invoke-TrustedProvisioning.ps1` runs on `LAB-DC01`, fingerprints `LAB-CLIENT01`, and returns a short-lived enrollment token.
2. The token is written to `C:\dlp\agent\agent.env` and the service registry `Environment` value.
3. The `DlpWindowsService` service is installed/updated and started.
4. The service consumes the token, enrolls, and creates the DPAPI-protected credential at `C:\dlp\agent\data\credentials\device.dpapi`.
5. By default, the token is removed from persistent configuration after enrollment succeeds.

Use `-RetainEnrollmentToken` only for troubleshooting.

### 6.3 Manual enrollment fallback

If trusted provisioning is unavailable, set the token manually:

```powershell
$env:DLP_AGENT_ENROLLMENT_TOKEN = '***from-runtime-provider***'

.\scripts\lab\Invoke-Client01Runtime.ps1 `
    -CallerMachine    hungdinh-lt `
    -ExecutionMachine LAB-CLIENT01 `
    -ProbeMachine     LAB-DC01 `
    -SecretProvider   Runtime `
    -Scenario         ServiceInstall `
    -Credential       $cred `
    -Apply
```

### 6.4 Reset enrollment

To delete an enrollment authority from the database (for re-enrollment tests):

```powershell
.\scripts\lab\Reset-DlpEnrollment.ps1 -DeviceId 'LAB-CLIENT01.lab.local'
```

## 7. Verification

### 7.1 Service state on LAB-CLIENT01

```powershell
Invoke-Command -VMName 'LAB-CLIENT01' -Credential $cred -ScriptBlock {
    Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue |
        Select-Object Name, Status, StartType
}
```

### 7.2 Health endpoints from LAB-CLIENT01

```powershell
Invoke-Command -VMName 'LAB-CLIENT01' -Credential $cred -ScriptBlock {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    Invoke-RestMethod -Uri 'https://LAB-DC01:8443/health/live'  -TimeoutSec 30
    Invoke-RestMethod -Uri 'https://LAB-DC01:8443/health/ready' -TimeoutSec 30
}
```

### 7.3 Verify token cleanup after enrollment

```powershell
Invoke-Command -VMName 'LAB-CLIENT01' -Credential $cred -ScriptBlock {
    $envLines = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\DlpWindowsService' -Name 'Environment' -ErrorAction SilentlyContinue
    $agentEnv  = Get-Content -Path 'C:\dlp\agent\agent.env' -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        TokenPersisted   = (($envLines -like 'DLP_AGENT_ENROLLMENT_TOKEN=*').Count -gt 0) -or
                           (($agentEnv -like 'DLP_AGENT_ENROLLMENT_TOKEN=*').Count -gt 0)
        CredentialExists = Test-Path 'C:\dlp\agent\data\credentials\device.dpapi'
        ServiceStatus    = (Get-Service -Name 'DlpWindowsService' -ErrorAction SilentlyContinue).Status
    }
}
```

Expected after successful enrollment:

```text
TokenPersisted   : False
CredentialExists : True
ServiceStatus    : Running
```

### 7.4 Run endpoint smoke tests

```powershell
.\tests\windows\Invoke-AgentServiceSmoke.ps1 `
    -CallerMachine   hungdinh-lt `
    -ExecutionMachine LAB-CLIENT01 `
    -ServerMachine   LAB-DC01 `
    -SecretProvider  Runtime `
    -Scenario        ServiceRestart
```

## 8. Environment Cleanup

To clean the developer host (`hungdinh-lt`) after a test run:

```powershell
# Show what would be removed
.\scripts\lab\Invoke-Phase1EnvironmentReconcile.ps1 `
    -ExecutionMachine hungdinh-lt `
    -ServerVm         LAB-DC01 `
    -SecondaryDcVm    LAB-DC02 `
    -EndpointVm       LAB-CLIENT01

# Apply cleanup
.\scripts\lab\Invoke-Phase1EnvironmentReconcile.ps1 `
    -ExecutionMachine hungdinh-lt `
    -ServerVm         LAB-DC01 `
    -SecondaryDcVm    LAB-DC02 `
    -EndpointVm       LAB-CLIENT01 `
    -Apply
```

This removes DLP services, processes, directories, certificate trust, and hosts entries from `hungdinh-lt` only. It does not touch the VMs.

## 9. Troubleshooting

| Symptom | Check / Fix |
|---------|-------------|
| `Invoke-Dc01Server.ps1` fails with `vm_credentials_required` | Set `DLP_VM_ADMIN_USER` / `DLP_VM_ADMIN_PASSWORD` or pass `-Credential`. |
| `Invoke-Client01Runtime.ps1` fails with `runtime_secrets_missing` | Ensure `DLP_DEVICE_ID`, `DLP_SERVER_URL`, `DLP_ROOT_CA_PEM`, and `DLP_CONFIGURATION_PUBLIC_KEY_HEX` are set. For manual enrollment, also set `DLP_AGENT_ENROLLMENT_TOKEN`. |
| `service_failed_to_start` | Check `C:\dlp\agent\dlp-windows-service.err`, verify WinFsp is installed, verify DPAPI identity, and inspect the System event log. |
| `server_failed_to_bind` | Check `C:\dlp\server\dlp-server.err` on LAB-DC01; verify port 8443 is not in use and the firewall rule exists. |
| `provisioning_client_failed` | Check `C:\dlp\provisioning\dlpctl.log` and `dlpctl.err` on LAB-DC01; verify the server is reachable and the admin cert chains to `admin-ca.pem`. |
| `enrollment_token_invalid` | The token exceeded 512 characters or contained disallowed characters; re-run trusted provisioning. |
| PostgreSQL migration fails | Verify `DLP_DATABASE_URL`, SSH to LAB-SERVER01, and run `sudo systemctl status postgresql`. |
| Certificate verification fails | Run `Verify-DlpLabCertificates.ps1` and regenerate any CA missing `CA:TRUE` or `Certificate Sign` key usage. |
| VM network/DNS issues | Verify Hyper-V VM network adapters and DNS resolution of `LAB-DC01.lab.local`. |

For Hyper-V VM power management issues, see [.planning/docs/HYPERV-VM-START-GUIDE.md](HYPERV-VM-START-GUIDE.md).

For day-to-day boot and service startup, see [.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md](HYPERV-DLP-STARTUP-GUIDE.md).

For the independent `DlpLogDebugService` diagnostic runbook, see [.planning/docs/DLP-LOG-DEBUG-SERVICE.md](DLP-LOG-DEBUG-SERVICE.md).

## 10. Lab Scripts Inventory

See `scripts/lab/README.md` for a summary of every script, its prerequisites, and example invocations.

## 11. Related Documentation

- [.planning/docs/ENV-VARS.md](ENV-VARS.md) — canonical environment variable reference.
- [.planning/docs/PEM-KEY-GUIDE.md](PEM-KEY-GUIDE.md) — PKI generation and PEM/KEY file mapping.
- [.planning/docs/LAB-SERVER01-SETUP.md](LAB-SERVER01-SETUP.md) — native PostgreSQL setup.
- [.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md](HYPERV-DLP-STARTUP-GUIDE.md) — daily cold-start and service startup.
- [.planning/docs/HYPERV-VM-START-GUIDE.md](HYPERV-VM-START-GUIDE.md) — Hyper-V VM power management.
- [.planning/docs/DLP-LOG-DEBUG-SERVICE.md](DLP-LOG-DEBUG-SERVICE.md) — development-only log debugger.
- [.planning/STATE.md](STATE.md) — current project state and blockers.
- [.planning/WINDOWS.md](WINDOWS.md) — broken-windows ledger.
