# LAB-SERVER01 Ubuntu PostgreSQL Setup Guide

This guide provisions a dedicated Hyper-V VM named **LAB-SERVER01** at `192.168.50.12` that hosts the Phase 1 PostgreSQL database. The management server and trusted provisioning remain on **LAB-DC01** (`192.168.50.10`), with **LAB-DC02** (`192.168.50.11`) as the secondary AD authority and **LAB-CLIENT01** (`192.168.50.15`) as the endpoint runtime.

| VM | Role | IP |
|---|---|---|
| LAB-DC01 | Primary AD / management server / trusted provisioning | `192.168.50.10` |
| LAB-DC02 | Secondary AD authority | `192.168.50.11` |
| **LAB-SERVER01** | **PostgreSQL database host** | `192.168.50.12` |
| LAB-CLIENT01 | Endpoint runtime | `192.168.50.15` |
| hungdinh-lt | Developer orchestrator | DHCP / existing |

> Important: This guide installs PostgreSQL directly with `apt`, not Docker. The management server on LAB-DC01 connects to LAB-SERVER01 over the lab network.

---

## 1. Create the Hyper-V VM

On **hungdinh-lt**, open an elevated PowerShell window and run:

```powershell
$VMName      = "LAB-SERVER01"
$Memory      = 4GB
$VHDSize     = 80GB
$SwitchName  = "LabInternal"
$ISO         = "C:\ISOs\ubuntu-22.04-server-amd64.iso"
$VHDPath     = "C:\VMs\LAB-SERVER01\disk.vhdx"

New-VM -Name $VMName -MemoryStartupBytes $Memory -Generation 2 `
       -SwitchName $SwitchName -NewVHDPath $VHDPath -NewVHDSizeBytes $VHDSize

Set-VMProcessor -VMName $VMName -Count 2
Set-VMMemory    -VMName $VMName -DynamicMemoryEnabled $true `
                -MinimumBytes 2GB -MaximumBytes $Memory

Add-VMDvdDrive -VMName $VMName -Path $ISO
Set-VMFirmware -VMName $VMName -EnableSecureBoot Off
Start-VM -Name $VMName
```

### Ubuntu Server installation choices

- **Hostname:** `lab-server01`
- **Username:** `dlpadmin`
- **Password:** strong password stored in your password manager
- **SSH:** Enable OpenSSH server
- **Featured Server Snaps:** None required

---

## 2. Configure Static IP and DNS

Connect via Hyper-V console or SSH. Edit the netplan configuration:

```bash
sudo nano /etc/netplan/00-installer-config.yaml
```

Paste this exact configuration:

```yaml
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: no
      addresses:
        - 192.168.50.12/24
      routes:
        - to: default
          via: 192.168.50.1
      nameservers:
        addresses:
          - 192.168.50.10
          - 192.168.50.11
```

Apply and verify:

```bash
sudo netplan apply
ip addr show eth0
resolvectl status
ping -c 3 192.168.50.10
ping -c 3 192.168.50.11
```

---

## 3. Install PostgreSQL

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y postgresql postgresql-contrib
```

Verify the service:

```bash
sudo systemctl status postgresql
sudo systemctl enable postgresql
psql --version
```

Ubuntu 22.04 typically installs PostgreSQL 14.

---

## 4. Create the Database Role and Database

Switch to the `postgres` system user:

```bash
sudo -u postgres psql
```

Run these SQL commands:

```sql
CREATE USER dlp_server WITH PASSWORD 'your-strong-32-char-password-here';
CREATE DATABASE dlp OWNER dlp_server;

\c dlp
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CREATE ON SCHEMA public TO dlp_server;

\q
```

> Replace `your-strong-32-char-password-here` with a generated password. Save it securely.

---

## 5. Configure PostgreSQL for Remote Access

### 5.1 `pg_hba.conf`

```bash
sudo nano /etc/postgresql/14/main/pg_hba.conf
```

Add above any generic rules:

```text
# DLP lab network access
host    dlp             dlp_server      192.168.50.0/24         scram-sha-256
```

### 5.2 `postgresql.conf`

```bash
sudo nano /etc/postgresql/14/main/postgresql.conf
```

Set:

```text
listen_addresses = '192.168.50.12,localhost'
```

### 5.3 Restart and verify

```bash
sudo systemctl restart postgresql
sudo systemctl status postgresql
```

From **hungdinh-lt**:

```powershell
Test-NetConnection -ComputerName 192.168.50.12 -Port 5432
```

---

## 6. Copy Migrations to LAB-SERVER01

On LAB-SERVER01:

```bash
sudo mkdir -p /opt/dlp/migrations
sudo chown -R dlpadmin:dlpadmin /opt/dlp
```

From **hungdinh-lt**:

```powershell
scp C:\Users\nhdinh\dev\dleakprevention\migrations\*.sql dlpadmin@192.168.50.12:/opt/dlp/migrations/
```

---

## 7. Install sqlx-cli and Run Migrations (Optional)

If you want to run SQLx migrations directly on LAB-SERVER01:

```bash
sudo apt install -y curl build-essential pkg-config libssl-dev

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

cargo install sqlx-cli --no-default-features --features native-tls,postgres
```

Run migrations:

```bash
export DATABASE_URL="postgres://dlp_server:your-password@192.168.50.12:5432/dlp"
cd /opt/dlp
sqlx migrate run
sqlx migrate info
```

---

## 8. Runtime Secret Provider on hungdinh-lt

The 01-13 plan requires secrets to be supplied without placing them in repository files, command lines, logs, or evidence. Load them into a PowerShell session from secure local files.

### 8.1 Create a secure secrets directory

```powershell
New-Item -ItemType Directory -Path C:\dlp\secrets -Force
$Path = "C:\dlp\secrets"
$Acl = Get-Acl $Path
$Acl.SetAccessRuleProtection($true, $false)
$Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $env:USERNAME, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$Acl.SetAccessRule($Rule)
Set-Acl $Path $Acl
```

### 8.2 PKI material source

The Phase 1 PKI fixtures were generated by Plan 01-07 and live in the repository at `target/01-07-pki/`. Copy the required files into `C:\dlp\secrets\`:

| Secret file | Source in repository |
|---|---|
| `server-cert.pem` | `target/01-07-pki/server.cert.pem` |
| `server-key.pem` | `target/01-07-pki/server.key.pem` |
| `admin-ca.pem` | `target/01-07-pki/admin-root.cert.pem` |
| `root-ca.pem` | `target/01-07-pki/phase1-root.cert.pem` |
| `device-issuing-ca.pem` | `target/01-07-pki/device-issuer.cert.pem` |
| `device-issuing-ca.key` | `target/01-07-pki/device-issuer.key.pem` |

From **hungdinh-lt**:

```powershell
$RepoRoot = "C:\Users\nhdinh\dev\dleakprevention"
$PkiDir   = "$RepoRoot\target\01-07-pki"
$SecretDir = "C:\dlp\secrets"

Copy-Item "$PkiDir\server.cert.pem"          "$SecretDir\server-cert.pem"
Copy-Item "$PkiDir\server.key.pem"           "$SecretDir\server-key.pem"
Copy-Item "$PkiDir\admin-root.cert.pem"      "$SecretDir\admin-ca.pem"
Copy-Item "$PkiDir\phase1-root.cert.pem"     "$SecretDir\root-ca.pem"
Copy-Item "$PkiDir\device-issuer.cert.pem"   "$SecretDir\device-issuing-ca.pem"
Copy-Item "$PkiDir\device-issuer.key.pem"    "$SecretDir\device-issuing-ca.key"
```

> For real lab use with your own AD domain and hostname, regenerate these fixtures with `target/01-07-pki/create-fixtures.ps1` and set the server DNS SAN to the management-server hostname (e.g., `management.corp.example.com`). The existing fixtures use `management.test.local`.

### 8.3 Load runtime variables into the PowerShell session

Run this in the same PowerShell window before invoking 01-13 scripts:

```powershell
$env:DLP_SERVER_HOST                     = "192.168.50.12"
$env:DLP_DATABASE_URL                    = "postgres://dlp_server:your-password@192.168.50.12:5432/dlp"

$env:DLP_SERVER_CERT_PEM                 = Get-Content "C:\dlp\secrets\server-cert.pem"   -Raw
$env:DLP_SERVER_KEY_PEM                  = Get-Content "C:\dlp\secrets\server-key.pem"    -Raw
$env:DLP_ADMIN_CA_CERT_PEM               = Get-Content "C:\dlp\secrets\admin-ca.pem"      -Raw
$env:DLP_PHASE1_ROOT_CA_CERT_PEM         = Get-Content "C:\dlp\secrets\root-ca.pem"       -Raw
$env:DLP_DEVICE_ISSUING_CA_CERT_PEM      = Get-Content "C:\dlp\secrets\device-issuing-ca.pem" -Raw
$env:DLP_DEVICE_ISSUING_CA_KEY_PEM       = Get-Content "C:\dlp\secrets\device-issuing-ca.key" -Raw

$env:DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX = "<64-char-hex>"
$env:DLP_ADMIN_PROVISIONING_KEY          = "<32-char-random>"
$env:DLP_APPROVED_PRIVILEGE_MANIFEST_DIGEST = "a6067377ef6b8ebb1c61aeddbbfd460b13d7ddaf1149b1afde50f8802d509638"

# AD / WinRM / LDAPS configuration
$env:DLP_AD_BIND_USER                    = "LAB\svc_dlp_bind"
$env:DLP_AD_BIND_PASSWORD                = "<AD-password>"
$env:DLP_LDAPS_SERVER                    = "192.168.50.10"
$env:DLP_WINRM_TARGET_FQDN               = "LAB-CLIENT01.lab.local"
```

Generate random values:

```powershell
function New-DlpRandomHex {
    param([int]$ByteCount = 16)
    $bytes = [byte[]]::new($ByteCount)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
}

New-DlpRandomHex -ByteCount 16   # 32 hex chars
New-DlpRandomHex -ByteCount 32   # 64 hex chars
```

---

## 9. Validation Checklist

From **hungdinh-lt**:

```powershell
# Reachability
Test-NetConnection -ComputerName 192.168.50.12 -Port 22
Test-NetConnection -ComputerName 192.168.50.12 -Port 5432

# SSH health check
ssh dlpadmin@192.168.50.12 "sudo systemctl is-active postgresql"

# Database connectivity
$env:DLP_DATABASE_URL = "postgres://dlp_server:your-password@192.168.50.12:5432/dlp"
# If psql is available via WSL:
wsl psql "$env:DLP_DATABASE_URL" -c "\conninfo"

# Required DLP environment variables
$Required = @(
    "DLP_DATABASE_URL",
    "DLP_SERVER_CERT_PEM",
    "DLP_SERVER_KEY_PEM",
    "DLP_ADMIN_CA_CERT_PEM",
    "DLP_PHASE1_ROOT_CA_CERT_PEM",
    "DLP_DEVICE_ISSUING_CA_CERT_PEM",
    "DLP_DEVICE_ISSUING_CA_KEY_PEM",
    "DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX",
    "DLP_ADMIN_PROVISIONING_KEY",
    "DLP_APPROVED_PRIVILEGE_MANIFEST_DIGEST"
)

$Required | ForEach-Object {
    if ((-not (Get-ChildItem Env:$_) -or (Get-ChildItem Env:$_).Length -eq 0) {
        throw "$_ is missing or empty"
    }
    Write-Host "$_ OK" -ForegroundColor Green
}
```

---

## 10. Resume 01-13 Execution

Once the checklist passes, invoke the 01-13 orchestration. Note that the server VM is still **LAB-DC01** (management server + trusted provisioning), while the database now lives on **LAB-SERVER01**:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/lab/Invoke-Phase1EnvironmentReconcile.ps1 `
  -ExecutionMachine hungdinh-lt `
  -ServerVm LAB-DC01 `
  -DatabaseVm LAB-SERVER01 `
  -SecondaryDcVm LAB-DC02 `
  -EndpointVm LAB-CLIENT01 `
  -Apply
```

If the orchestration scripts do not yet support a separate database VM, update them so the management server on LAB-DC01 uses `DLP_DATABASE_URL` pointing to `192.168.50.12`.

---

## Summary of Topology Change

| Original | Updated |
|---|---|
| PostgreSQL database on LAB-DC01 | PostgreSQL database on LAB-SERVER01 (`192.168.50.12`) |
| Management server on LAB-DC01 | Unchanged |
| Trusted provisioning on LAB-DC01 | Unchanged |
| AD primary on LAB-DC01 (`192.168.50.10`) | Unchanged |
| AD secondary on LAB-DC02 (`192.168.50.11`) | Unchanged |
| Endpoint runtime on LAB-CLIENT01 (`192.168.50.15`) | Unchanged |
