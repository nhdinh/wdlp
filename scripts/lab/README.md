# Lab Scripts

PowerShell/Python scripts for setting up, running, and tearing down the Phase 1 DLP lab environment. All scripts are meant to be run from the developer orchestration host (`hungdinh-lt`) unless otherwise noted.

> **Security:** These scripts handle runtime-only secrets. Never commit generated `.env` files, PEM/KEY material, or enrollment tokens to source control.

## Environment Setup

### Initialize-DlpEnvironment.ps1

Interactive setup wizard for all DLP environment variables.

**When to use:** First-time lab setup or whenever you need to reconfigure secrets.

**Prerequisites:** PowerShell 5.1+ on `hungdinh-lt`.

**Example:**

```powershell
.\scripts\lab\Initialize-DlpEnvironment.ps1 -OutEnvFile .\config\lab.env.local
```

### Set-DlpEnvironment.ps1

Loads saved environment variables from a file.

**When to use:** Re-entering a lab session after closing PowerShell.

**Example:**

```powershell
.\scripts\lab\Set-DlpEnvironment.ps1 -EnvFile .\config\lab.env.local
```

## PKI and Certificates

### Rotate-DlpAdminCa.ps1

Generates a new administrator CA and a provisioning admin certificate signed by it.

**When to use:** Initial PKI creation or rotating the admin CA.

**Example:**

```powershell
.\scripts\lab\Rotate-DlpAdminCa.ps1 -OutputDirectory C:\dlp\secrets -Force
```

### Rotate-DlpProvisioningAdmin.ps1

Rotates only the provisioning admin certificate, keeping the existing admin CA.

**When to use:** Re-issuing the `dlpctl` client certificate.

**Example:**

```powershell
.\scripts\lab\Rotate-DlpProvisioningAdmin.ps1 -OutputDirectory C:\dlp\secrets -Force
```

### Verify-DlpLabCertificates.ps1

Validates certificate/key pairs, chains, extensions, expiration, hostname, and rustls/ring compatibility.

**When to use:** After generating or rotating PKI, before deploying the server or endpoint.

**Example:**

```powershell
.\scripts\lab\Verify-DlpLabCertificates.ps1 -ServerHostname 'LAB-DC01.lab.local'
```

### Fetch-DC01Cert.ps1

Exports Active Directory CA certificates from the directory to the desktop.

**When to use:** Obtaining the LDAPS trust anchor for `DLP_AD_CA_CERT_PEM`.

**Example:**

```powershell
# Run on LAB-DC01 or a domain-joined host
.\scripts\lab\Fetch-DC01Cert.ps1
```

## Database

### Reset-DlpPostgres.py

Resets the `dlp` database on `LAB-SERVER01` via SSH and `sudo -u postgres`.

**When to use:** Cleaning the database before a fresh migration run.

**Prerequisites:** `DLP_SERVER01_ADMIN_PASSWORD` set; Paramiko installed.

**Example:**

```powershell
$env:DLP_SERVER01_ADMIN_PASSWORD = '***'
python .\scripts\lab\Reset-DlpPostgres.py
sqlx migrate run --source migrations/
```

### Reset-DlpEnrollment.ps1

Deletes a device's enrollment authority row from PostgreSQL.

**When to use:** Re-enrolling a device after a configuration change.

**Example:**

```powershell
.\scripts\lab\Reset-DlpEnrollment.ps1 -DeviceId 'LAB-CLIENT01.lab.local'
```

## Management Server (LAB-DC01)

### Invoke-Dc01Server.ps1

Builds `dlp-server.exe`, deploys it to `LAB-DC01`, installs secrets, and runs scenarios.

**When to use:** Starting or verifying the management server.

**Example:**

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

Valid scenarios: `Tracer`, `PostgresFresh`, `PostgresRepeat`, `MigrationFailure`, `ConcurrentStart`, `ReadinessConcurrency`, `TrustedProvisioning`, `All`.

### Invoke-TrustedProvisioning.ps1

Runs on `LAB-DC01` to fingerprint `LAB-CLIENT01` and return an enrollment token.

**When to use:** Usually invoked automatically by `Invoke-Client01Runtime.ps1`; run manually only for debugging.

**Example:**

```powershell
# Run inside a LAB-DC01 PowerShell Direct session
.\scripts\lab\Invoke-TrustedProvisioning.ps1 `
    -ExecutionMachine        LAB-DC01 `
    -TargetComputer          LAB-CLIENT01.lab.local `
    -PrivilegeManifestDigest c5b6820546e0cc31eb37c075acf67cdd58e9a257f5779cf19488feb4db7807ba `
    -PreferredDriveLetter   P
```

## Endpoint (LAB-CLIENT01)

### Invoke-Client01Runtime.ps1

Builds `dlp-windows-service.exe`, deploys it to `LAB-CLIENT01`, installs the service, and starts it.

**When to use:** Deploying or updating the endpoint agent.

**Example with trusted provisioning:**

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

Valid scenarios: `Tracer`, `ServiceInstall`, `All`.

Use `-RetainEnrollmentToken` to keep the enrollment token after startup (troubleshooting only).

### Debug-Fingerprint.ps1

Collects SMBIOS/BIOS/disk identity from `LAB-CLIENT01` for troubleshooting trusted-provisioning fingerprint failures.

**When to use:** Trusted provisioning fails with `fingerprint_source_invalid`.

**Example:**

```powershell
# Run on LAB-DC01 against LAB-CLIENT01
.\scripts\lab\Debug-Fingerprint.ps1
```

## Cleanup

### Invoke-Phase1EnvironmentReconcile.ps1

Audits and removes DLP artifacts from the developer host (`hungdinh-lt`).

**When to use:** Cleaning up leaked services, processes, directories, certs, or hosts entries on the orchestration host.

**Example:**

```powershell
# Dry run
.\scripts\lab\Invoke-Phase1EnvironmentReconcile.ps1 `
    -ExecutionMachine hungdinh-lt `
    -ServerVm         LAB-DC01 `
    -SecondaryDcVm    LAB-DC02 `
    -EndpointVm       LAB-CLIENT01

# Apply
.\scripts\lab\Invoke-Phase1EnvironmentReconcile.ps1 `
    -ExecutionMachine hungdinh-lt `
    -ServerVm         LAB-DC01 `
    -SecondaryDcVm    LAB-DC02 `
    -EndpointVm       LAB-CLIENT01 `
    -Apply
```

## Related Documentation

- [.planning/docs/LAB-SETUP-GUIDE.md](../.planning/docs/LAB-SETUP-GUIDE.md) — start-here lab setup walkthrough.
- [.planning/docs/ENV-VARS.md](../.planning/docs/ENV-VARS.md) — environment variable reference.
- [.planning/docs/PEM-KEY-GUIDE.md](../.planning/docs/PEM-KEY-GUIDE.md) — PKI generation guide.
- [.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md](../.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md) — daily cold-start and service startup.
