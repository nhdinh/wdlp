# Lab Scripts

PowerShell/Python scripts for setting up, running, and tearing down the Phase 1 DLP lab environment. All scripts are meant to be run from the developer orchestration host (`hungdinh-lt`) unless otherwise noted.

> **Security:** These scripts handle runtime-only secrets. Never commit generated `.env` files, PEM/KEY material, or enrollment tokens to source control.

## Invocation Roles and Prerequisites

Use scripts labeled **orchestrator-invoked** through their owning runner unless the entry explicitly says it is a debugging exception. All other entries are **manual** tools; their examples are run from the repository root on `hungdinh-lt` unless another host is named.

| Script | Invocation role | Prerequisites |
| --- | --- | --- |
| `Debug-Fingerprint.ps1` | Manual diagnostic | LAB-DC01 connectivity to LAB-CLIENT01 through CIM/WinRM; write access to `C:\dlp\server`. |
| `Debug-TrustedProvisioningTls.ps1` | Manual diagnostic | Run on LAB-DC01 with OpenSSL and the existing provisioning/server runtime files. |
| `Fetch-DC01Cert.ps1` | Manual certificate export | Run on LAB-DC01 or a domain-joined host with directory access. |
| `Initialize-DlpEnvironment.ps1` | Manual setup wizard | PowerShell 5.1+ and runtime-only values from the secret provider. |
| `Invoke-Client01Runtime.ps1` | Orchestrator-invoked endpoint runner | Authorized LAB-CLIENT01 credentials and required runtime secrets. |
| `Invoke-Dc01Server.ps1` | Orchestrator-invoked management-server runner | Authorized LAB-DC01 credentials, LAB-SERVER01 database reachability, and runtime secrets. |
| `Invoke-Phase1EnvironmentReconcile.ps1` | Manual cleanup runner | Run on `hungdinh-lt`; review the default dry run before `-Apply`. |
| `Invoke-TrustedProvisioning.ps1` | Orchestrator-invoked provisioning helper | Run on LAB-DC01 with an approved privilege-manifest digest and runtime PEM material. |
| `Reset-DlpEnrollment.ps1` | Manual database repair | `DLP_DATABASE_URL` and PostgreSQL client tools (`psql`). |
| `Reset-DlpPostgres.py` | Manual database reset | Python with Paramiko, `DLP_SERVER01_ADMIN_PASSWORD`, and a pinned SSH known-hosts file. |
| `Rotate-DlpAdminCa.ps1` | Manual PKI rotation | OpenSSL and a protected writable output directory. |
| `Rotate-DlpDeviceIssuingCa.ps1` | Manual PKI rotation | OpenSSL and a protected writable output directory. |
| `Rotate-DlpProvisioningAdmin.ps1` | Manual PKI rotation | OpenSSL, existing administrator-CA material, and a protected writable output directory. |
| `Rotate-DlpServerCert.ps1` | Manual PKI rotation | OpenSSL, existing Phase 1 root-CA material, and a protected writable output directory. |
| `Set-DlpEnvironment.ps1` | Manual session setup | An environment file created by the setup wizard or an explicit `-EnvFile`. |
| `Verify-DlpLabCertificates.ps1` | Manual validation | OpenSSL and the required PKI environment values or rotated files. |

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

### New-DlpPhase1RootCa.ps1

Creates the Phase 1 HTTPS root CA for a new lab. This is a first-time initialization command; replacing the root requires regenerating the server certificate and redeploying endpoint trust anchors.

```powershell
.\scripts\lab\New-DlpPhase1RootCa.ps1 -OutputDirectory C:\dlp\secrets
```

### Rotate-DlpDeviceIssuingCa.ps1

Generates or rotates the device-issuing CA used to issue endpoint mTLS certificates.

**When to use:** Manual PKI rotation after protecting the output directory and arranging deployment of the replacement trust material.

**Example:**

```powershell
.\scripts\lab\Rotate-DlpDeviceIssuingCa.ps1 -OutputDirectory C:\dlp\secrets -Force
```

### Rotate-DlpServerCert.ps1

Generates or rotates the LAB-DC01 management-server TLS certificate using the existing Phase 1 root CA.

**When to use:** Manual server-certificate rotation; verify and deploy the replacement before restarting the management server.

**Example:**

```powershell
.\scripts\lab\Rotate-DlpServerCert.ps1 -OutputDirectory C:\dlp\secrets -RootCaCertPath C:\dlp\secrets\phase1-root-ca.pem -RootCaKeyPath C:\dlp\secrets\phase1-root-ca-key.pem -Force
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

With `-SecretProvider Runtime`, set `DLP_DATABASE_URL`, `DLP_SERVER_CERT_PEM`, `DLP_SERVER_KEY_PEM`, `DLP_ADMIN_CA_CERT_PEM`, `DLP_PHASE1_ROOT_CA_CERT_PEM`, `DLP_DEVICE_ISSUING_CA_CERT_PEM`, `DLP_DEVICE_ISSUING_CA_KEY_PEM`, and `DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX`. `TrustedProvisioning` and `All` also require the provisioning mTLS inputs and AD/LDAPS inputs listed in [ENV-VARS.md](../../.planning/docs/ENV-VARS.md). Do **not** set the obsolete `DLP_ADMIN_PROVISIONING_KEY`; the runner neither requires nor deploys that legacy bearer secret.

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

**Ordinary ServiceInstall (TrustedProvisioning is the default):**

```powershell
$cred = Get-Credential -Message "LAB admin credential"

.\scripts\lab\Invoke-Client01Runtime.ps1 `
    -CallerMachine            hungdinh-lt `
    -ExecutionMachine         LAB-CLIENT01 `
    -ProbeMachine             LAB-DC01 `
    -SecretProvider           Runtime `
    -Scenario                 ServiceInstall `
    -Credential               $cred `
    -Apply
```

Valid scenarios: `Tracer`, `ServiceInstall`, `All`.

The ordinary command requires no manual token copy. Administrator mTLS certificate/key material remains on LAB-DC01; LAB-CLIENT01 receives only a fresh short-lived token. A usable `C:\dlp\agent\data\credentials\device.dpapi` skips provisioning. The service is installed with Automatic startup, and success requires both a non-empty `active_policy_version` and `active_policy_state=Active` after the first signed policy is verified and activated.

Manual is an explicit offline fallback only:

```powershell
$env:DLP_AGENT_ENROLLMENT_TOKEN = '<FROM-RUNTIME-PROVIDER>'
.\scripts\lab\Invoke-Client01Runtime.ps1 `
    -CallerMachine hungdinh-lt -ExecutionMachine LAB-CLIENT01 -ProbeMachine LAB-DC01 `
    -SecretProvider Runtime -Scenario ServiceInstall -EnrollmentTokenProvider Manual `
    -Credential $cred -Apply
```

Credential replacement is allowed only with `-ForceReenrollment -Apply`; without `-Apply`, force mode is preview-only. Replacement and failed startup preserve the service, binaries, data directory, and cache directory. Token cleanup covers both `C:\dlp\agent\agent.env` and `HKLM:\SYSTEM\CurrentControlSet\Services\DlpWindowsService\Environment`; cleanup failure is fatal. Repair both locations and retry so TrustedProvisioning obtains a fresh token rather than reusing prior material.

Use `-RetainEnrollmentToken` after a successful startup only for explicit troubleshooting. Use `-Diagnostic` only for opt-in redacted output (names, lengths, paths, fingerprints, counts, status, and bounded error metadata). Never expose enrollment tokens, administrator mTLS material, private keys, passwords, full certificates, or raw credential blobs.

### Debug-Fingerprint.ps1

Collects SMBIOS/BIOS/disk identity from `LAB-CLIENT01` for troubleshooting trusted-provisioning fingerprint failures.

**When to use:** Trusted provisioning fails with `fingerprint_source_invalid`.

**Example:**

```powershell
# Run on LAB-DC01 against LAB-CLIENT01
.\scripts\lab\Debug-Fingerprint.ps1
```

### Debug-TrustedProvisioningTls.ps1

Collects a redacted diagnostic JSON snapshot for a trusted-provisioning TLS abort.

**When to use:** Run manually on LAB-DC01 immediately before a provisioning TLS failure. It is a diagnostic helper, not a daily startup entrypoint.

**Example:**

```powershell
# Reproduce only when the incident procedure calls for it.
.\scripts\lab\Debug-TrustedProvisioningTls.ps1 -RunReproduction
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

- [.planning/docs/README.md](../../.planning/docs/README.md) — documentation front door and ownership map.
- [.planning/docs/LAB-SETUP-GUIDE.md](../../.planning/docs/LAB-SETUP-GUIDE.md) — start-here lab setup walkthrough.
- [.planning/docs/ENV-VARS.md](../../.planning/docs/ENV-VARS.md) — environment variable reference.
- [.planning/docs/PEM-KEY-GUIDE.md](../../.planning/docs/PEM-KEY-GUIDE.md) — PKI generation guide.
- [.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md](../../.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md) — daily cold-start and service startup.
