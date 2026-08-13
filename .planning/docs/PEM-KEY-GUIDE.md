# DLP Phase 1 Lab PEM/KEY Collection Guide

This guide explains how to obtain or create every PEM and KEY file referenced by the Phase 1 lab environment variables. These files are **runtime-only secrets** and must never be committed to source control.

For the canonical list of variables and how the service consumes them, see [ENV-VARS.md](ENV-VARS.md). For the full lab cold-start walkthrough, see [HYPERV-DLP-STARTUP-GUIDE.md](HYPERV-DLP-STARTUP-GUIDE.md).

---

## PKI Topology at a Glance

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Phase 1 Lab PKI                            │
├─────────────────────────────────────────────────────────────────────┤
│  phase1-root (self-signed root CA)                                  │
│  ├─ server-cert       → dlp-server TLS listener                     │
│  ├─ admin-ca          → dlp-server admin mTLS verifier              │
│  │   └─ admin-cert    → dlpctl trusted-provisioning client          │
│  └─ device-issuer     → dlp-server device certificate issuer        │
│       └─ device-cert  → dlp-windows-service mTLS client             │
├─────────────────────────────────────────────────────────────────────┤
│  ad-ca                → Active Directory LDAPS trust anchor         │
│  (export from AD CS or use a lab-generated cert)                    │
└─────────────────────────────────────────────────────────────────────┘
```

Files are written to `C:\dlp\secrets\` on the relevant machines by `Invoke-Dc01Server.ps1` and `Invoke-Client01Runtime.ps1`.

---

## Option A: Generate a Self-Signed Lab PKI with OpenSSL

For a private lab you can create all certificates yourself. The commands below use OpenSSL on Windows (available via Git Bash, WSL, or `choco install openssl`).

### 1. Create the Phase 1 root CA

```powershell
$Secrets = 'C:\dlp\secrets'
New-Item -ItemType Directory -Path $Secrets -Force | Out-Null

# Generate private key
openssl genrsa -out "$Secrets\phase1-root.key.pem" 4096

# Self-sign root CA (10-year validity)
openssl req -x509 -new -nodes `
    -key "$Secrets\phase1-root.key.pem" `
    -sha256 -days 3650 `
    -subj '/CN=phase1-root-ca/O=DLP Lab' `
    -out "$Secrets\phase1-root.cert.pem"
```

Env vars that use this file:

| Variable | Where |
|----------|-------|
| `DLP_PHASE1_ROOT_CA_CERT_PEM` | Management server (`LAB-DC01`) |
| `DLP_ROOT_CA_PEM` | Endpoint agent (`LAB-CLIENT01`) |

> Store `phase1-root.key.pem` offline. The management server and agent only need the public certificate.

---

### 2. Create the server TLS certificate

The server certificate must include the DNS name and/or IP address clients use to reach `LAB-DC01`.

Create a SAN file `server-ext.cnf`:

```ini
subjectAltName = DNS:LAB-DC01, DNS:LAB-DC01.lab.local, IP:192.168.50.10
extendedKeyUsage = serverAuth
```

Generate and sign:

```powershell
openssl genrsa -out "$Secrets\server.key.pem" 2048

openssl req -new `
    -key "$Secrets\server.key.pem" `
    -subj '/CN=LAB-DC01.lab.local/O=DLP Lab' `
    -out "$Secrets\server.csr"

openssl x509 -req `
    -in "$Secrets\server.csr" `
    -CA "$Secrets\phase1-root.cert.pem" `
    -CAkey "$Secrets\phase1-root.key.pem" `
    -CAcreateserial `
    -extfile server-ext.cnf `
    -days 365 -sha256 `
    -out "$Secrets\server.cert.pem"
```

Env vars:

| Variable | Purpose |
|----------|---------|
| `DLP_SERVER_CERT_PEM` | Server's TLS certificate (public) |
| `DLP_SERVER_KEY_PEM` | Server's TLS private key |

---

### 3. Create the administrator CA and provisioning certificate

The management server uses `DLP_ADMIN_CA_CERT_PEM` to verify administrator client certificates. The trusted-provisioning flow uses an administrator certificate + key to authenticate `dlpctl` to the `/api/v1/admin/provisioning` route.

#### 3a. Create the admin CA

```powershell
openssl genrsa -out "$Secrets\admin-ca.key.pem" 4096

openssl req -x509 -new -nodes `
    -key "$Secrets\admin-ca.key.pem" `
    -sha256 -days 3650 `
    -subj '/CN=admin-ca/O=DLP Lab' `
    -out "$Secrets\admin-ca.cert.pem"
```

Env var:

| Variable | Where |
|----------|-------|
| `DLP_ADMIN_CA_CERT_PEM` | Management server (`LAB-DC01`) |

#### 3b. Create the provisioning administrator certificate

```powershell
openssl genrsa -out "$Secrets\admin.key.pem" 2048

openssl req -new `
    -key "$Secrets\admin.key.pem" `
    -subj '/CN=dlp-provisioning-admin/O=DLP Lab' `
    -out "$Secrets\admin.csr"

openssl x509 -req `
    -in "$Secrets\admin.csr" `
    -CA "$Secrets\admin-ca.cert.pem" `
    -CAkey "$Secrets\admin-ca.key.pem" `
    -CAcreateserial `
    -days 365 -sha256 `
    -out "$Secrets\admin-cert.pem"
```

Env vars (trusted provisioning on `hungdinh-lt` / `LAB-DC01`):

| Variable | Purpose |
|----------|---------|
| `DLP_PROVISIONING_ROOT_CA_PATH` | Trust anchor for the provisioning HTTPS connection (usually `phase1-root.cert.pem`) |
| `DLP_PROVISIONING_ADMIN_CERT_PATH` | Administrator client certificate (public) |
| `DLP_PROVISIONING_ADMIN_KEY_PATH` | Administrator client certificate private key |

---

### 4. Create the device-issuing CA

The device-issuing CA signs the mTLS client certificates presented by enrolled endpoints. The management server needs both the certificate and the private key so it can issue device certificates during enrollment.

```powershell
openssl genrsa -out "$Secrets\device-issuer.key.pem" 4096

openssl req -x509 -new -nodes `
    -key "$Secrets\device-issuer.key.pem" `
    -sha256 -days 3650 `
    -subj '/CN=device-issuer-ca/O=DLP Lab' `
    -out "$Secrets\device-issuer.cert.pem"
```

Env vars:

| Variable | Purpose |
|----------|---------|
| `DLP_DEVICE_ISSUING_CA_CERT_PEM` | Public CA certificate used to validate device client certs |
| `DLP_DEVICE_ISSUING_CA_KEY_PEM` | Private key used to issue new device certificates |

---

### 5. Export the Active Directory LDAPS CA

If `LAB-DC01` is also a domain controller, LDAPS typically uses the Active Directory Certificate Services (AD CS) enterprise CA.

To export the AD CS root CA:

1. Open **Certlm.msc** on `LAB-DC01`.
2. Navigate to **Trusted Root Certification Authorities → Certificates**.
3. Find the CA that issued the domain controller certificate.
4. Right-click → **All Tasks → Export**.
5. Choose **Base-64 encoded X.509 (.CER)**.
6. Save as `ad-ca.cert.pem` and place it in `C:\dlp\secrets\`.

If you do not have AD CS, generate a standalone CA and import it into the domain controller certificate store:

```powershell
openssl genrsa -out "$Secrets\ad-ca.key.pem" 4096
openssl req -x509 -new -nodes -key "$Secrets\ad-ca.key.pem" `
    -sha256 -days 3650 -subj '/CN=ad-ca/O=DLP Lab' `
    -out "$Secrets\ad-ca.cert.pem"
```

Env var:

| Variable | Purpose |
|----------|---------|
| `DLP_AD_CA_CERT_PEM` | Trust anchor for LDAPS connections to Active Directory |

---

## Option B: Use an Existing Enterprise PKI

If your organization already operates a CA:

1. Request a **server TLS certificate** for `LAB-DC01.lab.local` with SANs for all names/IPs clients will use.
2. Request or create an **issuing CA** for device certificates and export its certificate + private key.
3. Request or create an **administrator CA** for provisioning client certificates.
4. Export the **AD CS root CA** for LDAPS.
5. Update `DLP_PHASE1_ROOT_CA_CERT_PEM` and `DLP_ROOT_CA_PEM` to point to the public root that anchors your server and device chains.

> Do not use production private keys in a lab. If you export an issuing CA key, treat it as a high-value secret and rotate it after the lab is decommissioned.

---

## Option C: Reuse Previously Generated Lab Artifacts

The project sometimes writes generated PKI material under `target/01-07-pki/`:

```powershell
Get-ChildItem -Path 'C:\Users\nhdinh\dev\dleakprevention\target\01-07-pki\'
```

If these files match your lab topology, copy them to `C:\dlp\secrets\` and update the environment variables. Verify the certificate subjects and SANs before reuse.

---

## Environment Variable to File Mapping

| Environment Variable | File (example) | Machine | Origin |
|----------------------|----------------|---------|--------|
| `DLP_SERVER_CERT_PEM` | `C:\dlp\secrets\server.cert.pem` | `LAB-DC01` | Leaf TLS certificate signed by Phase 1 root |
| `DLP_SERVER_KEY_PEM` | `C:\dlp\secrets\server.key.pem` | `LAB-DC01` | Private key for server certificate |
| `DLP_ADMIN_CA_CERT_PEM` | `C:\dlp\secrets\admin-ca.cert.pem` | `LAB-DC01` | CA that signed provisioning admin certs |
| `DLP_PHASE1_ROOT_CA_CERT_PEM` | `C:\dlp\secrets\phase1-root.cert.pem` | `LAB-DC01` | Self-signed root CA |
| `DLP_DEVICE_ISSUING_CA_CERT_PEM` | `C:\dlp\secrets\device-issuer.cert.pem` | `LAB-DC01` | CA that issues device mTLS certs |
| `DLP_DEVICE_ISSUING_CA_KEY_PEM` | `C:\dlp\secrets\device-issuer.key.pem` | `LAB-DC01` | Private key of device-issuing CA |
| `DLP_AD_CA_CERT_PEM` | `C:\dlp\secrets\ad-ca.cert.pem` | `LAB-DC01` | Active Directory LDAPS root CA |
| `DLP_PROVISIONING_ROOT_CA_PATH` | `C:\dlp\secrets\phase1-root.cert.pem` | `hungdinh-lt` | HTTPS trust anchor for provisioning endpoint |
| `DLP_PROVISIONING_ADMIN_CERT_PATH` | `C:\dlp\secrets\admin-cert.pem` | `hungdinh-lt` | Admin client certificate for `dlpctl` |
| `DLP_PROVISIONING_ADMIN_KEY_PATH` | `C:\dlp\secrets\admin-key.pem` | `hungdinh-lt` | Private key for admin client certificate |
| `DLP_ROOT_CA_PEM` | `C:\dlp\secrets\phase1-root.cert.pem` | `LAB-CLIENT01` | Same root CA the agent pins for server TLS |

---

## Loading Values into the Environment

`Set-DlpEnvironment.ps1` sets every variable to a default path. Before running lab scripts, either:

1. Copy the PEM/KEY content into `config/lab.env.local`:

```text
DLP_SERVER_CERT_PEM=-----BEGIN CERTIFICATE-----
MIIC...
-----END CERTIFICATE-----
```

Then load it:

```powershell
.\scripts\lab\Set-DlpEnvironment.ps1 -EnvFile .\config\lab.env.local
```

2. Or set the variables directly in PowerShell:

```powershell
$env:DLP_SERVER_CERT_PEM = Get-Content -Raw 'C:\dlp\secrets\server.cert.pem'
$env:DLP_SERVER_KEY_PEM  = Get-Content -Raw 'C:\dlp\secrets\server.key.pem'
# ... etc
```

> Do not commit `lab.env.local` or any file containing private keys.

---

## Quick Verification

After generating or copying artifacts, verify the chain of trust:

```powershell
# Server certificate chains to Phase 1 root
openssl verify -CAfile C:\dlp\secrets\phase1-root.cert.pem C:\dlp\secrets\server.cert.pem

# Admin cert chains to admin CA
openssl verify -CAfile C:\dlp\secrets\admin-ca.cert.pem C:\dlp\secrets\admin-cert.pem
```

---

## Related Docs

- [ENV-VARS.md](ENV-VARS.md) — complete agent runtime environment variable reference.
- [HYPERV-DLP-STARTUP-GUIDE.md](HYPERV-DLP-STARTUP-GUIDE.md) — full lab cold-start walkthrough.
- `scripts/lab/Set-DlpEnvironment.ps1` — loads default paths and env files.
- `scripts/lab/Invoke-Dc01Server.ps1` — deploys server secrets to `LAB-DC01`.
- `scripts/lab/Invoke-Client01Runtime.ps1` — deploys agent secrets to `LAB-CLIENT01`.
