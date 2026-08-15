# Phase 1 Lab PKI and PEM Guide

This guide covers public certificates and private keys used by the Phase 1 lab. Generate them only in a protected secrets directory, such as `C:\dlp\secrets`, and never commit the directory, an env file containing paths to it, tokens, or private keys. The full variable contract is [ENV-VARS.md](ENV-VARS.md); the ordered first-time workflow is [LAB-SETUP-GUIDE.md](LAB-SETUP-GUIDE.md).

## Three separate trust roles

These are **separate trust roles**, not a hierarchy beneath the Phase 1 root:

```text
Phase 1 root CA (self-signed) ── signs ── server-cert.pem
  public root anchors agent/provisioning HTTPS validation

Administrator CA (self-signed) ── signs ── provisioning-admin-cert.pem
  public admin CA is the management server's administrator-peer root

Device-issuing CA (self-signed) ── signs ── enrolled device client certificates
  public device CA is the management server's device-peer root

AD/enterprise issuer ── signs ── active DC LDAPS certificate
  its exported issuer certificate anchors LDAPS independently
```

The Phase 1 root does **not** sign the administrator or device-issuing CAs. The management server must never receive `phase1-root-ca-key.pem`, `admin-ca-key.pem`, or the provisioning administrator key except where the documented server/provisioning role explicitly needs a private key. The endpoint receives only the public `phase1-root-ca.pem`.

## Preferred lab generation

Use the rotation scripts from `scripts/lab/` on the protected orchestration host. They generate temporary extension files under the selected secrets directory and remove them after signing:

```powershell
.\scripts\lab\New-DlpPhase1RootCa.ps1 -OutputDirectory C:\dlp\secrets
.\scripts\lab\Rotate-DlpAdminCa.ps1 -OutputDirectory C:\dlp\secrets
.\scripts\lab\Rotate-DlpDeviceIssuingCa.ps1 -OutputDirectory C:\dlp\secrets
.\scripts\lab\Rotate-DlpServerCert.ps1 -OutputDirectory C:\dlp\secrets
.\scripts\lab\Verify-DlpLabCertificates.ps1 -SecretsDirectory C:\dlp\secrets -ServerHostname LAB-DC01.lab.local
```

Run `New-DlpPhase1RootCa.ps1` only for first-time setup. Pass `-Force` only when intentionally replacing or rotating existing lab material; replacing the Phase 1 root requires regenerating the server certificate and redeploying the endpoint trust anchor. The verifier checks headers, key pairs, CA/basic constraints, leaf key usages and EKU roles, DNS SAN/hostname expectations, and the chains that really exist: server to Phase 1 root and provisioning administrator to administrator CA. Pass the same directory to `-SecretsDirectory` when it is not the default.

## Equivalent OpenSSL profiles

The following manual commands produce the same certificate profiles as the scripts. `$Secrets` must already be a protected local directory. On Windows PowerShell 5.1, prefer the scripts because they write OpenSSL configuration files as UTF-8 without a byte-order mark.

### Phase 1 root and server leaf

```powershell
$Secrets = 'C:\dlp\secrets'
New-Item -ItemType Directory -Path $Secrets -Force | Out-Null
openssl genrsa -out "$Secrets\phase1-root-ca-key.pem" 4096
$rootExt = @'
[v3_ca]
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
'@
$rootExt | Set-Content -Path "$Secrets\phase1-root-ca-ext.cnf" -Encoding UTF8
openssl req -x509 -new -nodes -key "$Secrets\phase1-root-ca-key.pem" -sha256 -days 3650 `
  -subj '/CN=phase1-root-ca/O=DLP Lab' -config "$Secrets\phase1-root-ca-ext.cnf" -extensions v3_ca `
  -out "$Secrets\phase1-root-ca.pem"

openssl genrsa -out "$Secrets\server-key.pem" 2048
openssl req -new -key "$Secrets\server-key.pem" -subj '/CN=LAB-DC01.lab.local/O=DLP Lab' -out "$Secrets\server.csr"
$serverExt = @'
[v3_server]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:LAB-DC01, DNS:LAB-DC01.lab.local, IP:192.168.50.10
'@
$serverExt | Set-Content -Path "$Secrets\server-ext.cnf" -Encoding UTF8
openssl x509 -req -in "$Secrets\server.csr" -CA "$Secrets\phase1-root-ca.pem" `
  -CAkey "$Secrets\phase1-root-ca-key.pem" -CAcreateserial -days 365 -sha256 `
  -extfile "$Secrets\server-ext.cnf" -extensions v3_server -out "$Secrets\server-cert.pem"
```

### Administrator CA and provisioning administrator leaf

The following retained extension profile is required: the administrator CA is CA-capable, and the provisioning identity is a non-CA client certificate.

```powershell
openssl genrsa -out "$Secrets\admin-ca-key.pem" 4096
$adminCaExt = @'
[v3_ca]
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
'@
$adminCaExt | Set-Content -Path "$Secrets\admin-ca-ext.cnf" -Encoding UTF8
openssl req -x509 -new -nodes -key "$Secrets\admin-ca-key.pem" -sha256 -days 3650 `
  -subj '/CN=admin-ca/O=DLP Lab' -config "$Secrets\admin-ca-ext.cnf" -extensions v3_ca -out "$Secrets\admin-ca.pem"

openssl genrsa -out "$Secrets\provisioning-admin-key.pem" 2048
openssl req -new -key "$Secrets\provisioning-admin-key.pem" -subj '/CN=dlp-provisioning-admin/O=DLP Lab' -out "$Secrets\provisioning-admin.csr"
$provAdminExt = @'
[v3_client]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
'@
$provAdminExt | Set-Content -Path "$Secrets\provisioning-admin-ext.cnf" -Encoding UTF8
openssl x509 -req -in "$Secrets\provisioning-admin.csr" -CA "$Secrets\admin-ca.pem" `
  -CAkey "$Secrets\admin-ca-key.pem" -CAcreateserial -days 365 -sha256 `
  -extfile "$Secrets\provisioning-admin-ext.cnf" -extensions v3_client -out "$Secrets\provisioning-admin-cert.pem"
```

### Device-issuing CA

This retained CA profile is distinct from the administrator CA. The management server uses its private key only to issue enrolled device leaves.

```powershell
openssl genrsa -out "$Secrets\device-issuing-ca-key.pem" 4096
$deviceCaExt = @'
[v3_ca]
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
'@
$deviceCaExt | Set-Content -Path "$Secrets\device-issuing-ca-ext.cnf" -Encoding UTF8
openssl req -x509 -new -nodes -key "$Secrets\device-issuing-ca-key.pem" -sha256 -days 3650 `
  -subj '/CN=device-issuing-ca/O=DLP Lab' -config "$Secrets\device-issuing-ca-ext.cnf" -extensions v3_ca -out "$Secrets\device-issuing-ca.pem"
```

### AD/LDAPS CA (`ad-ca.pem`)

The DLP certificate-generation scripts do **not** create `ad-ca.pem`. It belongs to the Active Directory LDAPS trust chain, not to the DLP administrator PKI. Obtain it from the CA that issued the active LDAPS certificates on `LAB-DC01` and `LAB-DC02`; do not copy or rename `admin-ca.pem`.

On each domain controller, inspect the active certificate that supports TLS server authentication:

```powershell
Get-ChildItem Cert:\LocalMachine\My |
  Where-Object {
    $_.HasPrivateKey -and
    $_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.1'
  } |
  Format-List Subject, Issuer, Thumbprint, NotAfter
```

The certificate's `Issuer` identifies the issuing CA certificate to export. On the domain controller:

1. Run `certlm.msc`.
2. Find that CA certificate under **Trusted Root Certification Authorities > Certificates** or **Intermediate Certification Authorities > Certificates**.
3. Select **All Tasks > Export**, do not export a private key, and choose **Base-64 encoded X.509 (.CER)**.
4. Save the exported public certificate and transfer it securely to `C:\dlp\secrets\ad-ca.pem` on the machine from which `Invoke-Dc01Server.ps1` will run. Base-64 X.509 certificate content is PEM content even if the export wizard originally gives it a `.cer` extension.

If both domain controllers use the same issuing CA, one exported certificate is sufficient. If they use different issuers, or validation requires an intermediate CA, concatenate the required public CA certificates into one PEM bundle:

```powershell
Get-Content C:\dlp\secrets\lab-dc01-issuer.pem,
            C:\dlp\secrets\lab-dc02-issuer.pem |
  Set-Content C:\dlp\secrets\ad-ca.pem -Encoding ascii
```

Verify the resulting certificate or bundle, then set the runner input in the same PowerShell session used to start the server:

```powershell
openssl crl2pkcs7 -nocrl -certfile C:\dlp\secrets\ad-ca.pem |
  openssl pkcs7 -print_certs -noout

$env:DLP_AD_CA_CERT_PEM = 'C:\dlp\secrets\ad-ca.pem'
```

For a protected local environment file used by `Initialize-DlpEnvironment.ps1`, add the equivalent one-line entry:

```dotenv
DLP_AD_CA_CERT_PEM=C:\dlp\secrets\ad-ca.pem
```

`Invoke-Dc01Server.ps1` reads the path on the calling machine, copies the certificate content into the LAB-DC01 secret directory, and configures the server to use it when validating LDAPS connections.

## Names and assignments

| File | Consumers / environment name | Handling |
| --- | --- | --- |
| `phase1-root-ca.pem` | Server: `DLP_PHASE1_ROOT_CA_CERT_PEM`; endpoint: `DLP_ROOT_CA_PEM`; provisioning: `DLP_PROVISIONING_ROOT_CA_PATH`. | Public certificate. Env files use its one-line path. The endpoint runner accepts a path or inline certificate then deploys certificate content. |
| `phase1-root-ca-key.pem` | Server-cert rotation only. | Private/offline; never server/agent runtime. |
| `server-cert.pem`, `server-key.pem` | `DLP_SERVER_CERT_PEM`, `DLP_SERVER_KEY_PEM` on LAB-DC01. | Public leaf and private server key. |
| `admin-ca.pem`, `admin-ca-key.pem` | `DLP_ADMIN_CA_CERT_PEM`; admin rotation. | Public administrator-peer root; private CA key protected on issuer host. |
| `provisioning-admin-cert.pem`, `provisioning-admin-key.pem` | `DLP_PROVISIONING_ADMIN_CERT_PATH`, `DLP_PROVISIONING_ADMIN_KEY_PATH` (or script-only `_PEM` aliases). | mTLS client leaf and private key. |
| `device-issuing-ca.pem`, `device-issuing-ca-key.pem` | `DLP_DEVICE_ISSUING_CA_CERT_PEM`, `DLP_DEVICE_ISSUING_CA_KEY_PEM` on LAB-DC01. | Server trusts public root and uses its private key only to issue device leaves. |
| `ad-ca.pem` | `DLP_AD_CA_CERT_PEM`. | Export the issuer of the active domain-controller LDAPS certificate. Creating an unrelated standalone CA and importing only its root does not configure LDAPS. |

## Verify before deployment

```powershell
openssl verify -CAfile "$Secrets\phase1-root-ca.pem" "$Secrets\server-cert.pem"
openssl verify -CAfile "$Secrets\admin-ca.pem" "$Secrets\provisioning-admin-cert.pem"
openssl x509 -in "$Secrets\server-cert.pem" -noout -text
openssl x509 -in "$Secrets\provisioning-admin-cert.pem" -noout -text
.\scripts\lab\Verify-DlpLabCertificates.ps1
```

Check that CA certificates report critical `CA:TRUE` and `Certificate Sign`; server leaf reports `CA:FALSE`, `serverAuth`, and the LAB-DC01 hostname SANs; provisioning leaf reports `CA:FALSE`, digital signature, and `clientAuth`. Do not claim a device/client leaf chains to the Phase 1 root: it chains to the device-issuing CA.
