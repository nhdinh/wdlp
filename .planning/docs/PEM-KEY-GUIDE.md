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
.\scripts\lab\Rotate-DlpAdminCa.ps1 -OutputDirectory C:\dlp\secrets
.\scripts\lab\Rotate-DlpDeviceIssuingCa.ps1 -OutputDirectory C:\dlp\secrets
.\scripts\lab\Rotate-DlpServerCert.ps1 -OutputDirectory C:\dlp\secrets
.\scripts\lab\Verify-DlpLabCertificates.ps1
```

Pass `-Force` only when intentionally rotating existing lab material. The verifier checks headers, key pairs, CA/basic constraints, EKU roles, SAN/hostname expectations, and the chains that really exist: server to Phase 1 root and provisioning administrator to administrator CA.

## Equivalent OpenSSL profiles

The following manual commands are equivalent to the scripts. `$Secrets` must already be a protected local directory.

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
