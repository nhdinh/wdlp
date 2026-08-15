# Certificate-Related Names and Filenames Audit

Date: 2026-08-14  
Scope: Source code, documentation, configuration, scripts, and generated fixtures under `C:\Users\nhdinh\dev\dleakprevention`.

---

## Summary of Inconsistencies

The project currently mixes three on-disk filename conventions for PEM-encoded certificates and keys:

1. **Kebab-case single-extension** (`{role}-{kind}.pem`) — dominant in scripts and test fixtures.
2. **Dot-separated double-extension** (`{role}.{kind}.pem`) — dominant in `PEM-KEY-GUIDE.md` and some config examples.
3. **Mixed key extensions** — CA keys appear as both `.key.pem` (docs) and `.key` (scripts).

Environment variable names are mostly consistent (`DLP_<ROLE>_<KIND>_PEM` or `_PATH`), but two different variables (`DLP_PHASE1_ROOT_CA_CERT_PEM` for the server and `DLP_ROOT_CA_PEM` for the agent) point to the same logical file, and the provisioning material uses both `_PEM` (content hand-off) and `_PATH` (path consumed by `dlpctl`) suffixes for the same artifacts.

Rust code identifiers generally follow snake_case and are already fairly consistent, but a few field/parameter names (`root_ca_pem`, `admin_cert_pem_path`) do not make the role unambiguous.

---

## 1. Environment Variables

| Variable | Consumer | Current Example File | Logical Role |
|----------|----------|----------------------|--------------|
| `DLP_SERVER_CERT_PEM` | `dlp-server` (`TlsPaths`) | `server-cert.pem` / `server.cert.pem` | Server TLS leaf certificate |
| `DLP_SERVER_KEY_PEM` | `dlp-server` (`TlsPaths`) | `server-key.pem` / `server.key.pem` | Server TLS private key |
| `DLP_ADMIN_CA_CERT_PEM` | `dlp-server` (`TlsPaths`) | `admin-ca.pem` / `admin-ca.cert.pem` | Admin CA certificate |
| `DLP_PHASE1_ROOT_CA_CERT_PEM` | `dlp-server` (`TlsPaths`) | `root-ca.pem` / `phase1-root.cert.pem` | Phase 1 root CA certificate |
| `DLP_DEVICE_ISSUING_CA_CERT_PEM` | `dlp-server` (`TlsPaths`) | `device-issuing-ca.pem` / `device-issuer.cert.pem` | Device-issuing CA certificate |
| `DLP_DEVICE_ISSUING_CA_KEY_PEM` | `dlp-server` (`TlsPaths`) | `device-issuing-ca.key` / `device-issuer.key.pem` | Device-issuing CA private key |
| `DLP_AD_CA_CERT_PEM` | `dlp-server` (AD LDAPS) | `ad-ca.pem` / `ad-ca.cert.pem` | AD LDAPS root CA certificate |
| `DLP_ROOT_CA_PEM` | `dlp-windows-service` (`ServiceConfig`) | `root-ca.pem` / `phase1-root.cert.pem` | Same Phase 1 root CA certificate |
| `DLP_PROVISIONING_ROOT_CA_PEM` | Orchestrator → `Invoke-TrustedProvisioning.ps1` | (PEM content) | Phase 1 root CA content hand-off |
| `DLP_PROVISIONING_ROOT_CA_PATH` | `dlpctl` (`ProvisioningClient`) | `root-ca.pem` | Path to Phase 1 root CA |
| `DLP_PROVISIONING_ADMIN_CERT_PEM` | Orchestrator → `Invoke-TrustedProvisioning.ps1` | (PEM content) | Admin client certificate content hand-off |
| `DLP_PROVISIONING_ADMIN_CERT_PATH` | `dlpctl` (`ProvisioningClient`) | `admin-cert.pem` | Path to admin client certificate |
| `DLP_PROVISIONING_ADMIN_KEY_PEM` | Orchestrator → `Invoke-TrustedProvisioning.ps1` | (PEM content) | Admin client key content hand-off |
| `DLP_PROVISIONING_ADMIN_KEY_PATH` | `dlpctl` (`ProvisioningClient`) | `admin-key.pem` | Path to admin client key |

### Inconsistencies

- `DLP_PHASE1_ROOT_CA_CERT_PEM` and `DLP_ROOT_CA_PEM` are semantically the same file but have different names.
- `DLP_PROVISIONING_*_PEM` variables carry PEM content, while `DLP_PROVISIONING_*_PATH` variables carry filesystem paths to the same material. This is intentional but can be confusing.
- `DLP_DEVICE_ISSUING_CA_KEY_PEM` points to `device-issuing-ca.key` in scripts but `device-issuer.key.pem` in docs/config.

---

## 2. On-Disk Filenames

### 2.1 Committed/generated test fixtures (`target/01-07-pki/`)

| Filename | Role | Convention |
|----------|------|------------|
| `device.cert.pem` | Test device leaf certificate | dot-separated double-extension |
| `server-cert.pem` | Server TLS certificate | kebab-case single-extension |
| `server-key.pem` | Server TLS private key | kebab-case single-extension |
| `admin-ca.pem` | Admin CA certificate | kebab-case single-extension |
| `root-ca.pem` | Phase 1 root CA certificate | kebab-case single-extension |
| `device-issuing-ca.pem` | Device-issuing CA certificate | kebab-case single-extension |

### 2.2 Files written by lab scripts on target VMs

From `scripts/lab/Invoke-Dc01Server.ps1` (`C:\dlp\secrets\`):

- `server-cert.pem`
- `server-key.pem`
- `admin-ca.pem`
- `root-ca.pem`
- `device-issuing-ca.pem`
- `device-issuing-ca.key` (key without `.pem` suffix)
- `ad-ca.pem` (optional)

From `scripts/lab/Invoke-Client01Runtime.ps1` (`C:\dlp\secrets\`):

- `root-ca.pem`

From `scripts/lab/Invoke-TrustedProvisioning.ps1` (`C:\dlp\provisioning\`):

- `root-ca.pem`
- `admin-cert.pem`
- `admin-key.pem`

### 2.3 Filenames documented in `PEM-KEY-GUIDE.md`

| Documented Filename | Role | Convention |
|---------------------|------|------------|
| `phase1-root.key.pem` | Phase 1 root CA private key | dot-separated double-extension |
| `phase1-root.cert.pem` | Phase 1 root CA certificate | dot-separated double-extension |
| `server.key.pem` | Server TLS private key | dot-separated double-extension |
| `server.cert.pem` | Server TLS certificate | dot-separated double-extension |
| `admin-ca.key.pem` | Admin CA private key | dot-separated double-extension |
| `admin-ca.cert.pem` | Admin CA certificate | dot-separated double-extension |
| `admin.key.pem` | Admin client private key | dot-separated double-extension |
| `admin-cert.pem` | Admin client certificate | kebab-case single-extension |
| `device-issuer.key.pem` | Device-issuing CA private key | dot-separated double-extension |
| `device-issuer.cert.pem` | Device-issuing CA certificate | dot-separated double-extension |
| `ad-ca.key.pem` | AD CA private key | dot-separated double-extension |
| `ad-ca.cert.pem` | AD CA certificate | dot-separated double-extension |

### 2.4 Filenames in example configuration files

`config/lab.env.example`:

- `server.cert.pem`
- `server.key.pem`
- `admin-ca.cert.pem`
- `phase1-root.cert.pem`
- `device-issuer.cert.pem`
- `device-issuer.key.pem`
- `ad-ca.cert.pem`
- `lab-ca.pem`
- `admin-cert.pem`
- `admin-key.pem`

`config/server.env.example`:

- Comments mention `admin-root-ca.pem`, `admin-provisioner-cert.pem`, `admin-provisioner-key.pem` for provisioning.

`deploy/compose.yaml`:

- `server.cert.pem`
- `server.key.pem`
- `admin-ca.cert.pem`
- `phase1-root.cert.pem`
- `device-issuer.cert.pem`
- `device-issuer.key.pem`

---

## 3. Rust Code Identifiers

### 3.1 `crates/dlp-server/src/tls.rs`

```rust
pub struct TlsPaths {
    pub server_certificate: PathBuf,
    pub server_private_key: PathBuf,
    pub administrator_ca: PathBuf,
    pub phase1_root_ca: PathBuf,
    pub device_issuing_ca: PathBuf,
}
```

These names are already descriptive and consistent. They read environment variables that are also consistent.

### 3.2 `crates/dlp-windows-service/src/service.rs`

```rust
pub struct ServiceConfig {
    pub root_ca_pem: String,
    // ...
}
```

`root_ca_pem` is ambiguous — it is the Phase 1 root CA, not the admin or device root.

### 3.3 `crates/dlpctl/src/lib.rs`

```rust
pub fn new(
    endpoint: impl Into<String>,
    root_ca_pem_path: &Path,
    admin_cert_pem_path: &Path,
    admin_key_pem_path: &Path,
) -> Result<Self, ProvisioningError>
```

`root_ca_pem_path` and `admin_cert_pem_path` are ambiguous. They refer to the provisioning trust anchor and the provisioning admin identity.

### 3.4 `crates/dlpctl/src/main.rs`

Reads:

- `DLP_PROVISIONING_ROOT_CA_PATH`
- `DLP_PROVISIONING_ADMIN_CERT_PATH`
- `DLP_PROVISIONING_ADMIN_KEY_PATH`

These names are consistent with each other and with the file they read.

### 3.5 `crates/dlp-server/src/lib.rs`

Lists required environment variables. All use the `DLP_<ROLE>_<KIND>_PEM` pattern.

---

## 4. Documentation References

### 4.1 `.planning/docs/PEM-KEY-GUIDE.md`

Primary source of dot-separated filenames. Contains the full PKI generation instructions and the environment-variable-to-file mapping table.

### 4.2 `.planning/docs/ENV-VARS.md`

References `C:\dlp\secrets\root-ca.pem` and describes `DLP_ROOT_CA_PEM`. Links to `PEM-KEY-GUIDE.md`.

### 4.3 `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md`

Uses `DLP_SERVER_CERT_PEM`, `DLP_SERVER_KEY_PEM`, `DLP_ROOT_CA_PEM` as example environment values.

### 4.4 Phase plans and quick-task summaries

Multiple phase plans (`01-13`, `01-14`, `01-22`, `01-23`) and quick tasks (`20260813-pem-key-collection-guide`, `20260813-provisioning-token-capture`, `20260813-deploy-client01-runtime`) reference the same set of variables and filenames.

---

## 5. Test and Fixture References

### 5.1 `tests/e2e/server_enrollment.rs`

Hardcodes fixture filenames:

```rust
("DLP_SERVER_CERT_PEM", "server-cert.pem"),
("DLP_SERVER_KEY_PEM", "server-key.pem"),
("DLP_ADMIN_CA_CERT_PEM", "admin-ca.pem"),
("DLP_PHASE1_ROOT_CA_CERT_PEM", "root-ca.pem"),
("DLP_DEVICE_ISSUING_CA_CERT_PEM", "device-issuing-ca.pem"),
("DLP_DEVICE_ISSUING_CA_KEY_PEM", "device-issuing-ca.key"),
```

Also generates `device.cert.pem` if it does not exist.

### 5.2 `crates/dlp-agent-core/tests/enrollment_activation.rs`

May reference enrollment certificate material. (Not fully audited in this pass; covered by the general rename sweep.)

---

## 6. Scripts and Orchestration

### 6.1 `scripts/lab/Set-DlpEnvironment.ps1`

Sets all environment variables to default paths. Uses dot-separated filenames (`server.cert.pem`, `phase1-root.cert.pem`, `device-issuer.cert.pem`, etc.).

### 6.2 `scripts/lab/Invoke-Dc01Server.ps1`

- Writes kebab-case single-extension files to `C:\dlp\secrets\`.
- Uses `device-issuing-ca.key` for the CA key (inconsistent with cert filename).
- Sets environment variables to point to the written files.

### 6.3 `scripts/lab/Invoke-Client01Runtime.ps1`

- Writes `root-ca.pem` to `C:\dlp\secrets\`.
- Sets `DLP_ROOT_CA_PEM=C:\dlp\secrets\root-ca.pem`.

### 6.4 `scripts/lab/Invoke-TrustedProvisioning.ps1`

- Consumes `DLP_PROVISIONING_ROOT_CA_PEM`, `DLP_PROVISIONING_ADMIN_CERT_PEM`, `DLP_PROVISIONING_ADMIN_KEY_PEM` (content).
- Writes `root-ca.pem`, `admin-cert.pem`, `admin-key.pem` to `C:\dlp\provisioning\`.
- Sets the corresponding `_PATH` variables.

### 6.5 `scripts/verify-phase1-evidence.ps1`

References `DLP_ADMIN_PROVISIONING_KEY` (obsolete bearer token) and checks that production code does not contain it.

---

## 7. Grouped by Current Convention

### 7.1 Kebab-case single-extension (`{role}-{kind}.pem`)

- `server-cert.pem`
- `server-key.pem`
- `admin-ca.pem`
- `root-ca.pem`
- `device-issuing-ca.pem`
- `device-issuing-ca.key` (key variant without `.pem`)
- `ad-ca.pem`
- `admin-cert.pem`
- `admin-key.pem`

Used by: test fixtures, VM deployment scripts, `tests/e2e/server_enrollment.rs`.

### 7.2 Dot-separated double-extension (`{role}.{kind}.pem`)

- `device.cert.pem`
- `server.cert.pem`
- `server.key.pem`
- `admin-ca.cert.pem`
- `admin-ca.key.pem`
- `phase1-root.cert.pem`
- `phase1-root.key.pem`
- `device-issuer.cert.pem`
- `device-issuer.key.pem`
- `ad-ca.cert.pem`
- `ad-ca.key.pem`
- `admin.cert.pem` (mentioned in docs generation commands)
- `admin.key.pem`

Used by: `PEM-KEY-GUIDE.md`, `config/lab.env.example`, `deploy/compose.yaml`, `Set-DlpEnvironment.ps1`.

### 7.3 One-off/ambiguous names

- `lab-ca.pem` — in `config/lab.env.example`, should be the Phase 1 root CA.
- `admin-root-ca.pem` — in `config/server.env.example` comment.
- `admin-provisioner-cert.pem` — in `config/server.env.example` comment.
- `admin-provisioner-key.pem` — in `config/server.env.example` comment.

---

## 8. Key Decision Points for Unification

1. **Filename convention**: choose kebab-case single-extension (less churn) or dot-separated double-extension (more explicit, matches OpenSSL conventions).
2. **CA key filenames**: ensure keys always end in `.pem`.
3. **Phase 1 root CA name**: choose one role name (`phase1-root` vs `root`) and use it in filenames, env vars, and code.
4. **Device-issuing CA name**: choose `device-issuing` (matches env var) or `device-issuer` (matches current doc usage).
5. **Provisioning admin cert/key**: choose a role name that disambiguates from the admin CA (`provisioning-admin` recommended).
6. **Agent-side root CA env var**: align `DLP_ROOT_CA_PEM` with the server-side `DLP_PHASE1_ROOT_CA_CERT_PEM` or keep as a documented alias.
7. **Code identifiers**: optionally rename `ServiceConfig.root_ca_pem` and `ProvisioningClient` parameter names for clarity.
