---
title: Unify certificate names and filenames across codebase and docs
description: |
  Adopt a single kebab-case PEM filename convention, rename all fixtures and
  on-disk references, and align documentation, configuration, scripts, and code.
created: 2026-08-14
quick_id: 260814-07h
---

# Goal

All certificate-related names and filenames in code, documentation, scripts,
and configuration files use one consistent naming convention. After this plan
is executed, a developer can predict every certificate filename from its
environment variable name and role.

# Proposed Unified Convention

Adopt **kebab-case single-extension PEM filenames**:

| Kind | Pattern | Example |
|------|---------|---------|
| Leaf certificate | `{role}-cert.pem` | `server-cert.pem` |
| Leaf private key | `{role}-key.pem` | `server-key.pem` |
| CA certificate | `{role}-ca.pem` | `admin-ca.pem` |
| CA private key | `{role}-ca-key.pem` | `device-issuing-ca-key.pem` |

**Role names (canonical)**

| Role | Meaning |
|------|---------|
| `phase1-root` | Phase 1 self-signed root CA |
| `server` | Management server TLS leaf |
| `admin` | Administrator CA (provisioning client cert issuer) |
| `device-issuing` | Device mTLS client certificate issuer |
| `ad` | Active Directory LDAPS trust anchor |
| `provisioning-admin` | Admin client certificate used by `dlpctl` trusted provisioning |
| `device` | Enrolled endpoint mTLS client leaf |

**Rationale**

- The convention is already dominant in scripts and test fixtures, so churn is
  minimized.
- PEM encoding is unambiguous from the `-----BEGIN ...-----` headers; a single
  `.pem` suffix is sufficient and keeps paths short.
- CA keys always end in `.pem`, fixing the current `device-issuing-ca.key`
  inconsistency.
- Role names match the `DLP_<ROLE>_<KIND>_PEM` environment variable pattern.

# Exact Rename Map

## Filenames

| Current Name | New Name | Notes |
|--------------|----------|-------|
| `root-ca.pem` | `phase1-root-ca.pem` | Same file referenced by both server and agent |
| `phase1-root.cert.pem` | `phase1-root-ca.pem` | Docs/config example |
| `phase1-root.key.pem` | `phase1-root-ca-key.pem` | Docs only (offline secret) |
| `server.cert.pem` | `server-cert.pem` | Docs/config example |
| `server.key.pem` | `server-key.pem` | Docs/config example (already correct in scripts) |
| `admin-ca.cert.pem` | `admin-ca.pem` | Docs/config example |
| `admin-ca.key.pem` | `admin-ca-key.pem` | Docs only (offline secret) |
| `admin-cert.pem` | `provisioning-admin-cert.pem` | Disambiguate from admin CA |
| `admin.key.pem` | `provisioning-admin-key.pem` | Docs only |
| `device-issuer.cert.pem` | `device-issuing-ca.pem` | Align role with env var |
| `device-issuer.key.pem` | `device-issuing-ca-key.pem` | Align role with env var |
| `device-issuing-ca.key` | `device-issuing-ca-key.pem` | Add missing `.pem` suffix |
| `ad-ca.cert.pem` | `ad-ca.pem` | Docs/config example |
| `ad-ca.key.pem` | `ad-ca-key.pem` | Docs only (offline secret) |
| `device.cert.pem` | `device-cert.pem` | Test fixture |
| `lab-ca.pem` | `phase1-root-ca.pem` | Config example |
| `admin-root-ca.pem` | `phase1-root-ca.pem` | Config comment |
| `admin-provisioner-cert.pem` | `provisioning-admin-cert.pem` | Config comment |
| `admin-provisioner-key.pem` | `provisioning-admin-key.pem` | Config comment |

## Environment Variables (keep names, align default files)

| Variable | Unified File | Notes |
|----------|--------------|-------|
| `DLP_SERVER_CERT_PEM` | `.../server-cert.pem` | Already consistent |
| `DLP_SERVER_KEY_PEM` | `.../server-key.pem` | Already consistent |
| `DLP_ADMIN_CA_CERT_PEM` | `.../admin-ca.pem` | Already consistent |
| `DLP_PHASE1_ROOT_CA_CERT_PEM` | `.../phase1-root-ca.pem` | File renamed |
| `DLP_DEVICE_ISSUING_CA_CERT_PEM` | `.../device-issuing-ca.pem` | Already consistent |
| `DLP_DEVICE_ISSUING_CA_KEY_PEM` | `.../device-issuing-ca-key.pem` | File renamed |
| `DLP_AD_CA_CERT_PEM` | `.../ad-ca.pem` | Already consistent |
| `DLP_ROOT_CA_PEM` | `.../phase1-root-ca.pem` | Agent alias for the same Phase 1 root |
| `DLP_PROVISIONING_ROOT_CA_PATH` | `.../phase1-root-ca.pem` | File renamed |
| `DLP_PROVISIONING_ADMIN_CERT_PATH` | `.../provisioning-admin-cert.pem` | File renamed |
| `DLP_PROVISIONING_ADMIN_KEY_PATH` | `.../provisioning-admin-key.pem` | File renamed |

**Optional future alignment**: rename `DLP_ROOT_CA_PEM` to `DLP_PHASE1_ROOT_CA_CERT_PEM`
on the agent and/or rename `DLP_PROVISIONING_ADMIN_*` to
`DLP_PROVISIONING_ADMIN_CLIENT_*` to remove ambiguity. These are **not** part of
this plan because they change public runtime contracts.

## Rust Identifiers (optional, recommended)

| Current | Proposed | File |
|---------|----------|------|
| `ServiceConfig.root_ca_pem` | `ServiceConfig.phase1_root_ca_pem` | `crates/dlp-windows-service/src/service.rs` |
| `ProvisioningClient::new(root_ca_pem_path, ...)` | `ProvisioningClient::new(provisioning_root_ca_pem_path, ...)` | `crates/dlpctl/src/lib.rs` |
| `ProvisioningClient::new(..., admin_cert_pem_path, admin_key_pem_path)` | `ProvisioningClient::new(..., provisioning_admin_cert_pem_path, provisioning_admin_key_pem_path)` | `crates/dlpctl/src/lib.rs` |

These are safe internal renames because the public contract is the environment
variables consumed by `dlpctl` main.rs.

# Affected Files

## Source code

- `crates/dlp-server/src/tls.rs` — `TlsPaths` env var reads are consistent; only comments may need updates.
- `crates/dlp-server/src/lib.rs` — env var list is consistent; only comments.
- `crates/dlp-windows-service/src/service.rs` — rename `root_ca_pem` field and `DLP_ROOT_CA_PEM` loader comment to clarify Phase 1 root.
- `crates/dlpctl/src/lib.rs` — rename parameters for clarity.
- `crates/dlpctl/src/main.rs` — env var names stay; update local variable names and comments.
- `tests/e2e/server_enrollment.rs` — update fixture filenames.

## Scripts

- `scripts/lab/Set-DlpEnvironment.ps1` — update default paths to unified filenames.
- `scripts/lab/Invoke-Dc01Server.ps1` — update written filenames (`root-ca.pem` → `phase1-root-ca.pem`, `device-issuing-ca.key` → `device-issuing-ca-key.pem`) and env file paths.
- `scripts/lab/Invoke-Client01Runtime.ps1` — update written filename (`root-ca.pem` → `phase1-root-ca.pem`) and env file path.
- `scripts/lab/Invoke-TrustedProvisioning.ps1` — update written filenames (`admin-cert.pem` → `provisioning-admin-cert.pem`, `admin-key.pem` → `provisioning-admin-key.pem`).
- `scripts/verify-phase1-evidence.ps1` — no cert filename changes; confirm `DLP_ADMIN_PROVISIONING_KEY` remains obsolete.

## Configuration examples

- `config/lab.env.example` — update all example paths.
- `config/server.env.example` — update provisioning comment filenames.
- `deploy/compose.yaml` — update container secret paths.
- `config/agent.toml.example` — update `public_root_path` example.

## Documentation

- `.planning/docs/PEM-KEY-GUIDE.md` — update all generation commands, filenames, and mapping tables.
- `.planning/docs/ENV-VARS.md` — update example paths (`root-ca.pem` → `phase1-root-ca.pem`).
- `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md` — update any example paths.
- `.planning/quick/20260813-pem-key-collection-guide/SUMMARY.md` — update if filenames are referenced.
- `.planning/quick/20260813-provisioning-token-capture/SUMMARY.md` — update provisioning filenames.
- Phase plan SUMMARYs that mention specific filenames (e.g., `01-13`, `01-14`, `01-22`, `01-23`).

## Generated fixtures

- `target/01-07-pki/*` — rename files on disk. These are generated/committed fixtures used by tests and docs.
  - `device.cert.pem` → `device-cert.pem`
  - `server-cert.pem` (keep)
  - `server-key.pem` (keep)
  - `admin-ca.pem` (keep)
  - `root-ca.pem` → `phase1-root-ca.pem`
  - `device-issuing-ca.pem` (keep)

# Implementation Tasks

## Task 1: Rename fixture files and update Rust tests

- Rename files under `target/01-07-pki/`.
- Update `tests/e2e/server_enrollment.rs` fixture references.
- Update `crates/dlp-server/src/pki.rs` / test code if it references fixture paths.
- Run `cargo test --test server_enrollment` and affected unit tests.

## Task 2: Update scripts and configuration examples

- Update `scripts/lab/Set-DlpEnvironment.ps1` default paths.
- Update `scripts/lab/Invoke-Dc01Server.ps1` written filenames and env file paths.
- Update `scripts/lab/Invoke-Client01Runtime.ps1` written filename and env file path.
- Update `scripts/lab/Invoke-TrustedProvisioning.ps1` written filenames.
- Update `config/lab.env.example`, `config/server.env.example`, `deploy/compose.yaml`, `config/agent.toml.example`.
- Smoke-test by running `Set-DlpEnvironment.ps1` and reading back variables.

## Task 3: Update documentation

- Rewrite filename examples in `.planning/docs/PEM-KEY-GUIDE.md`.
- Update example paths in `.planning/docs/ENV-VARS.md` and `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md`.
- Update quick-task SUMMARYs and phase plan SUMMARYs where specific filenames appear.
- Grep the repo for any remaining old filenames and fix them.

## Task 4: Optional code identifier clarity renames

- Rename `ServiceConfig.root_ca_pem` → `phase1_root_ca_pem` in `crates/dlp-windows-service/src/service.rs`.
- Rename `ProvisioningClient` parameters in `crates/dlpctl/src/lib.rs`.
- Run `cargo check`, `cargo clippy`, and affected tests.

# Verification Steps

1. **No inconsistent filenames remain**
   ```powershell
   # Should return only expected unified names or intentional exceptions
   rg -i 'phase1-root\.cert\.pem|device-issuer\.(cert|key)\.pem|device\.cert\.pem|admin-provisioner|admin-root-ca|lab-ca\.pem|\.key(?!\.pem)' --glob '!target/**'
   ```

2. **All environment variable examples point to unified filenames**
   ```powershell
   rg -i 'DLP_.*PEM.*=.*\.pem' config/ deploy/ scripts/lab/ .planning/docs/ | rg -v 'phase1-root-ca\.pem|server-cert\.pem|server-key\.pem|admin-ca\.pem|device-issuing-ca(|-key)\.pem|ad-ca\.pem|provisioning-admin-(cert|key)\.pem'
   ```

3. **Rust tests pass**
   ```bash
   cargo test --test server_enrollment
   cargo test -p dlpctl
   cargo test -p dlp-windows-service
   ```

4. **PowerShell script syntax is valid**
   ```powershell
   Get-ChildItem scripts/lab/*.ps1 | ForEach-Object { Test-ScriptFileInfo $_.FullName -ErrorAction SilentlyContinue; $null }
   ```

5. **Compose file is valid**
   ```bash
   docker compose -f deploy/compose.yaml config
   ```

6. **Fixture directory listing matches convention**
   ```powershell
   Get-ChildItem target/01-07-pki/ | Select-Object Name
   # Expected:
   #   phase1-root-ca.pem
   #   server-cert.pem
   #   server-key.pem
   #   admin-ca.pem
   #   device-issuing-ca.pem
   #   device-cert.pem
   ```

# Rollback Notes

- This plan renames generated fixtures in `target/01-07-pki/`. If the files are
  regenerated by a test or build step, ensure the generator uses the new names.
- On lab VMs, old files (`C:\dlp\secrets\root-ca.pem`,
  `C:\dlp\secrets\device-issuing-ca.key`, `C:\dlp\provisioning\admin-cert.pem`,
  etc.) will be left behind after the first run of updated scripts. Add a
  cleanup step or accept stale files until the VM is reprovisioned.
- Environment variable names are **not** changed, so existing operator secrets
  stored as PEM content remain valid. Only path-valued variables need updates
  if operators hardcoded the old filenames.

# Success Criteria

- [ ] Every certificate filename in code, docs, config, and scripts follows the
      unified `{role}-{kind}.pem` convention.
- [ ] No mixed dot-separated (`*.cert.pem`) or bare-key (`*.key`) filenames
      remain except in external references.
- [ ] All Rust tests and the e2e enrollment test pass.
- [ ] `docker compose -f deploy/compose.yaml config` validates.
- [ ] `Set-DlpEnvironment.ps1` loads without error and points to unified paths.
- [ ] A grep for old filenames returns no unexpected matches.

# Out of Scope

- Renaming public environment variables (`DLP_ROOT_CA_PEM`,
  `DLP_PROVISIONING_ADMIN_*`). These are documented as future alignment items.
- Production PKI design or rotation policy.
- Changing certificate formats (e.g., from PEM to DER/PFX).
