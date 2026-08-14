---
slug: env-setup-instructions
description: Enhance Initialize-DlpEnvironment.ps1 to show step-by-step instructions for obtaining or generating each value at every prompt.
---

# Plan: Add per-prompt value instructions

## Goal
Make the interactive setup script self-guiding: when the user is prompted for any `DLP_*` variable, the script displays concise instructions explaining how to obtain or generate the value.

## Deliverables
- Update `scripts/lab/Initialize-DlpEnvironment.ps1`:
  - Add a `Help` property to each catalog entry.
  - Display the help text before each prompt.
  - Include step-by-step instructions or a PowerShell one-liner to generate the value where applicable.
- Update `SUMMARY.md` and `STATE.md`.
- Commit.

## Instructions to cover

### Server
- `DLP_LISTEN_ADDRESS`: use the lab topology default `0.0.0.0:8443`.
- `DLP_DATABASE_URL`: format `postgres://<user>:<password>@<host>:<port>/<db>`; password comes from PostgreSQL setup.
- `DLP_DATABASE_NAME` / `DLP_DATABASE_USER`: match the PostgreSQL user/database created during server provisioning.
- `DLP_SERVER_CERT_PEM` / `DLP_SERVER_KEY_PEM`: generate a server cert signed by Phase 1 root (see PEM-KEY-GUIDE.md).
- `DLP_ADMIN_CA_CERT_PEM`: generate admin CA.
- `DLP_PHASE1_ROOT_CA_CERT_PEM`: generate self-signed root CA.
- `DLP_DEVICE_ISSUING_CA_CERT_PEM` / `DLP_DEVICE_ISSUING_CA_KEY_PEM`: generate device-issuing CA.
- `DLP_CONFIGURATION_SIGNING_KEY_SEED_HEX`: generate 32 random bytes as hex.

### Active Directory
- `DLP_AD_PRIMARY_LDAPS_URL` / `DLP_AD_SECONDARY_LDAPS_URL`: use `ldaps://<DC>.lab.local:636`.
- `DLP_AD_BASE_DN`: derive from domain, e.g. `DC=lab,DC=local`.
- `DLP_AD_BIND_DN`: create service account.
- `DLP_AD_BIND_PASSWORD`: set the service account password.
- `DLP_AD_CA_CERT_PEM`: export AD CS root CA.

### Trusted provisioning
- `DLP_PROVISIONING_ENDPOINT`: URL from server hostname + `/api/v1/admin/provisioning`.
- `DLP_PROVISIONING_ROOT_CA_PATH`: usually the Phase 1 root CA.
- `DLP_PROVISIONING_ADMIN_CERT_PATH` / `DLP_PROVISIONING_ADMIN_KEY_PATH`: admin client cert/key.
- `DLP_PROVISIONING_AD_OBJECT_GUID`: `Get-ADComputer -Identity LAB-CLIENT01 | Select ObjectGUID`.
- `DLP_PROVISIONING_AD_OBJECT_SID`: `Get-ADComputer -Identity LAB-CLIENT01 | Select ObjectSID`.
- `DLP_PROVISIONING_TOKEN_HANDOFF_PATH`: writable path on LAB-DC01.
- `DLP_PROVISIONING_PREFERRED_DRIVE_LETTER`: choose a free drive letter, e.g. `P`.
- `DLP_PROVISIONING_DLPCTL_PATH`: build dlpctl with `cargo build --release -p dlpctl`.
- `DLP_PROVISIONING_COMPUTER`: target FQDN, e.g. `LAB-CLIENT01.lab.local`.
- `DLP_PROVISIONING_DISK_MODE`: `auto`, `serial`, or `pnp`.
- `DLP_APPROVED_PRIVILEGE_MANIFEST_DIGEST`: compute from `config/lab.phase1.example.yaml`.
- `DLP_LAB_ALLOW_VIRTUAL_DISK_UNIQUE_ID`: `true` for Hyper-V lab, otherwise omit.

### Agent runtime
- `DLP_AGENT_ENROLLMENT_TOKEN`: leave placeholder for trusted provisioning, or paste token.
- `DLP_DEVICE_ID`: use short hostname or asset tag.
- `DLP_SERVER_URL`: `https://LAB-DC01.lab.local:8443`.
- `DLP_ROOT_CA_PEM`: same as Phase 1 root CA.
- `DLP_CONFIGURATION_PUBLIC_KEY_HEX`: derive from configuration signing seed.
- directories/intervals: use defaults.

### Lab orchestration
- VM/server admin credentials: known lab credentials.
- `DLP_PKI_DIR`: local directory for PKI artifacts.
- `DLP_SERVER_HOST`: IP of LAB-DC01.
- `DLP_CONFIGURATION_KEY_ID`: human-readable key label.

## Verification
- Run script with empty env and visually confirm help text appears before each prompt.
- Run with existing env file and confirm no prompts/help shown for resolved values.
- PowerShell parses script cleanly.
