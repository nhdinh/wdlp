# Phase 1 Windows Test Matrix

This directory contains the production-provider Windows/Office test harness for Plan 01-16.

## Files

- `Invoke-Phase1Matrix.ps1` — orchestrates the complete D-16/D-17/D-18 matrix on the approved four-machine lab topology.
- `fixtures/manifest.json` — authoritative manifest covering applications, operations, sizes, negative-trust boundaries, and visual-checklist requirements.
- `results/phase1-evidence.json` — sanitized case-level evidence bundle produced by the matrix run on LAB-CLIENT01.
- `results/phase1-evidence.sha256` — SHA-256 digest of the evidence bundle for integrity verification.

## Scenarios

### VerticalSlice

Runs the production-provider enrollment-to-restart encrypted roundtrip:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests/windows/Invoke-Phase1Matrix.ps1 `
  -CallerMachine hungdinh-lt `
  -ServerMachine LAB-DC01 `
  -SecondaryDcMachine LAB-DC02 `
  -EndpointMachine LAB-CLIENT01 `
  -SecretProvider Runtime `
  -Scenario VerticalSlice
```

### ApplicationsOperationsSizes

Runs the complete D-16 through D-18 matrix:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests/windows/Invoke-Phase1Matrix.ps1 `
  -CallerMachine hungdinh-lt `
  -ServerMachine LAB-DC01 `
  -SecondaryDcMachine LAB-DC02 `
  -EndpointMachine LAB-CLIENT01 `
  -Scenario ApplicationsOperationsSizes
```

## Machine Roles

All matrix actions execute on the binding topology defined in `config/lab.phase1.example.yaml`:

- `hungdinh-lt` — developer orchestrator; source builds and Hyper-V orchestration only.
- `LAB-DC01` — primary directory server, management server, and trusted provisioning station.
- `LAB-DC02` — secondary directory authority for dual-DC corroboration.
- `LAB-SERVER01` — native PostgreSQL database server.
- `LAB-CLIENT01` — endpoint runtime; the only machine that produces application/operation/size evidence.

## Evidence Contract

All evidence follows `phase1-evidence/v1`:

- No protected content, secrets, tokens, private keys, or raw serials.
- Every case records execution-machine provenance, environment fingerprint, source/output hashes where applicable, and a non-vacuous backing-store marker scan.
- Visual checklist rows require an authenticated domain-operator review on LAB-CLIENT01.
- Machine-verifiable rows (PowerShell, Notepad, hash scans, status checks) remain fully automated.
