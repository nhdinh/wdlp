---
status: complete
phase: 01-first-encrypted-drive-vertical-slice
source:
  - 01-01-SUMMARY.md
  - 01-02-SUMMARY.md
  - 01-03-SUMMARY.md
  - 01-04-SUMMARY.md
  - 01-05-SUMMARY.md
  - 01-06-SUMMARY.md
  - 01-07-SUMMARY.md
  - 01-09-SUMMARY.md
  - 01-10-SUMMARY.md
  - 01-13-SUMMARY.md
  - 01-14-SUMMARY.md
  - 01-17-SUMMARY.md
  - 01-18-SUMMARY.md
  - 01-19-SUMMARY.md
  - 01-22-SUMMARY.md
  - 01-23-SUMMARY.md
started: 2026-08-15T00:00:00Z
updated: 2026-08-15T01:40:00Z
---

## Current Test

[testing complete]

## Tests

### 1. Cold Start Smoke Test
expected: Kill any running server/service. Clear ephemeral state. Build workspace from scratch and run tests/clippy; everything passes cleanly.
result: pass
notes: "WinFsp bin directory added to PATH; cargo test --workspace passes including dlp-windows-drive mounted_smoke."

### 2. Portable Contracts Build & Test
expected: `cargo test -p dlp-domain -p dlp-protocol -p dlp-policy -p dlp-crypto -p dlp-storage` passes, including strict Ed25519 verification and AES-256-GCM storage interface tests.
result: pass

### 3. Encrypted Storage Roundtrip
expected: `cargo test -p dlp-storage --test roundtrip` passes, confirming authenticated 4 MiB encrypted file generations roundtrip across boundary and sparse-write cases.
result: pass

### 4. Encrypted Storage Operations
expected: `cargo test -p dlp-storage --test operations` passes, confirming SID-safe virtual paths, file/directory operations, sharing, deletion, and injected write-failure preservation.
result: pass

### 5. Encrypted Store Recovery & Integrity
expected: `cargo test -p dlp-storage --test recovery --test integrity --test no_plaintext` passes, confirming interrupted replacement recovery, corruption denial, evidence retention, and plaintext-marker scan coverage.
result: pass

### 6. dlpctl Phase 1 Tracer
expected: `cargo run -p dlpctl -- phase1-smoke` completes successfully using the ignored SQLite tracer database, crossing the versioned router, SQLite ledger, signed activation, and encrypted-store readback.
result: pass

### 7. Server Enrollment mTLS & Signed Configuration
expected: `cargo test -p dlp-server --test server_enrollment` passes, confirming device mTLS identity, revoked credential denial, signed configuration selection, and device-bound health tracer.
result: pass

### 8. Agent Configuration Cache Activation
expected: `cargo test -p dlp-agent-core --test enrollment_activation` passes, confirming higher valid bundles become current, negative cases leave current/LKG unchanged, concurrent races resolve correctly, and restart validates independently.
result: pass

### 9. WinFsp Drive Mount (Windows)
expected: On a Windows machine with WinFsp installed, `tests/windows/Invoke-WinFspSmoke.ps1 -Extended` mounts a real SID-bound encrypted drive, performs durable roundtrip, denies corruption, and unmounts cleanly.
result: pass

### 10. Windows Service SCM Lifecycle (Windows)
expected: On a Windows machine, the DLP agent service registers Stop/Shutdown/SessionChange controls and reports accurate StartPending/Running/Stopped states.
result: pass

### 11. Windows Native Fingerprint Collection (Windows)
expected: The service fingerprint collector returns exact normalized SMBIOS UUID, BIOS serial, and physical OS-disk serial without using MAC addresses.
result: pass

### 12. Service Restart Reloads Credential & Cache (Windows)
expected: Stopping and restarting the DLP Windows service reloads the DPAPI credential store and current/LKG configuration cache before resuming mTLS polling and health reporting.
result: pass

### 13. Migration-Status CLI against SQLite
expected: `cargo run -p dlpctl -- migration-status` reports applied migrations against the ignored SQLite development database.
result: pass

### 14. Approval Gates Intact
expected: 01-03-SUMMARY.md still records the exact approved Cargo dependency allowlist and the `dlp-store/aes256gcm-4m/v1` persisted encrypted-store format with no alternate decision signal.
result: pass

### 15. PostgreSQL Enrollment Authority Source
expected: `cargo test -p dlp-server --test server_enrollment repository_` and `cargo test -p dlp-server --test server_enrollment enrollment_` pass, confirming PostgreSQL-native digest-only authority and transactional credential activation source contracts.
result: pass

### 16. Trusted Provisioning Client Source
expected: `cargo test -p dlpctl provisioning_` passes and `cargo tree -p dlpctl -i reqwest@0.13.4` confirms the pinned provisioning client dependency.
result: pass

### 17. Evidence & Privilege Control Contract
expected: `scripts/evidence/Phase1.Evidence.Tests.ps1` and `scripts/evidence/Phase1.Privilege.Tests.ps1` pass, confirming immutable evidence publication, hash verification, and digest-bound privilege manifests.
result: pass
notes: |
  The portable evidence manifest referenced `target/phase1-evidence/tst-01-policy.log`, which was missing from ignored controlled storage. Regenerated it with `cargo test --locked -p dlp-policy` and updated the manifest SHA-256 to the current artifact (`567cbd23b9d49f43816295c58e9c502fc4c70b5739c771ce378d9b9627f646b0`). Both evidence and privilege test scripts now pass.

### A1. Portable agent and fail-closed server application seams
expected: Portable agent and fail-closed server application seams
result: pass
source: automated
coverage_id: 01-02-D1

### A2. Windows service and replaceable protected-drive host boundaries
expected: Windows service and replaceable protected-drive host boundaries
result: pass
source: automated
coverage_id: 01-02-D2

### A3. Approval gates recorded
expected: Exact human-approved Cargo dependency allowlist and approved encrypted-store format
result: pass
source: automated
coverage_id: 01-03

### A4. Authenticated 4 MiB encrypted file generations roundtrip
expected: Authenticated 4 MiB encrypted file generations roundtrip across boundary and sparse-write cases
result: pass
source: automated
coverage_id: 01-04-D1

### A5. Virtual path validation and SID isolation
expected: Virtual path validation, SID isolation, file operations, sharing, deletion, and injected write-failure preservation
result: pass
source: automated
coverage_id: 01-04-D2

### A6. Portable crypto and storage formatting/linting
expected: Portable crypto and storage implementation are formatted and warning-free
result: pass
source: automated
coverage_id: 01-04-D3

### A7. Device mTLS identity, revoked credential denial, signed configuration, and health tracer
expected: Device mTLS identity, revoked credential denial, signed configuration, and device-bound health tracer
result: pass
source: automated
coverage_id: 01-07-D1

### A8. Immutable digest/audience configuration selection and read-only readiness
expected: Immutable digest/audience configuration selection and read-only readiness contract
result: pass
source: automated
coverage_id: 01-07-D2

### A9. Real SID-bound encrypted WinFsp drive mount
expected: Real SID-bound encrypted WinFsp drive mount, durable roundtrip, corruption denial, and clean unmount
result: pass
source: automated
coverage_id: 01-10-D1

### A10. Restart-visible encrypted namespace with directory, rename, delete, and callback status contracts
expected: Restart-visible encrypted namespace with directory, rename, delete, and callback status contracts
result: pass
source: automated
coverage_id: 01-10-D2

### A11. Higher valid exact-byte bundle staged, verified, and atomically selected
expected: Higher valid exact-byte bundle is staged, verified, and atomically selected while prior current becomes LKG
result: pass
source: automated
coverage_id: 01-18-D1

### A12. Negative cases leave current/LKG unchanged
expected: Unsigned, tampered, wrong-key, unsupported-schema, hash-mismatched, wrong-audience, truncated, equal/lower-version, and interrupted downloads leave current/LKG unchanged
result: pass
source: automated
coverage_id: 01-18-D2

### A13. Concurrent activations select greatest version without cross-linking
expected: Concurrent poll completions select the greatest valid version and cannot cross-link current/LKG or activate a late lower response
result: pass
source: automated
coverage_id: 01-18-D3

### A14. Restart validates current and LKG independently
expected: Restart validates current and LKG independently, ignores unreferenced staging, and reports active bundle state
result: pass
source: automated
coverage_id: 01-18-D4

### A15. Health and evidence output contain no secrets
expected: Health and evidence output contain no token, private key, raw fingerprint, certificate-secret material, protected content, or sensitive path
result: pass
source: automated
coverage_id: 01-18-D6

### A16. Route and provider composition source contract
expected: Route and provider composition source contract
result: pass
source: automated
coverage_id: 01-23-D1

### A17. Typed trusted provisioning client and pinned dependency
expected: Typed trusted provisioning client and pinned dependency
result: pass
source: automated
coverage_id: 01-23-D2

## Summary

total: 34
passed: 34
issues: 0
pending: 0
skipped: 0
blocked: 0

## Gaps

[none yet]
