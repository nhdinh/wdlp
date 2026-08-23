---
phase: 01-first-encrypted-drive-vertical-slice
reviewed: 2026-08-23T00:00:00Z
depth: standard
files_reviewed: 83
files_reviewed_list:
  - Cargo.toml
  - config/agent.toml.example
  - config/lab.phase1.example.yaml
  - config/lab.roles.example.json
  - config/server.env.example
  - crates/dlp-agent-core/src/client.rs
  - crates/dlp-agent-core/src/config_cache.rs
  - crates/dlp-agent-core/src/health.rs
  - crates/dlp-agent-core/src/lib.rs
  - crates/dlp-agent-core/tests/enrollment_activation.rs
  - crates/dlp-crypto/Cargo.toml
  - crates/dlp-crypto/src/aead.rs
  - crates/dlp-crypto/src/key.rs
  - crates/dlp-crypto/src/lib.rs
  - crates/dlp-domain/Cargo.toml
  - crates/dlp-domain/src/lib.rs
  - crates/dlp-policy/Cargo.toml
  - crates/dlp-policy/src/lib.rs
  - crates/dlp-protocol/Cargo.toml
  - crates/dlp-protocol/src/lib.rs
  - crates/dlp-server/src/ad.rs
  - crates/dlp-server/src/enrollment.rs
  - crates/dlp-server/src/health.rs
  - crates/dlp-server/src/lib.rs
  - crates/dlp-server/src/pki.rs
  - crates/dlp-server/src/repository.rs
  - crates/dlp-server/src/routes.rs
  - crates/dlp-server/src/tls.rs
  - crates/dlp-storage/Cargo.toml
  - crates/dlp-storage/src/format.rs
  - crates/dlp-storage/src/lib.rs
  - crates/dlp-storage/src/path.rs
  - crates/dlp-storage/src/recovery.rs
  - crates/dlp-storage/src/store.rs
  - crates/dlp-storage/tests/integrity.rs
  - crates/dlp-storage/tests/no_plaintext.rs
  - crates/dlp-storage/tests/operations.rs
  - crates/dlp-storage/tests/recovery.rs
  - crates/dlp-storage/tests/roundtrip.rs
  - crates/dlp-windows-drive/Cargo.toml
  - crates/dlp-windows-drive/src/bin/dlp-drive-host.rs
  - crates/dlp-windows-drive/src/filesystem.rs
  - crates/dlp-windows-drive/src/host.rs
  - crates/dlp-windows-drive/src/lib.rs
  - crates/dlp-windows-drive/src/status.rs
  - crates/dlp-windows-drive/src/wildmatch.rs
  - crates/dlp-windows-drive/tests/callback_contract.rs
  - crates/dlp-windows-drive/tests/mounted_smoke.rs
  - crates/dlp-windows-service/Cargo.toml
  - crates/dlp-windows-service/src/credential.rs
  - crates/dlp-windows-service/src/fingerprint.rs
  - crates/dlp-windows-service/src/lib.rs
  - crates/dlp-windows-service/src/pipe.rs
  - crates/dlp-windows-service/src/service.rs
  - crates/dlp-windows-service/src/session.rs
  - crates/dlp-windows-service/tests/session_lifecycle.rs
  - crates/dlpctl/Cargo.toml
  - crates/dlpctl/src/lib.rs
  - crates/dlpctl/src/main.rs
  - deploy/compose.yaml
  - evidence/phase1/manifests/cry-01-aead-store-integrity.json
  - evidence/phase1/requirement-matrix.yaml
  - evidence/phase1/schema/evidence-manifest.schema.json
  - evidence/phase1/security-closure.yaml
  - migrations-sqlite/202608070001_walking_skeleton.sql
  - migrations/202608070001_walking_skeleton.sql
  - migrations/202608070002_enrollment_authority.sql
  - migrations/202608070003_authenticated_routes.sql
  - rust-toolchain.toml
  - scripts/evidence/Phase1.Evidence.psm1
  - scripts/evidence/Phase1.Security.Tests.ps1
  - scripts/lab/Invoke-Dc01Server.ps1
  - scripts/lab/Invoke-Phase1EnvironmentReconcile.ps1
  - scripts/lab/Invoke-TrustedProvisioning.ps1
  - scripts/lab/Reset-DlpPostgres.py
  - scripts/verify-phase1-evidence.ps1
  - scripts/verify-phase1-security.ps1
  - tests/e2e/server_enrollment.rs
  - tests/e2e/walking_skeleton.rs
  - tests/windows/Install-WinFsp.ps1
  - tests/windows/Invoke-AbruptLossHarness.ps1
  - tests/windows/Invoke-AgentServiceSmoke.ps1
  - tests/windows/Invoke-ServiceSessionSmoke.ps1
findings:
  critical: 1
  warning: 1
  info: 0
  total: 2
status: issues_found
---

# Phase 01: Code Review Report

**Reviewed:** 2026-08-23T00:00:00Z
**Depth:** standard
**Files Reviewed:** 83
**Status:** issues_found

## Summary

The scope is the union of existing Phase 01 SUMMARY `key-files`, filtered to exclude planning artifacts, lockfiles, deleted files, ignored outputs, and generated result files, and cross-checked against the Phase 01 conventional-commit history beginning with `ebc0396^`. The review found one security blocker and one Windows resource-lifecycle warning.

The repository's required `cargo clippy --workspace --all-targets --locked -- -D warnings` gate also fails at five locations in `dlp-windows-service`. Those diagnostics are style-only and are intentionally not promoted into findings under this review's no-style-preference rule.

## Critical Issues

### CR-01: One-time enrollment token is accepted through the service process environment

**File:** `crates/dlp-windows-service/src/service.rs:672`
**Issue:** Production configuration reads `DLP_AGENT_ENROLLMENT_TOKEN` directly from the process environment. This keeps a reusable enrollment credential in the long-lived Windows service environment and allows it to be inherited by child processes. It also bypasses the hardened, access-controlled one-time token handoff and deletion lifecycle described by the Phase 01 security closure. A stale or accidentally persisted service environment therefore remains an enrollment authority after the intended handoff should have been consumed and removed.

**Fix:** Remove the environment fallback entirely. Load the token only from the SYSTEM-only handoff file, consume it into a zeroizing buffer, and delete the file before starting enrollment. Keep `ServiceConfig.enrollment_token` unset for normal environment-based configuration.

```rust
Ok(ServiceConfig {
    // ...
    enrollment_token: None,
    // ...
})
```

Pass the token returned by the protected handoff reader directly to the enrollment coordinator, and add a regression test proving that setting `DLP_AGENT_ENROLLMENT_TOKEN` does not enable enrollment.

## Warnings

### WR-01: Named-pipe authentication leaks token handles on error paths

**File:** `crates/dlp-windows-service/src/pipe.rs:605-620`
**Issue:** `open_thread_token_sid_session` closes `token` only on the successful tail path and two early failures. If `ConvertSidToStringSidW`, `pwstr_to_string`, or the `TokenSessionId` query fails, `?` returns before `CloseHandle(token)`. Repeated malformed or failing pipe authentications can therefore exhaust service handles and eventually prevent authentication or other service operations. The string SID allocation can also leak when UTF-16 conversion fails before `LocalFree` runs.

**Fix:** Wrap both owned Windows resources in RAII guards immediately after acquisition (for example, an `OwnedHandle`-style wrapper for `HANDLE` and a small `LocalFree` guard for the SID pointer), then let every return path release them automatically. Do not use fallible `?` operations while raw owned handles remain unguarded.

```rust
let token = OwnedTokenHandle::new(open_thread_token()?);
let string_sid = LocalSidString::from_token(&token)?;
let sid = string_sid.to_string()?;
let session = token.session_id()?;
Ok((sid, session))
```

---

_Reviewed: 2026-08-23T00:00:00Z_
_Reviewer: the agent (gsd-code-reviewer)_
_Depth: standard_
