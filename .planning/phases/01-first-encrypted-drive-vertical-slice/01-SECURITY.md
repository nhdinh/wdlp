---
phase: 01
slug: first-encrypted-drive-vertical-slice
status: complete
# threats_open = count of OPEN threats at or above workflow.security_block_on severity (the blocking gate)
threats_open: 0
asvs_level: 1
block_on: high
created: 2026-08-15
updated: 2026-08-21
---

# Phase 01 â€” Security

> Per-phase security contract: threat register, accepted risks, and audit trail for the first encrypted drive vertical slice.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| hungdinh-lt orchestration â†’ named VMs | A command executed on the wrong machine could install runtime state, collect invalid evidence, or damage developer tooling. | Orchestration commands, role assertions, cleanup inventories |
| LAB-DC01 server â†’ LAB-SERVER01 PostgreSQL | Migration ordering, concurrent startup, and secret injection determine authoritative state. | Migrations, connection strings, pooled DB sessions |
| LAB-CLIENT01 probe â†’ LAB-DC01 TLS listener | The client must validate the configured server identity; orchestration output is not endpoint evidence. | TLS handshake, server identity, readiness evidence |
| LAB-DC01 provisioning â†’ both DCs and LAB-CLIENT01 | Wrong-machine, single-DC, downgraded WinRM, stale time, or secret-bearing token handling could authorize an untrusted endpoint. | Token handoff, AD computer records, Kerberos WinRM, admin mTLS |
| LAB-CLIENT01 hardware/service â†’ LAB-DC01 enrollment | Local observations, token, CSR, and replacement metadata are untrusted until server authority checks succeed. | Enrollment token digest, CSR, device certificate |
| Endpoint-generated key + server response â†’ DPAPI file | The private key must stay local and the returned identity/profile plus owner/DACL must validate before use. | DPAPI-protected credential blob, ACL, zeroization |
| Device certificate â†’ protected agent route | Chain validity is insufficient; SAN/serial must resolve to an active device on every request. | Device mTLS, active serial lookup, route authorization |

---

## Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation | Status |
|-----------|----------|-----------|----------|-------------|------------|--------|
| T-01-13-01 | Tampering/Denial of service | developer-host cleanup | high | mitigate | Exact computer-role assertion, inventory/dry-run, target allowlist, post-diff, and explicit LLVM/Rust/Hyper-V exclusions in `Invoke-Phase1EnvironmentReconcile.ps1`. | closed |
| T-01-13-02 | Tampering | PostgreSQL migrations | high | mitigate | SQLx checksummed migrations, failure-before-bind, idempotency and concurrent-start tests on LAB-DC01. | closed |
| T-01-13-03 | Information disclosure | runtime secret flow | high | mitigate | Resolve secrets only inside the runtime provider on LAB-DC01; forbid values in arguments, files, logs, evidence, and commits. | closed |
| T-01-13-04 | Spoofing | evidence provenance | high | mitigate | Machine-role guard plus machine-tagged evidence; LAB-CLIENT01 performs the remote TLS probe and hungdinh-lt cannot satisfy runtime claims. | closed |
| T-01-13-05 | Repudiation | cleanup/deployment evidence | medium | mitigate | Hash-sealed sanitized before/after inventories and scenario results under ignored runtime output. | closed |
| T-01-13-06 | Repudiation/Tampering | evidence publication | high | mitigate | Plan 01-17 schema validation, immutable attempts, staleness and artifact checks, clock policy, matrix tier enforcement, and sanitized publication. | closed |
| T-01-13-07 | Spoofing/Information disclosure | trusted provisioning | high | mitigate | LAB-DC01 role guard, two equal DC records, Kerberos WinRM HTTPS/FQDN, exact digest, administrator mTLS, runtime-only token handoff, and approved evidence. | closed |
| T-01-14-01 | Spoofing | enrollment identity | high | mitigate | Exact version-1 observations, LAB-DC01 allowlist and dual-DC checks, single-use token, signed CSR, and transaction-backed replacement. | closed |
| T-01-14-02 | Information disclosure/Elevation | DPAPI credential | high | mitigate | UI-forbidden machine DPAPI, SYSTEM/service-SID owner/DACL, atomic file, ACL revalidation, zeroization, and ordinary-user denial. | closed |
| T-01-14-03 | Spoofing | TLS/mTLS client | high | mitigate | Installed public root, ordinary hostname validation, returned profile validation, active serial lookup, bounded transport, and no bearer fallback. | closed |
| T-01-14-04 | Information disclosure | diagnostics/evidence | high | mitigate | Stable codes/digests only and machine-specific marker scans for secrets, raw serials, paths, and protected content. | closed |
| T-01-14-05 | Elevation/Repudiation | privileged enrollment changes | high | mitigate | Separate digest-bound 01-14 manifest, role guard, baseline/apply/verify/remove, cleanup, and immutable Plan 01-17 evidence. | closed |
| T-01-14-SC | Tampering | dependency graph | high | mitigate | Preserve the approved Cargo.lock and reject any unaudited dependency change. | closed |
| T-01-15-01 | Spoofing/Elevation | session identity | high | mitigate | TokenUser-derived immutable session/SID, idempotent actors, no caller identity/store selector, adjacent/empty/concurrency tests. | closed |
| T-01-15-02 | Spoofing/Elevation | storage IPC | high | mitigate | Service-owned DACL plus connecting SID/session/PID/generation validation and bounded versioned messages. | closed |
| T-01-15-03 | Information disclosure | per-SID key/store | high | mitigate | Random DEK, machine-DPAPI wrapper, service-only ACL, zeroization, and marker scans. | closed |
| T-01-15-04 | Tampering/Denial of service | sign-out/restart | high | mitigate | Atomic draining, reject opens, 30-second bound, cancellation/unmount/resource disposal, and authenticated recovery before remount. | closed |
| T-01-15-05 | Information disclosure | health/evidence | medium | mitigate | Stable codes/opaque digests and machine-tagged marker scans; no raw SID, path, key, or content. | open â€” below high threshold |
| T-01-15-06 | Elevation/Repudiation | privileged session changes | high | mitigate | Separate digest-bound 01-15 manifest, baseline/apply/verify/remove/cleanup, role guard, and Plan 01-17 evidence gates. | closed |
| T-01-16-01 | Spoofing/Repudiation | machine provenance | high | mitigate | Role-guarded commands and required execution machine in every attempt. | closed |
| T-01-16-02 | Spoofing/Elevation | production trust chain | high | mitigate | No fixture providers and negative fingerprint, DC, CSR, cert, revocation, TLS, bundle, and IPC cases. | closed |
| T-01-16-03 | Tampering/Information disclosure | encrypted-store result | high | mitigate | Hash equality, unique markers, authenticate-before-copy, corruption denial, and non-vacuous scans. | closed |
| T-01-16-04 | Information disclosure | evidence/logs | high | mitigate | Strict sanitized schema, forbidden-field/marker scan, runtime-only secrets, and no protected payload bytes. | closed |
| T-01-16-05 | Denial of service | large/application matrix | medium | mitigate | Bounded manifest, per-case timeout/cleanup, deterministic retry, and isolated test-file cleanup. | open â€” below high threshold |
| T-01-16-06 | Elevation | matrix mutations | high | mitigate | Separate digest-bound 01-16 approval, baseline, role allowlist, idempotent apply/verify/remove, cleanup, and pinned tools. | closed |
| T-01-17-01 | Spoofing/Repudiation | evidence identity/provenance | high | mitigate | Schema-required evidence ID, authenticated operator/automation identity, machine role, procedure/build/environment fingerprints, and immutable hashes. | closed |
| T-01-17-02 | Tampering | matrix and attempt history | high | mitigate | Schema validation, immutable attempts, prior/superseded links, dependency-aware staleness, raw-artifact hash/access checks, and sealed matrix digest. | closed |
| T-01-17-03 | Information disclosure | publication/archive | high | mitigate | Field allowlist, source redaction, forbidden-marker scanning, controlled raw storage, and no secret-bearing commands or committed payloads. | closed |
| T-01-17-04 | Elevation/Tampering | privileged lab changes | high | mitigate | Per-plan exact manifests, digest-bound approval, role guard, baseline, idempotent apply/verify/remove, cleanup, pinned versions/hashes, and fresh approval on drift. | closed |
| T-01-17-05 | Spoofing | infrastructure substitutes | high | mitigate | Typed verification tiers and explicit substitute scopes prevent component fixtures from filling infrastructure/runtime rows. | closed |
| T-01-17-06 | Repudiation | visual/independent review | medium | mitigate | Authenticated identity, UTC, target/build, expected/actual result, deviations, matrix digest, and artifact-integrity attestation. | closed |
| T-01-18-01 | Tampering | configuration cache | high | mitigate | Exact-byte strict signature/hash/schema/key/audience/version gates, immutable staging, durable pointer swap, activation mutex/generation, and restart validation. | closed |
| T-01-18-02 | Spoofing | configuration transport | high | mitigate | Consume only Plan 01-14 device mTLS with ordinary server identity validation and no bearer fallback. | closed |
| T-01-18-03 | Information disclosure | diagnostics/evidence | high | mitigate | Stable codes and digests only, machine-specific redaction scans, and Plan 01-17 publication gates. | closed |
| T-01-18-04 | Elevation/Repudiation | service-data cache changes | high | mitigate | Separate digest-bound 01-18 manifest, LAB-CLIENT01 role guard, baseline/apply/verify/remove, cleanup, and immutable evidence. | closed |
| T-01-18-SC | Tampering | existing dependency graph | high | mitigate | Preserve the approved Cargo.lock sources/versions and run slopcheck before accepting any dependency change; no new package is authorized. | closed |
| T-01-19-01 | Spoofing | fingerprint collector | high | mitigate | Documented Windows API sources, exact normalization, server-side confirmation, missing/sentinel rejection, and no agent-selected identity. | closed |
| T-01-19-02 | Denial of service | SCM lifecycle | medium | mitigate | Accurate pending states, bounded stop/shutdown, last-usable state retention, and force-kill/restart checks. | closed |
| T-01-19-03 | Information disclosure | diagnostics | high | mitigate | Stable redacted codes and marker scans across health, logs, evidence, and configuration. | closed |
| T-01-19-04 | Elevation/Repudiation | privileged service changes | high | mitigate | Separate digest-bound 01-19 manifest, role guard, baseline/apply/verify/remove, cleanup, and immutable Plan 01-17 evidence. | closed |
| T-01-19-SC | Tampering | dependency graph | high | mitigate | Preserve the approved Cargo.lock and reject any unaudited dependency change. | closed |
| T-01-20-01 | Tampering/Information disclosure | corruption mapping | high | mitigate | Separate content/metadata corruption, authenticate before copy, exact integrity status, encrypted evidence preservation, and zero-plaintext checks. | closed |
| T-01-20-02 | Tampering/Denial of service | disk-full publication | high | mitigate | Injected NoSpace before pointer publication, exact disk-full status, baseline-hash readback, and no mixed generation. | closed |
| T-01-20-03 | Tampering | restart/reboot recovery | high | mitigate | Authenticate credential, current/LKG, selected pointer, manifest, and chunks before remount. | closed |
| T-01-20-04 | Tampering | WinFsp runtime provenance | high | mitigate | Prior package approval, pinned installer hash, Authenticode verification, LAB-CLIENT01 guard, and delay-load helper only. | closed |
| T-01-20-05 | Elevation/Repudiation | privileged runtime/evidence | high | mitigate | Separate digest-bound 01-20 manifest, baseline/apply/verify/remove/cleanup, role guard, and Plan 01-17 evidence gates. | closed |
| T-01-21-01 | Tampering/Repudiation | abrupt-loss harness | high | mitigate | Guest durability barrier, hungdinh-lt host-side hard-off, no graceful guest event, post-boot hash/provenance capture. | closed |
| T-01-21-02 | Spoofing/Repudiation | machine/tier provenance | high | mitigate | Role-guarded execution machine, verification-tier and substitute checks in `verify-phase1.ps1`. | closed |
| T-01-21-03 | Information disclosure | evidence bundle | high | mitigate | Allowlisted schema, forbidden-field and non-vacuous marker scans, runtime-only secrets, and sealed digest. | closed |
| T-01-21-04 | Repudiation/Tampering | independent review | high | mitigate | Authenticated independent identity, matrix digest, current/superseded attempts, deviation policy, artifact integrity, and retention/hold validation. | closed |
| T-01-21-05 | Elevation | final mutations | high | mitigate | Separate digest-bound 01-21 privilege approval, baseline, strict machine allowlist, idempotent apply/verify/remove, cleanup, and pinned tooling. | closed |
| T-01-22-01 | Spoofing/Tampering | authority repository | high | mitigate | PostgreSQL constraints, row locks, token digest/expiry, exact fingerprint and AD identity, no production in-memory adapter. | closed |
| T-01-22-02 | Spoofing | CSR/certificate issuance | high | mitigate | CSR signature verification and fixed CA:false, digitalSignature, clientAuth, URI-SAN, serial, and 30-day profile. | closed |
| T-01-22-03 | Tampering | replacement transaction | high | mitigate | One SQL transaction for token consumption, prior revocation, new activation, and rollback on every failure. | closed |
| T-01-22-04 | Information disclosure | secrets and diagnostics | high | mitigate | Digest-only token persistence, no raw serial observations/private keys, zeroization, and stable redacted errors/tests. | closed |
| T-01-22-SC | Tampering | dependency graph | high | mitigate | Preserve the approved Cargo.lock; no package install or dependency change is authorized. | closed |
| T-01-23-01 | Spoofing/Elevation | TLS/route partition | high | mitigate | Bootstrap-only optional peer, distinct administrator/device issuers, active-serial lookup, and no forwarded identity/header fallback. | closed |
| T-01-23-02 | Spoofing | directory corroboration | high | mitigate | Explicit independent DC hostname queries, equal enabled identity, bounded timeout, and deny on single/disagreeing result. | closed |
| T-01-23-03 | Spoofing/Tampering | remote hardware collection | high | mitigate | LAB-DC01 role guard, Kerberos WinRM HTTPS/FQDN, exact OS-disk association, fixed normalization, and no agent authority. | closed |
| T-01-23-04 | Information disclosure | provisioning token/admin secrets | high | mitigate | Runtime-provider handoff, no argv/stdout/env-file/log/evidence value, allowlisted publication, and leakage tests. | closed |
| T-01-23-05 | Tampering | production composition | high | mitigate | Concrete provider construction and validation before migration/listener binding; no default/test provider path. | closed |

*Status: open Â· closed Â· accepted risk Â· open â€” below {block_on} threshold (non-blocking)*
*Severity: critical > high > medium > low â€” only open threats at or above `workflow.security_block_on` count toward `threats_open`*
*Disposition: mitigate (implementation required) Â· accept (documented risk) Â· transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|

No accepted risks. All previously reviewed gaps are documented as open threats in the Threat Register.

*Accepted risks do not resurface in future audit runs.*

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open (blocking) | Open (non-blocking) | Accepted | Run By |
|------------|---------------|--------|-----------------|---------------------|----------|--------|
| 2026-08-15 | 62 | 41 | 19 | 2 | 0 | gsd-security-auditor (opus) |
| 2026-08-21 | 62 | 60 | 0 | 2 | 0 | lab/administrator |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [ ] Accepted risks documented in Accepted Risks Log (none)
- [x] `threats_open: 0` confirmed
- [x] `status: complete` set in frontmatter
- [x] Closure manifest `evidence/phase1/security-closure.yaml` verified for all 19 blocking threats
- [x] Signed-off verifier `scripts/verify-phase1-security.ps1 -RequireSignedOff` passed
- [x] Phase 1 FinalGate `scripts/verify-phase1.ps1` passed

**Approval:** complete — 0 blocking threats remain. Phase 01 security gate cleared.

*Closure basis: immutable requirement-matrix digest `5ab3ae9d9baab7412fe951b1490ea2df36bd76dd90eebfe890f09064ec50b414`, 19 verified closure records, independent verifier identity lab/administrator.*

---

## Remediation Routing

- Fix mitigations then re-run: `/gsd-secure-phase 01`
- Or document accepted risks in SECURITY.md and re-run.
