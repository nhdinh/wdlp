# Phase 01.3 Planning Coverage

## Deterministic Gate Declarations

**Requirement probe:** Visible skip — ROADMAP.md assigns Phase 01.3 `Requirements: TBD`, so there are no requirement IDs to probe. The plans retain `requirements: [TBD]` and derive observable predicates directly from the phase goal, D-01 through D-17, RESEARCH.md, and PATTERNS.md.

**No external API integration:** This phase only serves inbound `GET /logs` in a trusted lab; it calls no third-party or external API.

The endpoint remains outside the DLP management-server API surface, so external-API capability rows would be fabricated.

**No schema push:** The planned file set contains no ORM schema, database model, migration, or generated database client. Configuration is a local versioned JSON file parsed by the new crate; no schema-push command is applicable.

**Assumption-delta scan:** The orchestrator reported `detected=false`; no assumption-delta decision is required.

## Multi-Source Coverage Audit

| Source | ID | Feature / constraint | Plan and task | Status | Notes |
|---|---|---|---|---|---|
| GOAL | — | Developers can run a background endpoint debugger and retrieve logs over HTTP | 01.3-01 T1; 01.3-02 T1-T2; 01.3-03 T1-T2 | COVERED | Tracer proves one real read; expansions deliver remote access, SCM lifecycle, and lab verification. |
| REQ | — | Phase has no assigned requirement IDs | All plans | VISIBLE SKIP | `TBD` is preserved; no unassigned v1 requirement is claimed. |
| CONTEXT | D-01 | Separate Windows service | 01.3-02 T2 | COVERED | Dedicated SCM service name and dispatcher. |
| CONTEXT | D-02 | Development-only and outside DLP ecosystem | 01.3-01 T1; 01.3-03 T1 | COVERED | No agent/server dependencies or production packaging. |
| CONTEXT | D-03 | Manual standard-command install/start/stop/remove | 01.3-03 T1-T2 | COVERED | Dedicated runbook and blocking manual lab verification. |
| CONTEXT | D-04 | Debugger availability cannot affect DLP components | 01.3-02 T2; 01.3-03 T2 | COVERED | Independent process/dependency graph and before/after DlpWindowsService check. |
| CONTEXT | D-05 | Dedicated workspace crate; excluded from production packaging | 01.3-01 T1; 01.3-03 T1 | COVERED | Workspace member only; packaging and provisioning remain unchanged. |
| CONTEXT | D-06 | Listen on all interfaces | 01.3-02 T2 | COVERED | Listener binds `0.0.0.0:<configured-port>`. |
| CONTEXT | D-07 | Source-IP allowlist; no identity auth | 01.3-02 T1; 01.3-03 T1-T2 | COVERED | TCP peer address plus firewall RemoteAddress restriction. |
| CONTEXT | D-08 | Trusted IPs in local configuration | 01.3-01 T2; 01.3-03 T1 | COVERED | Strict versioned JSON schema and protected ProgramData file. |
| CONTEXT | D-09 | Missing/invalid/empty-trust configuration falls back to localhost-only | 01.3-01 T2; 01.3-02 T2 | COVERED | Service remains running with no remote clients or authorized folders. |
| CONTEXT | D-10 | Client supplies one absolute path; no discovery/aggregation | 01.3-02 T1 | COVERED | Typed `path` query only. |
| CONTEXT | D-11 | Only canonical direct children of allowlisted folders | 01.3-01 T2 | COVERED | Exact canonical parent equality. |
| CONTEXT | D-12 | Direct read; no cache/copy/archive/retention | 01.3-01 T1-T2 | COVERED | One-shot open/seek/read and immediate response. |
| CONTEXT | D-13 | Configurable hard byte cap and bounded tail | 01.3-01 T2 | COVERED | `max_response_bytes` gates allocation and read size. |
| CONTEXT | D-14 | `GET /logs?path=<absolute-path>&tail=<line-count>` | 01.3-02 T1 | COVERED | Exact route and query names. |
| CONTEXT | D-15 | Success body is raw plain log text | 01.3-01 T1; 01.3-02 T1 | COVERED | No JSON envelope or diagnostic headers. |
| CONTEXT | D-16 | Newest complete lines that fit; no marker | 01.3-01 T2 | COVERED | Edge fragments are excluded and source bytes are not decorated. |
| CONTEXT | D-17 | Standard statuses and short redacted text errors | 01.3-02 T1 | COVERED | Fixed error map with no OS/filesystem detail. |
| RESEARCH | R-01 | Use existing pinned Axum/Tokio/windows-service/Serde stack | 01.3-01 T1 | COVERED | Package audit is present and all five packages are `OK`; no new package family. |
| RESEARCH | R-02 | Separate SCM adapter from application core | 01.3-02 T2 | COVERED | `main.rs`/`service.rs` are thin; core remains portable safe Rust. |
| RESEARCH | R-03 | Fail-closed typed JSON configuration | 01.3-01 T2 | COVERED | Syntax and semantic failures select `LocalhostOnly`. |
| RESEARCH | R-04 | Canonical direct-child authorization before open/read | 01.3-01 T2 | COVERED | Traversal, nested, sibling-prefix, directory, and link escape cases are tested. |
| RESEARCH | R-05 | Bounded complete-line EOF snapshot | 01.3-01 T2 | COVERED | Cap, CRLF, exact-boundary, oversized-line, truncation, and append cases are tested. |
| RESEARCH | R-06 | Authorize actual TCP peer, not forwarding headers | 01.3-02 T1 | COVERED | `ConnectInfo<SocketAddr>` is the only remote identity input. |
| RESEARCH | R-07 | Graceful SCM Stop/Shutdown | 01.3-02 T2 | COVERED | Cancellation drains Axum before `Stopped`. |
| RESEARCH | R-08 | Protected config ACL and scoped manual firewall rule | 01.3-03 T1-T2 | COVERED | Exact `icacls`, `sc.exe`, and NetSecurity commands are documented and verified. |
| RESEARCH | R-09 | Invalid UTF-8 maps to generic failure | 01.3-01 T2 | COVERED | Planner discretion selects `read_failed`; no transcoding or binary response. |
| RESEARCH | R-10 | Do not log paths, content, raw errors, or trust forwarding headers | 01.3-02 T1-T2 | COVERED | Stable lifecycle/request codes only and negative contract tests. |
| RESEARCH | R-11 | Windows-only service/firewall evidence | 01.3-03 T2 | COVERED | LAB-CLIENT01 lifecycle plus permitted/unpermitted source checks. |
| RESEARCH | R-12 | Mutable-path race bounded by protected directories and immediate canonical open | 01.3-01 T2; 01.3-03 T1 | COVERED | Stronger handle-based enforcement is not assumed; runbook requires non-user-writable folders. |
| PATTERNS | P-01 | Root workspace membership | 01.3-01 T1 | COVERED | `Cargo.toml`. |
| PATTERNS | P-02 | Dedicated exact-pinned crate manifest | 01.3-01 T1 | COVERED | `crates/dlp-log-debug-service/Cargo.toml`. |
| PATTERNS | P-03 | Thin SCM executable entry | 01.3-02 T2 | COVERED | `src/main.rs`. |
| PATTERNS | P-04 | SCM state/cancellation adapter | 01.3-02 T2 | COVERED | `src/service.rs`. |
| PATTERNS | P-05 | Typed config and stable internal errors | 01.3-01 T2 | COVERED | `src/config.rs`. |
| PATTERNS | P-06 | Axum route/controller and peer metadata | 01.3-02 T1 | COVERED | `src/http.rs`. |
| PATTERNS | P-07 | Canonical filesystem authorization | 01.3-01 T2 | COVERED | `src/paths.rs`. |
| PATTERNS | P-08 | Bounded tail transformation | 01.3-01 T2 | COVERED | `src/tail.rs`. |
| PATTERNS | P-09 | Endpoint contract tests | 01.3-01 T2; 01.3-02 T1 | COVERED | `tests/endpoint_contract.rs`. |
| PATTERNS | P-10 | Synthetic configuration example | 01.3-03 T1 | COVERED | `config.example.json`. |

## Audit Result

All in-scope GOAL, CONTEXT, RESEARCH, and PATTERNS items are covered. CONTEXT.md contains no deferred ideas. No item is silently omitted or assigned to a later phase.
