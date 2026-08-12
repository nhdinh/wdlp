---
schema_version: 1
open_count: 9
waived_count: 0
fixed_count: 1
total_count: 10
last_updated: 2026-08-12T01:50:17.760Z
---

# Broken Windows Ledger

> Cross-phase defect register. With `workflow.windows_enforce` enabled, `/gsd-ship` blocks while `open_count > 0`.
> Waive with `gsd-tools windows waive <id> "<reason>"` (reason required).
> Mark fixed with `gsd-tools windows fixed <id>`.

| id | phase | kind | file | line | description | status | reason | recorded_at | resolved_at |
|----|-------|------|------|------|-------------|--------|--------|-------------|-------------|
| 1 | 01 | deviation | .planning/STATE.md |  | state.advance-plan could not parse the starter Plan: TBD value; visible State.md position was repaired. | fixed |  | 2026-08-08T08:42:20.609Z | 2026-08-08T08:43:13.247Z |
| 2 | 01 | unrun-verify | migrations/202608070001_walking_skeleton.sql |  | PostgreSQL SQLx migration, checksum-drift, and migration-before-listen evidence were not run; user-authorized SQLite substitution is not equivalent. | open |  | 2026-08-08T12:19:54.770Z |  |
| 3 | 01 | deviation | .planning/STATE.md |  | state.advance-plan and state.update-progress could not parse the existing Plan: 3 of 12 format; visible plan position was repaired. | open |  | 2026-08-08T12:21:11.946Z |  |
| 4 | 01 | unrun-verify | migrations/202608070001_walking_skeleton.sql |  | PostgreSQL migration, real PgPool repository, and migration-before-listener evidence were not run because DATABASE_URL is unavailable. | open |  | 2026-08-08T13:46:13.813Z |  |
| 5 | 01 | unrun-verify | deploy/compose.yaml |  | docker compose config was not run because Docker Compose is unavailable locally. | open |  | 2026-08-10T06:45:28.738Z |  |
| 6 | 01 | unrun-verify | migrations/202608070003_authenticated_routes.sql |  | PostgreSQL migration and readiness runtime evidence remain open under the user-authorized SQLite-only substitute. | open |  | 2026-08-10T06:45:29.791Z |  |
| 7 | 01 | stub | crates/dlp-server/src/routes.rs |  | Bootstrap and administrator handlers return 503 until PgAuthorityRepository and EnrollmentService route-state wiring is completed. | open |  | 2026-08-10T12:53:32.551Z |  |
| 8 | 01 | stub | crates/dlp-server/src/lib.rs |  | RuntimeRepository creates PostgreSQL adapters but protected routes still receive the in-memory RouteRepository adapter. | open |  | 2026-08-10T12:53:33.528Z |  |
| 9 | 01 | unrun-verify | tests/windows/Invoke-AgentServiceSmoke.ps1 |  | LAB-CLIENT01 ConfigurationCache smoke test script does not exist; runtime activation verification could not run | open |  | 2026-08-12T01:49:58.830Z |  |
| 10 | 01 | unrun-verify | scripts/verify-phase1-evidence.ps1 |  | ConfigurationCache evidence scenario is not implemented in verify-phase1-evidence.ps1 ValidateSet | open |  | 2026-08-12T01:50:17.760Z |  |

````json
[
  {
    "id": 1,
    "kind": "deviation",
    "phase": "01",
    "file": ".planning/STATE.md",
    "line": null,
    "description": "state.advance-plan could not parse the starter Plan: TBD value; visible State.md position was repaired.",
    "status": "fixed",
    "reason": "",
    "recorded_at": "2026-08-08T08:42:20.609Z",
    "resolved_at": "2026-08-08T08:43:13.247Z"
  },
  {
    "id": 2,
    "kind": "unrun-verify",
    "phase": "01",
    "file": "migrations/202608070001_walking_skeleton.sql",
    "line": null,
    "description": "PostgreSQL SQLx migration, checksum-drift, and migration-before-listen evidence were not run; user-authorized SQLite substitution is not equivalent.",
    "status": "open",
    "reason": "",
    "recorded_at": "2026-08-08T12:19:54.770Z",
    "resolved_at": null
  },
  {
    "id": 3,
    "kind": "deviation",
    "phase": "01",
    "file": ".planning/STATE.md",
    "line": null,
    "description": "state.advance-plan and state.update-progress could not parse the existing Plan: 3 of 12 format; visible plan position was repaired.",
    "status": "open",
    "reason": "",
    "recorded_at": "2026-08-08T12:21:11.946Z",
    "resolved_at": null
  },
  {
    "id": 4,
    "kind": "unrun-verify",
    "phase": "01",
    "file": "migrations/202608070001_walking_skeleton.sql",
    "line": null,
    "description": "PostgreSQL migration, real PgPool repository, and migration-before-listener evidence were not run because DATABASE_URL is unavailable.",
    "status": "open",
    "reason": "",
    "recorded_at": "2026-08-08T13:46:13.813Z",
    "resolved_at": null
  },
  {
    "id": 5,
    "kind": "unrun-verify",
    "phase": "01",
    "file": "deploy/compose.yaml",
    "line": null,
    "description": "docker compose config was not run because Docker Compose is unavailable locally.",
    "status": "open",
    "reason": "",
    "recorded_at": "2026-08-10T06:45:28.738Z",
    "resolved_at": null
  },
  {
    "id": 6,
    "kind": "unrun-verify",
    "phase": "01",
    "file": "migrations/202608070003_authenticated_routes.sql",
    "line": null,
    "description": "PostgreSQL migration and readiness runtime evidence remain open under the user-authorized SQLite-only substitute.",
    "status": "open",
    "reason": "",
    "recorded_at": "2026-08-10T06:45:29.791Z",
    "resolved_at": null
  },
  {
    "id": 7,
    "kind": "stub",
    "phase": "01",
    "file": "crates/dlp-server/src/routes.rs",
    "line": null,
    "description": "Bootstrap and administrator handlers return 503 until PgAuthorityRepository and EnrollmentService route-state wiring is completed.",
    "status": "open",
    "reason": "",
    "recorded_at": "2026-08-10T12:53:32.551Z",
    "resolved_at": null
  },
  {
    "id": 8,
    "kind": "stub",
    "phase": "01",
    "file": "crates/dlp-server/src/lib.rs",
    "line": null,
    "description": "RuntimeRepository creates PostgreSQL adapters but protected routes still receive the in-memory RouteRepository adapter.",
    "status": "open",
    "reason": "",
    "recorded_at": "2026-08-10T12:53:33.528Z",
    "resolved_at": null
  },
  {
    "id": 9,
    "kind": "unrun-verify",
    "phase": "01",
    "file": "tests/windows/Invoke-AgentServiceSmoke.ps1",
    "line": null,
    "description": "LAB-CLIENT01 ConfigurationCache smoke test script does not exist; runtime activation verification could not run",
    "status": "open",
    "reason": "",
    "recorded_at": "2026-08-12T01:49:58.830Z",
    "resolved_at": null
  },
  {
    "id": 10,
    "kind": "unrun-verify",
    "phase": "01",
    "file": "scripts/verify-phase1-evidence.ps1",
    "line": null,
    "description": "ConfigurationCache evidence scenario is not implemented in verify-phase1-evidence.ps1 ValidateSet",
    "status": "open",
    "reason": "",
    "recorded_at": "2026-08-12T01:50:17.760Z",
    "resolved_at": null
  }
]
````
