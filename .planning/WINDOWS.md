---
schema_version: 1
open_count: 3
waived_count: 0
fixed_count: 1
total_count: 4
last_updated: 2026-08-08T13:46:13.813Z
---

# Broken Windows Ledger

> Cross-phase defect register. `/gsd-ship` blocks while `open_count > 0`.
> Waive with `gsd-tools windows waive <id> "<reason>"` (reason required).
> Mark fixed with `gsd-tools windows fixed <id>`.

| id | phase | kind | file | line | description | status | reason | recorded_at | resolved_at |
|----|-------|------|------|------|-------------|--------|--------|-------------|-------------|
| 1 | 01 | deviation | .planning/STATE.md |  | state.advance-plan could not parse the starter Plan: TBD value; visible State.md position was repaired. | fixed |  | 2026-08-08T08:42:20.609Z | 2026-08-08T08:43:13.247Z |
| 2 | 01 | unrun-verify | migrations/202608070001_walking_skeleton.sql |  | PostgreSQL SQLx migration, checksum-drift, and migration-before-listen evidence were not run; user-authorized SQLite substitution is not equivalent. | open |  | 2026-08-08T12:19:54.770Z |  |
| 3 | 01 | deviation | .planning/STATE.md |  | state.advance-plan and state.update-progress could not parse the existing Plan: 3 of 12 format; visible plan position was repaired. | open |  | 2026-08-08T12:21:11.946Z |  |
| 4 | 01 | unrun-verify | migrations/202608070001_walking_skeleton.sql |  | PostgreSQL migration, real PgPool repository, and migration-before-listener evidence were not run because DATABASE_URL is unavailable. | open |  | 2026-08-08T13:46:13.813Z |  |

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
  }
]
````
