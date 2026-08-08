---
schema_version: 1
open_count: 0
waived_count: 0
fixed_count: 1
total_count: 1
last_updated: 2026-08-08T08:43:13.247Z
---

# Broken Windows Ledger

> Cross-phase defect register. `/gsd-ship` blocks while `open_count > 0`.
> Waive with `gsd-tools windows waive <id> "<reason>"` (reason required).
> Mark fixed with `gsd-tools windows fixed <id>`.

| id | phase | kind | file | line | description | status | reason | recorded_at | resolved_at |
|----|-------|------|------|------|-------------|--------|--------|-------------|-------------|
| 1 | 01 | deviation | .planning/STATE.md |  | state.advance-plan could not parse the starter Plan: TBD value; visible State.md position was repaired. | fixed |  | 2026-08-08T08:42:20.609Z | 2026-08-08T08:43:13.247Z |

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
  }
]
````
