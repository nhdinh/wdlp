# Deferred Items

## 01-16 session-host implementation gap

- **Found during:** Plan 01-16 Task 1 live LAB-CLIENT01 verification.
- **Evidence:** The approved deployment path now installs the verified
  dlp-drive-host.exe binary at the service's existing default location, but
  the running service creates an actor without launching it. The host source
  also retains placeholder pipe authentication, deterministic test-key store
  access, and preferred-letter selection.
- **Impact:** The active eligible session has no host process or protected
  P: mount, so Task 1 cannot provide a production encrypted roundtrip and
  Task 2's matrix precondition is not met.
- **Required follow-up:** Plan and implement the missing session actor launch,
  authenticated IPC/key handoff, and real user-session mount lifecycle before
  reattempting the Phase 01 production matrix.
- **Resolution plan:** `01-24-PLAN.md` now owns the implementation and real
  LAB-CLIENT01 proof. `01-16-PLAN.md` depends on 01-24 and resumes only after
  the corrective plan publishes passing runtime evidence.
