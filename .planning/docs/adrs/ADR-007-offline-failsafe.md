# ADR-007: Offline expiration and fail-safe behavior

## Status

Proposed

## Context

Endpoints must continue enforcing policy when disconnected from the server, but indefinite offline enforcement risks stale or revoked policies remaining active.

## Decision

Each signed configuration bundle carries an **offline allowance duration** (default seven days).

- While offline and within the allowance, the agent enforces the last valid signed policy.
- Beginning at 5/7 of the allowance (day five by default), the agent warns the user and reports degraded health.
- After the allowance expires, the agent **locks the protected drive** and denies new file access.
- Data is never deleted due to policy expiration.
- Access is restored by receiving a valid signed policy or a signed, time-limited administrator recovery authorization.

## Consequences

- **Positive:** Clear security boundary; users cannot work around revocation by staying offline.
- **Positive:** No data loss because the drive is locked, not wiped.
- **Negative:** Users on long offline trips must reconnect or obtain recovery authorization.
- **Risk:** Clock rollback attacks require detection; trusted time and monotonic counters should be used where available.

## Implementation Notes

- Policy bundle includes `offline_allowance_seconds` and `effective_at` timestamp.
- Agent records last successful server contact.
- Health reports include "offline degraded" and "offline locked" states.
- Recovery authorization is signed by the server and includes expiry time.

## References

- PROJECT.md offline operation requirements
- THREAT-MODEL.md offline policy circumvention
