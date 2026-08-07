# ADR-006: Per-user encryption key hierarchy and recovery behavior

## Status

Proposed

## Context

Each enrolled user needs an isolated encrypted backing store. Keys must be protected by Windows security facilities and tied to the intended user or machine identity. Recovery must be possible if a user forgets credentials or a machine is rebuilt.

Candidates considered:
- **DPAPI / DPAPI-NG** — Windows-native, ties keys to user or machine, but recovery requires domain/enterprise infrastructure.
- **TPM-backed keys via Windows CNG** — strong hardware binding, but complex and less portable.
- **Password-derived keys** — simple but weak if passwords are weak; poor recovery story.

## Decision

Use a **hybrid key hierarchy**:
- Each user store has a unique **data encryption key (DEK)**.
- The DEK is encrypted by a **key encryption key (KEK)** that is protected by Windows DPAPI-NG for the user (and optionally machine).
- The KEK can be escrowed on the server, encrypted by the server's recovery key, for organizational recovery.

## Consequences

- **Positive:** DEK is never stored plaintext; compromise of the KEK wrapper does not expose data without DPAPI access.
- **Positive:** Server escrow enables recovery after machine rebuild or credential loss.
- **Negative:** Recovery requires server involvement and proper authorization.
- **Risk:** If both local DPAPI-protected KEK and server escrow are unavailable, data is unrecoverable.

## Key Hierarchy

```text
User Store
├── DEK (random, per store)
├── KEK (random, per user)
│   ├── Wrapped by DPAPI-NG for user+machine
│   └── Escrowed on server (wrapped by server recovery key)
└── Metadata (encrypted with DEK, authenticated)
```

## Recovery Workflow

1. Administrator requests recovery for a device/user with proper authorization.
2. Server decrypts the escrowed KEK using the recovery key.
3. Server issues a signed, time-limited recovery authorization to the agent.
4. Agent uses the recovered KEK to unwrap the DEK and restore access.

## References

- PROJECT.md protected drive requirements
- THREAT-MODEL.md unauthorized mount and cross-user access
