# ADR-005: Policy signing and key rotation

## Status

Proposed

## Context

Agents must verify that policy/configuration bundles come from the legitimate server and have not been tampered with. The signing scheme must support key rotation without breaking enrolled agents.

Candidates considered:
- **Ed25519** — fast, compact signatures, widely supported in Rust (`ed25519-dalek`).
- **RSA-PSS with SHA-256** — common in enterprise, but larger signatures and slower.
- **ECDSA P-256** — standard, but more complex constant-time requirements.

## Decision

Use **Ed25519** for signing configuration bundles and administrative recovery authorizations.

Key rotation is supported by:
- Embedding a key identifier in each bundle.
- Distributing the current public key to agents during enrollment and via configuration bundles.
- Allowing a short overlap period where both old and new keys are accepted.

## Consequences

- **Positive:** Fast verification, small signatures, strong security margins.
- **Positive:** Good Rust ecosystem support.
- **Negative:** Ed25519 public keys are not X.509-native; may require custom key distribution.
- **Risk:** Key compromise requires revocation and re-enrollment if rotation window is missed.

## Signing Scope

Each agent-consumable bundle is signed over:
- Schema version
- Bundle version
- Effective timestamp
- Offline allowance
- Policy versions and compiled rules
- Agent settings

Agents verify the signature before activating any configuration.

## References

- PROJECT.md security requirements
- THREAT-MODEL.md server impersonation and tampering mitigations
