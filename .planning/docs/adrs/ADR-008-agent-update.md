# ADR-008: Agent update and rollback mechanism

## Status

Proposed

## Context

The agent must be installable, upgradable, and uninstallable through standard Windows mechanisms. Updates must be signed and must not leave the endpoint in a broken state.

## Decision

Use **Windows Installer (MSI)** produced by WiX v4 for packaging.

- MSI handles install, service registration, upgrade, repair, and uninstall.
- Major upgrades replace the agent binary while preserving data directories.
- The agent binary verifies downloaded updates via Ed25519 signature before applying them.
- The server controls rollout and minimum required agent version.
- Rollback to a previous agent version is supported only for the same data-format version; incompatible downgrades are blocked.

## Consequences

- **Positive:** Standard enterprise deployment mechanism; supports Group Policy/SCCM/Intune.
- **Positive:** MSI transaction model reduces partial-install risk.
- **Negative:** WiX has a learning curve and requires Windows build tooling.
- **Risk:** Agent downgrade attacks must be blocked by version checking and signature verification.

## Update Flow

1. Server publishes signed update manifest with version, hash, and URL.
2. Agent downloads update to a staging location.
3. Agent verifies signature and hash.
4. Agent triggers MSI install/upgrade through a scheduled or service-mediated process.
5. On failure, agent reports error and preserves last-known-good state.

## References

- PROJECT.md agent lifecycle requirements
- THREAT-MODEL.md agent update/rollback attack
