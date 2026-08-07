# ADR-009: Windows installer and enterprise deployment method

## Status

Proposed

## Context

The agent must install as a Windows service with minimal user interaction and integrate with common enterprise deployment tools.

## Decision

Ship the agent as an **MSI package** built with WiX v4. The MSI:
- Installs the agent binaries and a companion process executable.
- Registers the agent as a Windows service running under a dedicated service account.
- Creates per-user data directories with appropriate ACLs.
- Supports silent installation for enterprise deployment.

Enrollment can be performed by:
- Running `dlpctl enroll --token <token>` after installation, or
- Passing the enrollment token via an MSI property during silent install.

## Consequences

- **Positive:** Standard Windows deployment; integrates with Group Policy, SCCM, Intune, and endpoint management tools.
- **Positive:** WiX v4 supports Rust-friendly build pipelines.
- **Negative:** Requires Windows build environment and MSI testing.
- **Risk:** Silent install with an embedded token must not leak the token in logs or command-line history.

## References

- PROJECT.md agent installation requirements
- ADR-008: Agent update and rollback mechanism
