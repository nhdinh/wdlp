# DLP Documentation Index

This is the documentation front door for the Phase 1 DLP lab. Start with the setup guide for a new lab; use the daily-startup guide only after provisioning is complete. Script entrypoints and their invocation roles live in [scripts/README.md](../../scripts/README.md).

## Start Here

1. [LAB-SETUP-GUIDE.md](LAB-SETUP-GUIDE.md) — complete first-time lab setup order, prerequisites, outcomes, and recovery checks.
2. [HYPERV-DLP-STARTUP-GUIDE.md](HYPERV-DLP-STARTUP-GUIDE.md) — daily VM, database, management-server, and endpoint startup after the lab exists.
3. [HYPERV-VM-START-GUIDE.md](HYPERV-VM-START-GUIDE.md) — generic Hyper-V VM state, start, stop, and cold-start commands.

## Canonical Ownership

| Concern | Canonical document | Use it for |
| --- | --- | --- |
| First-time lab setup | [LAB-SETUP-GUIDE.md](LAB-SETUP-GUIDE.md) | End-to-end setup sequence and setup-specific verification. |
| Daily DLP startup | [HYPERV-DLP-STARTUP-GUIDE.md](HYPERV-DLP-STARTUP-GUIDE.md) | Warm/cold startup, runtime verification, cleanup, and operating troubleshooting. |
| VM power operations | [HYPERV-VM-START-GUIDE.md](HYPERV-VM-START-GUIDE.md) | Generic Hyper-V state and power management only. |
| Environment contract | [ENV-VARS.md](ENV-VARS.md) | Authoritative runtime variable names and acquisition guidance. |
| PKI material | [PEM-KEY-GUIDE.md](PEM-KEY-GUIDE.md) | PEM/key generation and file mapping. |
| PostgreSQL host | [LAB-SERVER01-SETUP.md](LAB-SERVER01-SETUP.md) | Native PostgreSQL provisioning, access controls, and migration checks. |
| Development log debugger | [DLP-LOG-DEBUG-SERVICE.md](DLP-LOG-DEBUG-SERVICE.md) | Isolated development-only debugger lifecycle and security constraints. |

## Operator Guides

- [LAB-SETUP-GUIDE.md](LAB-SETUP-GUIDE.md) — first-time lab provisioning.
- [HYPERV-DLP-STARTUP-GUIDE.md](HYPERV-DLP-STARTUP-GUIDE.md) — daily lab startup and service operation.
- [HYPERV-VM-START-GUIDE.md](HYPERV-VM-START-GUIDE.md) — Hyper-V power-management reference.
- [LAB-SERVER01-SETUP.md](LAB-SERVER01-SETUP.md) — PostgreSQL host provisioning and migration verification.
- [DLP-LOG-DEBUG-SERVICE.md](DLP-LOG-DEBUG-SERVICE.md) — development-only log-debug service runbook.

## Reference and Security

- [ENV-VARS.md](ENV-VARS.md) — DLP Windows endpoint-agent environment variables.
- [PEM-KEY-GUIDE.md](PEM-KEY-GUIDE.md) — Phase 1 lab PEM/KEY collection and generation.
- [THREAT-MODEL.md](THREAT-MODEL.md) — security model and trust-boundary analysis.

## Architecture Decisions

- [ADR-001-winfsp-framework.md](adrs/ADR-001-winfsp-framework.md) — User-space Windows file-system framework selection.
- [ADR-002-api-transport.md](adrs/ADR-002-api-transport.md) — Server API transport and protocol format.
- [ADR-003-database-migrations.md](adrs/ADR-003-database-migrations.md) — Database and migration strategy.
- [ADR-004-policy-expression.md](adrs/ADR-004-policy-expression.md) — Policy expression and compilation model.
- [ADR-005-policy-signing.md](adrs/ADR-005-policy-signing.md) — Policy signing and key rotation.
- [ADR-006-key-hierarchy.md](adrs/ADR-006-key-hierarchy.md) — Per-user encryption key hierarchy and recovery behavior.
- [ADR-007-offline-failsafe.md](adrs/ADR-007-offline-failsafe.md) — Offline expiration and fail-safe behavior.
- [ADR-008-agent-update.md](adrs/ADR-008-agent-update.md) — Agent update and rollback mechanism.
- [ADR-009-windows-installer.md](adrs/ADR-009-windows-installer.md) — Windows installer and enterprise deployment method.
- [ADR-010-windows-versions.md](adrs/ADR-010-windows-versions.md) — Supported Windows versions and file-system semantics.
