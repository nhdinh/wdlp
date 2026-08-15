# Script Index

This directory separates supported operator entrypoints from evidence support and lab helpers. For first-time lab setup and daily operations, begin with the documentation index at [.planning/docs/README.md](../.planning/docs/README.md).

## Supported Phase 1 Evidence Runner

- [verify-phase1-evidence.ps1](verify-phase1-evidence.ps1) is the supported Phase 1 evidence runner. Invoke it through the approved Phase 1 workflow; it is the public runner for collecting and validating evidence rather than a replacement for lab orchestration.

## Evidence Support (Not Alternative Operator Commands)

- [evidence/Phase1.Evidence.psm1](evidence/Phase1.Evidence.psm1) is the internal evidence module used by the runner and orchestration scripts.
- [evidence/Phase1.Evidence.Tests.ps1](evidence/Phase1.Evidence.Tests.ps1) and [evidence/Phase1.Privilege.Tests.ps1](evidence/Phase1.Privilege.Tests.ps1) are Pester test support for the evidence implementation and privilege contracts.

Do not substitute the module or tests for the supported evidence runner.

## Lab Operations

[lab/README.md](lab/README.md) catalogs every lab PowerShell/Python helper. It identifies which scripts are manual operator/diagnostic tools and which are normally invoked by an orchestrator, with prerequisites and parameter-valid examples.
